"""Bounded reads of PE headers. Never maps or loads executable code."""
import os
import struct


class PEError(ValueError):
    pass


MACHINES = {0x14c:'x86', 0x8664:'x64', 0xaa64:'ARM64', 0x1c4:'ARM32',
            0x200:'Itanium', 0xa641:'ARM64EC', 0xa64e:'ARM64X'}
SUBSYSTEMS = {1:'Native', 2:'Windows GUI', 3:'Консоль Windows', 7:'POSIX',
              9:'Windows CE', 10:'EFI Application', 11:'EFI Boot Service Driver',
              12:'EFI Runtime Driver', 14:'Xbox', 16:'Windows Boot Application'}


def has_certificate_table(handle):
    """Check certificate-table framing without reading certificate payloads.

    Return False only for an absent directory. Malformed/unsupported PE headers
    and malformed tables raise PEError, separately from ordinary PE metadata.
    """
    size = os.fstat(handle.fileno()).st_size

    def read_at(offset, length):
        if offset < 0 or offset + length > size:
            raise PEError('Таблица сертификатов или заголовок PE обрезаны.')
        handle.seek(offset)
        data = handle.read(length)
        if len(data) != length:
            raise PEError('Таблица сертификатов или заголовок PE обрезаны.')
        return data

    dos = read_at(0, 64)
    if dos[:2] != b'MZ':
        raise PEError('Заголовок MZ отсутствует.')
    offset = struct.unpack_from('<I', dos, 60)[0]
    if offset < 64:
        raise PEError('Некорректное смещение PE.')
    header = read_at(offset, 24)
    if header[:4] != b'PE\0\0':
        raise PEError('Заголовок PE отсутствует.')
    sections = struct.unpack_from('<H', header, 6)[0]
    optional_size = struct.unpack_from('<H', header, 20)[0]
    optional = read_at(offset + 24, optional_size)
    magic = struct.unpack_from('<H', optional)[0] if len(optional) >= 2 else 0
    base = {0x10b: 96, 0x20b: 112}.get(magic)
    if base is None or len(optional) < base:
        raise PEError('Некорректный необязательный заголовок PE.')
    count = struct.unpack_from('<I', optional, base - 4)[0]
    if count > (len(optional) - base) // 8:
        raise PEError('Таблица каталогов PE обрезана.')
    header_end = offset + 24 + optional_size + 40 * sections
    if header_end > size:
        raise PEError('Таблица секций PE обрезана.')
    if count <= 4:
        return False
    start, length = struct.unpack_from('<II', optional, base + 4 * 8)
    if not start and not length:
        return False
    if (not start or not length or start % 8 or start < header_end
            or start > size or length > size - start):
        raise PEError('Некорректные границы таблицы сертификатов.')
    end = start + length
    entries = 0
    while start < end:
        entries += 1
        if entries > 65536:
            raise PEError('Слишком много записей в таблице сертификатов.')
        if end - start < 8:
            raise PEError('Обрезан заголовок WIN_CERTIFICATE.')
        entry_length = struct.unpack_from('<I', read_at(start, 8))[0]
        aligned_length = (entry_length + 7) & ~7
        if entry_length < 8 or aligned_length > end - start:
            raise PEError('Некорректная длина WIN_CERTIFICATE.')
        start += aligned_length
    return True


def read_pe(handle):
    size = os.fstat(handle.fileno()).st_size
    handle.seek(0)
    dos = handle.read(64)
    if len(dos) != 64 or dos[:2] != b'MZ':
        raise PEError('Это не PE-файл Windows: заголовок MZ отсутствует или обрезан.')
    offset = struct.unpack_from('<I', dos, 60)[0]
    if offset < 64 or offset > size-24:
        raise PEError('Некорректное смещение заголовка PE.')
    handle.seek(offset)
    header = handle.read(24)
    if len(header) != 24 or header[:4] != b'PE\0\0':
        raise PEError('Сигнатура PE отсутствует или повреждена.')
    machine, sections = struct.unpack_from('<HH', header, 4)
    optional_size, characteristics = struct.unpack_from('<HH', header, 20)
    section_end = offset+24+optional_size+40*sections
    if section_end > size:
        raise PEError('Обрезаны необязательный заголовок или таблица секций PE.')
    optional = handle.read(optional_size)
    if len(optional) < 2:
        raise PEError('Необязательный заголовок PE отсутствует.')
    magic = struct.unpack_from('<H', optional)[0]
    if magic == 0x10b:
        pe_format, base = 'PE32', 96
    elif magic == 0x20b:
        pe_format, base = 'PE32+', 112
    else:
        raise PEError(f'Неизвестный формат PE: 0x{magic:04X}.')
    if len(optional) < base:
        raise PEError('Обрезан необязательный заголовок PE.')
    count = struct.unpack_from('<I', optional, base-4)[0]
    if count > (len(optional)-base)//8:
        raise PEError('Таблица каталогов PE выходит за пределы заголовка.')
    raw_sections=handle.read(40*sections)
    ranges=[]
    for index in range(sections):
        virtual_size, virtual_address, raw_size, raw_pointer=struct.unpack_from('<IIII',raw_sections,40*index+8)
        if raw_size and (raw_pointer < section_end or raw_pointer > size or raw_size > size-raw_pointer):
            raise PEError('Данные секции PE выходят за пределы файла или перекрывают заголовки.')
        ranges.append((virtual_address,raw_size,raw_pointer))
    managed = False
    if count > 14:
        rva, length = struct.unpack_from('<II', optional, base+14*8)
        if rva or length:
            image_size = struct.unpack_from('<I', optional, 56)[0]
            if not rva or length < 72 or rva+length > image_size:
                raise PEError('Некорректный каталог CLR (.NET).')
            clr_offset=None
            header_size=struct.unpack_from('<I',optional,60)[0]
            if rva+length <= min(header_size,size):
                clr_offset=rva
            for address,raw_size,raw_pointer in ranges:
                if address <= rva and rva-address+length <= raw_size:
                    clr_offset=raw_pointer+rva-address
                    break
            if clr_offset is None:
                raise PEError('Каталог CLR (.NET) не помещается в данные секций.')
            handle.seek(clr_offset)
            clr=handle.read(72)
            if len(clr)!=72 or not 72 <= struct.unpack_from('<I',clr)[0] <= length:
                raise PEError('Повреждён заголовок CLR (.NET).')
            managed=True
    subsystem = struct.unpack_from('<H', optional, 68)[0]
    kind = 'DLL' if characteristics & 0x2000 else 'EXE' if characteristics & 2 else 'PE-образ'
    return {'machine':MACHINES.get(machine, f'Неизвестная (0x{machine:04X})'),
            'machine_code':f'0x{machine:04X}', 'format':pe_format, 'kind':kind,
            'subsystem':SUBSYSTEMS.get(subsystem, f'Неизвестная ({subsystem})'),
            'managed':managed, 'sections':sections}
