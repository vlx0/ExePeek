from pathlib import Path
import struct
import tempfile
import unittest
from exepeek.pe import read_pe, has_certificate_table, PEError


def fixture(machine=0x8664, magic=0x20b, dll=False, managed=False):
    base = 112 if magic==0x20b else 96
    optional = bytearray(base+16*8)
    struct.pack_into('<H',optional,0,magic)
    struct.pack_into('<H',optional,68,3)
    struct.pack_into('<II',optional,56,0x2000,0x200)
    struct.pack_into('<I',optional,base-4,16)
    if managed:
        struct.pack_into('<II',optional,base+14*8,0x1000,72)
    dos = bytearray(128)
    dos[:2] = b'MZ'
    struct.pack_into('<I',dos,60,128)
    header = b'PE\0\0'+struct.pack('<HHIIIHH',machine,1,0,0,0,len(optional),2|(0x2000 if dll else 0))
    image=dos+header+optional+bytes(40)
    section=128+24+len(optional)
    struct.pack_into('<IIII',image,section+8,512,0x1000,512,512)
    image.extend(bytes(1024-len(image)))
    if managed:
        struct.pack_into('<I',image,512,72)
    return image


class PETests(unittest.TestCase):
    def parse(self, raw):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder,'fixture.exe')
            path.write_bytes(raw)
            with path.open('rb') as handle:
                return read_pe(handle)

    def test_architectures_and_dll(self):
        self.assertEqual(self.parse(fixture())['machine'],'x64')
        pe = self.parse(fixture(machine=0x14c,magic=0x10b,dll=True))
        self.assertEqual((pe['machine'],pe['format'],pe['kind']),('x86','PE32','DLL'))
        self.assertEqual(self.parse(fixture(machine=0xaa64))['machine'],'ARM64')

    def test_clr_is_metadata_not_runtime_bitness(self):
        self.assertTrue(self.parse(fixture(machine=0x14c,magic=0x10b,managed=True))['managed'])

    def test_clr_must_fit_declared_image(self):
        for image_size in (0, 0x1000, 0x1047):
            data = fixture(managed=True)
            struct.pack_into('<I', data, 128+24+56, image_size)
            with self.subTest(image_size=image_size), self.assertRaises(PEError):
                self.parse(data)
        data = fixture(managed=True)
        struct.pack_into('<I', data, 128+24+56, 0x1048)
        self.assertTrue(self.parse(data)['managed'])

    def test_certificate_table_bounds_and_entry_padding(self):
        def check(raw):
            with tempfile.TemporaryFile() as handle:
                handle.write(raw)
                handle.flush()
                return has_certificate_table(handle)

        for magic in (0x10b, 0x20b):
            base = 96 if magic == 0x10b else 112
            original = fixture(magic=magic)
            directory = 128+24+base+4*8
            self.assertFalse(check(original))
            data = original[:]
            struct.pack_into('<I', data, 128+24+base-4, 4)
            self.assertFalse(check(data))
            # Two entries, including a payload whose length needs alignment.
            table = struct.pack('<IHH', 9, 0x200, 2) + b'x' + bytes(7)
            table += struct.pack('<IHH', 8, 0x200, 0xffff)
            data = original + table
            struct.pack_into('<II', data, directory, 1024, len(table))
            self.assertTrue(check(data))
            for start, length, entry_length in (
                    (0, 8, 8), (1024, 0, 8), (1025, 8, 8),
                    (0xfffffff8, 8, 8), (1024, 0xffffffff, 8),
                    (1024, 7, 8), (1024, 8, 0), (1024, 8, 7),
                    (1024, 8, 0xffffffff), (1024, 9, 9),
                    (1024, 17, 9)):
                malformed = data[:]
                struct.pack_into('<II', malformed, directory, start, length)
                struct.pack_into('<I', malformed, 1024, entry_length)
                with self.subTest(magic=magic, start=start, length=length,
                                  entry_length=entry_length), self.assertRaises(PEError):
                    check(malformed)
                # Signature-only corruption must not discard other metadata.
                self.assertEqual(self.parse(malformed)['format'],
                                 'PE32' if magic == 0x10b else 'PE32+')

    def test_invalid_and_truncated(self):
        for data in (b'hello',fixture()[:100],fixture()[:-1]):
            with self.subTest(size=len(data)), self.assertRaises(PEError):
                self.parse(data)

    def test_hostile_pe_offset_and_directory_count(self):
        data = fixture()
        struct.pack_into('<I',data,60,0xffffffff)
        with self.assertRaises(PEError):
            self.parse(data)

    def test_invalid_clr_rva_is_not_managed(self):
        data=fixture(managed=True)
        struct.pack_into('<II',data,128+24+112+14*8,0xfffffff0,72)
        with self.assertRaises(PEError):
            self.parse(data)
        data = fixture()
        struct.pack_into('<I',data,128+24+108,0xffffffff)
        with self.assertRaises(PEError):
            self.parse(data)
