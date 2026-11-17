from pathlib import Path
import struct
import tempfile
import unittest
from exepeek.pe import read_pe, PEError


def fixture(machine=0x8664, magic=0x20b, dll=False, managed=False):
    base = 112 if magic==0x20b else 96
    optional = bytearray(base+16*8)
    struct.pack_into('<H',optional,0,magic)
    struct.pack_into('<H',optional,68,3)
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
