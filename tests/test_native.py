"""Run with python -B -m unittest discover -s tests -p test_native.py.

Windows integration uses Python itself or EXEPEEK_SIGNED_EXE as read-only input.
No inspected file is executed. Temporary fixtures are deleted automatically.
"""
import ctypes
import hashlib
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

from exepeek import native


class ClassificationTests(unittest.TestCase):
    def test_conservative_statuses_and_signed_hresult(self):
        cases = [(0, "valid"), (0x800B0100, "unknown"),
                 (0x80096010, "invalid"), (0x800B0109, "untrusted"),
                 (0x80092013, "unknown"), (0x800B010E, "unknown"),
                 (5, "unknown"), (0xDEADBEEF, "unknown")]
        for code, expected in cases:
            with self.subTest(code=hex(code)):
                self.assertEqual(native._classify(code)[0], expected)
                signed = ctypes.c_int32(code).value
                self.assertEqual(native._classify(signed)[0], expected)

    def test_non_windows_is_explicit(self):
        with patch.object(native.os, "name", "posix"):
            self.assertEqual(native.read_version("unused"), {})
            self.assertEqual(native.verify_signature("unused").status, "unknown")


@unittest.skipUnless(os.name == "nt", "Windows native APIs required")
class WindowsTests(unittest.TestCase):
    def test_64_bit_layout(self):
        if ctypes.sizeof(ctypes.c_void_p) == 8:
            self.assertEqual(ctypes.sizeof(native._FileInfo), 32)
            self.assertEqual(ctypes.sizeof(native._TrustData), 88)
            self.assertEqual(native._ProviderCertPrefix.pCert.offset, 8)

    def test_unsigned_pe_without_version_and_unicode_path(self):
        # Minimal PE32 image, with no certificate table or resource directory.
        image = bytearray(1024)
        image[:2] = b"MZ"
        struct.pack_into("<I", image, 0x3C, 0x80)
        image[0x80:0x84] = b"PE\0\0"
        struct.pack_into("<HHIIIHH", image, 0x84, 0x14C, 1, 0, 0, 0, 224, 0x102)
        opt = 0x98
        struct.pack_into("<H", image, opt, 0x10B)
        struct.pack_into("<I", image, opt + 28, 0x400000)
        struct.pack_into("<II", image, opt + 32, 0x1000, 0x200)
        struct.pack_into("<II", image, opt + 56, 0x2000, 0x200)
        struct.pack_into("<H", image, opt + 68, 3)
        struct.pack_into("<I", image, opt + 92, 16)
        section = opt + 224
        image[section:section + 8] = b".text\0\0\0"
        struct.pack_into("<IIII", image, section + 8, 1, 0x1000, 0x200, 0x200)
        struct.pack_into("<I", image, section + 36, 0x60000020)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "пример unsigned.exe"
            path.write_bytes(image)
            before = hashlib.sha256(path.read_bytes()).digest()
            self.assertEqual(native.read_version(path), {})
            result = native.verify_signature(path)
            self.assertEqual(result.status, "unsigned", result)
            self.assertEqual(result.code, 0x800B0100)
            self.assertEqual(result.signer, "")
            self.assertIn("каталоги", result.note)
            self.assertIn("отключена", result.note)
            self.assertEqual(hashlib.sha256(path.read_bytes()).digest(), before)

    def test_missing_file_is_unknown(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "missing.exe"
            self.assertEqual(native.read_version(path), {})
            self.assertEqual(native.verify_signature(path).status, "unknown")

    def test_state_closed_after_failure_and_signer_error(self):
        for result_code in (0, ctypes.c_int32(0x80096010).value):
            calls = []

            def verify(hwnd, action, pointer):
                trust = ctypes.cast(pointer, ctypes.POINTER(native._TrustData)).contents
                calls.append(trust.dwStateAction)
                self.assertEqual(trust.dwUIChoice, 2)
                self.assertEqual(trust.fdwRevocationChecks, 0)
                self.assertEqual(trust.dwProvFlags, 0x1010)
                self.assertEqual(trust.dwUnionChoice, 1)
                trust.hWVTStateData = 123
                return result_code

            with patch.object(native, "_dll"), patch.object(native, "_bind", return_value=verify), \
                    patch.object(native, "_signer", side_effect=OSError("identity unavailable")):
                result = native.verify_signature(sys.executable)
            self.assertEqual(calls, [1, 2])
            self.assertEqual(result.code, result_code & 0xFFFFFFFF)
            self.assertEqual(result.signer, "")

    def test_signed_executable_and_tampered_copy(self):
        path = Path(os.environ.get("EXEPEEK_SIGNED_EXE", sys.executable))
        before = hashlib.sha256(path.read_bytes()).digest()
        signature = native.verify_signature(path)
        if signature.status == "unsigned" and "EXEPEEK_SIGNED_EXE" not in os.environ:
            self.skipTest("Python has no embedded signature; set EXEPEEK_SIGNED_EXE")
        self.assertIn(signature.status, {"valid", "untrusted"}, signature)
        if signature.status == "valid":
            self.assertEqual(signature.code, 0)
        self.assertTrue(signature.signer, "Provider should expose this fixture's signer")
        version = native.read_version(path)
        self.assertTrue(version.get("file_version"), version)
        self.assertEqual(hashlib.sha256(path.read_bytes()).digest(), before)
        data = bytearray(path.read_bytes())
        self.assertEqual(data[:2], b"MZ")
        # DOS stub bytes are covered by Authenticode; leave PE offsets intact.
        data[0x40] ^= 1
        with tempfile.TemporaryDirectory() as folder:
            changed = Path(folder) / "tampered.exe"
            changed.write_bytes(data)
            result = native.verify_signature(changed)
            self.assertEqual(result.status, "invalid", result)
            self.assertEqual(result.code, 0x80096010)
            self.assertEqual(changed.read_bytes(), data)

    def test_signed_copy_with_corrupt_certificate_framing(self):
        path = Path(os.environ.get("EXEPEEK_SIGNED_EXE", sys.executable))
        original = path.read_bytes()
        signature = native.verify_signature(path)
        if signature.status == "unsigned" and "EXEPEEK_SIGNED_EXE" not in os.environ:
            self.skipTest("Python has no embedded signature; set EXEPEEK_SIGNED_EXE")
        self.assertIn(signature.status, {"valid", "untrusted"}, signature)
        optional = struct.unpack_from('<I', original, 60)[0] + 24
        base = 112 if struct.unpack_from('<H', original, optional)[0] == 0x20b else 96
        directory = optional + base + 4*8
        certificate, length = struct.unpack_from('<II', original, directory)
        self.assertGreater(length, 8)
        with tempfile.TemporaryDirectory() as folder:
            changed = Path(folder) / 'corrupt-certificate.exe'
            for offset, value in ((certificate, 0xffffffff), (certificate, 0),
                                  (directory, 0xffffffff), (directory+4, 0xffffffff)):
                data = bytearray(original)
                struct.pack_into('<I', data, offset, value)
                changed.write_bytes(data)
                with self.subTest(offset=offset, value=value):
                    result = native.verify_signature(changed)
                    self.assertEqual(result.status, 'unknown', result)
                    self.assertEqual(result.code, 0x800B0100)
                    self.assertIn('WIN_CERTIFICATE' if offset == certificate else
                                  'границы', result.note)
                    from exepeek.core import inspect_file
                    report = inspect_file(str(changed))
                    self.assertEqual(report['signature']['status'], 'unknown')
                    self.assertTrue(report['version'].get('file_version'))
                    self.assertEqual(changed.read_bytes(), data)
            # Well-framed but unrecognized entries also cannot prove absence.
            data = bytearray(original)
            struct.pack_into('<IHH', data, certificate, length, 0x200, 0xffff)
            changed.write_bytes(data)
            result = native.verify_signature(changed)
            self.assertEqual(result.status, 'unknown', result)
            self.assertNotEqual(result.code, 0)
        self.assertEqual(path.read_bytes(), original)

    def test_nosignature_requires_absent_table_and_always_closes_state(self):
        # A provider can return NOSIGNATURE for malformed or unrecognized data.
        from exepeek.pe import PEError
        cases = [(False, 'unsigned'), (True, 'unknown'),
                 (PEError('bad certificate framing'), 'unknown')]
        for table, expected in cases:
            calls = []

            def verify(hwnd, action, pointer):
                trust = ctypes.cast(pointer, ctypes.POINTER(native._TrustData)).contents
                calls.append(trust.dwStateAction)
                self.assertEqual(trust.dwProvFlags, 0x1010)
                trust.hWVTStateData = 123
                return ctypes.c_int32(0x800B0100).value

            kwargs = {'side_effect': table} if isinstance(table, Exception) else {'return_value': table}
            with self.subTest(table=table), patch.object(native, '_dll'), \
                    patch.object(native, '_bind', return_value=verify), \
                    patch.object(native, 'has_certificate_table', **kwargs):
                result = native.verify_signature(sys.executable)
            self.assertEqual(result.status, expected)
            self.assertEqual(result.code, 0x800B0100)
            self.assertEqual(calls, [1, 2])


if __name__ == "__main__":
    unittest.main()
