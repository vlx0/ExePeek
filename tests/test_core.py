from pathlib import Path
import tempfile
import unittest
from exepeek.core import locked_read


class LockTests(unittest.TestCase):
    def test_inspected_file_cannot_be_rewritten_or_replaced(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder,'original.bin')
            replacement=Path(folder,'replacement.bin')
            path.write_bytes(b'original')
            replacement.write_bytes(b'new file')
            with locked_read(str(path)) as handle:
                self.assertEqual(handle.read(),b'original')
                with self.assertRaises(PermissionError):
                    path.write_bytes(b'modified')
                with self.assertRaises(PermissionError):
                    replacement.replace(path)
            self.assertEqual(path.read_bytes(),b'original')
