from pathlib import Path
import sys
import tempfile
import threading
import unittest
from exepeek.client import inspect_cancellable


class ClientTests(unittest.TestCase):
    def test_read_known_pe_without_executing_it(self):
        result=inspect_cancellable(sys.executable,threading.Event())
        self.assertEqual(Path(result['path']),Path(sys.executable))
        self.assertIn(result['pe']['machine'],('x64','x86','ARM64'))
        self.assertTrue(result['version'].get('file_version'))
        self.assertIn(result['signature']['status'],('valid','untrusted','unsigned','unknown'))

    def test_non_pe_fails_as_data(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder,'bad.exe')
            path.write_text('not an executable')
            with self.assertRaises(OSError):
                inspect_cancellable(str(path),threading.Event())
            self.assertEqual(path.read_text(),'not an executable')

    def test_cancel_reaps_child(self):
        stop=threading.Event()
        processes=[]
        def started(proc):
            processes.append(proc)
            stop.set()
        with self.assertRaises(InterruptedError):
            inspect_cancellable(sys.executable,stop,on_process=started)
        self.assertIsNotNone(processes[0].poll())

    def test_timeout_reaps_child(self):
        processes=[]
        with self.assertRaises(TimeoutError):
            inspect_cancellable(sys.executable,threading.Event(),timeout=0,on_process=processes.append)
        self.assertIsNotNone(processes[0].poll())

    def test_callback_failure_reaps_child(self):
        processes=[]
        def callback(proc):
            processes.append(proc)
            raise ValueError('callback failed')
        with self.assertRaises(ValueError):
            inspect_cancellable(sys.executable,threading.Event(),on_process=callback)
        self.assertIsNotNone(processes[0].poll())
