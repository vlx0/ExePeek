import time
import unittest
import tempfile
import threading
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch
from exepeek.ui import App


class CloseTests(unittest.TestCase):
    def test_delayed_helper_start_is_cleaned_after_window_close(self):
        entered=threading.Event()
        release=threading.Event()
        processes=[]
        original=subprocess.Popen
        def delayed(*args,**kwargs):
            entered.set()
            if not release.wait(5):
                raise TimeoutError('test gate')
            proc=original(*args,**kwargs)
            processes.append(proc)
            return proc
        with tempfile.TemporaryDirectory() as folder, \
                patch('exepeek.ui.SETTINGS',Path(folder,'settings.json')), \
                patch('exepeek.client.subprocess.Popen',side_effect=delayed):
            app=App()
            app.withdraw()
            app.path.set(sys.executable)
            try:
                app.start()
                self.assertTrue(entered.wait(2))
                app.close()
            finally:
                release.set()
                if app.thread is not None:
                    app.thread.join(timeout=5)
                if app.tk.call('info','commands','.'):
                    app.destroy()
            self.assertFalse(app.thread.is_alive())
            self.assertEqual(len(processes),1)
            self.assertIsNotNone(processes[0].poll())


def result_fixture():
    return {'path':'C:/folder/example.exe','size':1234,
            'pe':{'machine':'x86','machine_code':'0x014C','kind':'EXE','format':'PE32',
                  'subsystem':'Консоль Windows','managed':True},
            'version':{'company':'Self-declared Company','file_version':'1.2.3'},
            'signature':{'status':'valid','label':'Подпись действительна','signer':'Certificate Signer',
                         'code':0,'note':'Только локальная проверка.'},'notes':[]}


class UiTests(unittest.TestCase):
    def setUp(self):
        self.app=App()
        self.app.withdraw()

    def tearDown(self):
        for job in self.app.tk.call('after','info'):
            self.app.after_cancel(job)
        self.app.destroy()

    def test_signer_and_version_company_are_separate(self):
        a=self.app
        a.result=result_fixture()
        a.render()
        self.assertEqual(a.signer.get(),'Certificate Signer')
        self.assertIn(('Компания (свойство файла)','Self-declared Company'),a.rows())
        self.assertIn('разрядность',dict(a.rows())['Каталог CLR (.NET)'])
        with patch.object(a,'clipboard_clear'), patch.object(a,'clipboard_append') as append:
            a.copy_report()
        text=append.call_args.args[0]
        self.assertIn('Подписант сертификата: Certificate Signer',text)
        self.assertIn('Компания (свойство файла): Self-declared Company',text)

    def test_new_path_invalidates_old_result(self):
        a=self.app
        a.result=result_fixture()
        a.render()
        a.set_busy(False)
        a.path.set('C:/different.exe')
        self.assertIsNone(a.result)
        self.assertEqual(a.signer.get(),'—')
        self.assertEqual(str(a.copy_button['state']),'disabled')

    def test_cancel_discards_already_queued_result(self):
        a=self.app
        a.set_busy(True)
        a.stop.set()
        a.events.put(('done',result_fixture()))
        a.poll()
        self.assertIsNone(a.result)
        self.assertFalse(a.busy)
        self.assertIn('остановлено',a.status.get())
        self.assertEqual(str(a.copy_button['state']),'disabled')

    def test_version_failure_notes_are_in_copied_report(self):
        a=self.app
        a.result=result_fixture()
        a.result['notes']=['Сведения о версии не прочитались: ресурс повреждён']
        with patch.object(a,'clipboard_clear'),patch.object(a,'clipboard_append') as append:
            a.copy_report()
        self.assertIn('ресурс повреждён',append.call_args.args[0])

    def test_signature_and_help_scroll_at_minimum_size(self):
        a=self.app
        a.deiconify()
        a.geometry('820x640')
        a.result=result_fixture()
        a.result['signature']['note']='Подробности проверки. '*200
        a.render()
        for index,canvas in ((1,a.trust_canvas),(2,a.help_canvas)):
            a.notebook.select(index)
            a.update()
            region=tuple(map(float,canvas.cget('scrollregion').split()))
            self.assertGreater(region[3],canvas.winfo_height())
            canvas.yview_moveto(1)
            self.assertGreater(canvas.yview()[0],0)
            self.assertAlmostEqual(canvas.yview()[1],1,places=2)

    def test_stop_does_not_show_false_result(self):
        a=self.app
        a.path.set('C:/cancelled.exe')
        with patch('exepeek.ui.inspect_cancellable',side_effect=InterruptedError()):
            a.start()
            deadline=time.monotonic()+3
            while a.busy and time.monotonic()<deadline:
                a.update()
        self.assertFalse(a.busy)
        self.assertIsNone(a.result)
        self.assertIn('остановлено',a.status.get())
