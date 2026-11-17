import time
import unittest
from unittest.mock import patch
from exepeek.ui import App


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
