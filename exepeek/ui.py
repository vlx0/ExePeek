"""ExePeek dark Russian UI."""
import ctypes
import json
import os
from pathlib import Path
import queue
import threading
import tkinter as tk
from tkinter import ttk, filedialog
from .client import inspect_cancellable
from .instance import TITLE

BG, CARD, FG, MUTED = '#101216', '#191d24', '#edf1f7', '#919baa'
EDGE, ACCENT = '#2a323f', '#9bbbfa'
GOOD, WARN, BAD = '#9cdbb0', '#e9cc87', '#f0a1a1'
SETTINGS = Path(os.environ.get('APPDATA',str(Path.home()))) / 'ExePeek' / 'settings.json'


def safe(text):
    return ''.join(char if char >= ' ' else ' ' for char in str(text))


def size_text(size):
    return f'{size:,} Б · {size/1024**2:.2f} МиБ'.replace(',',' ')


def scroll_tab(parent):
    outer=tk.Frame(parent,bg=CARD)
    canvas=tk.Canvas(outer,bg=CARD,bd=0,highlightthickness=0)
    scroll=ttk.Scrollbar(outer,orient='vertical',command=canvas.yview)
    canvas.configure(yscrollcommand=scroll.set)
    scroll.pack(side='right',fill='y')
    canvas.pack(side='left',fill='both',expand=True)
    body=tk.Frame(canvas,bg=CARD,padx=16,pady=16)
    window=canvas.create_window(0,0,window=body,anchor='nw')
    body.bind('<Configure>',lambda _e:canvas.configure(scrollregion=canvas.bbox('all')))
    canvas.bind('<Configure>',lambda e:canvas.itemconfigure(window,width=e.width))
    return outer,body,canvas


def bind_tab_wheel(body,canvas):
    def wheel(event):
        if event.delta:
            steps=int(-event.delta/120) or (-1 if event.delta>0 else 1)
            canvas.yview_scroll(steps,'units')
        return 'break'
    def bind(widget):
        widget.bind('<MouseWheel>',wheel)
        for child in widget.winfo_children():
            bind(child)
    bind(body)
    canvas.bind('<MouseWheel>',wheel)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(TITLE)
        self.geometry('960x740')
        self.minsize(820,640)
        self.configure(bg=BG)
        self.events = queue.Queue()
        self.stop = threading.Event()
        self.busy = False
        self.result = None
        self.thread = None
        self.process = None
        self.poll_job = None
        try:
            saved = json.loads(SETTINGS.read_text(encoding='utf-8'))
            if not isinstance(saved,dict):
                saved = {}
        except (OSError,ValueError):
            saved = {}
        self.configure_style()
        pad = tk.Frame(self,bg=BG)
        pad.pack(fill='both',expand=True,padx=26,pady=22)
        head = tk.Frame(pad,bg=BG)
        head.pack(fill='x')
        icon=tk.Canvas(head,width=42,height=48,bg=BG,bd=0,highlightthickness=0)
        icon.pack(side='left',padx=(0,14))
        icon.create_polygon(5,2,27,2,37,12,37,45,5,45,fill='#202c40',outline='#59749e',width=1)
        icon.create_line(27,2,27,12,37,12,fill='#59749e',width=1)
        icon.create_text(21,29,text='PE',fill=ACCENT,font=('Consolas',12,'bold'))
        title=tk.Frame(head,bg=BG)
        title.pack(side='left')
        tk.Label(title,text='ExePeek',bg=BG,fg=FG,font=('Segoe UI Semibold',23)).pack(anchor='w')
        tk.Label(title,text='Версия, архитектура и подпись файла',bg=BG,fg=MUTED,
                 font=('Segoe UI',10)).pack(anchor='w',pady=(1,0))
        tk.Label(head,text='ТОЛЬКО ЧТЕНИЕ',bg='#1b2630',fg='#a2bdc8',font=('Segoe UI Semibold',8),
                 padx=10,pady=6).pack(side='right')
        panel = tk.Frame(pad,bg=CARD,padx=14,pady=12,highlightbackground=EDGE,highlightthickness=1)
        panel.pack(fill='x',pady=(20,0))
        tk.Label(panel,text='EXE / DLL',bg=CARD,fg=MUTED,font=('Segoe UI Semibold',8)).pack(anchor='w',pady=(0,7))
        line = tk.Frame(panel,bg=CARD)
        line.pack(fill='x')
        self.path = tk.StringVar(value=str(saved.get('path','')))
        self.path_entry = ttk.Entry(line,textvariable=self.path)
        self.path_entry.grid(row=0,column=0,sticky='ew')
        line.columnconfigure(0,weight=1)
        self.browse = ttk.Button(line,text='Выбрать…',command=self.choose,cursor='hand2')
        self.browse.grid(row=0,column=1,padx=8)
        self.inspect_button = ttk.Button(line,text='Проверить',command=self.start,
                                         style='Primary.TButton',cursor='hand2')
        self.inspect_button.grid(row=0,column=2)
        self.stop_button = ttk.Button(line,text='Стоп',command=self.stop.set,state='disabled')
        self.stop_button.grid(row=0,column=3,padx=(8,0))
        self.stop_button.grid_remove()
        track = tk.Frame(pad,bg=BG,height=3)
        track.pack(fill='x',pady=(0,10))
        track.pack_propagate(False)
        self.progress = ttk.Progressbar(track,style='Scan.Horizontal.TProgressbar',mode='determinate')
        self.progress.pack(fill='both',expand=True)
        self.status = tk.StringVar(value='Выберите файл, чтобы прочитать его свойства.')
        self.status_label = tk.Label(pad,textvariable=self.status,bg=BG,fg=MUTED,anchor='w',justify='left',wraplength=900)
        self.status_label.pack(fill='x',pady=(0,12))
        pad.bind('<Configure>',lambda event:self.status_label.configure(wraplength=max(300,event.width)))
        cards = tk.Frame(pad,bg=BG)
        cards.pack(fill='x',pady=(0,18))
        self.arch = tk.StringVar(value='—')
        self.version = tk.StringVar(value='—')
        self.auth = tk.StringVar(value='—')
        self.auth_card = None
        self.metric_labels=[]
        self.metric_rules=[]
        for index,(label,value) in enumerate([('АРХИТЕКТУРА PE',self.arch),('ВЕРСИЯ ФАЙЛА',self.version),('ВСТРОЕННАЯ ПОДПИСЬ',self.auth)]):
            box = tk.Frame(cards,bg=CARD,highlightbackground=EDGE,highlightthickness=1)
            box.grid(row=0,column=index,sticky='nsew',padx=(0,10) if index<2 else 0)
            cards.columnconfigure(index,weight=1,uniform='cards')
            rule=tk.Frame(box,bg=EDGE,height=2)
            rule.pack(fill='x')
            self.metric_rules.append(rule)
            inside=tk.Frame(box,bg=CARD,padx=13,pady=11)
            inside.pack(fill='both',expand=True)
            tk.Label(inside,text=label,bg=CARD,fg=MUTED,font=('Segoe UI Semibold',8)).pack(anchor='w')
            lab = tk.Label(inside,textvariable=value,bg=CARD,fg=FG,font=('Segoe UI Semibold',14),wraplength=240,justify='left',anchor='w')
            lab.pack(fill='x',pady=(5,0))
            self.metric_labels.append(lab)
            inside.bind('<Configure>',lambda event,widget=lab:widget.configure(wraplength=max(100,event.width-26)))
            if index==2:
                self.auth_card=lab
        foot = tk.Frame(pad,bg=BG)
        foot.pack(side='bottom',fill='x',pady=(12,0))
        tk.Label(foot,text='День 86 / 365 · неделя «Софт»',bg=BG,fg=MUTED,font=('Segoe UI',8)).pack(side='left')
        tk.Label(foot,text='v1.0.0 · darkshade',bg=BG,fg=MUTED,font=('Segoe UI',8)).pack(side='right')
        actions = tk.Frame(pad,bg=BG)
        actions.pack(side='bottom',fill='x',pady=(12,0))
        self.copy_button = ttk.Button(actions,text='Копировать отчёт',command=self.copy_report,state='disabled')
        self.copy_button.pack(side='left')
        self.folder_button = ttk.Button(actions,text='Открыть папку',command=self.open_folder,state='disabled')
        self.folder_button.pack(side='left',padx=8)
        self.feedback = tk.StringVar()
        tk.Label(actions,textvariable=self.feedback,bg=BG,fg=MUTED,anchor='w').pack(side='left',padx=8)
        notebook = self.notebook = ttk.Notebook(pad)
        notebook.pack(fill='both',expand=True)
        general = tk.Frame(notebook,bg=CARD)
        trust_outer,trust,self.trust_canvas=scroll_tab(notebook)
        help_outer,help_tab,self.help_canvas=scroll_tab(notebook)
        notebook.add(general,text='  Обзор  ')
        notebook.add(trust_outer,text='  Подпись  ')
        notebook.add(help_outer,text='  Справка  ')
        self.selected_value=tk.StringVar(value='Выберите свойство — полное значение появится здесь')
        ttk.Entry(general,textvariable=self.selected_value,state='readonly').pack(side='bottom',fill='x',padx=12,pady=10)
        table_frame=tk.Frame(general,bg=CARD)
        table_frame.pack(fill='both',expand=True)
        self.table = ttk.Treeview(table_frame,columns=('field','value'),show='headings',selectmode='browse')
        self.table.heading('field',text='Свойство',anchor='w')
        self.table.heading('value',text='Значение',anchor='w')
        self.table.column('field',width=235,minwidth=190,stretch=False)
        self.table.column('value',width=550,minwidth=200)
        scroll = ttk.Scrollbar(table_frame,orient='vertical',command=self.table.yview)
        self.table.configure(yscrollcommand=scroll.set)
        self.table.pack(side='left',fill='both',expand=True)
        scroll.pack(side='right',fill='y')
        self.table.tag_configure('even',background='#1e2126')
        self.table.bind('<<TreeviewSelect>>',self.show_value)
        self.empty=tk.Label(self.table,text='Выберите EXE или DLL\n\nЗдесь появятся свойства файла',
                            bg=CARD,fg=MUTED,font=('Segoe UI',10),justify='center')
        self.empty.place(relx=.5,rely=.55,anchor='center')
        trust_banner=tk.Frame(trust,bg='#202732',highlightthickness=1,highlightbackground=EDGE)
        trust_banner.pack(fill='x',pady=(0,18))
        self.trust_accent=tk.Frame(trust_banner,bg=EDGE,width=3)
        self.trust_accent.pack(side='left',fill='y')
        banner_inside=tk.Frame(trust_banner,bg='#202732',padx=13,pady=12)
        banner_inside.pack(side='left',fill='both',expand=True)
        tk.Label(banner_inside,text='ВСТРОЕННАЯ AUTHENTICODE',bg='#202732',fg=MUTED,
                 font=('Segoe UI Semibold',8)).pack(anchor='w',pady=(0,5))
        self.signature_label = tk.Label(banner_inside,text='Подпись ещё не проверена',bg='#202732',fg=MUTED,
                                       font=('Segoe UI Semibold',15),anchor='w',justify='left')
        self.signature_label.pack(fill='x')
        banner_inside.bind('<Configure>',lambda event:self.signature_label.configure(wraplength=max(200,event.width-26)))
        self.signer = tk.StringVar(value='—')
        self.code = tk.StringVar(value='—')
        for label,var in [('ПОДПИСАНТ СЕРТИФИКАТА',self.signer),('КОД WINDOWS',self.code)]:
            tk.Label(trust,text=label,bg=CARD,fg=MUTED,font=('Segoe UI Semibold',8)).pack(anchor='w',pady=(0,5))
            ttk.Entry(trust,textvariable=var,state='readonly').pack(fill='x',pady=(0,12))
        self.trust_note = tk.StringVar(value='Здесь будет результат проверки Windows.')
        note = tk.Label(trust,textvariable=self.trust_note,bg=CARD,fg=MUTED,justify='left',anchor='nw',wraplength=800)
        note.pack(fill='x')
        trust.bind('<Configure>',lambda event: note.configure(wraplength=max(250,event.width-32)),add='+')
        help_labels=[]
        for title,text in [
            ('Свойства файла','Компанию и версию указывает автор файла. Эти поля сами по себе не подтверждают издателя.'),
            ('Что означает подпись','Подписант берётся из сертификата. Отсутствие подписи не означает вирус; действительная подпись не гарантирует безопасность.'),
            ('Локальная проверка','Свежий сетевой статус отзыва сертификата не запрашивается. Проверяются встроенные подписи; каталоги Windows не проверяются.'),
            ('Архитектура и .NET','Показывается поле машины в PE. Для .NET формат PE32 не всегда означает запуск только в 32-битном режиме.'),
            ('Открытие папки','Кнопка открывает расположение файла. Сам EXE или DLL не запускается.')]:
            tk.Label(help_tab,text=title,bg=CARD,fg=FG,font=('Segoe UI Semibold',11)).pack(anchor='w',pady=(0,5))
            label=tk.Label(help_tab,text=text,bg=CARD,fg=MUTED,justify='left',anchor='nw',wraplength=800,font=('Segoe UI',10))
            label.pack(fill='x',pady=(0,18))
            help_labels.append(label)
        help_tab.bind('<Configure>',lambda event:[label.configure(wraplength=max(250,event.width-32)) for label in help_labels],add='+')
        bind_tab_wheel(trust,self.trust_canvas)
        bind_tab_wheel(help_tab,self.help_canvas)
        self.path.trace_add('write',self.invalidate)
        self.protocol('WM_DELETE_WINDOW',self.close)
        self.poll_job=self.after(80,self.poll)

    def configure_style(self):
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure('.', background=BG, foreground=FG, fieldbackground=CARD,
                        font=('Segoe UI', 10), bordercolor=EDGE, lightcolor=EDGE, darkcolor=EDGE)
        style.configure('TEntry', padding=(10, 8), borderwidth=1, relief='flat',
                        insertcolor=FG, selectbackground='#354e74', selectforeground=FG)
        style.map('TEntry', bordercolor=[('focus', '#698bbe')],
                  fieldbackground=[('disabled', '#202226'), ('readonly', '#17191d')],
                  foreground=[('disabled', '#6e7480'), ('readonly', MUTED)])
        style.configure('TButton', padding=(13, 8), background='#292d34', foreground=FG,
                        borderwidth=0, relief='flat', focusthickness=0)
        style.map('TButton', background=[('disabled', '#202226'), ('pressed', '#373e48'),
                                        ('active', '#343a43')],
                  foreground=[('disabled', '#626873')], bordercolor=[('focus', '#698bbe')])
        style.configure('Primary.TButton', background=ACCENT, foreground='#101a2a',
                        font=('Segoe UI Semibold', 10))
        style.map('Primary.TButton', background=[('disabled', '#283346'), ('pressed', '#739cdd'),
                                                ('active', '#aecbff')],
                  foreground=[('disabled', '#6c7c94'), ('!disabled', '#101a2a')])
        style.configure('Treeview', background=CARD, fieldbackground=CARD,
                        foreground=FG, rowheight=32, borderwidth=0, relief='flat')
        style.configure('Treeview.Heading', background='#202631', foreground=MUTED,
                        font=('Segoe UI Semibold', 9), padding=(10, 8), borderwidth=0, relief='flat')
        style.map('Treeview.Heading', background=[('active', '#2b3038')])
        style.map('Treeview', background=[('selected', '#30486b')], foreground=[('selected', '#ffffff')])
        for orient in ('Vertical', 'Horizontal'):
            name = orient + '.TScrollbar'
            style.configure(name, background='#383d46', troughcolor=CARD, arrowcolor=MUTED,
                            borderwidth=0, arrowsize=12, gripcount=0, relief='flat')
            style.map(name, background=[('active', '#505967'), ('pressed', '#637083')])
        style.configure('Scan.Horizontal.TProgressbar', background=ACCENT, troughcolor=BG,
                        borderwidth=0, lightcolor=ACCENT, darkcolor=ACCENT, thickness=3)
        style.configure('TCombobox', padding=6, arrowcolor=FG)
        style.map('TCombobox', fieldbackground=[('readonly',CARD)], foreground=[('readonly',FG)])
        style.configure('TCheckbutton', background=BG, foreground=MUTED, padding=(4,6),
                        indicatorbackground=CARD, indicatorforeground=FG)
        style.map('TCheckbutton', background=[('active',BG)], foreground=[('selected',FG)],
                  indicatorbackground=[('selected','#5278ad')])

        style.configure('TNotebook',background=BG,borderwidth=0,tabmargins=(0,0,0,0))
        style.configure('TNotebook.Tab',padding=(18,10),background=BG,foreground=MUTED,borderwidth=0,
                        font=('Segoe UI Semibold',10),lightcolor=BG,darkcolor=BG,bordercolor=BG,focuscolor=CARD)
        style.map('TNotebook.Tab',background=[('selected',CARD),('active','#202631')],foreground=[('selected',ACCENT)])
        style.layout('TNotebook.Tab',[('Notebook.padding',{'sticky':'nswe','children':[
            ('Notebook.label',{'sticky':'nswe'})]})])

    def choose(self):
        path=filedialog.askopenfilename(parent=self,filetypes=[('EXE и DLL','*.exe *.dll'),('Все файлы','*.*')])
        if path:
            self.path.set(path)
            self.start()

    def clear(self):
        self.result=None
        self.table.delete(*self.table.get_children())
        for var in (self.arch,self.version,self.auth,self.signer,self.code):
            var.set('—')
        self.auth_card.configure(fg=FG)
        self.empty.place(relx=.5,rely=.55,anchor='center')
        self.selected_value.set('Выберите свойство — полное значение появится здесь')
        for rule in self.metric_rules:
            rule.configure(bg=EDGE)
        self.trust_accent.configure(bg=EDGE)
        self.signature_label.configure(text='Подпись ещё не проверена',fg=MUTED)
        self.trust_note.set('Здесь будет результат проверки Windows.')
        self.feedback.set('')
        self.copy_button.configure(state='disabled')
        self.folder_button.configure(state='disabled')

    def invalidate(self,*_):
        if not self.busy:
            self.clear()
            self.status.set('Нажмите «Проверить», чтобы прочитать сведения.')
            self.status_label.configure(fg=MUTED)

    def set_busy(self,busy):
        self.busy=busy
        for widget in (self.path_entry,self.browse,self.inspect_button):
            widget.configure(state='disabled' if busy else 'normal')
        self.stop_button.configure(state='normal' if busy else 'disabled')
        if busy:
            self.stop_button.grid()
        else:
            self.stop_button.grid_remove()
        for widget in (self.copy_button,self.folder_button):
            widget.configure(state='normal' if self.result and not busy else 'disabled')
        if busy:
            self.progress.configure(mode='indeterminate')
            self.progress.start(15)
        else:
            self.progress.stop()
            self.progress.configure(mode='determinate',value=0)

    def start(self):
        if self.busy:
            return
        path=self.path.get().strip().strip('"')
        if not path:
            return
        self.clear()
        self.stop.clear()
        self.set_busy(True)
        self.status.set('Читаю заголовки, версию и цифровую подпись…')
        self.status_label.configure(fg=ACCENT)
        owned_process=[None]
        def register(proc):
            owned_process[0]=proc
            self.process=proc
        def worker():
            try:
                data=inspect_cancellable(path,self.stop,on_process=register)
                self.events.put(('done',data))
            except InterruptedError:
                self.events.put(('cancelled',None))
            except Exception as exc:
                self.events.put(('error',str(exc)))
            finally:
                if self.process is owned_process[0]:
                    self.process=None
        # Allow cleanup to finish if closing beats process registration.
        self.thread=threading.Thread(target=worker,daemon=False)
        self.thread.start()

    def poll(self):
        self.poll_job=None
        try:
            kind,data=self.events.get_nowait()
        except queue.Empty:
            pass
        else:
            if kind=='done' and self.stop.is_set():
                kind='cancelled'
            if kind=='done':
                self.result=data
                self.render()
                self.status.set('Сведения прочитаны · файл не запускался')
                self.status_label.configure(fg=MUTED)
            elif kind=='cancelled':
                self.status.set('Чтение остановлено. Результат не получен.')
                self.status_label.configure(fg=MUTED)
            else:
                self.status.set('Ошибка: '+safe(data))
                self.status_label.configure(fg=BAD)
            self.set_busy(False)
        self.poll_job=self.after(80,self.poll)

    def rows(self):
        data=self.result
        pe,version=data['pe'],data['version']
        return [('Путь',data['path']),('Размер',size_text(data['size'])),('Тип',pe['kind']),
                ('Архитектура PE',pe['machine']+' · '+pe['machine_code']),('Формат PE',pe['format']),
                ('Подсистема',pe['subsystem']),('Каталог CLR (.NET)', 'Есть · разрядность запуска может отличаться' if pe['managed'] else 'Не указан'),
                ('Версия файла',version.get('file_version','—')),('Версия продукта',version.get('product_version','—')),
                ('Компания (свойство файла)',version.get('company','—')),('Название продукта',version.get('product','—')),
                ('Описание',version.get('description','—')),('Исходное имя',version.get('original','—'))]

    def render(self):
        data=self.result
        auth=data['signature']
        color=GOOD if auth['status']=='valid' else BAD if auth['status']=='invalid' else WARN
        self.arch.set(data['pe']['machine'])
        version=safe(data['version'].get('file_version','Не указана'))
        self.version.set(version if len(version)<=42 else version[:41]+'…')
        self.auth.set({'valid':'Действительна','unsigned':'Подписи нет','invalid':'Недействительна',
                       'untrusted':'Нет доверия','unknown':'Не установлено'}.get(auth['status'],'Не установлено'))
        self.auth_card.configure(fg=color)
        self.metric_rules[0].configure(bg='#5274a3')
        self.metric_rules[1].configure(bg='#5274a3')
        self.metric_rules[2].configure(bg=color)
        self.trust_accent.configure(bg=color)
        self.empty.place_forget()
        self.selected_value.set('Выберите свойство — полное значение появится здесь')
        self.signature_label.configure(text=safe(auth['label']),fg=color)
        self.signer.set(safe(auth.get('signer') or 'Не прочитан / не указан'))
        self.code.set(f"0x{auth['code'] & 0xffffffff:08X}")
        note=auth.get('note','')
        if data['notes']:
            note+='\n\n'+'\n'.join(data['notes'])
        self.trust_note.set(note)
        self.table.delete(*self.table.get_children())
        for index,(label,value) in enumerate(self.rows()):
            self.table.insert('','end',values=(label,safe(value)),tags=('even',) if index%2==0 else ())

    def show_value(self,_event=None):
        selected=self.table.selection()
        values=self.table.item(selected[0],'values') if selected else ()
        self.selected_value.set(values[1] if len(values)>1 else 'Выберите свойство — полное значение появится здесь')

    def copy_report(self):
        if not self.result or self.busy:
            return
        auth=self.result['signature']
        lines=['ExePeek · день 86 / 365']+[label+': '+safe(value) for label,value in self.rows()]
        lines += ['Подпись: '+safe(auth['label']),'Подписант сертификата: '+safe(auth.get('signer') or 'Не указан'),
                  f"Код Windows: 0x{auth['code'] & 0xffffffff:08X}",safe(auth.get('note','')),
                  'Действительная подпись не гарантирует безопасность файла.']
        lines += ['Примечание: '+safe(note) for note in self.result.get('notes',())]
        try:
            self.clipboard_clear()
            self.clipboard_append('\n'.join(lines))
            self.feedback.set('Отчёт скопирован')
        except (tk.TclError,UnicodeError):
            self.feedback.set('Не удалось скопировать — повторите')

    def open_folder(self):
        if self.result and not self.busy:
            try:
                os.startfile(os.path.dirname(self.result['path']))
            except OSError:
                self.feedback.set('Папка недоступна')

    def close(self):
        self.stop.set()
        proc=self.process
        if proc is not None and proc.poll() is None:
            try:
                proc.kill()
            except OSError:
                pass
        if self.thread is not None and self.thread.is_alive():
            self.thread.join(timeout=.7)
        self.progress.stop()
        if self.poll_job is not None:
            self.after_cancel(self.poll_job)
        try:
            SETTINGS.parent.mkdir(parents=True,exist_ok=True)
            SETTINGS.write_text(json.dumps({'path':self.path.get()},ensure_ascii=True),encoding='utf-8')
        except (OSError,ValueError,UnicodeError):
            pass
        finally:
            self.destroy()


def run():
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except OSError:
        pass
    App().mainloop()
