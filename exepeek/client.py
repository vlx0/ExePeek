"""Run our inspector as a child Python process, with stop and timeout."""
import json
from pathlib import Path
import subprocess
import sys
import time


def inspect_cancellable(path, stop, timeout=90, on_process=None):
    python = Path(sys.executable)
    if python.name.lower() == 'pythonw.exe' and python.with_name('python.exe').is_file():
        python = python.with_name('python.exe')
    if stop.is_set():
        raise InterruptedError('Проверка остановлена.')
    with subprocess.Popen([str(python), '-m', 'exepeek.worker', path],
                          cwd=str(Path(__file__).resolve().parent.parent),
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0)) as proc:
        try:
            if on_process:
                on_process(proc)
            deadline = time.monotonic()+timeout
            while True:
                if stop.is_set():
                    raise InterruptedError('Проверка остановлена.')
                if time.monotonic() >= deadline:
                    raise TimeoutError('Превышено время ожидания. Проверка остановлена.')
                try:
                    stdout, stderr = proc.communicate(timeout=.1)
                    break
                except subprocess.TimeoutExpired:
                    continue
            if stop.is_set():
                raise InterruptedError('Проверка остановлена.')
            if proc.returncode != 0:
                raise OSError('Не удалось прочитать файл: '+stderr.decode('utf-8',errors='replace')[-500:])
            response = json.loads(stdout.decode('utf-8'))
            if 'error' in response:
                raise OSError(response['error'])
            return response['result']
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
