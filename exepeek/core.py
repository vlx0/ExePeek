"""File inspection. Version company and certificate signer stay separate."""
from dataclasses import asdict
import os
from .pe import read_pe


def locked_read(path):
    """Deny write/delete opens while every native reader examines this file."""
    if os.name != 'nt':
        return open(path,'rb')
    import ctypes as C
    from ctypes import wintypes as W
    import msvcrt
    kernel=C.WinDLL('kernel32',use_last_error=True)
    create=kernel.CreateFileW
    create.argtypes=[W.LPCWSTR,W.DWORD,W.DWORD,C.c_void_p,W.DWORD,W.DWORD,W.HANDLE]
    create.restype=W.HANDLE
    kernel.CloseHandle.argtypes=[W.HANDLE]
    kernel.CloseHandle.restype=W.BOOL
    handle=create(path,0x80000000,1,None,3,0x80,None)  # READ, SHARE_READ, OPEN_EXISTING
    if handle == C.c_void_p(-1).value:
        raise C.WinError(C.get_last_error())
    try:
        fd=msvcrt.open_osfhandle(handle,os.O_RDONLY|os.O_BINARY)
    except Exception:
        kernel.CloseHandle(handle)
        raise
    try:
        return os.fdopen(fd,'rb')
    except Exception:
        os.close(fd)
        raise


def signature(meta):
    return meta.st_dev, meta.st_ino, meta.st_size, meta.st_mtime_ns


def inspect_file(path):
    from .native import read_version, verify_signature
    path = os.path.abspath(path)
    with locked_read(path) as handle:
        before = signature(os.fstat(handle.fileno()))
        pe = read_pe(handle)
        notes = []
        try:
            version = read_version(path)
        except OSError as exc:
            version = {}
            notes.append('Сведения о версии не прочитались: '+str(exc))
        auth = verify_signature(path)
        if before != signature(os.fstat(handle.fileno())) or before != signature(os.stat(path)):
            raise OSError('Файл изменился во время проверки. Откройте его заново.')
    return {'path':path, 'size':before[2], 'pe':pe, 'version':version,
            'signature':asdict(auth), 'notes':notes}
