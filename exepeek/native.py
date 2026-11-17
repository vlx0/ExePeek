"""Read-only Windows version resources and embedded Authenticode verification.

Only system DLLs are loaded, never the inspected image. Trust is evaluated using
the local machine policy/cache, without UI or online revocation retrieval.
"""
from __future__ import annotations

import ctypes as C
from ctypes import wintypes as W
from dataclasses import dataclass
import os
import uuid

from .pe import PEError, has_certificate_table


@dataclass(frozen=True)
class Signature:
    status: str
    label: str
    signer: str = ""
    code: int = 0
    note: str = ""


_NOTE = ("Проверяется только встроенная Authenticode-подпись; каталоги Windows "
         "не проверяются. Используется только локальный кэш; проверка отзыва "
         "отключена, свежие данные из сети не запрашиваются. Подпись не является "
         "гарантией отсутствия вредоносного кода.")


class _FileInfo(C.Structure):
    _fields_ = [("cbStruct", W.DWORD), ("pcwszFilePath", W.LPCWSTR),
                ("hFile", W.HANDLE), ("pgKnownSubject", C.c_void_p)]


class _TrustData(C.Structure):
    # The pointer-sized union is represented by its FILE member.
    _fields_ = [("cbStruct", W.DWORD), ("pPolicyCallbackData", C.c_void_p),
                ("pSIPClientData", C.c_void_p), ("dwUIChoice", W.DWORD),
                ("fdwRevocationChecks", W.DWORD), ("dwUnionChoice", W.DWORD),
                ("pFile", C.POINTER(_FileInfo)), ("dwStateAction", W.DWORD),
                ("hWVTStateData", W.HANDLE), ("pwszURLReference", W.LPCWSTR),
                ("dwProvFlags", W.DWORD), ("dwUIContext", W.DWORD),
                ("pSignatureSettings", C.c_void_p)]


class _ProviderCertPrefix(C.Structure):
    # Only the documented prefix is read; Windows owns the complete structure.
    _fields_ = [("cbStruct", W.DWORD), ("pCert", C.c_void_p)]


def _dll(name):
    # LOAD_LIBRARY_SEARCH_SYSTEM32 prevents inspected-directory DLL searching.
    return C.WinDLL(name, use_last_error=True, winmode=0x800)


def _bind(dll, name, result, *args):
    fn = getattr(dll, name)
    fn.restype, fn.argtypes = result, list(args)
    return fn


def read_version(path) -> dict:
    """Return available version fields, or {} when unavailable (also off Windows)."""
    if os.name != "nt":
        return {}
    path = os.path.abspath(os.fsdecode(path))
    dll = _dll("version.dll")
    size_fn = _bind(dll, "GetFileVersionInfoSizeW", W.DWORD, W.LPCWSTR,
                    C.POINTER(W.DWORD))
    get = _bind(dll, "GetFileVersionInfoW", W.BOOL, W.LPCWSTR, W.DWORD,
                W.DWORD, C.c_void_p)
    query = _bind(dll, "VerQueryValueW", W.BOOL, C.c_void_p, W.LPCWSTR,
                  C.POINTER(C.c_void_p), C.POINTER(W.UINT))
    ignored = W.DWORD()
    size = size_fn(path, C.byref(ignored))
    if not size:
        return {}
    if size > 16 * 1024**2:
        raise OSError('Ресурс версии больше 16 МиБ: чтение свойств пропущено.')
    buf = C.create_string_buffer(size)
    if not get(path, 0, size, buf):
        return {}

    def value(key):
        pointer, length = C.c_void_p(), W.UINT()
        if query(buf, key, C.byref(pointer), C.byref(length)) and pointer.value:
            return pointer, length.value
        return None, 0

    result = {}
    pointer, length = value("\\")
    if pointer and length >= 52:
        fixed = C.cast(pointer, C.POINTER(W.DWORD * 13)).contents
        if fixed[0] == 0xFEEF04BD:
            for key, index in (("file_version", 2), ("product_version", 4)):
                hi, lo = fixed[index], fixed[index + 1]
                result[key] = f"{hi >> 16}.{hi & 65535}.{lo >> 16}.{lo & 65535}"
    pointer, length = value("\\VarFileInfo\\Translation")
    translations = []
    if pointer:
        words = C.cast(pointer, C.POINTER(W.WORD))
        translations = [(words[i], words[i + 1]) for i in range(0, length // 2 - 1, 2)]
    translations += [(0x0409, 0x04B0), (0x0409, 0x04E4)]
    fields = {"file_version": "FileVersion", "product_version": "ProductVersion",
              "company": "CompanyName", "product": "ProductName",
              "description": "FileDescription", "original": "OriginalFilename"}
    for key, field in fields.items():
        for language, codepage in dict.fromkeys(translations):
            pointer, length = value(f"\\StringFileInfo\\{language:04x}{codepage:04x}\\{field}")
            if pointer and length:
                text = C.wstring_at(pointer, length).split("\0", 1)[0].strip()
                if text:
                    result[key] = text
                    break
    return result


def _classify(code):
    code &= 0xFFFFFFFF
    if code == 0:
        return "valid", "Подпись действительна"
    if code == 0x800B0100:  # TRUST_E_NOSIGNATURE
        return "unknown", "Не удалось распознать встроенную подпись"
    if code in {0x80096010, 0x80090006, 0x80096004}:  # digest/signature failures
        return "invalid", "Подпись повреждена или недействительна"
    if code in {0x800B0004, 0x800B0101, 0x800B0109, 0x800B010A,
                0x800B010C, 0x800B0110, 0x800B0111, 0x800B0112,
                0x800B0113, 0x800B0114}:
        return "untrusted", "Подпись не прошла проверку доверия"
    return "unknown", "Не удалось установить состояние подписи"


def _signer(dll, state):
    """Use the provider-selected primary signer, never a certificate-store guess."""
    data_fn = _bind(dll, "WTHelperProvDataFromStateData", C.c_void_p, W.HANDLE)
    signer_fn = _bind(dll, "WTHelperGetProvSignerFromChain", C.c_void_p,
                      C.c_void_p, W.DWORD, W.BOOL, W.DWORD)
    cert_fn = _bind(dll, "WTHelperGetProvCertFromChain",
                    C.POINTER(_ProviderCertPrefix), C.c_void_p, W.DWORD)
    data = data_fn(state)
    signer = signer_fn(data, 0, False, 0) if data else None
    cert = cert_fn(signer, 0) if signer else None
    if not cert or not cert.contents.pCert:
        return ""
    crypt = _dll("crypt32.dll")
    name_fn = _bind(crypt, "CertGetNameStringW", W.DWORD, C.c_void_p,
                    W.DWORD, W.DWORD, C.c_void_p, W.LPWSTR, W.DWORD)
    count = name_fn(cert.contents.pCert, 4, 0, None, None, 0)
    if count <= 1:
        return ""
    text = C.create_unicode_buffer(count)
    if name_fn(cert.contents.pCert, 4, 0, None, text, count) <= 1:
        return ""
    return text.value


def verify_signature(path) -> Signature:
    """Verify embedded signatures with WinVerifyTrust generic verify v2.

    No catalog lookup is performed. 'unsigned' says nothing about catalog trust.
    Unknown errors (including inaccessible files and offline-chain failures) are
    deliberately not treated as proof of either tampering or missing signatures.
    """
    if os.name != "nt":
        return Signature("unknown", "Проверка доступна только в Windows", note=_NOTE)
    try:
        path = os.path.abspath(os.fsdecode(path))
        # Distinguish inaccessible/missing input from a genuine absent signature.
        table_error = ""
        table_present = None
        with open(path, "rb") as handle:
            try:
                table_present = has_certificate_table(handle)
            except (PEError, OSError) as exc:
                table_error = str(exc)
        dll = _dll("wintrust.dll")
        verify = _bind(dll, "WinVerifyTrust", W.LONG, W.HWND,
                       C.c_void_p, C.POINTER(_TrustData))
        action = (C.c_ubyte * 16).from_buffer_copy(
            uuid.UUID("00aac56b-cd44-11d0-8cc2-00c04fc295ee").bytes_le)
        info = _FileInfo(C.sizeof(_FileInfo), path, None, None)
        trust = _TrustData()
        trust.cbStruct = C.sizeof(trust)
        trust.dwUIChoice = 2  # WTD_UI_NONE
        trust.dwUnionChoice = 1  # WTD_CHOICE_FILE: embedded only
        trust.pFile = C.pointer(info)
        trust.dwStateAction = 1  # WTD_STATEACTION_VERIFY
        trust.dwProvFlags = 0x1000 | 0x10  # CACHE_ONLY_URL_RETRIEVAL | REVOCATION_CHECK_NONE
        try:
            code = verify(W.HWND(-1), action, C.byref(trust)) & 0xFFFFFFFF
            status, label = _classify(code)
            note = _NOTE
            if table_error:
                status, label = "unknown", "Некорректная таблица сертификатов или заголовок PE"
                note += " Ошибка: " + table_error
            elif code == 0x800B0100 and table_present is False:
                status, label = "unsigned", "Встроенная подпись отсутствует"
            signer = ""
            if trust.hWVTStateData and status in {"valid", "untrusted"}:
                try:
                    signer = _signer(dll, trust.hWVTStateData)
                except (OSError, AttributeError, ValueError):
                    pass  # Identity is optional; verification remains authoritative.
            return Signature(status, label, signer, code, note)
        finally:
            # Close even failed verification states; all provider pointers expire.
            trust.dwStateAction = 2  # WTD_STATEACTION_CLOSE
            verify(W.HWND(-1), action, C.byref(trust))
    except (OSError, ValueError, TypeError) as exc:
        code = (getattr(exc, "winerror", None) or getattr(exc, "errno", None) or 0) & 0xFFFFFFFF
        return Signature("unknown", "Не удалось проверить подпись", code=code,
                         note=f"{_NOTE} Ошибка: {exc}")
