"""Windows DPAPI (TPM-backed) seal/unseal. Imported only on win32."""
from __future__ import annotations

import ctypes
from ctypes import wintypes

CRYPTPROTECT_UI_FORBIDDEN = 0x1


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _load():
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    return crypt32, kernel32


def _to_blob(data: bytes) -> _DATA_BLOB:
    buf = (ctypes.c_ubyte * len(data))(*data)
    return _DATA_BLOB(len(data), buf)


def _from_blob(blob: _DATA_BLOB) -> bytes:
    size = int(blob.cbData)
    ptr = ctypes.cast(blob.pbData, ctypes.POINTER(ctypes.c_ubyte))
    return bytes(ptr[:size])


def protect(data: bytes) -> bytes:
    crypt32, kernel32 = _load()
    in_blob, out_blob = _to_blob(data), _DATA_BLOB()
    ok = crypt32.CryptProtectData(
        ctypes.byref(in_blob), "PNASes", None, None, None,
        CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out_blob))
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    out = _from_blob(out_blob)
    kernel32.LocalFree(out_blob.pbData)
    return out


def unprotect(data: bytes) -> bytes:
    crypt32, kernel32 = _load()
    in_blob, out_blob = _to_blob(data), _DATA_BLOB()
    descr = wintypes.LPWSTR()
    ok = crypt32.CryptUnprotectData(
        ctypes.byref(in_blob), ctypes.byref(descr), None, None, None,
        CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out_blob))
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    out = _from_blob(out_blob)
    kernel32.LocalFree(out_blob.pbData)
    return out
