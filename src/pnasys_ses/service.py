"""SecureEncryptionService — TPM-backed vault (Windows) / AES vault (elsewhere).

Usage:
    from pnasys_ses import SecureEncryptionService
    SecureEncryptionService.BasePath = os.getcwd()  # optional; default below
    SecureEncryptionService.CreateEncryptedFile(Data, AccessKey, EncryptionKey)
    Data = SecureEncryptionService.DecryptEncryptedFile(AccessKey, EncryptionKey)

The EncryptionKey is mixed with the random per-file key: the pnasys
transport key is SHA256(file_key + "|" + EncryptionKey), so decryption
needs BOTH the access key (file selector) and the encryption key. The
per-file key itself is sealed with DPAPI (TPM-backed on Windows 11) or,
off-Windows (e.g. Pi, no TPM), with AES-256-GCM under SHA256(EncryptionKey).

Files live at (Directory or BasePath)/sha256(AccessKey).json. Default
BasePath: %LOCALAPPDATA%/PNASystems/SES on Windows, ~/.pnasys_ses elsewhere.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from pathlib import Path

from pnasys_encryption_service import DecryptString, EncryptString, GenerateEncryptionKey

_ACCESS_SUFFIX = ".json"


def _default_base() -> str:
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home())
        return os.path.join(base, "PNASystems", "SES")
    return os.path.join(str(Path.home()), ".pnasys_ses")


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# File-key sealing: DPAPI on Windows, AES-GCM elsewhere
# ---------------------------------------------------------------------------

def _seal(file_key: bytes, encryption_key: str) -> dict:
    if sys.platform == "win32":
        from pnasys_ses import _dpapi

        return {"backend": "dpapi",
                "blob_b64": base64.b64encode(_dpapi.protect(file_key)).decode("ascii")}
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    aes = AESGCM(hashlib.sha256(encryption_key.encode("utf-8")).digest())
    nonce = os.urandom(12)
    return {"backend": "aes-gcm",
            "nonce_b64": base64.b64encode(nonce).decode("ascii"),
            "blob_b64": base64.b64encode(aes.encrypt(nonce, file_key, None)).decode("ascii")}


def _unseal(sealed: dict, encryption_key: str) -> bytes:
    if sealed.get("backend") == "dpapi":
        if sys.platform != "win32":
            raise RuntimeError("DPAPI-sealed file cannot open off-Windows")
        from pnasys_ses import _dpapi

        return _dpapi.unprotect(base64.b64decode(sealed["blob_b64"]))
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    aes = AESGCM(hashlib.sha256(encryption_key.encode("utf-8")).digest())
    return aes.decrypt(base64.b64decode(sealed["nonce_b64"]),
                       base64.b64decode(sealed["blob_b64"]), None)


class SecureEncryptionService:
    """Class-based API (all methods classmethods; BasePath is overridable)."""

    BasePath: str = _default_base()

    @classmethod
    def _resolve(cls, directory: str | None) -> Path:
        base = Path(directory) if directory else Path(cls.BasePath)
        base.mkdir(parents=True, exist_ok=True)
        return base

    @classmethod
    def _path_for(cls, access_key: str, directory: str | None) -> Path:
        return cls._resolve(directory) / (_sha(access_key) + _ACCESS_SUFFIX)

    @classmethod
    def CreateEncryptedFile(cls, Data: str, AccessKey: str, EncryptionKey: str,
                            OptionalDirectoryToSaveTo: str | None = None) -> str:
        """Encrypt Data; returns the sha256 filename base. Needs both keys to open."""
        file_key = GenerateEncryptionKey()
        fk_str = file_key if isinstance(file_key, str) else base64.b64encode(file_key).decode("ascii")
        transport = _sha(fk_str + "|" + EncryptionKey)
        token = EncryptString(Data, transport)
        record = {
            "enc_data": token,
            "sealed_key": _seal(fk_str.encode("utf-8"), EncryptionKey),
            "access_sha256": _sha(AccessKey),
        }
        path = cls._path_for(AccessKey, OptionalDirectoryToSaveTo)
        path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
        return path.stem

    @classmethod
    def DecryptEncryptedFile(cls, AccessKey: str, EncryptionKey: str,
                             OptionalDirectoryToSaveTo: str | None = None) -> str:
        """Inverse of CreateEncryptedFile. Raises on wrong key / missing file."""
        path = cls._path_for(AccessKey, OptionalDirectoryToSaveTo)
        if not path.exists():
            raise FileNotFoundError(f"No entry for access key at: {path}")
        record = json.loads(path.read_text(encoding="utf-8"))
        fk_str = _unseal(record["sealed_key"], EncryptionKey).decode("utf-8")
        transport = _sha(fk_str + "|" + EncryptionKey)
        return DecryptString(record["enc_data"], transport)

    @classmethod
    def DeleteEncryptedFile(cls, AccessKey: str,
                            OptionalDirectoryToSaveTo: str | None = None) -> bool:
        try:
            cls._path_for(AccessKey, OptionalDirectoryToSaveTo).unlink()
            return True
        except FileNotFoundError:
            return False

    @classmethod
    def ListEntries(cls, OptionalDirectoryToSaveTo: str | None = None) -> list[str]:
        base = cls._resolve(OptionalDirectoryToSaveTo)
        return sorted(p.stem for p in base.glob("*" + _ACCESS_SUFFIX))
