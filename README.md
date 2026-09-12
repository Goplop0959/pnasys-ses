# pnasys-ses — PNASystems Secure Encryption Service

TPM-backed (Windows DPAPI) / AES-backed (everywhere else) vault with
**two-key** access: you need both the access key (file selector) and the
encryption key (mixed into the transport key) to open anything.

```python
from pnasys_ses import SecureEncryptionService
SecureEncryptionService.BasePath = os.getcwd()  # optional override
SecureEncryptionService.CreateEncryptedFile(Data, AccessKey, EncryptionKey)
SecureEncryptionService.CreateEncryptedFile(Data, AccessKey, EncryptionKey, "C:\\Example")
plain = SecureEncryptionService.DecryptEncryptedFile(AccessKey, EncryptionKey)
plain = SecureEncryptionService.DecryptEncryptedFile(AccessKey, EncryptionKey, "C:\\Example")
```

Files land at `<base>/sha256(AccessKey).json`. Default base:
`%LOCALAPPDATA%/PNASystems/SES` on Windows, `~/.pnasys_ses` elsewhere.

Interactive CLI: `pnases` (create/read/list/delete loop).
