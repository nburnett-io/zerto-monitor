"""Fernet encryption for everything sensitive that is stored.

Key resolution order (first wins):
  1. FERNET_KEY environment variable
  2. $CREDENTIALS_DIRECTORY/fernet.key  - systemd LoadCredential= (production)
  3. DATA_DIR/fernet.key                - created 0600 on first run (dev/local)

Losing the key means every stored credential must be re-entered. Back it up
separately from the database.
"""
import logging
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

DATA_DIR = Path(os.environ.get("DATA_DIR", "/opt/zerto-monitor/data"))
_KEY_FILE = DATA_DIR / "fernet.key"
_fernet: Fernet | None = None
_PREFIX = "gAAAA"          # every Fernet token starts with this
log = logging.getLogger("crypto")
_SYNCED = ("OneDrive", "OneDriveCommercial", "OneDriveConsumer")


def refuse_synced(path: Path) -> None:
    """A key file inside a synced folder is the same as plaintext: it travels with the
    database it unlocks. Refuse to create one there - set FERNET_KEY/SECRET_KEY or
    point DATA_DIR somewhere local instead."""
    p = os.path.normcase(os.path.realpath(path))
    for var in _SYNCED:
        root = os.environ.get(var)
        if root and p.startswith(os.path.normcase(os.path.realpath(root)) + os.sep):
            raise RuntimeError(f"{path} is inside {var}: set FERNET_KEY/SECRET_KEY or move DATA_DIR")


def key_source() -> str:
    if os.environ.get("FERNET_KEY"):
        return "env:FERNET_KEY"
    cd = os.environ.get("CREDENTIALS_DIRECTORY")
    if cd and (Path(cd) / "fernet.key").exists():
        return f"systemd:{cd}/fernet.key"
    return f"file:{_KEY_FILE}"


def _load() -> Fernet:
    global _fernet
    if _fernet:
        return _fernet
    key = os.environ.get("FERNET_KEY")
    if not key:
        cd = os.environ.get("CREDENTIALS_DIRECTORY")
        if cd and (Path(cd) / "fernet.key").exists():
            key = (Path(cd) / "fernet.key").read_text().strip()
    if not key:
        refuse_synced(_KEY_FILE)
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        if _KEY_FILE.exists():
            key = _KEY_FILE.read_text().strip()
        else:
            key = Fernet.generate_key().decode()
            write_private(_KEY_FILE, key)
    _fernet = Fernet(key.encode() if isinstance(key, str) else key)
    return _fernet


def encrypt(plain: str | None) -> str:
    if not plain:
        return ""
    return _load().encrypt(plain.encode()).decode()


def write_private(path: Path, text: str) -> None:
    """Create a secret file 0600 from its first byte (no write-then-chmod window)."""
    tmp = path.with_name(path.name + ".new")
    try:
        tmp.unlink()
    except FileNotFoundError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def decrypt(token: str | None) -> str:
    if not token:
        return ""
    if not is_token(token):
        # a stored credential that isn't encrypted is a bug or a pre-encryption row:
        # say so (never the value) - db.init() re-encrypts these at the next start
        log.warning("a stored credential was not encrypted; it will be re-encrypted on the next start")
        return token
    try:
        return _load().decrypt(token.encode()).decode()
    except InvalidToken:
        return ""


def encrypt_blob(data: bytes) -> str:
    """Compress, then encrypt: for stored documents (VPG settings backups)."""
    import zlib
    return _load().encrypt(zlib.compress(data, 6)).decode()


def decrypt_blob(token: str) -> bytes:
    import zlib
    return zlib.decompress(_load().decrypt(token.encode()))


def is_token(value: str | None) -> bool:
    return bool(value) and str(value).startswith(_PREFIX)
