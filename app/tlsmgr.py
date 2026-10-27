"""TLS state, hostname, and the bridge to the privileged helper.

The service runs sandboxed (NoNewPrivileges, ProtectSystem=strict): it cannot use
sudo, and even a root child of it would see /etc read-only. So privileged steps go
to /usr/local/sbin/zerto-monitor-admin through a systemd socket
(/run/zerto-monitor-admin.sock, root:zertomon 0660). systemd starts the helper per
connection OUTSIDE this sandbox. The helper accepts no file paths - staging
locations are fixed inside it - so nothing here can aim it at an arbitrary file.

The certificate is world-readable (it is public). The private key is root-only and
this process never reads it.
"""
from __future__ import annotations

import os
import re
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path

TLS_DIR = Path(os.environ.get("TLS_DIR", "/etc/zerto-monitor/tls"))
CERT = TLS_DIR / "fullchain.pem"
KEY = TLS_DIR / "privkey.pem"
HELPER_SOCK = os.environ.get("ADMIN_SOCKET", "/run/zerto-monitor-admin.sock")
# Uploaded key material is staged in the service's RuntimeDirectory (tmpfs: never on
# the persistent disk). The privileged helper reads the same fixed path.
STAGE = (Path(os.environ["RUNTIME_DIRECTORY"]) if os.environ.get("RUNTIME_DIRECTORY")
         else Path(os.environ.get("DATA_DIR", "/opt/zerto-monitor/data"))) / "staging"

_LABEL = r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
FQDN_RE = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(\.{_LABEL})*$")   # label by label: no 'a..b'
HOST_RE = re.compile(rf"^{_LABEL}$")
WORD_RE = re.compile(r"^[A-Za-z0-9_./:-]{1,253}$")


class TlsError(RuntimeError):
    pass


def helper_available() -> bool:
    return Path(HELPER_SOCK).exists()


def helper(*args: str, timeout: int = 180) -> str:
    """Send one request to the privileged helper; return its output.

    Raises TlsError carrying the helper's own message on failure. Every word is
    re-checked here so a request can never smuggle whitespace or a second line.
    """
    if not args or not all(WORD_RE.match(a) for a in args):
        raise TlsError("refusing a malformed helper request")
    if not helper_available():
        raise TlsError("the privileged helper is not installed on this host "
                       "(run: sudo python3 /opt/zerto-monitor/firstboot.py --upgrade)")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(HELPER_SOCK)
        s.sendall((" ".join(args) + "\n").encode())
        s.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            b = s.recv(65536)
            if not b:
                break
            chunks.append(b)
    except OSError as e:
        raise TlsError(f"helper unreachable: {e}") from e
    finally:
        s.close()
    lines = b"".join(chunks).decode(errors="replace").strip().splitlines()
    rc = 1
    if lines and lines[-1].startswith("__RC__="):
        try:
            rc = int(lines.pop().split("=", 1)[1])
        except ValueError:
            rc = 1
    text = "\n".join(lines).strip()
    if rc != 0:
        msg = next((ln[7:] for ln in reversed(lines) if ln.startswith("ERROR: ")), "")
        if not msg:
            msg = text.splitlines()[-1] if text else f"{args[0]} failed"
        raise TlsError(msg)
    return text




# ── reading current state ───────────────────────────────────────────────────
def state() -> dict:
    """What certificate is in force, parsed from the public half only."""
    out = {"present": False, "subject": "", "issuer": "", "sans": [], "self_signed": None,
           "not_before": "", "not_after": "", "days_left": None, "fingerprint": "",
           "key_algo": "", "error": "", "helper": helper_available()}
    if not CERT.exists():
        return out
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        data = CERT.read_bytes()
        c = x509.load_pem_x509_certificate(data)
        out["present"] = True
        out["subject"] = c.subject.rfc4514_string()
        out["issuer"] = c.issuer.rfc4514_string()
        out["self_signed"] = c.subject == c.issuer
        nb, na = c.not_valid_before_utc, c.not_valid_after_utc
        out["not_before"] = nb.strftime("%Y-%m-%d")
        out["not_after"] = na.strftime("%Y-%m-%d")
        out["days_left"] = (na - datetime.now(timezone.utc)).days
        out["fingerprint"] = c.fingerprint(hashes.SHA256()).hex(":", 2)
        out["key_algo"] = f"{c.public_key().__class__.__name__.lstrip('_')} " \
                          f"{getattr(c.public_key(), 'key_size', '')}".strip()
        try:
            ext = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            out["sans"] = [str(g.value) for g in ext]
        except x509.ExtensionNotFound:
            pass
        # how many certs are in the chain file
        out["chain_len"] = data.count(b"-----BEGIN CERTIFICATE-----")
    except Exception as e:                                  # noqa: BLE001
        out["error"] = f"{type(e).__name__}: {e}"
    return out


OVFENV_STATE = Path(os.environ.get("OVFENV_STATE", "/var/lib/zerto-monitor/ovfenv.state"))
OVF_LABELS = {"zm-root-password": "root password", "zm-admin-password": "admin (SSH/console) password",
              "zm-web-password": "web admin password", "zm-zvm-password": "ZVM password",
              "zm-zvm-user": "ZVM username"}


def ovfenv_state() -> dict:
    """What zerto-monitor-ovfscrub last found in the VM's vApp environment: which
    deploy-time secrets vCenter still hands this VM (names only - never values)."""
    out = {"known": False, "held": [], "labels": [], "guest": "", "checked": "", "source": ""}
    try:
        for ln in OVFENV_STATE.read_text().splitlines():
            if "=" in ln:
                k, v = ln.split("=", 1)
                out[k] = v
        out["known"] = True
    except OSError:
        return out
    out["held"] = [h for h in str(out.get("held") or "").split(",") if h]
    out["labels"] = [OVF_LABELS.get(h, h) for h in out["held"]]
    return out


def hostname() -> dict:
    def _run(*c):
        try:
            return subprocess.run(c, capture_output=True, text=True, timeout=15).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return ""
    short = _run("hostname") or ""
    return {"short": short, "fqdn": _run("hostname", "-f") or short,
            "domain": _run("hostname", "-d") or ""}


# ── changing it ─────────────────────────────────────────────────────────────
def _validate_pair(cert_pem: bytes, key_pem: bytes) -> str:
    """Parse and cross-check before anything privileged happens. Returns the CN."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    try:
        c = x509.load_pem_x509_certificate(cert_pem)
    except Exception as e:                                  # noqa: BLE001
        raise TlsError(f"certificate is not valid PEM: {str(e)[:160]}") from e
    try:
        k = serialization.load_pem_private_key(key_pem, password=None)
    except TypeError as e:
        raise TlsError("the private key is encrypted - decrypt it first "
                       "(openssl rsa -in key.pem -out plain.pem)") from e
    except Exception as e:                                  # noqa: BLE001
        raise TlsError(f"private key is not valid PEM: {str(e)[:160]}") from e

    pub_c = c.public_key().public_bytes(serialization.Encoding.DER,
                                        serialization.PublicFormat.SubjectPublicKeyInfo)
    pub_k = k.public_key().public_bytes(serialization.Encoding.DER,
                                        serialization.PublicFormat.SubjectPublicKeyInfo)
    if pub_c != pub_k:
        raise TlsError("that private key does not match that certificate")
    if c.not_valid_after_utc < datetime.now(timezone.utc):
        raise TlsError(f"that certificate expired on {c.not_valid_after_utc:%Y-%m-%d}")
    try:
        return c.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    except (IndexError, x509.ExtensionNotFound):
        return ""


def install(cert_pem: bytes, key_pem: bytes) -> dict:
    """Validate an uploaded cert/key pair, stage it, and let the helper install it."""
    cn = _validate_pair(cert_pem, key_pem)
    STAGE.mkdir(parents=True, exist_ok=True)
    os.chmod(STAGE, 0o700)
    sc, sk = STAGE / "cert.pem", STAGE / "key.pem"
    try:
        for f, data in ((sc, cert_pem), (sk, key_pem)):
            try:
                f.unlink()
            except FileNotFoundError:
                pass
            fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)    # private from byte one
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
        helper("tls-install")
    finally:
        for f in (sc, sk):                      # tmpfs: removing it removes it
            try:
                f.unlink()
            except OSError:
                pass
    return {"cn": cn, **state()}


def install_pfx(pfx: bytes, password: str = "") -> dict:
    """Accept a Windows-style .pfx/.p12 (cert + key + chain in one file)."""
    from cryptography.hazmat.primitives.serialization import (Encoding, NoEncryption,
                                                              PrivateFormat, pkcs12)
    try:
        key, cert, extra = pkcs12.load_key_and_certificates(
            pfx, password.encode() if password else None)
    except ValueError as e:
        raise TlsError("could not open the .pfx - wrong password, or not a PKCS#12 file") from e
    if key is None or cert is None:
        raise TlsError("the .pfx must contain both the certificate and its private key")
    chain = b"".join(c.public_bytes(Encoding.PEM) for c in (extra or []))
    return install(cert.public_bytes(Encoding.PEM) + chain,
                   key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))


def self_signed(fqdn: str, days: int = 3650) -> dict:
    fqdn = (fqdn or "").strip().rstrip(".")
    if not fqdn or not FQDN_RE.match(fqdn):
        raise TlsError("enter a valid DNS name, e.g. zertomon.example.com")
    helper("tls-selfsigned", fqdn, str(max(1, min(days, 7300))))
    return state()


def set_hostname(name: str) -> dict:
    """Set the short hostname. Does not touch the certificate."""
    name = (name or "").strip().split(".")[0]
    if not name or not HOST_RE.match(name):
        raise TlsError("hostname must be 1-63 letters, digits or hyphens")
    helper("hostname", name)
    return hostname()
