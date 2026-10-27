"""Self-update from signed release bundles - the web side.

An update is a signed bundle (zerto-monitor-<version>.zmupdate; see deploy/release_signing.py).
This module checks it the same way the root updater will (Ed25519 signature against the
pinned public key, payload hash, version), stages it, and asks the privileged helper to start
zerto-monitor-update.service, which re-verifies everything as root, backs up, installs, health-
checks and rolls back on failure. Nothing here can install unsigned code.

Where bundles come from: an admin uploads one, or picks a version from a release index, if
one is configured (none by default). The source is either a Gitea/Forgejo generic-package base
URL ({base}/zerto-monitor-index/current/releases.json, bundles at {base}/zerto-monitor/{ver}/...)
or the full URL of an index ending in .json (e.g. a GitHub release asset), whose entries give
each bundle's "url". Both downloads are public and unauthenticated and follow redirects.
Who can start one: an admin in the portal, or anything holding a DEPLOY TOKEN on the
/api/update/* endpoints. A token is shown once, stored only as a hash, expires, can be revoked,
and can do nothing but list, fetch and apply NEWER signed releases - never a downgrade.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import secrets
import tarfile
from pathlib import Path

import db

ROOT = Path(__file__).resolve().parent.parent
PUBKEY_PATHS = (Path("/etc/zerto-monitor/release-signing.pub"), ROOT / "appliance" / "release-signing.pub",
                ROOT / "deploy" / "appliance" / "release-signing.pub")
STATUS = Path(os.environ.get("UPDATE_STATUS", "/var/lib/zerto-monitor/update-status.json"))
DEFAULT_SOURCE = ""                         # no release index until an admin sets one
NO_SOURCE = "no release index configured - set one, or upload a .zmupdate"
MAX_BUNDLE = 64 << 20
VERSION_RE = re.compile(r"^\d+(\.\d+){1,3}$")
TOKEN_PREFIX = "zmd_"


class UpdateError(Exception):
    pass


def vtuple(v: str) -> tuple:
    return tuple(int(x) for x in v.split(".")) if VERSION_RE.match(v or "") else (0,)


def current_version() -> str:
    for p in (ROOT / "VERSION",):
        try:
            return p.read_text().strip()
        except OSError:
            pass
    try:                                    # development checkout: the version being built
        m = re.search(r'^VERSION = "([^"]+)"', (ROOT / "deploy/appliance/build_ova.py").read_text(), re.M)
        return m.group(1) if m else "dev"
    except OSError:
        return "dev"


def _pubkey():
    from cryptography.hazmat.primitives import serialization
    for p in PUBKEY_PATHS:
        if p.is_file():
            return serialization.load_pem_public_key(p.read_bytes()), p
    raise UpdateError("no release signing key is installed on this appliance")


def key_id() -> str | None:
    try:
        from cryptography.hazmat.primitives import serialization
        pub, _ = _pubkey()
        raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return hashlib.sha256(raw).hexdigest()[:16]
    except Exception:  # noqa: BLE001
        return None


def inspect(bundle: bytes) -> dict:
    """Verify a bundle like the root updater will. -> manifest + 'relation' to what's installed."""
    from cryptography.exceptions import InvalidSignature
    if len(bundle) > MAX_BUNDLE:
        raise UpdateError("that file is too large to be a release bundle")
    try:
        with tarfile.open(fileobj=io.BytesIO(bundle), mode="r:") as t:
            members = {m.name: m for m in t.getmembers()}
            if set(members) != {"manifest.json", "manifest.sig", "payload.tar.xz"} or \
                    not all(m.isfile() for m in members.values()):
                raise UpdateError("that isn't a Zerto Monitor release bundle (.zmupdate)")
            mbytes = t.extractfile("manifest.json").read()
            sig = t.extractfile("manifest.sig").read()
            payload = t.extractfile("payload.tar.xz").read()
    except tarfile.TarError as e:
        raise UpdateError("that isn't a Zerto Monitor release bundle (.zmupdate)") from e
    pub, _ = _pubkey()
    try:
        pub.verify(sig, mbytes)
    except InvalidSignature:
        raise UpdateError("SIGNATURE INVALID - this bundle was not signed with this appliance's release key") from None
    m = json.loads(mbytes)
    if m.get("product") != "zerto-monitor" or not VERSION_RE.match(str(m.get("version") or "")):
        raise UpdateError("the bundle's manifest is not a Zerto Monitor release")
    if m.get("sha256") != hashlib.sha256(payload).hexdigest():
        raise UpdateError("the payload does not match the signed manifest")
    cur = current_version()
    rel = ("newer" if vtuple(m["version"]) > vtuple(cur) else
           "same" if vtuple(m["version"]) == vtuple(cur) else "older")
    return {**m, "installed": cur, "relation": rel, "bundle_sha256": hashlib.sha256(bundle).hexdigest()}


def _stage_path() -> Path:
    import tlsmgr
    return tlsmgr.STAGE / "update.zmupdate"


def stage(bundle: bytes) -> dict:
    info = inspect(bundle)
    p = _stage_path()
    p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".new")
    tmp.unlink(missing_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(bundle)
    os.replace(tmp, p)
    return info


def staged() -> dict | None:
    p = _stage_path()
    if not p.is_file():
        return None
    try:
        return inspect(p.read_bytes())
    except UpdateError as e:
        return {"error": str(e)}


def discard_staged() -> None:
    _stage_path().unlink(missing_ok=True)


def start(by: str, allow_downgrade: bool = False) -> str:
    """Hand the staged bundle to the root updater. Re-checked here and again as root."""
    info = staged()
    if not info:
        raise UpdateError("nothing is staged")
    if info.get("error"):
        raise UpdateError(info["error"])
    if info["relation"] != "newer" and not allow_downgrade:
        raise UpdateError(f"{info['version']} is not newer than the installed {info['installed']}")
    st = status()
    if st.get("state") in ("verifying", "installing", "rolling_back"):
        raise UpdateError("an update is already running")
    import tlsmgr
    who = re.sub(r"[^A-Za-z0-9@._-]", "-", by)[:64] or "unknown"
    out = tlsmgr.helper("update-start", "allow-downgrade" if allow_downgrade else "normal", who)
    db.log_alert("[update]", "update", "", None,
                 f"{by} started the update {info['installed']} -> {info['version']} "
                 f"({'reinstall/downgrade allowed' if allow_downgrade else 'newer only'})", "-", True)
    return out


def status() -> dict:
    try:
        return json.loads(STATUS.read_text())
    except (OSError, ValueError):
        return {}


# ── the release index ───────────────────────────────────────────────────────
def source() -> str:
    return (db.get_setting("update_source") or DEFAULT_SOURCE).rstrip("/")


def releases() -> list[dict]:
    """Published releases, newest first: [{version, bundle, sha256, url, relation}]. Public
    and unauthenticated - the signature, not the transport, is what's trusted."""
    import requests
    from urllib.parse import urljoin
    src = source()
    if not src:
        raise UpdateError(NO_SOURCE)
    url = src if src.endswith(".json") else f"{src}/zerto-monitor-index/current/releases.json"
    try:
        r = requests.get(url, timeout=15, verify=False, allow_redirects=True)
    except requests.RequestException as e:
        raise UpdateError(f"couldn't reach the release index ({type(e).__name__})") from e
    if r.status_code != 200:
        raise UpdateError(f"the release index answered {r.status_code}")
    try:
        rows = [x for x in (r.json().get("releases") or []) if VERSION_RE.match(str(x.get("version") or ""))]
    except ValueError as e:
        raise UpdateError("the release index isn't valid JSON") from e
    cur = current_version()
    for x in rows:
        x["relation"] = ("newer" if vtuple(x["version"]) > vtuple(cur) else
                         "same" if vtuple(x["version"]) == vtuple(cur) else "older")
        x.setdefault("url", urljoin(url, x.get("bundle") or "") if url == src
                     else f"{src}/zerto-monitor/{x['version']}/{x.get('bundle')}")
    return sorted(rows, key=lambda x: vtuple(x["version"]), reverse=True)


def fetch(version: str) -> dict:
    """Download one published release's bundle, check it, stage it."""
    import requests
    if not VERSION_RE.match(version or ""):
        raise UpdateError("bad version")
    rel = next((x for x in releases() if x["version"] == version), None)
    if not rel:
        raise UpdateError(f"{version} isn't in the release index")
    try:
        r = requests.get(rel["url"], timeout=120, verify=False, allow_redirects=True, stream=True)
        data = r.raw.read(MAX_BUNDLE + 1, decode_content=True) if r.status_code == 200 else b""
    except requests.RequestException as e:
        raise UpdateError(f"download failed ({type(e).__name__})") from e
    if r.status_code != 200:
        raise UpdateError(f"download failed: {r.status_code}")
    if rel.get("sha256") and hashlib.sha256(data).hexdigest() != rel["sha256"]:
        raise UpdateError("the downloaded bundle doesn't match the index")
    return stage(data)


# ── deploy tokens ───────────────────────────────────────────────────────────
def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_token(name: str, days: int, by: str) -> str:
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    db.save_deploy_token(name, _hash(token), by, days)
    db.log_alert("[update]", "settings", "", None, f"{by} created deploy token '{name}' ({days} days)", "-", True)
    return token


def check_token(header: str | None) -> dict | None:
    if not header or not header.startswith("Bearer " + TOKEN_PREFIX):
        return None
    row = db.deploy_token_by_hash(_hash(header[7:].strip()))
    if row:
        db.touch_deploy_token(row["id"])
    return row
