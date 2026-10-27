"""Release signing for Zerto Monitor's self-update (workstation side).

    genkey --pub deploy/appliance/release-signing.pub   private PEM on STDOUT (for DPAPI storage)
    sign --payload P --version V --out DIR              private PEM on STDIN -> DIR/zerto-monitor-V.zmupdate
    verify --bundle B --pub P                            check a bundle like the appliance does

Never call these by hand with the key on a command line: deploy/new_release_key.ps1 and
the release owner's publish script pass the private key through stdin from DPAPI storage
($env:ZM_SIGNING_KEY, default ~\\.zerto-monitor\\release-signing.xml) and it is never
written to disk or printed.

Bundle = uncompressed tar of manifest.json, manifest.sig (raw Ed25519 over manifest.json's
exact bytes) and payload.tar.xz. The appliance (zerto-monitor-update) verifies the
signature with OpenSSL against its pinned copy of release-signing.pub.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def key_id(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def payload_version(payload: bytes) -> str | None:
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:xz") as t:
        try:
            return t.extractfile("VERSION").read().decode().strip()
        except KeyError:
            return None


def make_bundle(priv: Ed25519PrivateKey, payload: bytes, version: str) -> tuple[bytes, dict]:
    pv = payload_version(payload)
    if pv != version:
        raise SystemExit(f"refusing to sign: the payload is version {pv}, not {version} - rebuild it")
    manifest = {"product": "zerto-monitor", "version": version, "payload": "payload.tar.xz",
                "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload),
                "built_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "key_id": key_id(priv.public_key())}
    mbytes = json.dumps(manifest, sort_keys=True, indent=1).encode()
    sig = priv.sign(mbytes)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:", format=tarfile.USTAR_FORMAT) as t:
        for name, data in (("manifest.json", mbytes), ("manifest.sig", sig), ("payload.tar.xz", payload)):
            ti = tarfile.TarInfo(name)
            ti.size, ti.mtime, ti.mode = len(data), 0, 0o644
            t.addfile(ti, io.BytesIO(data))
    return buf.getvalue(), manifest


def verify_bundle(bundle: bytes, pub: Ed25519PublicKey) -> dict:
    with tarfile.open(fileobj=io.BytesIO(bundle), mode="r:") as t:
        names = {m.name for m in t.getmembers()}
        if names != {"manifest.json", "manifest.sig", "payload.tar.xz"}:
            raise ValueError(f"not a release bundle: {sorted(names)}")
        mbytes = t.extractfile("manifest.json").read()
        sig = t.extractfile("manifest.sig").read()
        payload = t.extractfile("payload.tar.xz").read()
    pub.verify(sig, mbytes)                          # InvalidSignature if not ours
    m = json.loads(mbytes)
    if m.get("sha256") != hashlib.sha256(payload).hexdigest():
        raise ValueError("payload does not match the signed manifest")
    return m


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("genkey")
    g.add_argument("--pub", required=True)
    s = sub.add_parser("sign")
    s.add_argument("--payload", required=True)
    s.add_argument("--version", required=True)
    s.add_argument("--out", required=True)
    v = sub.add_parser("verify")
    v.add_argument("--bundle", required=True)
    v.add_argument("--pub", required=True)
    a = ap.parse_args()
    if a.cmd == "genkey":
        priv = Ed25519PrivateKey.generate()
        Path(a.pub).write_bytes(priv.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        sys.stdout.write(priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()).decode())
        print(f"key id {key_id(priv.public_key())}", file=sys.stderr)
        return 0
    if a.cmd == "sign":
        pem = sys.stdin.read().encode()
        priv = serialization.load_pem_private_key(pem, password=None)
        bundle, m = make_bundle(priv, Path(a.payload).read_bytes(), a.version)
        out = Path(a.out) / f"zerto-monitor-{a.version}.zmupdate"
        out.write_bytes(bundle)
        print(json.dumps({"bundle": str(out), "sha256": hashlib.sha256(bundle).hexdigest(),
                          "key_id": m["key_id"], "version": m["version"]}))
        return 0
    pub = serialization.load_pem_public_key(Path(a.pub).read_bytes())
    m = verify_bundle(Path(a.bundle).read_bytes(), pub)
    print(json.dumps({"ok": True, "version": m["version"], "key_id": m["key_id"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
