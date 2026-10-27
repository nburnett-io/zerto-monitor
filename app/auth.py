"""Local users, bcrypt passwords, JWT in an HTTP-only cookie."""
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

import bcrypt
from fastapi import Cookie, HTTPException, Request, status
from jose import JWTError, jwt

import db

DATA_DIR = Path(os.environ.get("DATA_DIR", "/opt/zerto-monitor/data"))
ALGORITHM = "HS256"
EXPIRE_HOURS = int(os.environ.get("SESSION_HOURS", "8"))
COOKIE = "session"


def _secret() -> str:
    """The session-signing key. Resolution order (first wins):
      1. SECRET_KEY environment variable (development)
      2. $CREDENTIALS_DIRECTORY/session.key - systemd LoadCredential= (the appliance:
         root-owned 0600 in /etc/zerto-monitor, outside the app's writable data/)
      3. DATA_DIR/secret.key - created 0600 on first use (dev/local)
    """
    key = os.environ.get("SECRET_KEY")
    if key:
        return key
    cd = os.environ.get("CREDENTIALS_DIRECTORY")
    if cd and (Path(cd) / "session.key").is_file():
        return (Path(cd) / "session.key").read_text().strip()
    import crypto
    f = DATA_DIR / "secret.key"
    crypto.refuse_synced(f)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if f.exists():
        return f.read_text().strip()
    key = secrets.token_urlsafe(48)
    crypto.write_private(f, key)
    return key


def session_key_source() -> str:
    if os.environ.get("SECRET_KEY"):
        return "env:SECRET_KEY"
    cd = os.environ.get("CREDENTIALS_DIRECTORY")
    if cd and (Path(cd) / "session.key").is_file():
        return f"systemd:{cd}/session.key"
    return f"file:{DATA_DIR / 'secret.key'}"


_KEY: str | None = None


def _key() -> str:
    """Resolved on first use, not at import: importing this module (e.g. for
    hash_password during provisioning) must never create a stray key file."""
    global _KEY
    if _KEY is None:
        _KEY = _secret()
    return _KEY


def hash_password(p: str) -> str:
    return bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()


def verify_password(p: str, h: str) -> bool:
    # bcrypt reads at most 72 bytes and bcrypt 5 raises beyond that; such a password was never set
    return bool(h) and len(p.encode()) <= 72 and bcrypt.checkpw(p.encode(), h.encode())


def password_problem(p: str) -> str | None:
    if len(p) < 10:
        return "password too short (10 characters minimum)"
    if len(p.encode()) > 72:
        return "password too long (72 bytes maximum)"
    return None


def username_problem(u: str) -> str | None:
    # a '/' or blank name makes the user's own admin routes unreachable
    return None if re.fullmatch(r"[A-Za-z0-9._@-]{1,64}", u) else \
        "usernames are 1-64 letters, digits and . _ @ - only"


_DUMMY_HASH = bcrypt.hashpw(b"not-a-password", bcrypt.gensalt()).decode()


# ── roles ───────────────────────────────────────────────────────────────────
# admin    - everything: sources, credentials, TLS, alerting, users, SSO
# engineer - day-to-day operations from the dashboards: ignores, VRA sizing, pushes
# viewer   - read-only (what anonymous visitors get while sign-in isn't required)
ROLES = ("viewer", "engineer", "admin")


def role_of(row_or_claims: dict) -> str:
    r = row_or_claims.get("role")
    if r in ROLES:
        return r
    # sessions and rows from before roles existed carried only an admin flag
    return "admin" if (row_or_claims.get("admin") or row_or_claims.get("is_admin")) else "viewer"


def _session_user(p: dict) -> dict:
    """The signed-in user, with the role as it stands in the database NOW - not as it
    was when the cookie was issued - so a demotion or a deleted account takes effect
    on the very next request rather than when the session expires."""
    u = db.get_user(p["sub"])
    if not u:
        raise KeyError("account no longer exists")
    role = role_of(u)
    return {"username": u["username"], "role": role, "is_admin": role == "admin",
            "can_operate": role in ("admin", "engineer")}


def authenticate(username: str, password: str) -> dict | None:
    u = db.get_user(username)
    if not u or u.get("auth_source") == "entra":     # SSO users have no local password
        verify_password(password, _DUMMY_HASH)        # same time either way: no username probing
        return None
    if not verify_password(password, u["hashed_password"]):
        return None
    db.touch_login(u["username"])
    return {"username": u["username"], "role": role_of(u)}


# ── Entra ID (Microsoft) OIDC ───────────────────────────────────────────────
ENTRA_KEYS = ("entra_enabled", "entra_tenant_id", "entra_client_id",
              "entra_client_secret", "entra_redirect_uri", "entra_admin_group",
              "entra_engineer_group", "entra_button_label")
ENTRA_BUTTON_DEFAULT = "Sign in with Entra ID"
SCOPES = ["User.Read"]          # openid/profile/email are implied by MSAL


def entra_config() -> dict | None:
    """Return the SSO config if enabled and complete, else None."""
    import crypto
    cfg = {k: (db.get_setting(k) or "") for k in ENTRA_KEYS}
    cfg["entra_client_secret"] = crypto.decrypt(cfg["entra_client_secret"])
    if cfg["entra_enabled"] != "true":
        return None
    if not (cfg["entra_tenant_id"] and cfg["entra_client_id"] and cfg["entra_client_secret"]):
        return None
    return cfg


def entra_app(cfg: dict):
    import msal
    return msal.ConfidentialClientApplication(
        cfg["entra_client_id"], client_credential=cfg["entra_client_secret"],
        authority=f"https://login.microsoftonline.com/{cfg['entra_tenant_id']}")


def entra_role(cfg: dict, claims: dict) -> str:
    """Role from the token's groups/roles claims, re-evaluated at every sign-in:
    admin group wins, then engineer group, otherwise viewer. A group left blank
    grants nobody that role."""
    have = {str(g).lower() for g in (claims.get("groups") or []) + (claims.get("roles") or [])}
    for role, key in (("admin", "entra_admin_group"), ("engineer", "entra_engineer_group")):
        want = (cfg.get(key) or "").strip().lower()
        if want and want in have:
            return role
    return "viewer"


def create_token(username: str, role: str) -> str:
    role = role if role in ROLES else "viewer"
    exp = datetime.now(timezone.utc) + timedelta(hours=EXPIRE_HOURS)
    return jwt.encode({"sub": username, "role": role, "admin": role == "admin", "exp": exp},
                      _key(), algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    return jwt.decode(token, _key(), algorithms=[ALGORITHM])


class NotAuthenticated(HTTPException):
    def __init__(self):
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED)


async def current_user(session: str | None = Cookie(default=None)) -> dict:
    if not session:
        raise NotAuthenticated()
    try:
        return _session_user(decode_token(session))
    except (JWTError, KeyError):
        raise NotAuthenticated()


async def admin_user(session: str | None = Cookie(default=None)) -> dict:
    u = await current_user(session)
    if not u["is_admin"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin only")
    return u


async def engineer_user(session: str | None = Cookie(default=None)) -> dict:
    """Admins and engineers: the day-to-day operations on the dashboards."""
    u = await current_user(session)
    if not u["can_operate"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="engineer or admin only")
    return u


def optional_user(request: Request) -> dict | None:
    tok = request.cookies.get(COOKIE)
    if not tok:
        return None
    try:
        return _session_user(decode_token(tok))
    except (JWTError, KeyError):
        return None
