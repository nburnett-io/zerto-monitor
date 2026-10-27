"""SQLite persistence: users, monitored sources, latest snapshot per source,
and a compact per-poll history with retention.

Pages never poll a ZVM: they read the latest snapshot here. The background
collector is the only writer. WAL mode lets readers proceed during a write.

Every credential-bearing column is Fernet-encrypted via crypto.py:
  sources.identity       (username / client id)
  sources.secret_enc     (password / client secret)
  sources.reg_token_enc  (Keycloak registration access token)
  settings.entra_client_secret, smtp_password, snmp_trap_community,
  snmp_agent_community
Passwords for local admins are bcrypt hashes, never stored in clear.
"""
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import crypto

DATA_DIR = Path(os.environ.get("DATA_DIR", "/opt/zerto-monitor/data"))
DB_PATH = DATA_DIR / "monitor.db"
# every stored value that is a credential, or names one - all Fernet-encrypted
SECRET_SOURCE_COLS = ("identity", "secret_enc", "reg_token_enc", "reg_uri", "push_identity", "push_secret_enc")
SECRET_SETTINGS = ("smtp_password", "smtp_user", "snmp_trap_community", "snmp_agent_community",
                   "entra_client_secret")

@contextmanager
def _conn():
    """One connection per call: committed on success, rolled back on error, and
    ALWAYS closed.

    `with sqlite3.connect(...) as c:` on its own only commits - it never closes the
    connection. In production that leaked two file descriptors per call (the db and
    its WAL) until the process hit its 1024-fd limit and every request failed with
    "unable to open database file". Closing here is the fix; don't revert to the
    bare idiom.
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(DB_PATH), timeout=30)
    try:
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        # overwrite freed bytes with zeros on UPDATE/DELETE, so an old plaintext value
        # (or a rotated secret) doesn't linger in free pages / the WAL
        c.execute("PRAGMA secure_delete=ON")
        with c:                     # sqlite3's own commit / rollback semantics
            yield c
    finally:
        c.close()


def scrub() -> dict:
    """Checkpoint the WAL and VACUUM so nothing deleted/overwritten survives on disk.
    Safe to run while the app is up (readers wait briefly)."""
    before = DB_PATH.stat().st_size if DB_PATH.exists() else 0
    c = sqlite3.connect(str(DB_PATH), timeout=60, isolation_level=None)
    try:
        c.execute("PRAGMA secure_delete=ON")
        c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        c.execute("VACUUM")
        c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        c.close()
    after = DB_PATH.stat().st_size
    return {"bytes_before": before, "bytes_after": after}


def init():
    with _conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            hashed_password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            kind TEXT NOT NULL,              -- zvm | zcm
            host TEXT NOT NULL,
            auth_type TEXT NOT NULL,         -- password | client_credentials | basic
            identity TEXT,                   -- fernet(username | client_id)
            secret_enc TEXT,                 -- fernet(password | client_secret)
            verify_tls INTEGER DEFAULT 0,
            enabled INTEGER DEFAULT 1,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS snapshots (
            source_id INTEGER PRIMARY KEY,
            taken_at TEXT,
            ok INTEGER,
            error TEXT,
            duration_ms INTEGER,
            payload TEXT                     -- json, latest GOOD payload
        );
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id INTEGER NOT NULL,
            taken_at TEXT NOT NULL,
            ok INTEGER,
            duration_ms INTEGER,
            vpgs INTEGER, failure INTEGER, warning INTEGER, healthy INTEGER,
            vras INTEGER, vras_disconnected INTEGER, vras_mask_mismatch INTEGER,
            alerts_error INTEGER, alerts_warning INTEGER
        );
        CREATE INDEX IF NOT EXISTS ix_history_src_time ON history(source_id, taken_at);
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );
        -- alerting: which zORGs alert, after how long, and to whom.
        -- zorg is an exact zORG name or '*' (every zORG); the exact match wins.
        CREATE TABLE IF NOT EXISTS alert_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            zorg TEXT NOT NULL UNIQUE,
            error_minutes INTEGER NOT NULL DEFAULT 15,
            warning_minutes INTEGER NOT NULL DEFAULT 60,
            recipients TEXT,                 -- comma list; blank = default recipients
            email INTEGER DEFAULT 1,
            snmp INTEGER DEFAULT 1,
            enabled INTEGER DEFAULT 1,       -- 0 = muted
            created_at TEXT
        );
        -- per-zORG dwell tracking. fail_since = continuously in failure since;
        -- bad_since = continuously not-healthy since. alerted = level last notified.
        CREATE TABLE IF NOT EXISTS zorg_state (
            zorg TEXT PRIMARY KEY,
            health TEXT NOT NULL,
            fail_since TEXT,
            bad_since TEXT,
            alerted TEXT DEFAULT '',
            alerted_at TEXT,
            last_seen TEXT NOT NULL,
            detail TEXT
        );
        CREATE TABLE IF NOT EXISTS alert_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            at TEXT NOT NULL,
            zorg TEXT NOT NULL,
            event TEXT NOT NULL,             -- raised | escalated | reminder | cleared | test
            level TEXT,
            minutes INTEGER,
            summary TEXT,
            channels TEXT,
            ok INTEGER
        );
        CREATE INDEX IF NOT EXISTS ix_alert_log_at ON alert_log(at);
        -- Ignore a VPG (by VpgIdentifier) or a whole zORG (by name). mode 'ack' covers
        -- only the condition seen when it was set - snapshot = {vpg key: {codes, state,
        -- alert_status}} - so anything NEW or WORSE still alerts; 'all' covers everything.
        CREATE TABLE IF NOT EXISTS ignores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scope TEXT NOT NULL,             -- vpg | zorg
            target TEXT NOT NULL,            -- VpgIdentifier, or zORG name
            label TEXT,
            mode TEXT NOT NULL DEFAULT 'ack',
            snapshot TEXT,
            note TEXT,
            created_by TEXT,
            created_at TEXT,
            expires_at TEXT,                 -- NULL = until removed
            UNIQUE(scope, target)
        );
        -- Per-site VRA sizing standard, set on the VRA page.
        CREATE TABLE IF NOT EXISTS vra_standards (
            site TEXT PRIMARY KEY,
            memory_gb INTEGER NOT NULL,
            cpus INTEGER NOT NULL,
            allow_lower INTEGER DEFAULT 0,   -- 0 = a push only ever RAISES a VRA
            note TEXT,
            updated_by TEXT,
            updated_at TEXT
        );
        -- A VRA deliberately sized differently from its site standard.
        CREATE TABLE IF NOT EXISTS vra_pins (
            vra_key TEXT PRIMARY KEY,        -- <site>|<VraIdentifier or host>
            site TEXT NOT NULL,
            host TEXT,
            memory_gb INTEGER NOT NULL,
            cpus INTEGER NOT NULL,
            note TEXT,
            updated_by TEXT,
            updated_at TEXT
        );
        -- Every resize pushed to a ZVM, start to finish.
        CREATE TABLE IF NOT EXISTS vra_pushes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            at TEXT NOT NULL,
            by_user TEXT,
            site TEXT, source_id INTEGER, vra_id TEXT, host TEXT,
            from_mem INTEGER, from_cpus INTEGER, to_mem INTEGER, to_cpus INTEGER,
            task_id TEXT,
            state TEXT,                      -- planned | running | done | failed | aborted
            detail TEXT,
            finished_at TEXT
        );
        """)
        # engineers' own playbook entries ("team fixes"), shown before the researched ones
        c.executescript("""
        CREATE TABLE IF NOT EXISTS playbook_team (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL,               -- alert code (VPG0035) or cond:/sub:/status: key
            title TEXT, fix TEXT NOT NULL, caution TEXT,
            created_by TEXT, created_at TEXT, updated_by TEXT, updated_at TEXT
        );
        CREATE INDEX IF NOT EXISTS playbook_team_key ON playbook_team(key);
        """)
        cols = {r[1] for r in c.execute("PRAGMA table_info(users)").fetchall()}
        if "auth_source" not in cols:            # local | entra
            c.execute("ALTER TABLE users ADD COLUMN auth_source TEXT DEFAULT 'local'")
        if "last_login" not in cols:
            c.execute("ALTER TABLE users ADD COLUMN last_login TEXT")
        if "role" not in cols:                   # viewer | engineer | admin
            c.execute("ALTER TABLE users ADD COLUMN role TEXT")
            c.execute("UPDATE users SET role = CASE WHEN is_admin=1 THEN 'admin' ELSE 'viewer' END")
        scols = {r[1] for r in c.execute("PRAGMA table_info(sources)").fetchall()}
        # Keycloak dynamic client registration: where the client lives and the
        # (encrypted) token that lets us delete it again when the source is removed
        if "reg_uri" not in scols:
            c.execute("ALTER TABLE sources ADD COLUMN reg_uri TEXT")
        if "reg_token_enc" not in scols:
            c.execute("ALTER TABLE sources ADD COLUMN reg_token_enc TEXT")
        # the monitor is read-only unless an admin lets it change this site (VRA resizes)
        if "allow_changes" not in scols:
            c.execute("ALTER TABLE sources ADD COLUMN allow_changes INTEGER DEFAULT 0")
        # change settings per site (push_identity/push_secret_enc are unused since 1.4.2:
        # changes use the source's own credential; kept so older code still runs)
        for col in ("push_identity", "push_secret_enc", "push_cert_fp", "push_host_auth",
                    "push_host_auth_by", "push_host_auth_at"):
            if col not in scols:
                c.execute(f"ALTER TABLE sources ADD COLUMN {col} TEXT")
        pcols = {r[1] for r in c.execute("PRAGMA table_info(vra_pushes)").fetchall()}
        for col in ("vra_key", "cluster", "batch", "ticket", "attest", "affected", "preflight", "plan_hash",
                    "before_json", "request_json", "response_json", "task_json", "after_json", "observed",
                    "sent_at", "task_done_at", "vra_back_at", "vpgs_ok_at", "hold_until", "acked_by",
                    "acked_note", "lowers", "rule", "zvm", "zvm_version", "host_id"):
            if col not in pcols:
                c.execute(f"ALTER TABLE vra_pushes ADD COLUMN {col} TEXT")
        c.executescript("""
        CREATE TABLE IF NOT EXISTS vra_cluster_standards (
            site TEXT NOT NULL, cluster TEXT NOT NULL,
            memory_gb INTEGER NOT NULL, cpus INTEGER NOT NULL, allow_lower INTEGER DEFAULT 0,
            note TEXT, updated_by TEXT, updated_at TEXT,
            PRIMARY KEY (site, cluster)
        );
        """)
        # a Zerto case / change reference is required for any size beyond Zerto's guidance
        for t in ("vra_standards", "vra_cluster_standards", "vra_pins"):
            tcols = {r[1] for r in c.execute(f"PRAGMA table_info({t})").fetchall()}
            if "support_ref" not in tcols:
                c.execute(f"ALTER TABLE {t} ADD COLUMN support_ref TEXT")
        # pins follow the HOST: a VRA's identifier changes when it is reinstalled. A pin
        # already under the new key is newer than a legacy one: keep it, drop the legacy row
        for r in c.execute("SELECT vra_key, site, host FROM vra_pins").fetchall():
            want = f"{r['site']}|{(r['host'] or '').split('.')[0].strip().lower()}"
            if r["host"] and r["vra_key"] != want:
                if c.execute("SELECT 1 FROM vra_pins WHERE vra_key=?", (want,)).fetchone():
                    c.execute("DELETE FROM vra_pins WHERE vra_key=?", (r["vra_key"],))
                else:
                    c.execute("UPDATE vra_pins SET vra_key=? WHERE vra_key=?", (want, r["vra_key"]))
        # planned-outage holds: the affected VPGs of one resize, kept apart from engineers'
        # ignores and always expiring on their own
        c.executescript("""
        CREATE TABLE IF NOT EXISTS vra_push_holds (
            push_id INTEGER NOT NULL, vpg_key TEXT NOT NULL, label TEXT, org TEXT,
            expires_at TEXT NOT NULL, released_at TEXT, release_reason TEXT,
            PRIMARY KEY (push_id, vpg_key)
        );
        """)
        c.executescript("""
        -- Zerto events that matter to a DR engineer (changes, pauses, tests, failovers),
        -- kept for the timeline and the monthly report. The same event is reported by both
        -- ZVMs of a pair, with the same identifier.
        CREATE TABLE IF NOT EXISTS zevents (
            id TEXT PRIMARY KEY, at TEXT NOT NULL, site TEXT, source TEXT,
            type TEXT, kind TEXT,            -- Zerto's type name; ours: change|pause|test|failover|other
            text TEXT, user TEXT, ok INTEGER,
            vpg_ids TEXT, vpg_names TEXT,    -- JSON lists
            zorg_id TEXT, zorg TEXT
        );
        CREATE INDEX IF NOT EXISTS ix_zevents_at ON zevents(at);
        CREATE INDEX IF NOT EXISTS ix_zevents_zorg ON zevents(zorg, at);
        -- Zerto's failover-test reports (RTO, result, who, notes)
        CREATE TABLE IF NOT EXISTS test_reports (
            id TEXT PRIMARY KEY, vpg_id TEXT, vpg_name TEXT, zorg TEXT,
            protected_site TEXT, recovery_site TEXT, started TEXT, ended TEXT,
            rto_s REAL, status TEXT, by_user TEXT, notes TEXT, steps TEXT,
            rtype TEXT                       -- FailoverTest | Failover | Move ...
        );
        CREATE INDEX IF NOT EXISTS ix_test_reports_started ON test_reports(started);
        -- RPO / journal trends: one row per VPG per hour (35 days) and per day (400 days)
        CREATE TABLE IF NOT EXISTS vpg_hourly (
            vpg_key TEXT NOT NULL, period TEXT NOT NULL, org TEXT, name TEXT,
            samples INTEGER, rpo_sum INTEGER, rpo_max INTEGER, rpo_cfg INTEGER, rpo_breach INTEGER,
            hist_min INTEGER, hist_cfg INTEGER, hist_short INTEGER,
            journal_gb REAL, used_gb REAL, healthy INTEGER, warning INTEGER, failure INTEGER,
            PRIMARY KEY (vpg_key, period)
        );
        CREATE INDEX IF NOT EXISTS ix_vpg_hourly_org ON vpg_hourly(org, period);
        CREATE TABLE IF NOT EXISTS vpg_daily (
            vpg_key TEXT NOT NULL, period TEXT NOT NULL, org TEXT, name TEXT,
            samples INTEGER, rpo_sum INTEGER, rpo_max INTEGER, rpo_cfg INTEGER, rpo_breach INTEGER,
            hist_min INTEGER, hist_cfg INTEGER, hist_short INTEGER,
            journal_gb REAL, used_gb REAL, healthy INTEGER, warning INTEGER, failure INTEGER,
            PRIMARY KEY (vpg_key, period)
        );
        CREATE INDEX IF NOT EXISTS ix_vpg_daily_org ON vpg_daily(org, period);
        -- per-VM replication traffic from Zerto's cumulative counters: the last sample, and
        -- hourly deltas (8 days) - for VRA hot spots
        CREATE TABLE IF NOT EXISTS vm_counters (
            source_id INTEGER NOT NULL, vm_id TEXT NOT NULL, sample TEXT, write_mb INTEGER, net_mb INTEGER,
            PRIMARY KEY (source_id, vm_id)
        );
        CREATE TABLE IF NOT EXISTS vm_traffic (
            source_id INTEGER NOT NULL, vm_id TEXT NOT NULL, period TEXT NOT NULL,
            write_mb REAL DEFAULT 0, net_mb REAL DEFAULT 0, seconds REAL DEFAULT 0,
            PRIMARY KEY (source_id, vm_id, period)
        );
        CREATE INDEX IF NOT EXISTS ix_vm_traffic_period ON vm_traffic(period);
        -- VPG settings backups: Zerto's own daily export, one row per VPG per export,
        -- compressed and Fernet-encrypted (scripts' parameters can carry credentials)
        CREATE TABLE IF NOT EXISTS vpg_backups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site TEXT NOT NULL, source_id INTEGER, export_ts TEXT NOT NULL, captured_at TEXT NOT NULL,
            vpg_id TEXT, vpg_name TEXT NOT NULL, zorg TEXT, protected_site TEXT, recovery_site TEXT,
            sha256 TEXT, size INTEGER, data_enc TEXT NOT NULL, origin TEXT,
            UNIQUE (site, export_ts, vpg_name)
        );
        CREATE INDEX IF NOT EXISTS ix_vpg_backups_vpg ON vpg_backups(vpg_id, captured_at);
        CREATE INDEX IF NOT EXISTS ix_vpg_backups_zorg ON vpg_backups(zorg, captured_at);
        -- Zerto alert codes an admin has ignored estate-wide (e.g. VPG0035). A VPG whose ONLY
        -- problems are alerts with these codes, replication otherwise healthy, counts as ignored.
        CREATE TABLE IF NOT EXISTS code_ignores (
            code TEXT PRIMARY KEY, note TEXT, created_by TEXT, created_at TEXT, expires_at TEXT
        );
        -- deploy tokens for /api/update/*: only a hash is stored; the token is shown once
        CREATE TABLE IF NOT EXISTS deploy_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
            created_by TEXT, created_at TEXT, expires_at TEXT, last_used_at TEXT, revoked_at TEXT
        );
        -- every VPG restore and recovery-plan change sent to Zerto, start to finish
        CREATE TABLE IF NOT EXISTS zchanges (
            id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, kind TEXT NOT NULL,
            by_user TEXT, site TEXT, source_id INTEGER, target TEXT, zorg TEXT, ticket TEXT,
            state TEXT, detail TEXT, request_json TEXT, response_json TEXT, task_id TEXT,
            finished_at TEXT, backup_id INTEGER
        );
        """)
        if not c.execute("SELECT 1 FROM alert_rules WHERE zorg='*'").fetchone():
            c.execute("INSERT INTO alert_rules(zorg,error_minutes,warning_minutes,recipients,"
                      "email,snmp,enabled,created_at) VALUES('*',15,60,'',1,1,1,?)", (now_iso(),))
        # a certificate pin per port for sources not verified by a CA: {"443": sha256}
        if "tls_pin" not in scols:
            c.execute("ALTER TABLE sources ADD COLUMN tls_pin TEXT")
        # every credential-bearing value must be encrypted. Anything that isn't - an
        # earlier build's row, or a column that only became sensitive later (the
        # registration URI names the client id; the SMTP username) - is encrypted now,
        # then scrub() removes the old plaintext from free pages and the WAL
        migrated = 0
        for col in SECRET_SOURCE_COLS:
            for r in c.execute(f"SELECT id, {col} FROM sources").fetchall():
                if r[col] and not crypto.is_token(r[col]):
                    c.execute(f"UPDATE sources SET {col}=? WHERE id=?", (crypto.encrypt(r[col]), r["id"]))
                    migrated += 1
        for key in SECRET_SETTINGS:
            r = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
            if r and r["value"] and not crypto.is_token(r["value"]):
                c.execute("UPDATE settings SET value=? WHERE key=?", (crypto.encrypt(r["value"]), key))
                migrated += 1
        # 1.4.2: changes use the source's own credential; a separate change credential
        # from an earlier build is dead weight holding a secret, so it goes
        migrated += c.execute("UPDATE sources SET push_identity=NULL, push_secret_enc=NULL "
                              "WHERE push_identity IS NOT NULL OR push_secret_enc IS NOT NULL").rowcount
    if migrated:
        scrub()          # physically remove the pre-migration plaintext


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ── settings ────────────────────────────────────────────────────────────────
def get_setting(key: str, default: str | None = None) -> str | None:
    with _conn() as c:
        r = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return r["value"] if r else default


def set_setting(key: str, value: str):
    with _conn() as c:
        c.execute("INSERT INTO settings(key,value) VALUES(?,?) "
                  "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))


# ── users ───────────────────────────────────────────────────────────────────
def user_count() -> int:
    with _conn() as c:
        return c.execute("SELECT COUNT(*) FROM users").fetchone()[0]


def get_user(username: str) -> dict | None:
    with _conn() as c:
        r = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    return dict(r) if r else None


ROLES = ("viewer", "engineer", "admin")


def _role(role) -> str:
    """Accepts a role name, or the True/False admin flag older callers pass."""
    if role is True:
        return "admin"
    return role if role in ROLES else "viewer"


def list_users() -> list[dict]:
    with _conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT username,role,is_admin,created_at,auth_source,last_login FROM users ORDER BY username")]


def create_user(username: str, hashed: str, role="viewer", auth_source: str = "local"):
    role = _role(role)
    with _conn() as c:
        c.execute("INSERT INTO users(username,hashed_password,role,is_admin,created_at,auth_source) "
                  "VALUES(?,?,?,?,?,?)",
                  (username, hashed, role, int(role == "admin"), now_iso(), auth_source))


def upsert_sso_user(username: str, role: str) -> dict | None:
    """Entra sign-in: create on first login; refresh the role from group membership
    every time (group membership is the source of truth, not the local row). A LOCAL
    account with the same name is never taken over (None): that is the break-glass admin."""
    role = _role(role)
    with _conn() as c:
        row = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if row and row["auth_source"] != "entra":
            return None
        if row:
            c.execute("UPDATE users SET role=?, is_admin=?, last_login=?, auth_source='entra' WHERE username=?",
                      (role, int(role == "admin"), now_iso(), username))
        else:
            c.execute("INSERT INTO users(username,hashed_password,role,is_admin,created_at,auth_source,last_login) "
                      "VALUES(?,'',?,?,?,'entra',?)", (username, role, int(role == "admin"), now_iso(), now_iso()))
    return {"username": username, "role": role}


def touch_login(username: str):
    with _conn() as c:
        c.execute("UPDATE users SET last_login=? WHERE username=?", (now_iso(), username))


def delete_user(username: str):
    with _conn() as c:
        c.execute("DELETE FROM users WHERE username=?", (username,))


def set_password(username: str, hashed: str):
    with _conn() as c:
        c.execute("UPDATE users SET hashed_password=? WHERE username=?", (hashed, username))


def set_role(username: str, role: str):
    role = _role(role)
    with _conn() as c:
        c.execute("UPDATE users SET role=?, is_admin=? WHERE username=?",
                  (role, int(role == "admin"), username))


def admin_count() -> int:
    with _conn() as c:
        return c.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0]


# ── sources (identity + secret encrypted at rest) ───────────────────────────
def _row_to_source(r) -> dict:
    d = dict(r)
    d["identity"] = crypto.decrypt(d.get("identity"))
    return d


def list_sources(enabled_only: bool = False) -> list[dict]:
    q = "SELECT * FROM sources" + (" WHERE enabled=1" if enabled_only else "") + " ORDER BY kind, name"
    with _conn() as c:
        return [_row_to_source(r) for r in c.execute(q)]


def get_source(sid: int) -> dict | None:
    with _conn() as c:
        r = c.execute("SELECT * FROM sources WHERE id=?", (sid,)).fetchone()
    return _row_to_source(r) if r else None


def add_source(name, kind, host, auth_type, identity, secret_enc, verify_tls) -> int:
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO sources(name,kind,host,auth_type,identity,secret_enc,verify_tls,enabled,created_at) "
            "VALUES(?,?,?,?,?,?,?,1,?)",
            (name, kind, host, auth_type, crypto.encrypt(identity), secret_enc, int(verify_tls), now_iso()))
        return cur.lastrowid


def update_source(sid, name, host, auth_type, identity, secret_enc, verify_tls, enabled):
    with _conn() as c:
        if secret_enc:
            c.execute("UPDATE sources SET name=?,host=?,auth_type=?,identity=?,secret_enc=?,verify_tls=?,enabled=? WHERE id=?",
                      (name, host, auth_type, crypto.encrypt(identity), secret_enc, int(verify_tls), int(enabled), sid))
        else:
            c.execute("UPDATE sources SET name=?,host=?,auth_type=?,identity=?,verify_tls=?,enabled=? WHERE id=?",
                      (name, host, auth_type, crypto.encrypt(identity), int(verify_tls), int(enabled), sid))


def delete_source(sid: int):
    with _conn() as c:
        c.execute("DELETE FROM sources WHERE id=?", (sid,))
        c.execute("DELETE FROM snapshots WHERE source_id=?", (sid,))
        c.execute("DELETE FROM history WHERE source_id=?", (sid,))


def set_registration(sid: int, reg_uri: str | None, reg_token: str | None):
    """Remember a Keycloak dynamic registration (token encrypted) for later cleanup."""
    with _conn() as c:
        c.execute("UPDATE sources SET reg_uri=?, reg_token_enc=? WHERE id=?",
                  (crypto.encrypt(reg_uri) if reg_uri else None,
                   crypto.encrypt(reg_token) if reg_token else None, sid))


def set_source_pins(sid: int, pins: dict | None):
    import json as _json
    with _conn() as c:
        c.execute("UPDATE sources SET tls_pin=? WHERE id=?", (_json.dumps(pins) if pins else None, sid))


def source_pins(src: dict) -> dict:
    import json as _json
    try:
        return {int(k): v for k, v in (_json.loads(src.get("tls_pin") or "{}") or {}).items()}
    except (ValueError, TypeError):
        return {}


def unencrypted_count() -> int:
    """How many stored credential values are NOT encrypted - the Security card's proof."""
    n = 0
    with _conn() as c:
        for col in SECRET_SOURCE_COLS:
            n += sum(1 for r in c.execute(f"SELECT {col} FROM sources") if r[0] and not crypto.is_token(r[0]))
        for key in SECRET_SETTINGS:
            r = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
            n += bool(r and r[0] and not crypto.is_token(r[0]))
    return n


# ── alerting ────────────────────────────────────────────────────────────────
def alert_rules() -> list[dict]:
    with _conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM alert_rules ORDER BY CASE WHEN zorg='*' THEN 0 ELSE 1 END, lower(zorg)")]


def save_alert_rule(zorg: str, error_minutes: int, warning_minutes: int, recipients: str,
                    email: bool, snmp: bool, enabled: bool):
    with _conn() as c:
        c.execute(
            "INSERT INTO alert_rules(zorg,error_minutes,warning_minutes,recipients,email,snmp,enabled,created_at) "
            "VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(zorg) DO UPDATE SET "
            "error_minutes=excluded.error_minutes, warning_minutes=excluded.warning_minutes, "
            "recipients=excluded.recipients, email=excluded.email, snmp=excluded.snmp, "
            "enabled=excluded.enabled",
            (zorg, error_minutes, warning_minutes, recipients, int(email), int(snmp), int(enabled), now_iso()))


def delete_alert_rule(rule_id: int):
    with _conn() as c:
        c.execute("DELETE FROM alert_rules WHERE id=? AND zorg<>'*'", (rule_id,))


def zorg_states() -> dict[str, dict]:
    with _conn() as c:
        return {r["zorg"]: dict(r) for r in c.execute("SELECT * FROM zorg_state")}


def save_zorg_states(rows: list[dict], gone: list[str]):
    with _conn() as c:
        for r in rows:
            c.execute(
                "INSERT INTO zorg_state(zorg,health,fail_since,bad_since,alerted,alerted_at,last_seen,detail) "
                "VALUES(:zorg,:health,:fail_since,:bad_since,:alerted,:alerted_at,:last_seen,:detail) "
                "ON CONFLICT(zorg) DO UPDATE SET health=excluded.health, fail_since=excluded.fail_since, "
                "bad_since=excluded.bad_since, alerted=excluded.alerted, alerted_at=excluded.alerted_at, "
                "last_seen=excluded.last_seen, detail=excluded.detail", r)
        for z in gone:
            c.execute("DELETE FROM zorg_state WHERE zorg=?", (z,))


def log_alert(zorg: str, event: str, level: str, minutes: int | None, summary: str,
              channels: str, ok: bool):
    with _conn() as c:
        c.execute("INSERT INTO alert_log(at,zorg,event,level,minutes,summary,channels,ok) "
                  "VALUES(?,?,?,?,?,?,?,?)",
                  (now_iso(), zorg, event, level, minutes, summary, channels, int(ok)))
        # 400 days, like events and trends: the monthly reports go back 13 months
        cutoff = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat(timespec="seconds")
        c.execute("DELETE FROM alert_log WHERE at < ?", (cutoff,))


def alerts_between(zorg: str, since: str, until: str) -> list[dict]:
    with _conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM alert_log WHERE zorg=? AND at>=? AND at<? ORDER BY at", (zorg, since, until))]


def recent_alerts(limit: int = 50) -> list[dict]:
    with _conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM alert_log ORDER BY id DESC LIMIT ?", (limit,))]


# ── ignores ─────────────────────────────────────────────────────────────────
def list_ignores(active_only: bool = True) -> list[dict]:
    q = "SELECT * FROM ignores"
    args: tuple = ()
    if active_only:
        q += " WHERE expires_at IS NULL OR expires_at > ?"
        args = (now_iso(),)
    with _conn() as c:
        rows = [dict(r) for r in c.execute(q + " ORDER BY scope, lower(label)", args)]
    for r in rows:
        try:
            r["snapshot"] = json.loads(r["snapshot"]) if r.get("snapshot") else {}
        except ValueError:
            r["snapshot"] = {}
    return rows


def save_ignore(scope: str, target: str, label: str, mode: str, snapshot: dict, note: str,
                by: str, expires_at: str | None) -> None:
    with _conn() as c:
        c.execute(
            "INSERT INTO ignores(scope,target,label,mode,snapshot,note,created_by,created_at,expires_at) "
            "VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(scope,target) DO UPDATE SET label=excluded.label, "
            "mode=excluded.mode, snapshot=excluded.snapshot, note=excluded.note, "
            "created_by=excluded.created_by, created_at=excluded.created_at, expires_at=excluded.expires_at",
            (scope, target, label, mode, json.dumps(snapshot or {}), note, by, now_iso(), expires_at))


def get_ignore(ignore_id: int) -> dict | None:
    with _conn() as c:
        r = c.execute("SELECT * FROM ignores WHERE id=?", (ignore_id,)).fetchone()
    return dict(r) if r else None


def delete_ignore(ignore_id: int) -> None:
    with _conn() as c:
        c.execute("DELETE FROM ignores WHERE id=?", (ignore_id,))


def purge_expired_ignores(days: int = 30) -> None:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
    with _conn() as c:
        c.execute("DELETE FROM ignores WHERE expires_at IS NOT NULL AND expires_at < ?", (cutoff,))
        c.execute("DELETE FROM code_ignores WHERE expires_at IS NOT NULL AND expires_at < ?", (cutoff,))


def save_deploy_token(name: str, token_hash: str, by: str, days: int) -> None:
    expires = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat(timespec="seconds")
    with _conn() as c:
        c.execute("INSERT INTO deploy_tokens(name,token_hash,created_by,created_at,expires_at) VALUES(?,?,?,?,?)",
                  (name, token_hash, by, now_iso(), expires))


def deploy_token_by_hash(token_hash: str) -> dict | None:
    with _conn() as c:
        r = c.execute("SELECT * FROM deploy_tokens WHERE token_hash=? AND revoked_at IS NULL AND expires_at > ?",
                      (token_hash, now_iso())).fetchone()
    return dict(r) if r else None


def touch_deploy_token(token_id: int) -> None:
    with _conn() as c:
        c.execute("UPDATE deploy_tokens SET last_used_at=? WHERE id=?", (now_iso(), token_id))


def list_deploy_tokens() -> list[dict]:
    with _conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT id,name,created_by,created_at,expires_at,last_used_at,revoked_at FROM deploy_tokens ORDER BY id DESC")]


def revoke_deploy_token(token_id: int) -> None:
    with _conn() as c:
        c.execute("UPDATE deploy_tokens SET revoked_at=? WHERE id=? AND revoked_at IS NULL", (now_iso(), token_id))


def list_code_ignores(active_only: bool = True) -> list[dict]:
    q, args = "SELECT * FROM code_ignores", ()
    if active_only:
        q, args = q + " WHERE expires_at IS NULL OR expires_at > ?", (now_iso(),)
    with _conn() as c:
        return [dict(r) for r in c.execute(q + " ORDER BY code", args)]


def save_code_ignore(code: str, note: str, by: str, expires_at: str | None) -> None:
    with _conn() as c:
        c.execute("INSERT INTO code_ignores(code,note,created_by,created_at,expires_at) VALUES(?,?,?,?,?) "
                  "ON CONFLICT(code) DO UPDATE SET note=excluded.note, created_by=excluded.created_by, "
                  "created_at=excluded.created_at, expires_at=excluded.expires_at",
                  (code, note, by, now_iso(), expires_at))


def delete_code_ignore(code: str) -> None:
    with _conn() as c:
        c.execute("DELETE FROM code_ignores WHERE code=?", (code,))


# ── team playbook entries ───────────────────────────────────────────────────
def team_fixes() -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    with _conn() as c:
        for r in c.execute("SELECT * FROM playbook_team ORDER BY COALESCE(updated_at, created_at) DESC"):
            out.setdefault(r["key"], []).append(dict(r))
    return out


def get_team_fix(fix_id: int) -> dict | None:
    with _conn() as c:
        r = c.execute("SELECT * FROM playbook_team WHERE id=?", (fix_id,)).fetchone()
    return dict(r) if r else None


def save_team_fix(fix_id: int | None, key: str, title: str, fix: str, caution: str, by: str) -> int:
    with _conn() as c:
        if fix_id:
            c.execute("UPDATE playbook_team SET key=?, title=?, fix=?, caution=?, updated_by=?, updated_at=? "
                      "WHERE id=?", (key, title, fix, caution, by, now_iso(), fix_id))
            return fix_id
        cur = c.execute("INSERT INTO playbook_team(key,title,fix,caution,created_by,created_at) "
                        "VALUES(?,?,?,?,?,?)", (key, title, fix, caution, by, now_iso()))
        return cur.lastrowid


def delete_team_fix(fix_id: int) -> None:
    with _conn() as c:
        c.execute("DELETE FROM playbook_team WHERE id=?", (fix_id,))


# ── VRA sizing ──────────────────────────────────────────────────────────────
def vra_standards() -> dict[str, dict]:
    with _conn() as c:
        return {r["site"]: dict(r) for r in c.execute("SELECT * FROM vra_standards")}


def save_vra_standard(site: str, memory_gb: int, cpus: int, allow_lower: bool, note: str, by: str,
                      support_ref: str = ""):
    with _conn() as c:
        c.execute(
            "INSERT INTO vra_standards(site,memory_gb,cpus,allow_lower,note,updated_by,updated_at,support_ref) "
            "VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(site) DO UPDATE SET memory_gb=excluded.memory_gb, "
            "cpus=excluded.cpus, allow_lower=excluded.allow_lower, note=excluded.note, "
            "updated_by=excluded.updated_by, updated_at=excluded.updated_at, support_ref=excluded.support_ref",
            (site, memory_gb, cpus, int(allow_lower), note, by, now_iso(), support_ref))


def delete_vra_standard(site: str):
    with _conn() as c:
        c.execute("DELETE FROM vra_standards WHERE site=?", (site,))


def vra_cluster_standards() -> dict[tuple, dict]:
    with _conn() as c:
        return {(r["site"], r["cluster"]): dict(r) for r in c.execute("SELECT * FROM vra_cluster_standards")}


def save_vra_cluster_standard(site: str, cluster: str, memory_gb: int, cpus: int, allow_lower: bool,
                              note: str, by: str, support_ref: str = ""):
    with _conn() as c:
        c.execute(
            "INSERT INTO vra_cluster_standards(site,cluster,memory_gb,cpus,allow_lower,note,updated_by,updated_at,"
            "support_ref) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(site,cluster) DO UPDATE SET "
            "memory_gb=excluded.memory_gb, cpus=excluded.cpus, allow_lower=excluded.allow_lower, "
            "note=excluded.note, updated_by=excluded.updated_by, updated_at=excluded.updated_at, "
            "support_ref=excluded.support_ref",
            (site, cluster, memory_gb, cpus, int(allow_lower), note, by, now_iso(), support_ref))


def delete_vra_cluster_standard(site: str, cluster: str):
    with _conn() as c:
        c.execute("DELETE FROM vra_cluster_standards WHERE site=? AND cluster=?", (site, cluster))


def set_source_allow_changes(sid: int, allow: bool):
    with _conn() as c:
        c.execute("UPDATE sources SET allow_changes=? WHERE id=?", (int(allow), sid))


PUSH_ACTIVE = ("queued", "sending", "task_running", "vra_returning", "vpgs_recovering")


def active_vra_pushes() -> list[dict]:
    """Resizes queued or in flight, oldest first - the worker's to-do list."""
    with _conn() as c:
        return [dict(r) for r in c.execute(
            f"SELECT * FROM vra_pushes WHERE state IN ({','.join('?' * len(PUSH_ACTIVE))}) ORDER BY id",
            PUSH_ACTIVE)]


def vra_pushes_since(iso: str) -> list[dict]:
    with _conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM vra_pushes WHERE at >= ? ORDER BY id", (iso,))]


def vra_push_done_count() -> int:
    with _conn() as c:
        return c.execute("SELECT COUNT(*) FROM vra_pushes WHERE state='done'").fetchone()[0]


def last_done_push() -> dict | None:
    with _conn() as c:
        r = c.execute("SELECT * FROM vra_pushes WHERE state='done' ORDER BY finished_at DESC LIMIT 1").fetchone()
    return dict(r) if r else None


def set_source_push(sid: int, **f):
    cols = [k for k in ("push_identity", "push_secret_enc", "push_cert_fp", "push_host_auth",
                        "push_host_auth_by", "push_host_auth_at") if k in f]
    if cols:
        with _conn() as c:
            c.execute(f"UPDATE sources SET {', '.join(k + '=?' for k in cols)} WHERE id=?",
                      (*[f[k] for k in cols], sid))


# ── planned-outage holds ────────────────────────────────────────────────────
def add_holds(push_id: int, vpgs: list[dict], expires_at: str):
    with _conn() as c:
        for v in vpgs:
            if not v.get("key"):              # no identifier: nothing to match a hold against
                continue
            c.execute("INSERT OR REPLACE INTO vra_push_holds(push_id,vpg_key,label,org,expires_at) VALUES(?,?,?,?,?)",
                      (push_id, v["key"], v.get("name"), v.get("org"), expires_at))


def active_holds() -> dict[str, dict]:
    with _conn() as c:
        rows = c.execute("SELECT * FROM vra_push_holds WHERE released_at IS NULL AND expires_at > ?",
                         (now_iso(),)).fetchall()
    return {r["vpg_key"]: dict(r) for r in rows}


def release_holds(push_id: int, reason: str, vpg_key: str | None = None):
    with _conn() as c:
        q = "UPDATE vra_push_holds SET released_at=?, release_reason=? WHERE push_id=? AND released_at IS NULL"
        args = [now_iso(), reason, push_id]
        if vpg_key is not None:
            q += " AND vpg_key=?"
            args.append(vpg_key)
        c.execute(q, args)


def get_vra_push(push_id: int) -> dict | None:
    with _conn() as c:
        r = c.execute("SELECT * FROM vra_pushes WHERE id=?", (push_id,)).fetchone()
    return dict(r) if r else None


def vra_pins() -> dict[str, dict]:
    with _conn() as c:
        return {r["vra_key"]: dict(r) for r in c.execute("SELECT * FROM vra_pins")}


def save_vra_pin(vra_key: str, site: str, host: str, memory_gb: int, cpus: int, note: str, by: str,
                 support_ref: str = ""):
    with _conn() as c:
        c.execute(
            "INSERT INTO vra_pins(vra_key,site,host,memory_gb,cpus,note,updated_by,updated_at,support_ref) "
            "VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(vra_key) DO UPDATE SET memory_gb=excluded.memory_gb, "
            "cpus=excluded.cpus, note=excluded.note, updated_by=excluded.updated_by, "
            "updated_at=excluded.updated_at, support_ref=excluded.support_ref",
            (vra_key, site, host, memory_gb, cpus, note, by, now_iso(), support_ref))


def delete_vra_pin(vra_key: str):
    with _conn() as c:
        c.execute("DELETE FROM vra_pins WHERE vra_key=?", (vra_key,))


def log_vra_push(**f) -> int:
    # ONE insert: the worker polls every 5 s and must never see a queued row half-written
    cols = {"at": now_iso(), "state": f.get("state", "planned"),
            **{k: f.get(k) for k in ("by_user", "site", "source_id", "vra_id", "vra_key", "cluster", "batch",
                                     "host", "from_mem", "from_cpus", "to_mem", "to_cpus", "detail")},
            **{k: f[k] for k in PUSH_FIELDS if k in f and k != "state"}}
    with _conn() as c:
        return c.execute(f"INSERT INTO vra_pushes({','.join(cols)}) VALUES({','.join('?' * len(cols))})",
                         tuple(cols.values())).lastrowid


PUSH_FIELDS = ("task_id", "state", "detail", "finished_at", "ticket", "attest", "affected", "preflight",
               "plan_hash", "before_json", "request_json", "response_json", "task_json", "after_json",
               "observed", "sent_at", "task_done_at", "vra_back_at", "vpgs_ok_at", "hold_until", "acked_by",
               "acked_note", "lowers", "rule", "zvm", "zvm_version", "host_id")


def update_vra_push(push_id: int, **f):
    cols = [k for k in PUSH_FIELDS if k in f]
    if not cols:
        return
    with _conn() as c:
        c.execute(f"UPDATE vra_pushes SET {', '.join(k + '=?' for k in cols)} WHERE id=?",
                  (*[f[k] for k in cols], push_id))


PUSH_PUBLIC = ("id", "at", "by_user", "site", "host", "cluster", "from_mem", "from_cpus", "to_mem", "to_cpus",
               "lowers", "state", "detail", "hold_until", "finished_at", "ticket")


def recent_vra_pushes(site: str | None = None, limit: int = 30, full: bool = False) -> list[dict]:
    """Resize history. Without full=True only what the VRA page shows - never the request
    and response bodies, attestations or notes, which the public API would otherwise expose."""
    with _conn() as c:
        if site:
            rows = c.execute("SELECT * FROM vra_pushes WHERE site=? ORDER BY id DESC LIMIT ?", (site, limit))
        else:
            rows = c.execute("SELECT * FROM vra_pushes ORDER BY id DESC LIMIT ?", (limit,))
        out = [dict(r) for r in rows]
    return out if full else [{k: r.get(k) for k in PUSH_PUBLIC} for r in out]


# ── events, tests, trends, traffic (1.3) ────────────────────────────────────
def save_events(rows: list[dict]) -> int:
    n = 0
    with _conn() as c:
        for e in rows:
            cur = c.execute(
                "INSERT OR IGNORE INTO zevents(id,at,site,source,type,kind,text,user,ok,vpg_ids,vpg_names,zorg_id,zorg) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (e["id"], e["at"], e.get("site"), e.get("source"), e.get("type"), e.get("kind"), e.get("text"),
                 e.get("user"), None if e.get("ok") is None else int(bool(e["ok"])),
                 json.dumps(e.get("vpg_ids") or []), json.dumps(e.get("vpg_names") or []),
                 e.get("zorg_id"), e.get("zorg")))
            n += cur.rowcount
    return n


def events(zorg: str | None = None, vpg_id: str | None = None, since: str | None = None,
           until: str | None = None, kinds: tuple | None = None, limit: int = 500) -> list[dict]:
    q, args = "SELECT * FROM zevents WHERE 1=1", []
    if zorg is not None:
        q += " AND zorg=?"
        args.append(zorg)
    if vpg_id:
        q += " AND vpg_ids LIKE ?"
        args.append(f'%"{vpg_id}"%')
    if since:
        q += " AND at>=?"
        args.append(since)
    if until:
        q += " AND at<?"
        args.append(until)
    if kinds:
        q += f" AND kind IN ({','.join('?' * len(kinds))})"
        args += list(kinds)
    with _conn() as c:
        rows = [dict(r) for r in c.execute(q + " ORDER BY at DESC LIMIT ?", (*args, limit))]
    for r in rows:
        r["vpg_ids"], r["vpg_names"] = json.loads(r["vpg_ids"] or "[]"), json.loads(r["vpg_names"] or "[]")
    return rows


def save_test_reports(rows: list[dict]) -> int:
    n = 0
    with _conn() as c:
        for t in rows:
            cur = c.execute(
                "INSERT INTO test_reports(id,vpg_id,vpg_name,zorg,protected_site,recovery_site,started,ended,rto_s,"
                "status,by_user,notes,steps,rtype) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
                "ended=excluded.ended, rto_s=excluded.rto_s, status=excluded.status, notes=excluded.notes, "
                "steps=excluded.steps, zorg=COALESCE(excluded.zorg, test_reports.zorg)",
                (t["id"], t.get("vpg_id"), t.get("vpg_name"), t.get("zorg"), t.get("protected_site"),
                 t.get("recovery_site"), t.get("started"), t.get("ended"), t.get("rto_s"), t.get("status"),
                 t.get("by_user"), t.get("notes"), json.dumps(t.get("steps") or []), t.get("rtype")))
            n += cur.rowcount
    return n


def test_reports(zorg: str | None = None, vpg_id: str | None = None, since: str | None = None,
                 until: str | None = None, limit: int = 500) -> list[dict]:
    q, args = "SELECT * FROM test_reports WHERE 1=1", []
    for col, op, val in (("zorg", "=", zorg), ("vpg_id", "=", vpg_id), ("started", ">=", since), ("started", "<", until)):
        if val is not None:
            q += f" AND {col}{op}?"
            args.append(val)
    with _conn() as c:
        rows = [dict(r) for r in c.execute(q + " ORDER BY started DESC LIMIT ?", (*args, limit))]
    for r in rows:
        r["steps"] = json.loads(r["steps"] or "[]")
    return rows


TREND_COLS = ("samples", "rpo_sum", "rpo_max", "rpo_cfg", "rpo_breach", "hist_min", "hist_cfg", "hist_short",
              "journal_gb", "used_gb", "healthy", "warning", "failure")


def record_trend_samples(samples: list[dict], hour: str, day: str) -> None:
    """Fold one poll's per-VPG sample into its hour and day buckets (one transaction)."""
    sql = ("INSERT INTO {t}(vpg_key,period,org,name,samples,rpo_sum,rpo_max,rpo_cfg,rpo_breach,hist_min,hist_cfg,"
           "hist_short,journal_gb,used_gb,healthy,warning,failure) VALUES(?,?,?,?,1,?,?,?,?,?,?,?,?,?,?,?,?) "
           "ON CONFLICT(vpg_key,period) DO UPDATE SET org=excluded.org, name=excluded.name, samples=samples+1, "
           "rpo_sum=rpo_sum+excluded.rpo_sum, rpo_max=MAX(rpo_max,excluded.rpo_max), rpo_cfg=excluded.rpo_cfg, "
           "rpo_breach=rpo_breach+excluded.rpo_breach, "
           "hist_min=CASE WHEN excluded.hist_min IS NULL THEN hist_min WHEN hist_min IS NULL THEN excluded.hist_min "
           "ELSE MIN(hist_min,excluded.hist_min) END, hist_cfg=excluded.hist_cfg, "
           "hist_short=hist_short+excluded.hist_short, journal_gb=MAX(COALESCE(journal_gb,0),excluded.journal_gb), "
           "used_gb=excluded.used_gb, healthy=healthy+excluded.healthy, warning=warning+excluded.warning, "
           "failure=failure+excluded.failure")
    with _conn() as c:
        for t, period in (("vpg_hourly", hour), ("vpg_daily", day)):
            c.executemany(sql.format(t=t), [
                (s["key"], period, s["org"], s["name"], s["rpo"], s["rpo"], s["rpo_cfg"], s["rpo_breach"],
                 s["hist_min"], s["hist_cfg"], s["hist_short"], s["journal_gb"], s["used_gb"],
                 int(s["health"] == "healthy"), int(s["health"] == "warning"), int(s["health"] == "failure"))
                for s in samples])


def trend_rows(table: str, vpg_key: str | None = None, org: str | None = None, since: str | None = None,
               until: str | None = None) -> list[dict]:
    assert table in ("vpg_hourly", "vpg_daily")
    q, args = f"SELECT * FROM {table} WHERE 1=1", []
    for col, op, val in (("vpg_key", "=", vpg_key), ("org", "=", org), ("period", ">=", since), ("period", "<", until)):
        if val is not None:
            q += f" AND {col}{op}?"
            args.append(val)
    with _conn() as c:
        return [dict(r) for r in c.execute(q + " ORDER BY period", args)]


def record_vm_counters(source_id: int, rows: list[dict], period: str) -> None:
    """Zerto's per-VM counters are cumulative: store the latest sample per VM and add the
    difference since the previous one to the VM's traffic for this hour. A counter that
    went backwards (VRA restarted) starts over without adding anything."""
    with _conn() as c:
        prev = {r["vm_id"]: dict(r) for r in c.execute("SELECT * FROM vm_counters WHERE source_id=?", (source_id,))}
        adds = []
        for r in rows:
            p = prev.get(r["vm_id"])
            if p and p["sample"] and r["sample"] and r["sample"] > p["sample"]:
                dw, dn = r["write_mb"] - (p["write_mb"] or 0), r["net_mb"] - (p["net_mb"] or 0)
                try:
                    secs = (datetime.fromisoformat(r["sample"].replace("Z", "+00:00")) -
                            datetime.fromisoformat(p["sample"].replace("Z", "+00:00"))).total_seconds()
                except ValueError:
                    secs = 0
                if dw >= 0 and dn >= 0 and 0 < secs < 3 * 3600:
                    adds.append((source_id, r["vm_id"], period, dw, dn, secs))
        c.executemany("INSERT INTO vm_traffic(source_id,vm_id,period,write_mb,net_mb,seconds) VALUES(?,?,?,?,?,?) "
                      "ON CONFLICT(source_id,vm_id,period) DO UPDATE SET write_mb=write_mb+excluded.write_mb, "
                      "net_mb=net_mb+excluded.net_mb, seconds=seconds+excluded.seconds", adds)
        c.executemany("INSERT INTO vm_counters(source_id,vm_id,sample,write_mb,net_mb) VALUES(?,?,?,?,?) "
                      "ON CONFLICT(source_id,vm_id) DO UPDATE SET sample=excluded.sample, "
                      "write_mb=excluded.write_mb, net_mb=excluded.net_mb",
                      [(source_id, r["vm_id"], r["sample"], r["write_mb"], r["net_mb"]) for r in rows])


def vm_traffic(source_id: int, since: str) -> dict[str, dict]:
    with _conn() as c:
        return {r["vm_id"]: dict(r) for r in c.execute(
            "SELECT vm_id, SUM(write_mb) AS write_mb, SUM(net_mb) AS net_mb, SUM(seconds) AS seconds "
            "FROM vm_traffic WHERE source_id=? AND period>=? GROUP BY vm_id", (source_id, since))}


# ── VPG settings backups ────────────────────────────────────────────────────
def backup_exists(site: str, export_ts: str) -> bool:
    with _conn() as c:
        return c.execute("SELECT 1 FROM vpg_backups WHERE site=? AND export_ts=? LIMIT 1",
                         (site, export_ts)).fetchone() is not None


def save_backups(rows: list[dict]) -> int:
    n = 0
    with _conn() as c:
        for b in rows:
            cur = c.execute(
                "INSERT OR IGNORE INTO vpg_backups(site,source_id,export_ts,captured_at,vpg_id,vpg_name,zorg,"
                "protected_site,recovery_site,sha256,size,data_enc,origin) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (b["site"], b.get("source_id"), b["export_ts"], b.get("captured_at") or now_iso(), b.get("vpg_id"),
                 b["vpg_name"], b.get("zorg"), b.get("protected_site"), b.get("recovery_site"), b.get("sha256"),
                 b.get("size"), b["data_enc"], b.get("origin") or "daily"))
            n += cur.rowcount
    return n


BACKUP_COLS = ("id", "site", "source_id", "export_ts", "captured_at", "vpg_id", "vpg_name", "zorg",
               "protected_site", "recovery_site", "sha256", "size", "origin")


def list_backups(zorg: str | None = None, vpg_id: str | None = None, vpg_name: str | None = None,
                 site: str | None = None, limit: int = 2000) -> list[dict]:
    q, args = f"SELECT {','.join(BACKUP_COLS)} FROM vpg_backups WHERE 1=1", []
    for col, val in (("zorg", zorg), ("vpg_id", vpg_id), ("vpg_name", vpg_name), ("site", site)):
        if val is not None:
            q += f" AND {col}=?"
            args.append(val)
    with _conn() as c:
        return [dict(r) for r in c.execute(q + " ORDER BY export_ts DESC, vpg_name LIMIT ?", (*args, limit))]


def latest_backups(zorg: str | None = None) -> list[dict]:
    """The newest backup of every (site, VPG) and how many copies are kept. SQLite fills the
    other columns from the row that holds the MAX()."""
    cols = ",".join(c for c in BACKUP_COLS if c != "export_ts")
    q = f"SELECT {cols}, MAX(export_ts) AS export_ts, COUNT(*) AS copies FROM vpg_backups"
    with _conn() as c:
        return [dict(r) for r in c.execute(q + (" WHERE zorg=?" if zorg is not None else "") +
                                           " GROUP BY site, vpg_name", (zorg,) if zorg is not None else ())]


def get_backup(backup_id: int) -> dict | None:
    with _conn() as c:
        r = c.execute("SELECT * FROM vpg_backups WHERE id=?", (backup_id,)).fetchone()
    return dict(r) if r else None


def backup_summary() -> list[dict]:
    with _conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT site, export_ts, origin, COUNT(*) AS vpgs, SUM(size) AS bytes, MIN(captured_at) AS captured_at "
            "FROM vpg_backups GROUP BY site, export_ts, origin ORDER BY export_ts DESC")]


# ── changes sent to Zerto (restores, recovery plans) ────────────────────────
CHANGE_FIELDS = ("state", "detail", "request_json", "response_json", "task_id", "finished_at")


def log_change(**f) -> int:
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO zchanges(at,kind,by_user,site,source_id,target,zorg,ticket,state,detail,request_json,backup_id) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (now_iso(), f["kind"], f.get("by_user"), f.get("site"), f.get("source_id"), f.get("target"),
             f.get("zorg"), f.get("ticket"), f.get("state", "queued"), f.get("detail"), f.get("request_json"),
             f.get("backup_id")))
        return cur.lastrowid


def update_change(change_id: int, **f) -> None:
    cols = [k for k in CHANGE_FIELDS if k in f]
    if cols:
        with _conn() as c:
            c.execute(f"UPDATE zchanges SET {', '.join(k + '=?' for k in cols)} WHERE id=?",
                      (*[f[k] for k in cols], change_id))


def get_change(change_id: int) -> dict | None:
    with _conn() as c:
        r = c.execute("SELECT * FROM zchanges WHERE id=?", (change_id,)).fetchone()
    return dict(r) if r else None


def changes(kind: str | None = None, zorg: str | None = None, state: str | None = None, limit: int = 50) -> list[dict]:
    q, args = "SELECT * FROM zchanges WHERE 1=1", []
    for col, val in (("kind", kind), ("zorg", zorg), ("state", state)):
        if val is not None:
            q += f" AND {col}=?"
            args.append(val)
    with _conn() as c:
        return [dict(r) for r in c.execute(q + " ORDER BY id DESC LIMIT ?", (*args, limit))]


def purge(now: datetime | None = None) -> dict:
    """Retention for everything 1.3 keeps. Called once an hour from the poll loop."""
    now = now or datetime.now(timezone.utc)
    iso = lambda d: (now - timedelta(days=d)).isoformat(timespec="seconds")  # noqa: E731
    days = max(1, min(int(get_setting("backup_days", "7") or 7), 90))
    out = {}
    with _conn() as c:
        for name, sql, arg in (
                ("backups", "DELETE FROM vpg_backups WHERE captured_at < ?", iso(days)),
                ("hourly", "DELETE FROM vpg_hourly WHERE period < ?", iso(35)[:13]),
                ("daily", "DELETE FROM vpg_daily WHERE period < ?", iso(400)[:10]),
                ("traffic", "DELETE FROM vm_traffic WHERE period < ?", iso(8)[:13]),
                ("events", "DELETE FROM zevents WHERE at < ?", iso(400)),
                ("tests", "DELETE FROM test_reports WHERE started < ?", iso(400)),
                ("changes", "DELETE FROM zchanges WHERE at < ?", iso(400))):
            out[name] = c.execute(sql, (arg,)).rowcount
    purge_expired_ignores()
    return out


# ── snapshots + history ─────────────────────────────────────────────────────
def save_snapshot(source_id: int, ok: bool, error: str | None, duration_ms: int, payload: dict | None):
    counts = (payload or {}).get("counts") or {}
    with _conn() as c:
        c.execute(
            "INSERT INTO snapshots(source_id,taken_at,ok,error,duration_ms,payload) VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(source_id) DO UPDATE SET taken_at=excluded.taken_at, ok=excluded.ok, "
            "error=excluded.error, duration_ms=excluded.duration_ms, "
            "payload=CASE WHEN excluded.ok=1 THEN excluded.payload ELSE snapshots.payload END",
            (source_id, now_iso(), int(ok), error, duration_ms,
             json.dumps(payload) if payload is not None else None))
        c.execute(
            "INSERT INTO history(source_id,taken_at,ok,duration_ms,vpgs,failure,warning,healthy,"
            "vras,vras_disconnected,vras_mask_mismatch,alerts_error,alerts_warning) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (source_id, now_iso(), int(ok), duration_ms,
             counts.get("vpgs"), counts.get("failure"), counts.get("warning"), counts.get("healthy"),
             counts.get("vras"), counts.get("vras_disconnected"), counts.get("vras_mask_mismatch"),
             counts.get("alerts_error"), counts.get("alerts_warning")))
        days = int(get_setting("history_days", "30") or 30)
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
        c.execute("DELETE FROM history WHERE taken_at < ?", (cutoff,))


def get_snapshots() -> dict[int, dict]:
    out = {}
    with _conn() as c:
        for r in c.execute("SELECT * FROM snapshots"):
            d = dict(r)
            d["payload"] = json.loads(d["payload"]) if d["payload"] else None
            out[d["source_id"]] = d
    return out


def history(source_id: int | None = None, hours: int = 24) -> list[dict]:
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(timespec="seconds")
    with _conn() as c:
        if source_id is None:
            rows = c.execute("SELECT * FROM history WHERE taken_at>=? ORDER BY taken_at", (since,))
        else:
            rows = c.execute("SELECT * FROM history WHERE source_id=? AND taken_at>=? ORDER BY taken_at",
                             (source_id, since))
        return [dict(r) for r in rows]


def history_baseline(hours: int = 24) -> dict[int, dict]:
    """Oldest OK history row per source within the window - the 'N hours ago' comparison point."""
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(timespec="seconds")
    out: dict[int, dict] = {}
    with _conn() as c:
        for r in c.execute("SELECT * FROM history WHERE ok=1 AND taken_at>=? ORDER BY taken_at", (since,)):
            out.setdefault(r["source_id"], dict(r))
    return out
