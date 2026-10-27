"""Zerto Virtual Manager client + normalisation.

Handles both ZVM flavours in the estate:
  * Zerto 10.x appliance  -> HTTPS/443, Keycloak. Password grant needs scope=openid;
                            client_credentials works for a confidential client.
  * Legacy Windows ZVM    -> HTTPS/9669, POST /v1/session/add, x-zerto-session header.
                            9.7 omits StatusDescription/SubStatusDescription entirely
                            and sends numeric Status/SubStatus - mapped below. The
                            maps were derived from 10.x sites where both forms exist.

Everything is collected into one plain-dict payload that the views consume.
"""
from __future__ import annotations

import base64
import json
import re
import time
from datetime import datetime, timezone

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

STATUS_MAP = {0: "Initializing", 1: "MeetingSLA", 2: "NotMeetingSLA",
              3: "RpoNotMeetingSLA", 4: "HistoryNotMeetingSLA", 5: "FailingOver",
              6: "Moving", 7: "Deleting", 8: "Recovered"}
SUB_MAP = {0: "None", 1: "InitialSync", 2: "Creating", 3: "VolumeInitialSync", 4: "Sync",
           5: "RecoveryPossible", 6: "DeltaSync", 7: "NeedsConfiguration", 8: "Error",
           12: "VolumeDeltaSync", 23: "BitmapSync", 30: "RecoveryStorageError",
           35: "ReplicationPausedForMissingVolume"}

# VpgApi.AlertStatus - Zerto's own per-VPG alert state, the yellow/red a VPG shows in
# the Zerto UI even while its replication status is MeetingSLA (journal over 50%,
# resources outside the zORG, unreachable datastore...). Verified on a 10.9
# ZVM 2026-10-05: every alert pointing at an AlertStatus=1 VPG was Level "Warning".
ALERT_STATUS_HEALTH = {1: "warning", 2: "failure"}

SYNCING = {"InitialSync", "VolumeInitialSync", "Sync", "DeltaSync", "VolumeDeltaSync",
           "BitmapSync", "Creating"}
FAIL_SUB = {"Error", "RecoveryStorageError", "ReplicationPausedForMissingVolume",
            "NeedsConfiguration"}
FAIL_STATUS = {"NotMeetingSLA"}
WARN_STATUS = {"RpoNotMeetingSLA", "HistoryNotMeetingSLA", "Initializing"}


class ZvmError(Exception):
    pass


REALM = "/auth/realms/zerto"
# Interactive users get their API rights from client roles of 'zerto-client'
# (ZertoRole_Admin, ZertoPrivilege_*). A client registered with an initial access
# token was observed on Zerto 10.9 (2026-10-05) to receive the realm role 'viewer'
# automatically, which reads everything the collector uses - so normally nothing
# needs granting. VIEWER_ROLE is the fallback if a ZVM refuses the client anyway.
VIEWER_ROLE = "ZertoPrivilege_Viewer"


def role_hint(client_id: str) -> str:
    return (f"Grant it read access in the ZVM's Keycloak (https://<zvm>/auth/admin, realm 'zerto'): "
            f"Clients -> {client_id or '<client>'} -> Service accounts roles -> Assign role -> "
            f"filter by clients -> zerto-client -> {VIEWER_ROLE}.")


def _jwt_claims(token: str) -> dict | None:
    """Read a JWT's claims WITHOUT verifying it - for diagnosis only, never trust."""
    import base64
    import json as _json
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        pad = parts[1] + "=" * (-len(parts[1]) % 4)
        return _json.loads(base64.urlsafe_b64decode(pad))
    except (ValueError, TypeError):
        return None


def _same_server(a: str, b: str) -> bool:
    """True if two host names/addresses resolve to at least one common IP."""
    import socket as _s

    def ips(h):
        try:
            return {i[4][0] for i in _s.getaddrinfo(h, 443, proto=_s.IPPROTO_TCP)}
        except OSError:
            return set()
    return bool(ips(a) & ips(b))


def inspect_iat(host: str, token: str) -> str:
    """Check an initial access token before spending it; return the host to register at.

    This ZVM's Keycloak derives its issuer from the hostname of each request
    (https://<whatever you typed>/auth/realms/zerto), and it rejects a token unless the
    token's issuer equals the issuer of the request presenting it. So a token created
    with the console open at the IP fails at the FQDN with a bare 401. When that's the
    only problem - and both names reach the same server - register at the token's host.
    """
    from urllib.parse import urlparse
    t = token.strip()
    if re.fullmatch(r"[0-9a-fA-F-]{32,36}", t):
        raise ZvmError("that's the token's ID, not the token. Keycloak shows the token itself "
                       "only once, in the dialog right after you create it - create a new one "
                       "and copy the long value from that dialog")
    claims = _jwt_claims(t)
    if not claims:
        raise ZvmError("that doesn't look like a Keycloak token (expected a long value with two "
                       "dots in it). Make sure nothing was cut off or wrapped when copying")
    typ = claims.get("typ") or ""
    if typ and typ != "InitialAccessToken":
        raise ZvmError(f"that's a Keycloak '{typ}' token, not an initial access token. Create one "
                       "under Clients -> Client registration -> Initial access token")
    iss = claims.get("iss") or ""
    m = re.match(r"^https?://([^/]+)(/.*)?/realms/([^/]+)$", iss)
    if not m:
        raise ZvmError(f"the token's issuer is unrecognisable: {iss[:120]}")
    iss_host, realm = m.group(1), m.group(3)
    if realm != "zerto":
        raise ZvmError(f"that token was issued in realm '{realm}', not 'zerto'. In the Keycloak "
                       "console switch the realm selector to 'zerto' and create a new token there")
    exp = claims.get("exp")
    if isinstance(exp, (int, float)) and exp < time.time():
        ago = int((time.time() - exp) // 60)
        raise ZvmError(f"that token expired {ago} minute{'s' if ago != 1 else ''} ago. Create a "
                       "new one (Keycloak's default lifetime is short) and use it straight away")
    want = urlparse(f"https://{host}").hostname or host
    got = urlparse(f"https://{iss_host}").hostname or iss_host
    if got.lower() != want.lower():
        if not _same_server(want, got):
            raise ZvmError(f"that token was issued by {got}, which is not the server at {want}. "
                           f"Create the token in the Keycloak console of {want} itself")
        return iss_host                     # same Keycloak, reached by another name
    return host


def register_client(host: str, initial_access_token: str, verify: bool = False,
                    name: str = "zerto-monitor", session: requests.Session | None = None) -> dict:
    """Spend a Keycloak *initial access token* on a confidential client of our own.

    Zerto's built-in 'zerto-client' is PUBLIC, so Keycloak refuses it the
    client_credentials grant ("Public client not allowed to retrieve service
    account"). An initial access token lets us use OpenID Connect Dynamic Client
    Registration (RFC 7591) at the realm's advertised registration endpoint to create
    a CONFIDENTIAL client instead; Keycloak turns grant_types=["client_credentials"]
    into a service account. The id+secret that comes back authenticates without
    anybody's password.

    The initial access token is spent here and never stored. We keep (encrypted) the
    registration access token so the client can be deleted again when the source is
    removed. Registration itself grants no roles; on Zerto 10.9 the service account
    picks up the realm role 'viewer' on its own, which is enough to read. If a ZVM
    refuses it, ZvmClient.get() surfaces role_hint().
    """
    token = initial_access_token.strip()
    reg_host = inspect_iat(host, token)            # raises with a precise reason if it can't work
    url = f"https://{reg_host}{REALM}/clients-registrations/openid-connect"
    body = {"client_name": name, "grant_types": ["client_credentials"],
            "token_endpoint_auth_method": "client_secret_post"}
    try:
        r = (session or requests).post(url, json=body, verify=verify, timeout=30, allow_redirects=False,
                                       headers={"Authorization": f"Bearer {token}",
                                                "Content-Type": "application/json"})
    except requests.RequestException as e:
        raise ZvmError(f"could not reach {reg_host}: {type(e).__name__}") from e
    refuse_redirect(r, "client registration")
    detail = ""
    try:
        j = r.json()
        detail = j.get("error_description") or j.get("errorMessage") or j.get("error") or ""
    except ValueError:
        j, detail = {}, r.text[:160]
    if r.status_code == 401:
        # the claims looked right, so the usual remaining cause is a spent token
        raise ZvmError("Keycloak rejected the token although it looks valid - most likely its "
                       f"use count is spent (each token registers a set number of clients). "
                       f"Keycloak said: {detail or 'unauthorized'}")
    if r.status_code == 403:
        raise ZvmError(f"a Keycloak client-registration policy refused the request: {detail}")
    if r.status_code not in (200, 201):
        raise ZvmError(f"client registration failed ({r.status_code}): {detail}")
    if not j.get("client_id") or not j.get("client_secret"):
        raise ZvmError("Keycloak registered a client but returned no secret")
    return {"client_id": j["client_id"], "client_secret": j["client_secret"],
            "registration_access_token": j.get("registration_access_token") or "",
            "registration_client_uri": j.get("registration_client_uri") or "",
            "registered_via": reg_host}


def deregister_client(host: str, reg_uri: str, reg_token: str, verify: bool = False,
                      session: requests.Session | None = None) -> str:
    """Delete a client we registered. Only ever touches this host's registration API."""
    from urllib.parse import urlparse
    if not reg_uri or not reg_token:
        return "nothing to remove"
    u = urlparse(reg_uri)
    # the client may have been registered via another name for the same server
    # (see inspect_iat), so accept that - but only if it really is the same machine
    if u.scheme != "https" or not u.path.startswith(f"{REALM}/clients-registrations/") \
            or not (u.hostname == host or _same_server(u.hostname or "", host)):
        return "refused: stored registration URI does not belong to this ZVM"
    try:
        r = (session or requests).delete(reg_uri, headers={"Authorization": f"Bearer {reg_token}"},
                                         verify=verify, timeout=30, allow_redirects=False)
    except requests.RequestException as e:
        return f"could not reach {host}: {type(e).__name__}"
    if r.is_redirect:
        return f"Keycloak answered with a {r.status_code} redirect - not followed; remove the client by hand"
    if r.status_code in (200, 204):
        return "client removed from Keycloak"
    if r.status_code == 404:
        return "client was already gone"
    return f"Keycloak said {r.status_code}; remove the client by hand"


def ci(d: dict | None, key: str, default=None):
    """Case-insensitive key lookup: live 10.9 responses are PascalCase, the spec camelCase."""
    if not isinstance(d, dict):
        return default
    if key in d:
        return d[key]
    low = key.lower()
    return next((v for k, v in d.items() if k.lower() == low), default)


class _PinnedAdapter(requests.adapters.HTTPAdapter):
    """Accept exactly one certificate (by SHA-256 fingerprint), self-signed or not."""

    def __init__(self, fingerprint: str, **kw):
        self._fp = fingerprint
        super().__init__(**kw)

    def init_poolmanager(self, *a, **kw):
        kw["assert_fingerprint"] = self._fp
        return super().init_poolmanager(*a, **kw)


class _RefuseAdapter(requests.adapters.HTTPAdapter):
    """For any origin without a pin: refuse rather than talk to it unverified."""

    def send(self, request, *a, **kw):
        raise requests.exceptions.SSLError(f"no certificate pin for {request.url.split('?')[0]} - refusing")


def origin(host: str, port: int = 443) -> str:
    return f"https://{host}/" if int(port) == 443 else f"https://{host}:{port}/"


def pinned_session(host: str, pins) -> requests.Session:
    """A session that accepts only the pinned certificate on each pinned origin
    (pins: {port: sha256 fingerprint}, or one fingerprint for 443) and refuses every
    other HTTPS origin outright."""
    if isinstance(pins, str):
        pins = {443: pins}
    s = requests.Session()
    # never via a proxy from the environment: requests would hand the connection to a
    # proxy manager that never sees assert_fingerprint, i.e. credentials over unverified TLS
    s.trust_env = False
    s.proxies = {}
    s.verify = False                          # identity comes from the pin instead
    s.mount("https://", _RefuseAdapter())
    for port, fp in (pins or {}).items():
        s.mount(origin(host, int(port)), _PinnedAdapter(fp))
    return s


def refuse_redirect(r: requests.Response, what: str) -> None:
    """Credentials are never re-sent to wherever a redirect points."""
    if r.is_redirect or r.status_code in (301, 302, 303, 307, 308):
        raise ZvmError(f"refused a {r.status_code} redirect from {what} - credentials are never re-sent elsewhere")


def cert_fingerprint(host: str, port: int = 443) -> str:
    """SHA-256 of the certificate a host presents right now, colon-separated."""
    import hashlib
    import socket
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=15) as s, ctx.wrap_socket(s, server_hostname=host) as t:
        der = t.getpeercert(binary_form=True)
    h = hashlib.sha256(der).hexdigest()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


VRA_NET_KEYS = ("VraIPConfigurationTypeApi", "VraIPAddress", "VraIPAddressRangeEnd", "SubnetMask", "DefaultGateway")


def build_resize_body(cur: dict, memory_gb: int, cpus: int) -> dict:
    """The exact edit body for a VRA resize, from a fresh GET of that VRA.

    Both sizes always sent (an omitted numOfCpus may mean 1); bandwidth group and
    network echoed EXACTLY as read, never derived (a value Zerto doesn't recognise
    can flip static to DHCP); usePublicKeyInsteadOfCredentials sent explicitly, because
    it's a non-nullable bool that would otherwise default to password mode. Anything
    unexpected in what was read refuses the whole thing rather than guess."""
    group = ci(cur, "VraGroup")
    nd = ci(cur, "VraNetworkDataApi")
    if not group:
        raise ZvmError("the VRA's bandwidth group came back empty - refusing to send an edit that could reset it")
    if not isinstance(nd, dict) or not nd:
        raise ZvmError("the VRA's network settings came back missing - refusing")
    extra = [k for k in nd if k.lower() not in {x.lower() for x in VRA_NET_KEYS}]
    if extra:
        raise ZvmError(f"unexpected network fields {extra} - refusing to echo a shape the monitor doesn't know")
    if ci(nd, "VraIPConfigurationTypeApi") is None:
        raise ZvmError("the VRA's IP configuration type came back empty - refusing")
    return {"memoryInGb": int(memory_gb), "numOfCpus": int(cpus), "groupName": group,
            "vraNetworkDataApi": {k[0].lower() + k[1:]: ci(nd, k) for k in VRA_NET_KEYS},
            "usePublicKeyInsteadOfCredentials": True}


def parse_task_id(resp) -> str | None:
    """PUT /v1/vras/{id} returns a bare JSON string (spec) or {"TaskIdentifier": ...} (legacy)."""
    if isinstance(resp, str):
        s = resp.strip().strip('"').strip()
        return s or None
    if isinstance(resp, dict):
        v = ci(resp, "TaskIdentifier")
        return str(v) if v else None
    return None


# matched with fullmatch (no trailing newline) and no id may start with '.', so '.' / '..'
# segments - which requests normalises away - can't turn an allowed path into another
WRITE_ALLOWED = re.compile(r"/v1/vras/[A-Za-z0-9][A-Za-z0-9._:\-]*")
_UUID = r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
# Every change the monitor can make, per feature. A client is built with exactly one of
# these lists and refuses any other write, whatever a caller asks for. Polling clients
# get none at all.
WRITES_RESIZE = (("PUT", WRITE_ALLOWED),)
WRITES_PLANS = (("POST", re.compile(r"^/v1/recoveryPlans$")),
                ("PUT", re.compile(rf"^/v1/recoveryPlans/{_UUID}$")))
WRITES_PLAN_DELETE = (("DELETE", re.compile(rf"^/v1/recoveryPlans/{_UUID}$")),)
WRITES_RESTORE = (("POST", re.compile(r"^/v1/vpgSettings/import$")),)
WRITES_EXPORT = (("POST", re.compile(r"^/v1/vpgSettings/exportSettings$")),)
# Zerto models "read this export file" as a POST; these change nothing and any client may send them
READ_POSTS = (re.compile(r"/v1/vpgSettings/exportedSettings/[0-9][0-9A-Za-z:.\-]*"),)


def token_roles(token: str) -> list[str]:
    """The roles a Keycloak access token carries, for display: which Zerto rights the ZVM
    actually gave this credential. Read from our own token's payload; the ZVM enforces them."""
    try:
        p = token.split(".")[1]
        j = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    except (IndexError, ValueError):
        return []
    roles = set((j.get("realm_access") or {}).get("roles") or [])
    for cl in (j.get("resource_access") or {}).values():
        roles.update((cl or {}).get("roles") or [])
    return sorted(r for r in roles if not r.startswith(("default-roles", "offline_access", "uma_")))


class ZvmClient:
    def __init__(self, host: str, auth_type: str, identity: str, secret: str,
                 verify_tls: bool = False, timeout: int = 90, session: requests.Session | None = None,
                 writes: tuple = ()):
        self.host = host
        self.auth_type = auth_type
        self.identity = identity
        self.secret = secret
        self.verify = verify_tls
        self.timeout = timeout
        self.base = None
        self.headers = None
        self.flavour = None
        self.roles: list[str] = []
        # a pinned session for the resize credential; plain requests for polling
        self._http = session or requests
        if session is not None and session.verify is False:
            self.verify = False
        self.writes = tuple(writes)

    # ── auth ────────────────────────────────────────────────────────────────
    def login(self):
        errors = []
        # 1) appliance (Keycloak)
        if self.auth_type in ("password", "client_credentials"):
            try:
                data = {"client_id": "zerto-client", "scope": "openid"}
                if self.auth_type == "password":
                    data.update(grant_type="password", username=self.identity, password=self.secret)
                else:
                    data.update(grant_type="client_credentials", client_id=self.identity,
                                client_secret=self.secret)
                r = self._http.post(f"https://{self.host}/auth/realms/zerto/protocol/openid-connect/token",
                                    data=data, verify=self.verify, timeout=30, allow_redirects=False)
                refuse_redirect(r, "the Keycloak token endpoint")
                if r.status_code == 200:
                    self.base = f"https://{self.host}"
                    tok = r.json()["access_token"]
                    self.roles = token_roles(tok)
                    self.headers = {"Authorization": f"Bearer {tok}", "Accept": "application/json"}
                    self.flavour = "appliance"
                    return
                errors.append(f"keycloak {r.status_code}: {r.text[:120]}")
            except requests.RequestException as e:
                errors.append(f"keycloak: {type(e).__name__}")
        # 2) legacy Windows ZVM
        if self.auth_type in ("password", "basic"):
            try:
                r = self._http.post(f"https://{self.host}:9669/v1/session/add",
                                    auth=(self.identity, self.secret),
                                    headers={"Content-Type": "application/json"},
                                    json={"AuthenticationMethod": 1},
                                    verify=self.verify, timeout=30, allow_redirects=False)
                refuse_redirect(r, "the legacy ZVM login")
                sid = r.headers.get("x-zerto-session")
                if r.status_code == 200 and sid:
                    self.base = f"https://{self.host}:9669"
                    self.headers = {"x-zerto-session": sid, "Accept": "application/json"}
                    self.flavour = "legacy"
                    return
                errors.append(f"legacy {r.status_code}: {r.text[:120]}")
            except requests.RequestException as e:
                errors.append(f"legacy: {type(e).__name__}")
        raise ZvmError("; ".join(errors) or "no auth method applicable")

    def get(self, path: str):
        r = self._http.get(f"{self.base}{path}", headers=self.headers,
                           verify=self.verify, timeout=self.timeout, allow_redirects=False)
        refuse_redirect(r, path)
        if r.status_code in (401, 403) and self.auth_type == "client_credentials":
            # signed in fine, but the service account has no Zerto role yet (the client
            # id is deliberately not in the message: errors are shown and logged)
            raise ZvmError(f"the API client authenticated but Zerto refused it ({r.status_code}) - "
                           f"it needs read access. {role_hint('')}")
        if r.status_code != 200:
            raise ZvmError(f"GET {path} -> {r.status_code}: {r.text[:150]}")
        return r.json()

    def write(self, method: str, path: str, body=None, denied: str = "") -> tuple[int, object]:
        """One change to Zerto - only if this client was built for it (see WRITES_*).
        Returns (HTTP status, parsed body); never retries."""
        method = method.upper()
        if not any(m == method and rx.fullmatch(path) for m, rx in self.writes):
            raise ZvmError(f"refusing {method} {path}: not a change this client may make")
        r = self._http.request(method, f"{self.base}{path}",
                               headers={**self.headers, "Content-Type": "application/json"},
                               json=body, verify=self.verify, timeout=120, allow_redirects=False)
        refuse_redirect(r, path)
        try:
            parsed = r.json()
        except ValueError:
            parsed = r.text
        if r.status_code in (401, 403):
            raise ZvmError(f"this source's credential may not do this ({r.status_code}). {denied} "
                           "Grant it in the ZVM's Keycloak (Admin → Changes to Zerto shows its roles).".strip())
        return r.status_code, parsed

    def put(self, path: str, body: dict) -> tuple[int, object]:
        """The VRA resize's one write: PUT /v1/vras/{id}."""
        if not WRITE_ALLOWED.fullmatch(path):
            raise ZvmError(f"refusing {path}: a resize's only write is PUT /v1/vras/{{id}}")
        return self.write("PUT", path, body, "Zerto's 'Edit VRA' needs the ManageVRA privilege.")

    def post_read(self, path: str, body: dict):
        """A POST that only reads (Zerto's export files). Nothing else goes through here."""
        if not any(rx.fullmatch(path) for rx in READ_POSTS):
            raise ZvmError(f"refusing POST {path}: not a read")
        r = self._http.post(f"{self.base}{path}", headers={**self.headers, "Content-Type": "application/json"},
                            json=body, verify=self.verify, timeout=300, allow_redirects=False)
        refuse_redirect(r, path)
        if r.status_code != 200:
            raise ZvmError(f"POST {path} -> {r.status_code}: {r.text[:150]}")
        return r.json()

    def task(self, task_id: str) -> dict:
        return self.get(f"/v1/tasks/{task_id}")

    # ── collection ──────────────────────────────────────────────────────────
    def collect(self, events_since: str | None = None) -> dict:
        """One poll. Besides the payload, returns bulky side data under keys starting with
        '_' (per-VM statistics, new events) that the collector hands on and never stores
        in the snapshot."""
        t0 = time.time()
        self.login()
        site = self.get("/v1/localsite")
        vpgs = self.get("/v1/vpgs") or []
        vms = self.get("/v1/vms") or []
        vras = self.get("/v1/vras") or []
        alerts = self.get("/v1/alerts") or []
        try:
            peers = self.get("/v1/peersites") or []
        except ZvmError:
            peers = []
        try:
            zorgs = self.get("/v1/zorgs") or []
        except ZvmError:
            zorgs = []
        try:
            plans = self.get("/v1/recoveryPlans") or []
        except ZvmError:
            plans = None                    # older ZVM, or not allowed: say "unknown", not "none"
        try:
            stats = self.get("/v1/statistics/vms") or []
        except ZvmError:
            stats = None
        events, event_types = None, None
        if events_since and self.flavour == "appliance":
            # the API returns at most the latest 1000 events and filters after that cap, so
            # this is called every poll for a short window (see events.py for the backfill)
            try:
                now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
                events = self.get(f"/v1/events?startDate={events_since}&endDate={now}&eventCategory=Events") or []
                event_types = self.get("/v1/events/types") or []
            except ZvmError:
                events = None
        # which vSphere cluster each VRA's host is in (for per-cluster sizing)
        cluster_of: dict[str, tuple] = {}
        if site.get("SiteIdentifier"):
            try:
                for c in self.get(f"/v1/virtualizationsites/{site['SiteIdentifier']}/hostclusters") or []:
                    for h in c.get("AssociatedHosts") or []:
                        hid = h.get("HostIdentifier") if isinstance(h, dict) else h
                        if hid:
                            cluster_of[hid] = (c.get("ClusterIdentifier"), c.get("VirtualizationClusterName"))
            except ZvmError:
                pass

        local_name = site.get("SiteName")
        # VMs carry no VPG identifier, only its name - and two customers can name a VPG
        # alike, so key by (name, organisation)
        vm_by_vpg: dict[tuple, list] = {}
        for m in vms:
            vm_by_vpg.setdefault((m.get("VpgName") or "", m.get("OrganizationName") or ""), []).append({
                "id": m.get("VmIdentifier"),
                "name": m.get("VmName"),
                "protected_host": m.get("OwningHostName"),
                "recovery_host": m.get("RecoveryHostName"),
                # exact VRA-to-VPG matching (a resize's blast radius) uses these, never names
                "protected_host_id": m.get("OwningHostIdentifier"),
                "recovery_host_id": m.get("RecoveryHostIdentifier"),
                "journal_gb": round((m.get("JournalUsedStorageMb") or 0) / 1024, 1),
                "prov_gb": round((m.get("ProvisionedStorageInMB") or 0) / 1024, 1),
                "rpo": m.get("ActualRPO"),
                "thru": m.get("ThroughputInMB"),
                "wan_mbps": m.get("OutgoingBandWidthInMbps"),
            })

        disc_ips, disc_hosts = set(), set()
        peer_down = []
        for a in alerts:
            hid = a.get("HelpIdentifier")
            d = a.get("Description") or ""
            if hid == "ZVM0002":
                m = re.search(r"VRA (\S+) on host (\S+?)(?:\.|\s)", d)
                if m:
                    disc_ips.add(m.group(1))
                    disc_hosts.add(m.group(2).lower())
            elif hid == "ZVM0003":
                peer_down.append(d[:200])

        # Which alerts belong to which VPG. Zerto names them exactly in AffectedVpgs;
        # use that. Only an API old enough to lack the field falls back to finding
        # "VPG <name>" in the text - as a whole name, so VPG "Acme-05" can't claim an
        # alert about "Acme-05-SQL01" the way a plain substring match would.
        by_vpg_id: dict[str, list] = {}
        textual = []
        for a in alerts:
            if a.get("IsDismissed"):
                continue        # dismissed in Zerto: never the reason a VPG is flagged
            rec = {"level": a.get("Level"), "id": a.get("HelpIdentifier"),
                   "text": (a.get("Description") or "")[:300], "since": a.get("TurnedOn")}
            if a.get("AffectedVpgs") is not None:
                for x in a["AffectedVpgs"]:
                    if isinstance(x, dict) and x.get("identifier"):
                        by_vpg_id.setdefault(x["identifier"], []).append(rec)
            else:
                textual.append((a.get("Description") or "", rec))

        norm_vpgs = []
        for v in vpgs:
            st = v.get("StatusDescription") or STATUS_MAP.get(v.get("Status"), f"Status{v.get('Status')}")
            sub = v.get("SubStatusDescription") or SUB_MAP.get(v.get("SubStatus"), "None")
            sub = sub or "None"
            rpo = v.get("ActualRPO")
            try:
                rpo = int(rpo) if rpo is not None else -1
            except (TypeError, ValueError):
                rpo = -1
            try:
                alert_status = int(v.get("AlertStatus") or 0)
            except (TypeError, ValueError):
                alert_status = 0
            name = v.get("VpgName")
            members = vm_by_vpg.get((name or "", v.get("OrganizationName") or ""), [])
            hist = v.get("HistoryStatusApi") or {}
            procs = v.get("ActiveProcessesApi") or {}
            hosts = {(m.get("protected_host") or "").split(".")[0].lower() for m in members}
            on_disc = sorted(h for h in hosts if h and h in disc_hosts)
            related_alerts = list(by_vpg_id.get(v.get("VpgIdentifier"), []))
            if name and textual:
                pat = re.compile(r"\bVPG\s+" + re.escape(name) + r"(?=[\s.,;:)]|$)")
                related_alerts += [rec for text, rec in textual if pat.search(text)]
            norm_vpgs.append({
                "name": name,
                "id": v.get("VpgIdentifier"),
                "org": v.get("OrganizationName") or "",
                "zorg_id": (v.get("Zorg") or {}).get("identifier"),
                "status": st, "sub": sub,
                "rpo": rpo, "rpo_cfg": v.get("ConfiguredRpoSeconds"),
                "progress": v.get("ProgressPercentage") or 0,
                "thru": v.get("ThroughputInMB") or 0,
                "iops": v.get("IOPs") or 0,
                "vms": v.get("VmsCount"),
                "prov_gb": round((v.get("ProvisionedStorageInMB") or 0) / 1024, 1),
                "used_gb": round((v.get("UsedStorageInMB") or 0) / 1024, 1),
                "protected_site": v.get("ProtectedSiteName"),
                "recovery_site": v.get("RecoverySiteName"),
                "direction": "outbound" if v.get("ProtectedSiteName") == local_name else "inbound",
                "priority": v.get("Priority"),
                "service_profile": v.get("ServiceProfileName"),
                "last_test": v.get("LastTest"),
                "members": members,
                "protected_hosts": sorted(h for h in hosts if h),
                "on_disconnected_vra": on_disc,
                "alerts": related_alerts,
                "alert_status": alert_status,
                "history_cfg_min": hist.get("ConfiguredHistoryInMinutes"),
                "history_min": hist.get("ActualHistoryInMinutes"),
                "testing": bool(procs.get("RunningFailOverTestApi")),
                "health": classify(st, sub, rpo, alert_status),
            })

        # VRA subnet-mask consistency: the majority mask per gateway is "correct"
        masks_by_gw: dict[str, dict[str, int]] = {}
        for r in vras:
            nd = r.get("VraNetworkDataApi") or {}
            gw, mask = nd.get("DefaultGateway"), nd.get("SubnetMask")
            if gw and mask:
                masks_by_gw.setdefault(gw, {}).setdefault(mask, 0)
                masks_by_gw[gw][mask] += 1
        majority = {gw: max(m.items(), key=lambda kv: kv[1])[0] for gw, m in masks_by_gw.items()}

        norm_vras = []
        for r in vras:
            nd = r.get("VraNetworkDataApi") or {}
            pc = r.get("ProtectedCounters") or {}
            rc = r.get("RecoveryCounters") or {}
            ip = nd.get("VraIPAddress") or r.get("IpAddress")
            gw = nd.get("DefaultGateway")
            mask = nd.get("SubnetMask")
            norm_vras.append({
                # identifiers a resize push needs (PUT /v1/vras/{id}); the spec types
                # vraIdentifier as an integer, so keep it as a string to be safe
                "id": str(r["VraIdentifier"]) if r.get("VraIdentifier") is not None else None,
                "host_id": r.get("HostIdentifier"),
                "cluster_id": (cluster_of.get(r.get("HostIdentifier")) or (None, None))[0],
                "cluster": (cluster_of.get(r.get("HostIdentifier")) or (None, None))[1],
                "upgrade_status": r.get("UpgradeStatus"),
                "progress": r.get("Progress"),
                "is_ghost": bool(r.get("IsGhost")),
                "group": r.get("VraGroup"),
                "name": r.get("VraName"),
                "host": r.get("HostDisplayName"),
                "ip": ip, "mask": mask, "gw": gw,
                "mask_expected": majority.get(gw),
                "mask_mismatch": bool(gw and mask and majority.get(gw) and mask != majority[gw]),
                "status": r.get("Status"),
                "version": r.get("VraVersion"),
                "host_version": r.get("HostVersion"),
                "mem_gb": r.get("MemoryInGB"), "cpus": r.get("NumOfCpus"),
                "datastore": r.get("DatastoreName"),
                "protected_vpgs": pc.get("Vpgs", 0), "protected_vols": pc.get("Volumes", 0),
                "recovery_vpgs": rc.get("Vpgs", 0), "recovery_vols": rc.get("Volumes", 0),
                "disconnected": ip in disc_ips,
                "alert_status": (r.get("VraAlerts") or {}).get("VraAlertsStatus"),
                "is_vaio": bool(r.get("IsVaio")),
                "display_version": r.get("VraDisplayVersion"),
                "ip_config": nd.get("VraIPConfigurationTypeApi"),
                "datastore_id": r.get("DatastoreIdentifier"),
                "network_id": r.get("NetworkIdentifier"),
                "protected_vms": pc.get("Vms", 0), "recovery_vms": rc.get("Vms", 0),
            })

        return {
            "site": local_name, "version": site.get("Version"), "site_type": site.get("SiteType"),
            "location": site.get("Location"), "flavour": self.flavour, "token_roles": self.roles,
            "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "duration_ms": int((time.time() - t0) * 1000),
            "vpgs": norm_vpgs, "vras": norm_vras,
            # AffectedZorgs lets zORG pages pick up ZCC alerts (ZCC0001 ghost,
            # ZCC0002 powered off, ZCC0003 orphaned), which the ZVM raises, not the ZCM.
            "alerts": [{"level": a.get("Level"), "id": a.get("HelpIdentifier"),
                        "entity": a.get("Entity"), "text": (a.get("Description") or "")[:300],
                        "since": a.get("TurnedOn"), "dismissed": bool(a.get("IsDismissed")),
                        "zorgs": [z.get("identifier") for z in (a.get("AffectedZorgs") or [])
                                  if isinstance(z, dict) and z.get("identifier")],
                        "vpgs": [x.get("identifier") for x in (a.get("AffectedVpgs") or [])
                                 if isinstance(x, dict) and x.get("identifier")]}
                       for a in alerts],
            "peers": [{"name": p.get("PeerSiteName"), "type": p.get("SiteType"),
                       "version": p.get("Version"), "host": p.get("HostName"),
                       "pairing": p.get("PairingStatus"),
                       "in_mbps": p.get("IncomingThroughputInMb"),
                       "out_mbps": p.get("OutgoingBandWidth")} for p in peers],
            "peer_down": peer_down,
            "zorgs": [{"name": z.get("ZorgName") or z.get("Name"),
                       "id": z.get("ZorgIdentifier") or z.get("Identifier")} for z in zorgs],
            # Zerto 10.9 recovery plans (ordered failover blocks); None = couldn't read them
            "plans": None if plans is None else [{
                "id": ci(p, "Id"), "name": ci(p, "Name"), "type": ci(p, "Type"), "status": ci(p, "Status"),
                "last_run": ci(p, "LastRun"), "last_ok": ci(p, "LastSuccessfulRun"),
                "blocks": [{"type": ci(b, "BlockType"), "vpg_ids": list(ci(b, "VpgIds") or []),
                            "delay": ci(b, "DelayInMinutes"), "script": ci(b, "ScriptPath"),
                            "params": list(ci(b, "ScriptParameters") or [])} for b in ci(p, "Blocks") or []]}
                for p in plans],
            "site_id": site.get("SiteIdentifier"),
            "_stats": stats, "_events": events, "_event_types": event_types,
            "counts": {
                "vpgs": len(norm_vpgs),
                "failure": sum(1 for v in norm_vpgs if v["health"] == "failure"),
                "warning": sum(1 for v in norm_vpgs if v["health"] == "warning"),
                "healthy": sum(1 for v in norm_vpgs if v["health"] == "healthy"),
                "vras": len(norm_vras),
                "vras_disconnected": sum(1 for r in norm_vras if r["disconnected"]),
                "vras_mask_mismatch": sum(1 for r in norm_vras if r["mask_mismatch"]),
                "alerts_error": sum(1 for a in alerts if a.get("Level") == "Error" and not a.get("IsDismissed")),
                "alerts_warning": sum(1 for a in alerts if a.get("Level") == "Warning" and not a.get("IsDismissed")),
            },
        }


HEALTH_ORDER = {"failure": 0, "warning": 1, "healthy": 2}


def worst(*healths: str) -> str:
    return min(healths, key=lambda h: HEALTH_ORDER.get(h, 1))


def classify(status: str, sub: str, rpo: int, alert_status: int = 0) -> str:
    """failure | warning | healthy.

    Close to the colour Zerto shows, with one deliberate difference: syncing substatuses
    (BitmapSync, DeltaSync, ...) are 'warning' here, while Zerto shows them green.
    Two independent inputs, and the worse one wins: the replication state
    (status / substatus / RPO), and Zerto's own AlertStatus for the VPG. The second
    is what turns a MeetingSLA VPG yellow in Zerto when, say, its journal passes 50%.
    """
    if status in FAIL_STATUS or sub in FAIL_SUB:
        by_state = "failure"
    elif rpo is not None and rpo < 0 and status not in ("Initializing", "Moving", "FailingOver", "Deleting"):
        by_state = "failure"      # no recovery point at all
    elif status in WARN_STATUS or sub in SYNCING or sub == "RecoveryPossible":
        by_state = "warning"
    elif status == "MeetingSLA" and sub == "None":
        by_state = "healthy"
    else:
        by_state = "warning"
    a = alert_status or 0
    # 3 and 4 are legal in Zerto's 9.0 schema but undocumented: fail closed
    return worst(by_state, ALERT_STATUS_HEALTH.get(a, "warning" if a else "healthy"))


def alert_key(a: dict) -> tuple:
    """Identity of one Zerto condition across ZVMs and payload versions: pre-fix payloads
    cut the text at 220 chars, current ones at 300. TurnedOn is left out on purpose: each
    ZVM raises its own copy of e.g. VPG0058 a few ms apart."""
    return (a.get("id"), (a.get("text") or "")[:220])


def reason(v: dict) -> str:
    """One human sentence explaining WHY this VPG is not healthy."""
    bits = []
    st, sub, rpo = v["status"], v["sub"], v["rpo"]
    if sub == "ReplicationPausedForMissingVolume":
        bits.append("paused - a protected VM/volume no longer exists")
    elif sub in ("Error", "RecoveryStorageError"):
        bits.append(f"{sub} - Zerto cannot continue without intervention")
    elif sub == "RecoveryPossible":
        bits.append("RecoveryPossible - replicating, but the protected site's ZVM has lost its hypervisor")
    elif sub in SYNCING:
        if (v.get("thru") or 0) < 0.5 and (v.get("progress") or 0) == 0:
            bits.append(f"{sub} at 0% with no data moving - stalled")
        else:
            bits.append(f"{sub} {v.get('progress', 0):.0f}% at {v.get('thru', 0):.1f} MiB/s")
    if v.get("on_disconnected_vra"):
        bits.append("protected VM sits on a DISCONNECTED VRA (" + ", ".join(v["on_disconnected_vra"]) + ")")
    if rpo is not None:
        if rpo < 0:
            bits.append("no recovery point")
        elif v.get("rpo_cfg") and rpo > v["rpo_cfg"]:
            bits.append(f"RPO {fmt_age(rpo)} vs {fmt_age(v['rpo_cfg'])} target")
    if st in ("HistoryNotMeetingSLA",):
        bits.append("journal history short of configured")
    if not bits and classify(st, sub, rpo) != "healthy":
        bits.append(f"{st} / {sub}")        # bad replication state with no phrase of its own
    # Zerto's alerts on this VPG, worst first - the reason for a MeetingSLA VPG that
    # Zerto still shows yellow or red
    live = sorted((a for a in v.get("alerts", []) if a.get("level") in ("Error", "Warning")),
                  key=lambda a: (a["level"] != "Error", a.get("id") or "", a.get("since") or ""))
    if live:
        first = live[0]
        text = (first.get("text") or "").strip()
        if len(text) > 150:
            cut = text.rfind(". ", 0, 150)
            text = text[:cut + 1] if cut > 40 else text[:147].rstrip() + "..."
        extra = len({alert_key(a) for a in live}) - 1
        label = first.get("id") or first["level"]
        bits.append((f"{label}: {text}" if text else label)
                    + (f" (+{extra} more alert{'s' if extra > 1 else ''})" if extra > 0 else ""))
    # Zerto's own flag, when no linked alert accounts for it - say so without guessing why
    sev = v.get("alert_status") or 0
    covered = (sev == 1 and live) or (sev == 2 and any(a["level"] == "Error" for a in live))
    if sev and not covered:
        bits.append(f"Zerto flags {'an error' if sev == 2 else 'a warning'}-level alert on this VPG that "
                    "no active alert here explains (dismissed, unlinked or raised elsewhere)"
                    if sev in ALERT_STATUS_HEALTH else f"Zerto AlertStatus {sev} (undocumented value)")
    if v.get("stale_from"):
        bits.append(f"(from {', '.join(v['stale_from'])}'s last good poll - source not answering)")
    return "; ".join(bits) or f"{st} / {sub}"


def fmt_age(seconds) -> str:
    try:
        s = int(seconds)
    except (TypeError, ValueError):
        return "?"
    if s < 0:
        return "none"
    if s < 90:
        return f"{s}s"
    if s < 5400:
        return f"{s // 60}m"
    if s < 172800:
        return f"{s / 3600:.1f}h"
    return f"{s / 86400:.1f}d"
