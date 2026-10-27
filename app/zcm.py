"""Zerto Cloud Manager client.

The ZCM REST API listens on 9989. Per the ZCM API reference (legacy 7.x/8.x
copies are the only readable ones): POST /v1/session/add with Basic
username/password and body {"AuthenticationMethod": 0}, where
  0 = Windows        - the account on the machine where ZCM is installed (DEFAULT)
  1 = VirtualizationManager - vCenter/SCVMM credentials
The empty-body response carries x-zerto-session, which every later call must
send; sessions expire after 30 min idle. There is no API token/key mechanism.
The account must be a member of the ZCM server's local Administrators group
(typically via a domain group) - otherwise "Provide Administrator credentials".

ZCC health (per /v1/cloudconnectors): Status (Installed/Installing/Removing/
Orphaned), GhostStatus, SitePaired, Progress.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CANDIDATES = ["/v1/zorgs", "/v1/cloudconnectors", "/v1/serviceprofiles",
              "/v1/sites", "/v1/localsite", "/v1/alerts", "/v1/zccs"]


class ZcmError(Exception):
    pass


class ZcmClient:
    def __init__(self, host: str, identity: str, secret: str, verify_tls: bool = False,
                 port: int = 9989, timeout: int = 60, session: requests.Session | None = None):
        self.base = f"https://{host}:{port}"
        self.auth = (identity, secret)
        self.verify = verify_tls if session is None else False
        self.timeout = timeout
        self.headers = {"Accept": "application/json"}
        self.session_header = None
        self._http = session or requests          # pinned session when the source isn't CA-verified

    @staticmethod
    def _no_redirect(r, what):
        # credentials (Basic auth, the x-zerto-session header) are never re-sent elsewhere
        if r.is_redirect or r.status_code in (301, 302, 303, 307, 308):
            raise ZcmError(f"refused a {r.status_code} redirect from {what}")

    def _get(self, path: str):
        h = dict(self.headers)
        if self.session_header:
            h.update(self.session_header)
        r = self._http.get(f"{self.base}{path}", headers=h,
                           auth=None if self.session_header else self.auth,
                           verify=self.verify, timeout=self.timeout, allow_redirects=False)
        self._no_redirect(r, path)
        return r

    def login(self):
        errors = []
        # Windows auth (0) is the ZCM default; VirtualizationManager (1) as fallback.
        for method in (0, 1):
            s = self._http.post(f"{self.base}/v1/session/add", auth=self.auth,
                                headers={"Content-Type": "application/json"},
                                json={"AuthenticationMethod": method},
                                verify=self.verify, timeout=30, allow_redirects=False)
            self._no_redirect(s, "the ZCM login")
            sid = s.headers.get("x-zerto-session")
            if s.status_code == 200 and sid:
                self.session_header = {"x-zerto-session": sid}
                return
            errors.append(f"method {method}: {s.status_code} {s.text[:110]}")
        # Some builds accept Basic per request; last resort.
        r = self._get("/v1/zorgs")
        if r.status_code == 200:
            return
        hint = ""
        if any("Administrator credentials" in e for e in errors):
            hint = " -> account recognised but is not a ZCM administrator: add it to the ZCM server's local Administrators group"
        raise ZcmError("auth failed: " + " | ".join(errors) + hint)

    def collect(self) -> dict:
        t0 = time.time()
        self.login()
        out = {"collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
               "endpoints": {}, "zorgs": [], "cloud_connectors": []}
        for p in CANDIDATES:
            try:
                r = self._get(p)
                if r.status_code == 200:
                    try:
                        out["endpoints"][p] = r.json()
                    except ValueError:
                        out["endpoints"][p] = r.text[:500]
                else:
                    out["endpoints"][p] = {"_status": r.status_code}
            except requests.RequestException as e:
                out["endpoints"][p] = {"_error": type(e).__name__}

        z = out["endpoints"].get("/v1/zorgs")
        if isinstance(z, list):
            out["zorgs"] = [_flat(x) for x in z]
        # The documented list form is per-zORG: /v1/cloudconnectors?zorgidentifier=<id>.
        # A bare GET may or may not return everything, so try it and then fill any
        # gaps zORG by zORG.
        seen: dict[str, dict] = {}
        cc = out["endpoints"].get("/v1/cloudconnectors")
        if isinstance(cc, list):
            for x in cc:
                f = _flat(x)
                seen[str(x.get("CloudConnectorIdentifier") or f.get("_name") or id(x))] = f
        if isinstance(z, list):
            for zo in z:
                zid = zo.get("ZorgIdentifier") or zo.get("Identifier")
                zname = zo.get("ZorgName") or zo.get("Name")
                if not zid:
                    continue
                try:
                    r = self._get(f"/v1/cloudconnectors?zorgidentifier={zid}")
                    if r.status_code == 200 and isinstance(r.json(), list):
                        for x in r.json():
                            f = _flat(x)
                            f.setdefault("_zorg", zname)
                            f["_zorg_id"] = zid
                            key = str(x.get("CloudConnectorIdentifier") or f.get("_name") or id(x))
                            seen[key] = {**seen.get(key, {}), **f}
                except (requests.RequestException, ValueError):
                    pass
        out["cloud_connectors"] = list(seen.values())
        out["duration_ms"] = int((time.time() - t0) * 1000)
        return out


def _flat(obj: dict) -> dict:
    """Keep scalar fields plus a normalised name/status/zorg/healthy.
    Cloud connectors: Status in {Installed, Installing, Removing, Orphaned},
    plus GhostStatus, SitePaired and Progress. zORGs: ZorgName / ZorgIdentifier."""
    flat = {k: v for k, v in obj.items() if isinstance(v, (str, int, float, bool)) or v is None}
    # nested zorg refs sometimes arrive as {"ZorgName":..,"ZorgIdentifier":..}
    zref = obj.get("Zorg") if isinstance(obj.get("Zorg"), dict) else {}
    name = next((obj.get(k) for k in ("ZorgName", "CloudConnectorName", "Name", "VmName",
                                       "DisplayName") if obj.get(k)), None)
    status = next((obj.get(k) for k in ("Status", "StatusDescription", "State", "Health",
                                         "ConnectionStatus") if obj.get(k) is not None), None)
    zorg = next((x for x in (obj.get("ZorgName"), zref.get("ZorgName"), obj.get("OrganizationName"),
                             obj.get("ZorgIdentifier"), zref.get("ZorgIdentifier")) if x), None)
    flat["_name"], flat["_status"], flat["_zorg"] = name, status, zorg
    # the ZCM sends GhostStatus as the TEXT "False"/"True" (verified 2026-10-06), and a
    # non-empty string is truthy in a template - so normalise it to a real bool here
    flat["_ghost"] = _is_ghost(obj.get("GhostStatus"))
    flat["_paired"] = obj.get("SitePaired")
    # Progress is the install/removal progress: always 0 on an installed connector, so it
    # only means something while one is being installed or removed
    busy = str(status or "").lower() in ("installing", "removing")
    flat["_progress"] = obj.get("Progress") if busy else None
    flat["_healthy"] = _looks_healthy(status, flat["_ghost"], flat["_paired"])
    return flat


def _is_ghost(v) -> bool | None:
    """GhostStatus -> True/False, or None if absent. Unknown values count as ghost (fail closed)."""
    if v is None:
        return None
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() not in ("0", "false", "none", "notghost", "")


def _looks_healthy(status, ghost=None, paired=None) -> bool | None:
    if status is None:
        return None
    s = str(status).lower()
    if s == "orphaned" or ghost is True:
        return False
    if paired is False or str(paired).lower() == "false":
        return False
    if s in ("installed", "0", "ok", "connected", "healthy", "running", "up", "true", "normal"):
        return True
    if s in ("installing", "removing"):
        return None
    if any(x in s for x in ("error", "disconnect", "fail", "down", "unreach", "warn")):
        return False
    return None
