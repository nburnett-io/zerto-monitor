# Backlog

Prioritised build list. It draws on the final code review of v1.2 (2026-10-05, app and appliance
reviewed separately, every finding checked against the code) and on a review of the Zerto 10.9
ZVM API (452 paths) for what would make this the engineers' one-stop shop for customer DR.

Sizes: **S** is under a day, **M** is a few days, **L** is a week or more. File references are to v1.2.

## Status after 1.5.0 (first public release)

- **Done in 1.5.0:** a neutral brand; the release index is configurable (any Gitea/Forgejo
  generic-package registry, or a `releases.json` URL such as a GitHub release); nothing
  environment-specific in the repository.

## Status after 1.4.2 (2026-10-21)

1.4.2 was a full code audit (five parallel reviews) and its fixes; [CHANGELOG.md](CHANGELOG.md)
lists them.
- **Done in 1.4.2:**
  - P0 #1 CSRF;
  - #6, the identity part;
  - #9, the helper `set -e`;
  - #11, duplicate alerts;
  - #12, stale-poller detection.
  - From P2:
    - JS injection in `confirm()`;
    - `remove_ignore` logging the wrong zORG;
    - Entra taking over local accounts;
    - the cloud-init / `install.ps1` path (deleted);
    - upgrade backup and rollback (console Apply now uses the signed updater);
    - username validation;
    - the netplan driver match (MAC only now).
- **Changed by request:** one read/write credential per ZVM. The separate change credential
  is gone. The arming switches, per-write allowlists and pinning stay.
- **Still open:**
  - P0 #7, first-boot lock-down in `finally`;
  - #8, the scrubber with ISO transport;
  - #10, wiping residue on fresh deploys;
  - the rest of P2: login lockout, revocable sessions, `/setup` token, PKCE/nonce and
    `tid`+`oid` keys for Entra, a per-source poll deadline.

## Status after 1.3 (2026-10-06)

**Done in 1.3:**
- P0 #2–6, the resize items:
  - a resize always ends;
  - recovery is judged on fresh data only;
  - the resize pin is checked against the polling pin;
  - pinned sessions ignore proxy environment variables;
  - the public API no longer exposes resize bodies;
  - plus queued resizes expire, *waiting for user input* counts as a conflict, holds get
    slack, and holds skip VPGs without an identifier.
- P1 console menu.
- P1 #1, VPG backup and restore.
- P1 #3, recovery plans per zORG.
- From the P1 #5 table: event timeline, RPO and journal trends, hot-spot detection, monthly
  report with PDF.
- Product branding (logo, report header).
- `purge_expired_ignores` is now called.

**Decided not to build:** unprotected-VM detection and ransomware alerts (2026-10-06).

**Still open:**
- P0 #1 CSRF, #7–9 first-boot lock-down, scrubber and helper `set -e`, #10 wipe residue on
  fresh deploys, #11 duplicate alerts, #12 stale-poller detection.
- P1 #2 vSphere ↔ vCD conversion wizard; P1 #4 automated DR tests.
- From the P1 #5 table: checkpoint tagging, VMs without MoRefId, capacity, licence and
  version, guarded bulk actions.
- SNMPv3.
- All of P2.
- **Verify on first use:**
  - the recovery-plan create body against a live 10.9 ZVM (no plan existed to learn from);
  - the import (restore) on a test VPG;
  - the Keycloak privileges each change needs.

---

## P0 — fix before the first real VRA resize, and before "production"

These are safety or security gaps. None of them is exploited today: no resize has run, and the
UI is internal. All of them need fixing before arming resizes or switching **Require sign-in** on.

| # | Item | Size |
|---|---|---|
| 1 | **CSRF.** No state-changing POST checks Origin or carries a token, and `SameSite=Lax` doesn't help, because every host under the same internal domain counts as the same site (`.local` isn't a public suffix). A script on any other internal web app could make a signed-in admin create an admin, repoint SSO or start a resize. Fix: reject any POST whose Origin/Referer isn't this host, and add a per-form token. | S |
| 2 | **A resize can be stranded.** `vrapush.run_one` catches only `ZvmError`/`RequestException`. A re-login after the PUT (`cl.login()` at vrapush.py:492 and :522, outside the try), a sqlite lock, or a None VPG key in `add_holds` leaves the push in `task_running`/`queued`. The VRA may then be powered off with no halt and no alert, every later resize is blocked, and a `queued` row is retried every 5 s. Fix: `except Exception` gives *unknown* with holds kept after the PUT and *refused* before it; expire `queued` rows after 10 min. | S |
| 3 | **False "all recovered".** During VPG recovery, a failed poll leaves the last good snapshot in place, which is the pre-outage, all-healthy one. The runner can pass on that data. Fix: trust only `ok=1` snapshots taken after the VRA came back, and make `_refresh` raise on failure. | S |
| 4 | **The resize credential's pin** is a fresh capture at click time, not compared with the source's existing polling pin. Fix: default to the existing pin, and refuse on mismatch. | S |
| 5 | **Proxy environment bypasses the pin.** `pinned_session` honours `HTTPS_PROXY`, which drops `assert_fingerprint`. Fix: `trust_env = False`. | S |
| 6 | **Public API over-shares.** `/api/vras/{site}` returns full resize audit rows (request and response bodies, ticket, attestation). `/api/sources` and the admin form show source usernames/client ids that are encrypted at rest. Fix: project only the columns the page renders, and show "stored" instead of the identity. | S |
| 7 | **The OVF lock-down can be skipped.** If first boot fails before the lock-down runs (for example a bad admin username makes `chpasswd` raise), cloud-init stays enabled and guestinfo keeps the deploy passwords, readable by any local user, for good. Fix: run the lock-down in `finally`, and validate input up front. | S |
| 8 | **The scrubber can report a false all-clear.** On ISO-transport deploys first boot ejects the CD before the scrub, so the scrub reports "nothing held" while vCenter still holds the passwords. An unparseable guestinfo environment is left unscrubbed. Fix: scrub before ejecting; keep the last known state when media is absent; blank secrets by regex when the XML won't parse, and report "unknown", not clean. | S |
| 9 | **Root helper errors are swallowed.** `zerto-monitor-admin` runs `( dispatch ) \|\| rc=$?`, which disables `set -e`, so failed `hostnamectl`, nginx reload or snmpd writes report OK. Fix: `( set -e; dispatch ); rc=$?`. | S |
| 10 | **Fresh deploys leave residue on disk.** On the live box it took three passes to clear (done 2026-10-05; see *Disk residue* below). A new deploy will have the same residue from first boot. Fix: at the end of first boot, after the lock-down, run one free-space wipe with ext4 `reserved_clusters` set to 0. Keep journald volatile until first boot finishes. Use a discard-capable controller (pvscsi, thin disk) so `fstrim` works. | S |
| 11 | **Duplicate alerts.** "Poll all" can run `alerts.evaluate` twice at once, which sends duplicate emails/traps and makes the clocks race. Fix: a lock around `evaluate`. | S |
| 12 | **A dead poller looks healthy.** Source health is the last snapshot's `ok`, with no age check. A hung loop leaves everything green, SNMP polling sees `sources_down=0`, and alerting stops. Fix: treat snapshots older than 3× the poll interval as down, and alert on it. | S |

## P1 — appliance console menu (your request)

Today SSH or the console drops you straight into bash. Instead, an **appliance menu** like
vCenter's DCUI: a `whiptail` TUI that runs on tty1 in place of getty, and at SSH login for the
admin account. The menu holds:

- **Network**: DHCP or static, IP/prefix/gateway, DNS and search domains, and NIC selection by
  MAC/driver. It uses `netplan try` (auto-rollback in 120 s if you lose the session), then
  regenerates the self-signed certificate so its SANs match. Fixes appliance review findings 5
  and 9: netplan currently binds to the NIC name, and a replaced vNIC or new IP leaves the box
  unreachable or the certificate stale.
- **Hostname**: wraps the existing helper verb, plus the certificate.
- **Disk expansion**: rescan the SCSI bus, then `growpart` and `resize2fs`. Cloud-init is
  disabled after first boot, so nothing grows the 10 GB root today.
- **Time**: NTP servers, timezone, chrony status.
- **Services**: status, restart, the last 50 log lines, connectivity tests (DNS, plus TCP
  443/9669/9989 to each source).
- **Upgrade**: apply a payload from `/tmp`, with a backup first (see P2 *Backups*).
- **Break-glass**: reset the web admin password, toggle SSH password auth, show the security
  posture.
- **Shell**: needs the sudo password; reboot and shut down.

The menu only calls validated verbs in the root helper, so there is one code path to harden.
Same release: make a password mandatory when there's no root password, or add NOPASSWD sudo
when the admin uses a key only (finding 6). Today a key-only admin can't become root. **Size: M.**

## P1 — engineer one-stop shop (Zerto API)

### 1. VPG configuration backup, kept 7 days — yes

The API supports two read paths.

- **`copyVpgSettings` per VPG (recommended).**
  - Steps: `POST /v1/vpgSettings/copyVpgSettings {vpgIdentifier}`, then
    `GET /v1/vpgSettings/{id}`, then `DELETE /v1/vpgSettings/{id}`.
  - What you get: the complete settings — basic (RPO, journal history, test interval, zORG,
    service profile), recovery target (host/cluster/datastore, or vCD org vDC), networks, per-VM
    NICs and volumes, journal, scratch, scripts and boot groups.
  - Nothing is left behind on the ZVM.
- **`exportSettings`.**
  - Steps: `POST /v1/vpgSettings/exportSettings {vpgNames[]}`, then fetch with
    `POST /v1/vpgSettings/exportedSettings/{timeStamp}`.
  - What you get: the whole site in one call.
  - Drawback: the API has no delete for exports, so they pile up on the ZVM.

Build:
- A nightly job (plus "back up now" per VPG or zORG) stores each VPG's settings JSON compressed
  in SQLite, Fernet-encrypted for consistency, and purges after 7 days. Retention is a setting.
- **Diff view**: "what changed on this VPG since yesterday". This catches journal shrinks,
  RPO edits, removed VMs and moved recovery targets, which today nobody notices.
- **Restore**: `POST /v1/vpgSettings/import` recreates a deleted or broken VPG from a backup. It
  is a write, so it's admin-only and gated like the resize (preview the body, ticket, one shot).

Caveat: creating a settings copy is an edit session. It needs a credential with VPG-edit
privilege; verify the exact Keycloak role on a test ZVM. Skip VPGs that have an operation running.
**Size: M** (backup + diff), **M** (restore).

### 2. Convert a VPG between vSphere and vCD recovery — not in place, but it can be guided

Zerto won't change a VPG's recovery type, or its org vDC, on an existing VPG. The API
models the target as either `recovery.vcd.orgVdcIdentifier` or host/cluster/datastore. The only
path is **recreate with preseed**:

1. Back up the settings (feature 1).
2. Delete the VPG and **keep the recovery volumes**: `DELETE /v1/vpgs/{id}` with body
   `{keepRecoveryVolumes: true}`.
3. Build new settings with the other target type:
   - vCD: an org vDC plus a vCD network mapping;
   - vSphere: host/cluster, datastore and port groups.
   - Each disk points at its kept volume through `volumes[].preseed {datastoreIdentifier, path}`.
4. Validate (settings objects return validation errors before commit), then commit.

Cost:
- **All journal history and checkpoints are lost.** No point-in-time before the cutover.
- The first sync is a delta sync, which reads every protected disk end to end.
- For vCD, the kept disks must sit on a datastore the org vDC's storage policy can use, and the
  VPG must belong to that org's zORG.

Build: a wizard that does steps 1, 3 and 4 as a dry run and shows the full body and a
validation result, then an admin-only commit. Step 2 stays manual in the Zerto UI the first
few times. **Prove it on a test VPG before any customer. Size: L.**

### 3. Recovery plans per zORG, in order — yes, quickly

10.9 has `/v1/recoveryPlans` (GET, POST, PUT, DELETE, plus `startfol`, `startfot`, `pause`,
`resume`). A plan is an ordered list of blocks:
- **VPG** (a set of VPGs that start together);
- **WaitRecoveryOperationCompletion** (finish this tier before the next);
- **Delay** (minutes);
- **Script** (a script from the ZVM's script repository, with parameters).

Plans are `Standard` or `Cyber`.

Build:
- **"Create recovery plan" on the zORG page.**
  - The zORG's VPGs are pre-listed; drag them into tiers (DCs → SQL → app → web).
  - A *wait for completion* goes between tiers, with optional delays and script blocks.
  - Name it `<zORG> DR`, preview the body, then POST.
  - Save tier layouts as templates: "AD first, then everything" covers most small customers.
- **Plan health** on the zORG page and the dashboard, from `/v1/recoveryPlans/summary` and
  `/v1/reports/recoveryPlans`: status (Ready, Error, Completed…), last run, last successful run.
- **Plan drift**: flag zORGs with **no plan**, and plans **missing a VPG**. A VPG added after the
  plan was built is silently left out of a real failover. That's the one that bites.

Verify on a test ZVM which site owns the plan (expected: recovery side), then it's straightforward.
**Size: M.**

### 4. Automated DR tests for smaller customers — yes, with real verification

Zerto can run a test: per VPG, `POST /v1/vpgs/{id}/FailoverTest {checkpointIdentifier}`
then `FailoverTestStop {failoverTestSuccess, failoverTestSummary}`; or a whole plan in order
with `POST /v1/recoveryPlans/{id}/startfot`. **Zerto only proves the VMs were created and
powered on.** "Success" needs proof that the guests came up. In order of effort:

1. **VMware Tools heartbeat green and a guest IP present** on each test VM. This is a read-only
   query to the recovery vCenter or vCD.
2. **A console screenshot** of each test VM after N minutes (vSphere `CreateScreenshot_Task`),
   attached to the report. A Windows lock screen is strong evidence and customers understand it.
3. **Service checks** (ports, HTTP, SQL login) from a small probe VM placed in the customer's
   isolated test network. This is optional per customer, and it's the only way into a test
   network that is isolated by design.

Build:
- **Per-zORG opt-in**, a monthly or quarterly window, and one test at a time per site.
- **Pre-checks**: every VPG Meeting SLA, journal and scratch headroom, recovery-site capacity in
  the org vDC, no other operation running, and an opt-out list of zORGs never to test.
- **Hard stop** at a maximum duration (default 60 min); tests consume scratch, and a forgotten
  test fills it.
- **Write the verdict back into Zerto** with `failoverTestSummary`, so it appears in Zerto's own
  reports and the customer's ZSSP.
- **Per-test report** (VMs, RTO from `/v1/reports/recovery`, heartbeat/IP/screenshot per VM): an
  HTML/PDF the customer can use as audit evidence.
- **Test-recency SLA** per zORG (e.g. quarterly), and an "overdue tests" tile. In practice
  several zORGs turn out never to have been tested.

Starts and stops are writes, so they need a separate engineer-armed credential, like resizes.
**Size: L** (scheduler + checks 1–2 + report); probe VM later.

### 5. What I'd add as the engineer responsible for customer DR

| Feature | API | Why | Size |
|---|---|---|---|
| **Unprotected VMs**: VMs in a customer's vApp/org vDC that are in no VPG | `/v1/virtualizationsites/{id}/vms` (eligible, unprotected), `…/vcdvapps` (unprotected vApps) | The most common real-world DR gap: a customer adds a server and nobody protects it | M |
| **Ransomware (encryption detection)** at the top of the dashboard and in alerts | `/v1/encryptionDetection/suspected/{vpgs,vms,volumes}` | Zerto already detects it, but nobody is looking | S |
| **Event timeline** per VPG and zORG: who edited, paused, force-synced, tested | `/v1/events` | "What changed?" is the first troubleshooting question | S |
| **RPO and journal trend** per VPG (7–30 days), plus "journal not meeting configured history" | VPG history (already collected), `/v1/statistics/vms` | Shows slow degradation before it breaches; capacity planning | M |
| **Tag a checkpoint** button before customer maintenance or a patch night | `POST /v1/vpgs/{id}/checkpoints` | A known-good restore point with a name; harmless write | S |
| **VMs without MoRefId** (restored vCD VMs that can never be protected) | `/v1/vcd/vmsWithoutMorefId` | A trap we've already hit; list it per zORG with the fix | S |
| **Hot-spot detection**: one VM or VPG dominating a VRA's inbound (one VM was 42% of a whole site's inbound replication) | `/v1/statistics/vms`, VRA mapping | Explains whole-site lag that looks like a platform issue | M |
| **Capacity**: recovery-site datastores, journal and scratch headroom, VRA memory vs load | `/v1/reports/resources`, datastores | Fail over only works if there's room | M |
| **Licence and version**: licence usage and expiry, ZVM/VRA version drift, upgrade readiness | `/v1/license`, `/v1/licenses`, VRA versions | Avoid surprise expiry; plan upgrades | S |
| **Guarded bulk actions**: pause, resume, force-sync, with confirmation and audit | `/v1/vpgs/{id}/pause\|resume\|forcesync` | Common fixes without logging in to each ZVM | M |
| **Monthly customer DR report** per zORG: RPO, tests, alerts, plan status | all of the above | Something to hand the customer; shows the service working | M |

## P1 — coverage

- **SNMPv3** (authPriv) for the agent and traps; v2c communities are plaintext on the wire by
  design. **M**

## P2 — code review findings, robustness and hardening

**Auth and sessions**
- **Entra SSO can take over local accounts.** Users are matched by mutable UPN/email, so SSO can
  overwrite a local admin's role. Fix: key on `tid`+`oid`, never merge into `local` rows, and
  enforce the last-admin guard. Also use PKCE/nonce (`initiate_auth_code_flow`), handle
  groups-claim overage, and default `next=/`. (M)
- **Login lockout**: per-IP and per-user backoff. (S)
- **Revocable sessions**: a per-user `session_gen` in the JWT, bumped on logout or password reset. (S)
- **`/setup` is open** when no web password was given at deploy; require a console-shown
  one-time token. (S)
- **JS-string injection** in `confirm('{{ name }}')` (admin.html:49, 53, 340); use `|tojson`. (S)

**Polling and the event loop**
- **Blocking sqlite and JSON on the event loop** (snapshot save, per-request user lookups); move
  them to threads. (M)
- **No per-source deadline per poll**: one sick ZVM delays everyone. Fix: `wait_for` per source,
  and cache the ZCM's per-zORG lookups. (S)
- **Poll interval**: cap it at 3600 s and apply changes immediately. (S)
- **`crypto.decrypt`** returns "" on a wrong key; warn, and count it on the Security card. (S)

**Validation and routing**
- **`/` in zORG or site names breaks routes** (use `{name:path}`). (S)
- **Login redirect loses the query string.** (S)
- **Source host and auth type** aren't validated on edit. (S)
- **snmptrap argv** needs `POSIXLY_CORRECT`. (S)

**Resize and data**
- **Holds** need 15 min slack. Check the task-status codes; is 2 "waiting for user input"? It
  isn't in the spec. (S)
- **`purge_expired_ignores`** is never called. (S)
- **Pin rekey migration** can overwrite a newer pin. (S)
- **`remove_ignore`** logs the wrong zORG. (S)

**Appliance hardening**
- **Network input** isn't validated before netplan (rolled into the console menu). (S)
- **nginx error log** can record `?code=` query strings; set `error_log … crit`. (S)
- **Self-signed key generated in disk-backed `/tmp`**; use `/run`. (S)
- **SNMP cache file** at a predictable `/tmp` path; move it to `/run`. (S)
- **SSH**: password auth only for the admin (`Match User`), plus `AllowUsers` and
  `MaxAuthTries`. Remove the leftover `ubuntu` user and its NOPASSWD sudoers file. (S)
- **Backups**:
  - `--upgrade` should take a `VACUUM INTO` copy and the code tree first, and offer rollback.
  - Add a documented **Fernet key escrow**; losing the key loses every stored credential.
  - (M)
- **Upgrade**: stop the service before chowns, and extract into a fresh directory and swap, so
  deleted files don't linger. (S)
- **`run_local.ps1`** leaves the dev keys in the calling shell's environment; clear them in
  `finally`. (S)

**Docs and deploy path**
- **Retire or fix the `cloud-init.yaml` + `install.ps1` path.** It makes the code
  service-writable, `install.ps1` can't write as the admin account, and it references a missing
  `install.sh`. (S)
- **README corrections**:
  - list `snmpd.conf` and the TLS private key as deliberate plaintext exceptions;
  - first boot needs apt + PyPI (offline wheels can't be pre-placed);
  - re-running first boot is destructive;
  - also clear `zm-zvm-user` in vCenter;
  - stale check counts and sizes.
  (S)
- **`validate_ova.py`**: syntax-check the root helper, XML-escape the synthetic environment, and
  test wizard values containing `& " <`. (S)

**UX**
- The login page still says only Admin needs a login.
- 403s on form posts render as JSON.
- Self-host the Google font.
- Close legacy ZVM/ZCM sessions.
- Swap python-jose for PyJWT.
- Add a "test resize credential" button.

## Disk residue (live box, 2026-10-05)

**Resolved: the raw disk now has 0 copies of any credential.** The check decrypts every stored
credential on the box, takes the deploy-time password, and searches the whole 10.7 GB
`/dev/sda` for each value in raw, HTML, URL, JSON and UTF-16 forms. Each hit is mapped to its
partition, block and owning file through `debugfs`.

The VM's disk advertises no discard/TRIM, so deleted data stays on disk until it's overwritten.

| pass | what | hits left |
|---|---|---|
| start | after the 1.2 secrets fixes | 27: deploy password ×5, client ids ×21, SNMP community ×1 |
| 1 | `journalctl --vacuum`, then a dd zero-fill of free space | 18 |
| 2 | persistent journal deleted (the live `system.journal` held pre-1.2 client-id lines), WAL checked, zero-fill again | 11 |
| 3 | ext4 `reserved_clusters` set 4096 → 0 for the fill, then restored | **0** |

**Lessons:**
- **A dd zero-fill never reaches ext4's reserved clusters.** Up to 16 MB of genuinely free blocks
  can't be allocated by ordinary writes, even root's. Every copy that survived two fills was there.
  Setting `/sys/fs/ext4/<dev>/reserved_clusters` to 0 for the fill fixes it.
- **Vacuuming the journal doesn't touch the active file.** Stop journald and delete the files
  instead.
- **Earlier raw scans were wrong.** One note said the raw-disk scan found 0. That scan was broken
  (its grep silently failed) and found nothing at all. The scan that produced the results above
  starts from known values, so a broken scan would show up immediately.
