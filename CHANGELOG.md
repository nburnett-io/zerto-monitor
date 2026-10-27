# Changelog

## 1.5.0 — first public release
- **Open source** under Apache-2.0 (LICENSE, NOTICE). Nothing environment-specific in the
  repository: no company, customer, host or site names, and only documentation-range IP
  addresses in tests and examples.
- **Neutral brand.** "Zerto Monitor" is the only brand, with a text-based SVG logo. No company
  logo or name appears in the UI, reports, emails, certificates or the OVA.
- **Release index is configurable** (Admin → Updates → update source).
  - It can be a Gitea/Forgejo generic-package base URL, or a full `releases.json` URL such as
    `https://github.com/OWNER/REPO/releases/latest/download/releases.json`.
  - The default is none: upload a `.zmupdate` instead.
  - Index and bundle downloads follow redirects (GitHub's CDN). The Ed25519 signature is still
    the only trust anchor.
- **Release signing key path** defaults to `%USERPROFILE%\.zerto-monitor\release-signing.xml`,
  or `ZM_SIGNING_KEY`.
## 1.4.2 — 2026-10-21
A full code audit (five parallel reviews: web and sign-in, data and alerting, Zerto writes,
root updater and helper, console and tooling) and its fixes. 52 fixes in all.
- **Version footer** on every page; `/healthz` reports the running version, and the updater
  checks it.
- **One read/write credential per ZVM.** Changes (resize, restore, plans, fresh exports) use
  the source's own credential. The separate change credential is gone, and any stored one is
  wiped.
  - **Unchanged safety gates:** per-feature switches, site arming, admin-only starts,
    per-write path allowlists and pinned TLS.
  - **Write rights:** the credential needs them granted in the ZVM's Keycloak. The source card
    shows the roles its token holds.
- **Security:**
  - **Cross-site request protection on every POST.** It matters now that Require sign-in is
    on: every host under one internal domain counts as the same site.
  - The update API accepts JSON only.
  - Write allowlists are full-string matches, and no id may be a `.` or `..` segment.
  - `/api/sources` no longer returns identities.
  - Entra sign-in never takes over a local account.
  - Login runs bcrypt off the event loop, in constant time for unknown users.
  - Passwords over 72 bytes and usernames with `/` are refused instead of crashing.
  - `confirm()` prompts are JS-safe.
  - A source whose Keycloak client can't be deleted is kept (with a "remove anyway"), and
    deregistration is always pinned.
- **Alerting:**
  - The failure threshold uses its own continuous-failure clock, so one-poll blips no longer
    email "Failure".
  - No false "Recovered" for a VPG that disappeared.
  - A failed send is retried next poll.
  - Storm roll-ups go per recipient set.
  - Polls can't overlap, so there are no duplicate emails.
  - A hung poller counts as down.
  - A global code ignore no longer hides an AlertStatus=2 VPG.
- **Recovery plans:**
  - A plan holding another zORG's VPGs, or steps the builder can't reproduce, can't be edited
    (saving would have dropped them).
  - A plan id is checked against the zORG, for both update and delete.
  - Duplicate names are refused.
  - A timeout or 5xx after sending is "unknown", not "failed".
  - Stuck "sending" rows are cleared at start.
- **VRA resize:**
  - Recovery is judged by VPG id, not host membership.
  - The halt is recorded first.
  - Nothing reads "sent" before the PUT starts.
  - The host-alert filter matches the preview's.
- **Root updater:**
  - Any error after the backup rolls back.
  - A backup failure installs nothing.
  - The upgrade timeout fits inside the unit's timeout.
- **Root helper:** errors propagate (P0 #9).
- **Console:**
  - A rolled-back network change is really reverted.
  - A second adapter can't wipe the first.
  - NICs are matched by MAC only.
  - Netplan snapshots are named in UTC, and restore refuses a missing snapshot.
  - Upgrade → Apply now installs a signed `.zmupdate` through the root updater: verified,
    backed up, rolled back.
- **Data:**
  - The alert log is kept 400 days, so reports older than 90 days no longer say "no alerts".
  - Report event counts are no longer capped.
  - The backups page is no longer cut off at 20,000 rows.
  - Fewer full-snapshot parses: alert delivery, the backups page, `/timeline`, update status
    and plan routes no longer block the event loop.
  - The events window advances past noise and has a 30-minute overlap.
- **Release tooling:**
  - The signed payload is secret-scanned.
  - `.pub` and the logo PNGs are published.
  - `-Rotate` won't overwrite a waiting key.
  - Multiple base images fail the build.
  - The index re-upload is retried.
  - `install.ps1`, `cloud-init.yaml` and `peek_ova.py` are deleted.
- **Dead code removed:**
  - `alerts._vpg_lines` and the dead `_digest` branches;
  - `db.set_admin`, `playbook.has_entry`, `auth.entra_is_admin`, `tlsmgr._helper`;
  - duplicated helpers.
- **Tests:** smoke_v15_web, smoke_v15_data and smoke_v15_appliance.

## 1.4.1 — 2026-10-16
- **Entra ID sign-in button label is configurable** (Admin → Entra ID single sign-on → *Sign-in
  button label*). For example "Sign in with Entra ID (corp.example.com)". Blank gives "Sign in
  with Entra ID".
- **The role fields are relabelled** *Admin app-role value* and *Engineer app-role value*, with
  `ZertoMonitor.Admin` / `ZertoMonitor.Engineer` as placeholders. Entra never sends group
  **names** in the token, only app-role values (`roles`) or group object IDs (`groups`). The
  first production setup used the group names, and every sign-in fell through to viewer.
- Tests: a smoke_v13 events check had a fixed date that aged past the one-day window clamp. It
  now expects the clamp.

## 1.4.0 — 2026-10-06
- **Signed self-update.** Releases can be installed without SSH or an appliance password.
  - **How a deploy happens:** an admin uses **Admin → Updates** (pick a published release or
    upload a bundle, type the version, apply), or anyone holding a **deploy token** calls
    `POST /api/update/apply {"version": "x.y.z"}`.
  - **The signature is the trust anchor.** Every release is a bundle signed with an Ed25519
    key that never leaves the release workstation. The appliance checks the signature as
    root against its pinned public key, plus the payload hash, the payload paths and the
    version.
  - **What it refuses:** anything unsigned or tampered with; older or same versions unless
    an admin ticks *reinstall/downgrade*. Tokens can never downgrade.
  - **On install:** it backs up the code and database, installs, health-checks, and **rolls
    back automatically** if the check fails.
  - **Deploy tokens** are shown once, stored only as a hash, expire, can be revoked, and can
    do nothing but update.
  - **Publishing:** the release script now also signs and uploads the bundle and keeps a
    public release index in the package registry.
- **`deploy/UPDATING.md`**: the release and deploy procedure, covering both roles, four
  deploy routes, post-deploy checks, rollback, signing-key management and troubleshooting.
- **`CLAUDE.md`**: the directive for people and AI agents working in the repository, with the
  non-negotiable rules and the commands.
- **Tests now live in the repository** (`tests/`, `tests\run_all.ps1`), with a sanitized
  fixture. No customer data is in the repo.

## 1.3.5 — 2026-10-06
- **Ignore a Zerto alert code everywhere** (Admin → Ignores, admins only), e.g. `VPG0035`.
  - **Covers a VPG only when** every live alert on it has an ignored code and its
    replication is otherwise healthy. Another alert, an RPO breach or a sync problem still
    alerts.
  - **What happens:** covered VPGs keep showing, badged *ignored: CODE (global)*, but leave
    the counts, the emails and the SNMP figures.
  - **The admin page shows** how many VPGs each code hides now, and the codes on unhealthy
    VPGs right now to pick from.
  - **Expiry:** set for 7, 30 or 90 days, or until removed. Every change is logged.
- Fix: the ignore badge no longer offers a broken "remove" for planned-outage holds.

## 1.3.4 — 2026-10-06
- **Filters on the VPG issues page.**
  - **Filters:** zORG, VPG name (contains, any case), state (failure or warning), and which
    ZVM reports the VPG.
  - **They're in the URL**, so the page's auto-refresh keeps them and a filtered view can be
    bookmarked or shared.
  - **The heading shows "N of M"**, while the counts at the top stay estate-wide.
  - **Forms on the page return to the filtered view:** ignore, and add a team fix.

## 1.3.3 — 2026-10-06
- **Alert emails are per VPG, not one digest.**
  - **Subject:** `[Zerto Monitor] <zORG> - <VPG> - Failure`, `Warning` or `Recovered`.
  - **Body:** what's wrong, status, RPO against its target, journal history, path, VMs,
    priority, last test, the Zerto alerts, the suggested fix, and links to the VPG's page and
    the zORG in the monitor.
  - **When:** each VPG has its own clock and is emailed when it passes its zORG rule's
    threshold, when it gets worse, as a reminder while it holds, and once when it recovers.
    A VPG ignored mid-alert sends no "Recovered".
  - **Storm guard:** more than 25 VPG emails in one poll sends the rest as one roll-up.
  - **No duplicates at the switch:** VPGs a digest already announced are not re-sent; their
    reminders continue on schedule.
  - **Unchanged:** SNMP traps (one per zORG event), and ZVM-unreachable alerts (their own
    email).

## 1.3.2 — 2026-10-06
- **Fix: dropdowns closed before an option could be picked** (the Timeline filters, and the same
  pattern on Reports, Backups, the plan editor, Admin and the ignore and team-fix forms). Each
  `<select>` was nested inside its `<label>`. In current Chromium-based browsers a click inside
  the label can be re-sent to the control, which closes the picker. Selects now sit beside their
  caption, with an `aria-label` for screen readers. A test fails if one is ever nested again.

## 1.3.1 — 2026-10-06
- **Fix: every cloud connector (ZCC) showed as "ghost".** The ZCM sends `GhostStatus` as the
  text `"False"`. The zORG page treated any non-empty value as a ghost. The health verdict was
  already right.
  - Ghost status is now read as a real true/false.
  - An unrecognised value still counts as a ghost, and shows `?` on the page.
- **Fix: the ZCC progress % showed on every installed connector.** `Progress` is the ZCM's
  install/removal progress (always 0 once installed). It now shows only while a connector is
  installing or being removed.

## 1.3 — 2026-10-06
**For engineers**
- **VPG settings backups** are collected hourly from Zerto's own daily export, using the
  read-only credential.
  - Each VPG's settings are stored compressed and encrypted, and kept 7 days (configurable,
    1–90). They're kept off the ZVM.
  - Any two backups can be compared field by field; script parameters are never shown.
  - VPGs that Zerto itself fails to export are flagged; the rest are still stored.
  - *Back up now* is available. **Restore** re-creates a deleted VPG through Zerto's import:
    admin only, gated, sent once, with its task followed.
- **DR failover plans per zORG**, using Zerto 10.9 recovery plans.
  - The zORG page shows each plan's status, last runs and ordered tiers, and flags VPGs
    left out of the plan.
  - A builder puts VPGs into tiers (wait, script, delay after each), previews the request,
    and creates or updates the plan on the recovery site's ZVM.
- **Timeline** of changes, pauses, tests and failovers, from Zerto's events. Collected every
  poll, because a busy ZVM keeps only a few days of events (about 3 on a large site). Whatever the ZVM still
  holds is read back once, and the monitor keeps events 400 days. The **failover-test
  history** (RTO, verdict, who, notes, steps) comes from Zerto's recovery reports.
- **RPO and journal trends** per VPG, hourly for 35 days and daily for 400 days. The new
  **VPG page** shows the charts, timeline, tests and backups.
- **VRA hot spots**: per-VM replication load from Zerto's counters. It flags one VM dominating
  a VRA, or a site's inbound or outbound load.
- **Monthly DR report** per zORG, on screen and as a branded PDF (WeasyPrint). It covers
  compliance %, charts, tests with RTO, the plan and its gaps, changes, alerts, open issues and
  backup coverage.
- **Branding**: navy brand bar with the logo, favicon, a logo on the sign-in page, and a
  branded header on alert emails and reports.
- **Appliance console menu** on SSH and the VM console: network, hostname, time, disk expansion,
  services, upgrade, break-glass. See `deploy/appliance/README.md`.

**Safety and security**
- **VRA resize hardening** (from the final code review):
  - **It always ends.** An unexpected error before sending refuses it; after sending, it
    ends as *unknown* and halts. A failed token refresh mid-run no longer crashes the runner.
  - **Fresh data only.** Recovery is judged only on a good poll taken after the VRA came back.
  - **Certificate pin.** The pin must match the polling pin, and the polling pin is reused by
    default.
  - **Pacing.** Queued resizes expire after 10 minutes. Tasks *waiting for user input* count
    as conflicts. Holds get 15 minutes of slack.
  - **Source and holds.** Disabled sources never stand in for a site. VPGs without an
    identifier are skipped when holding.
  - **Public API.** `/api/vras/{site}` no longer exposes the resize request and response
    bodies.
- **Write allowlists per feature.** Every change client permits exactly one kind of request,
  and polling clients none. Pinned sessions ignore proxy environment variables.
- **Retention.** Expired ignores are now actually purged.

**Housekeeping**
- A publish script sends the source and the OVA to the package registry, behind a secret gate.
- Added `OVERVIEW.md`, `BACKLOG.md` (final code review and Zerto API review) and this changelog.
- Live appliance: wiped old credential residue from the raw disk, which now has 0 copies. Three
  passes were needed: the journal, then ext4 reserved clusters.

## 1.2 — 2026-10-05
- **Roles**: viewer / engineer / admin, from local users or two Entra ID groups. The role is
  re-read on every request. **Require sign-in** switch.
- **Ignores** per VPG or zORG, for a set period or until removed. "Acknowledge current problems"
  lifts itself on anything new or worse.
- **VRA sizing**: VRAs grouped by vSphere cluster. Target size is a pin, a cluster override or a
  site standard, raise-only per dimension. Sizes beyond Zerto guidance need a case reference.
- **VRA resize** (admin, armed in five places, off by default): preview with checks G1–G12 and
  the blast radius, one PUT that is never retried, holds on affected VPGs, a halt latch on
  anything but success, and pacing.
- **Suggested fixes**: 79 researched playbook entries, plus team fixes written by engineers
  (`/playbook`).
- Health includes Zerto's `AlertStatus`, so Meeting-SLA VPGs with alerts now show up. One
  cross-ZVM merge (`merged_vpgs`) feeds every page, metric and alert.
- **Secrets audit** (16 fixes):
  - ZVM/ZCM certificates pinned on first use; redirects refused on credentialed calls;
  - stored secrets never follow a changed host, SMTP server or trap receiver;
  - `reg_uri` and `smtp_user` encrypted; error text scrubbed;
  - session key moved to `LoadCredential`;
  - the OVF environment scrubbed at every boot, with cloud-init disabled after first boot;
  - TLS staging in tmpfs; query strings kept out of access logs; crash dumps off; SNMP view
    restricted.
- Responsive tables; light/dark toggle.

## 1.1 — 2026-10-05
- HTTPS only (nginx, HSTS, TLS 1.2/1.3), with a self-signed certificate at first boot.
  **Hostname & TLS** admin page (PEM or `.pfx`).
- Privileged root helper (`zerto-monitor-admin`), socket-activated outside the app sandbox.
- zORG alerting: dwell clocks, email digests, SNMP v2c traps. SNMP polling for RMM / network monitoring systems.
- Sources can be added with a Keycloak initial access token, so no password is stored.
- Fix: sqlite connection leak (fd exhaustion).

## 1.0 — 2026-09-03
- First appliance OVA (Ubuntu 26.04, built in pure Python), configured from vApp properties at
  first boot.
- Dashboard, VRAs, zORGs with failover-test recency, ZCM cloud-connector health, Entra ID SSO,
  Fernet-encrypted credentials, and history with a 24-hour trend.
