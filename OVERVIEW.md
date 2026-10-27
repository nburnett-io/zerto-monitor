# Zerto Monitor: project overview

**One page for every Zerto site.** Zerto Monitor polls all of your ZVMs and the ZCM. It shows
engineers only what needs attention:
- VPGs in failure or warning, with the reason in plain English and a suggested fix;
- VRA health and sizing;
- a per-customer (zORG) view with RPO, failover-test recency and cloud-connector health.

It alerts by email and SNMP, and your RMM or network monitoring system can poll it over SNMP.

Without it, checking DR health means logging in to each ZVM separately. A VPG with a
replication problem on one site, or one that looks fine on one side but not the other, is easy
to miss.

| | |
|---|---|
| **Ships as** | a vSphere appliance (Ubuntu OVA) on each GitHub release, plus a signed `.zmupdate` bundle for in-place updates |
| **Detail** | [README.md](README.md) covers features, security and operations; [deploy/appliance/README.md](deploy/appliance/README.md) covers deploying and upgrading the appliance |
| **Releasing / deploying** | [deploy/UPDATING.md](deploy/UPDATING.md): signed releases, Admin → Updates or the update API with a deploy token |
| **Next** | [BACKLOG.md](BACKLOG.md) is the prioritised build list; [CHANGELOG.md](CHANGELOG.md) lists what shipped |
| **Licence** | Apache-2.0 ([LICENSE](LICENSE), [NOTICE](NOTICE)); not affiliated with Zerto or HPE |

## What engineers get

- **Dashboard (`/`)**: failure and warning VPGs across all sites, de-duplicated. A VPG
  between two of your sites appears once, and the worse side wins. Each one shows a reason, a
  suggested fix and the trend against 24 hours ago.
- **zORGs (`/zorgs`)**: every customer ranked by trouble, with the last failover test
  (*never* and *>90 days* are called out). Drill down to VPGs, VMs, RPO, journal, alerts and
  ZCC health.
- **VRAs (`/vras`)**: disconnects, subnet-mask drift, version lag, and sizing against a
  standard.
  - Sizing is a pin, a cluster override, or a site standard, grouped by vSphere cluster.
  - A gated, admin-only **resize** changes a VRA's size in Zerto.
- **VPG page (`/vpgs/…`)**: RPO, journal-history and journal-size trends, the VPG's timeline,
  failover tests with RTO, and its settings backups.
- **Timeline (`/timeline`)**: who changed, paused, tested or failed over what, on every ZVM.
- **Backups (`/backups`)**: every VPG's settings collected from Zerto's daily export and kept 7
  days off the ZVM. Compare any two; an admin can re-create a deleted VPG.
- **DR failover plans** on each zORG page: Zerto recovery plans with their order and status,
  VPGs missing from a plan flagged, and a builder for engineers.
- **Reports (`/reports`)**: a monthly DR report per customer, on screen or as a PDF.
- **Hot spots** on each site's VRA page: one VM dominating a VRA's or a site's replication.
- **Playbook (`/playbook`)**: researched fixes keyed by Zerto alert code or replication
  condition, plus **team fixes** that engineers add when they find what actually worked.
- **Ignores**: knowingly accepted problems (for example a customer's on-prem warning) can be
  ignored per VPG, per zORG or by Zerto alert code. "Acknowledge current problems" lifts
  itself if anything new or worse appears.
- **Alerting**: one email per VPG, SNMP traps, and a dead ZVM alerts too. `/api/metrics` and
  the SNMP agent serve your monitoring system.

## How it works

```
 ZVMs (Keycloak REST, 10.x / legacy 9669)  ─┐
 ZCM  (:9989, Windows auth)                 ─┼─► collector (every poll interval, pinned TLS)
                                              │        │
                                              │        ▼
                                              │   SQLite: latest snapshot per source + history
                                              │        │
                                              │        ├─► pages + /api/*   (never poll a ZVM themselves)
                                              │        ├─► alert engine ──► email / SNMP traps
                                              │        └─► /api/metrics ──► snmpd ──► your RMM / NMS
                                              │
 changes (admin-armed only) ──────────────────┘  resize, restore, recovery plans: one allowlisted write each
```

- **Stack:** FastAPI + Jinja2 + SQLite (WAL), on Python 3 under systemd, behind nginx (HTTPS only).
- **Appliance:** Ubuntu 26.04 OVA.
  - First boot reads the vApp properties (network, accounts, first ZVM), then locks the OVF
    environment down.
  - Signed updates install in place and keep data, keys and certificates. A failed health
    check rolls back to the previous version.
- **Roles:** viewer / engineer / admin, as local users or two Entra ID app roles. Dashboards
  are readable without sign-in until **Require sign-in** is switched on.

## Security model (summary)

The rule for this project: **no secret is ever stored, logged, rendered or transmitted in plain
text.**

- Every stored credential is Fernet-encrypted, including usernames and client ids. The key is
  delivered by systemd `LoadCredential` and is never kept beside the database.
- Sources are added with a one-time Keycloak initial access token. The monitor registers its own
  API client, so no password is stored.
- ZVM and ZCM certificates are pinned on first use. Redirects are refused on credentialed calls.
  A stored secret never follows a changed host.
- The appliance scrubs its own OVF environment at every boot. **Admin → Security** shows the live
  posture, including what isn't protected yet.

[README.md](README.md#storage-and-security) has the full detail.

## Repo layout

| path | what |
|---|---|
| `app/` | the application: `collector.py` polling, `zerto.py`/`zcm.py` API clients, `views.py` health logic, `alerts.py`, `vrapush.py` resize runner, `backups.py`, `plans.py`, `updates.py`, `playbook.json` fixes, `db.py` schema and migrations |
| `templates/`, `static/` | Jinja2 pages, CSS and the logo |
| `deploy/appliance/` | OVA builder (`build_ova.py`, pure Python, no ovftool), validator, first boot, root helper, console menu, OVF scrubber, signed updater |
| `deploy/` | release tooling: `release_signing.py`, `new_release_key.ps1`, `UPDATING.md` |
| `tests/` | offline smoke suites; `tests\run_all.ps1` runs them all |

## Making a release

1. Update `CHANGELOG.md`.
2. Bump `VERSION` in `deploy/appliance/build_ova.py`.
3. Run `tests\run_all.ps1`.
4. Build and validate the OVA.
5. Sign the update bundle with your release key.
6. Publish the OVA, the `.zmupdate` bundle and `releases.json` on the release.

[deploy/UPDATING.md](deploy/UPDATING.md) has every step.
