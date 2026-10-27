# Zerto Monitor

One page for every Zerto site. A FastAPI dashboard that aggregates every Zerto ZVM (and
the ZCM) into one view:
- only the VPGs in **failure** or **warning**, with a plain-English reason and a suggested
  fix for each;
- VRA status, including disconnects and subnet-mask drift;
- a per-zORG drill-down with cloud-connector health from the ZCM.

Built for service providers who run several Zerto sites and host many customers (zORGs). It
ships as a self-configuring **vSphere appliance** (Ubuntu OVA) with signed self-updates.
The stack is FastAPI, Jinja2, SQLite, bcrypt, a JWT cookie and Fernet-encrypted credentials.

Apache-2.0 licensed (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). This is an independent
project, not affiliated with or supported by Zerto or Hewlett Packard Enterprise.

## Quick start
1. Download the OVA from the latest GitHub release and deploy it in vCenter (*Deploy OVF
   Template*).
2. Fill in *Customize template*: network, accounts and, optionally, a first ZVM.
3. Power the VM on. First boot needs outbound HTTPS to the Ubuntu archive and PyPI.
4. Browse to `https://<appliance>/`, sign in as the web admin you set, and add sources under
   **Admin → Sources**.

[deploy/appliance/README.md](deploy/appliance/README.md) covers every wizard field and the
first-boot steps.

## Pages
Until an admin turns on **Require sign-in** (Admin → *Users & access*), the dashboards
are readable without signing in. Changing anything always needs a sign-in.

| path | what |
|---|---|
| `/` | failure + warning VPGs across all sources, deduplicated, with reasons and a **suggested fix**; filter by zORG, VPG name, state and ZVM |
| `/vras` | overall VRA health + per-site rollup → `/vras/{site}` for the full list (disconnects, subnet-mask drift, **sizing standard**) |
| `/zorgs` | all zORGs ranked by trouble, with **last failover test** (never / >90 days counts) |
| `/zorgs/{name}` | drill-down: VPGs, VMs, RPO, storage, alerts with fixes, test recency, ZCC health, **DR failover plans**, last 30 days of tests and changes, monthly report links |
| `/vpgs/{id}` | one VPG: **RPO / journal-history / journal-size trends**, its timeline, failover tests with RTO, settings backups |
| `/timeline` | who changed, paused, tested or failed over what, across every ZVM (filter by zORG, type, days) |
| `/backups` | **VPG settings backups** (7 days), compare any two, restore a deleted VPG (admin) |
| `/reports` | **monthly DR report** per zORG, on screen or as a branded PDF |
| `/playbook` | every suggested-fix entry, researched and team-written; engineers add and edit team fixes here |
| `/admin` | security posture, sources, hostname & TLS, alerting, ignores, SNMP, users & roles, Entra ID SSO, polling (**admin only**) |
| `/api/*` | JSON for everything above (`/api/sources` is admin-only) |
| `/api/metrics` | flat integers for SNMP polling by your RMM / network monitoring system |

Every page has a light/dark toggle in the nav. It follows the OS until clicked, then
remembers the choice per browser. Tables use the full window width. As the window narrows
they drop their least important columns first, so nothing scrolls sideways on a laptop.

## Users, roles and sign-in
| role | can |
|---|---|
| viewer | read everything (anonymous visitors get this while sign-in isn't required) |
| engineer | + ignore VPGs/zORGs, set VRA standards, cluster overrides and pins, preview VRA resizes, write team fixes |
| admin | + everything on `/admin` (sources and credentials, TLS, alerting, users, SSO, VRA-resize arming) and starting a VRA resize |

- **Local users**: Admin → *Users & access*. Pick a role when adding, and change it in
  the table. Role changes and deletions apply on the user's very next request. The app
  won't let you remove or demote the last admin. The first run creates the initial admin at `/setup`.
- **Entra ID SSO**: Admin → *Entra ID single sign-on*, using MSAL/OIDC. SAML isn't needed,
  since Entra does OIDC natively.
  - **Fields:** tenant ID, application (client) ID, client secret, redirect URI
    (`https://<host>/auth/callback`), the two role values, and the sign-in button's label
    (e.g. "Sign in with Entra ID (corp.example.com)").
  - **Roles:** **admin value → admin**, else **engineer value → engineer**, else **viewer**.
    The role is re-read from the token at every sign-in.
  - **Recommended setup:**
    - Create app roles `ZertoMonitor.Admin` and `ZertoMonitor.Engineer` on the app
      registration.
    - Assign your admin and engineer groups to those roles in the enterprise app, with
      *Assignment required* on.
    - Enter the **role values** in the monitor.
  - **Never enter a group name.** Entra doesn't put group names in the token, only role values
    or group object IDs. Members must be direct members of the group.
- **Require sign-in**: one switch on Admin → *Users & access*. On, every page and API
  needs a session, except `/login`, `/static`, `/healthz`, and `/api/metrics` from the
  appliance's own loopback for its SNMP agent.

## Ignoring a VPG or a whole zORG
For VPGs you knowingly accept, such as an on-prem customer replicating into one of your sites
with a standing warning, an engineer can ignore one VPG or a whole zORG from the dashboard
or the zORG page, for 1, 7, 30 or 90 days or until removed:

- **Acknowledge current problems** (default): the monitor remembers exactly what's wrong
  now (alert codes, Zerto's alert level, the replication state). Anything **new or worse**
  lifts the ignore automatically and alerts as normal, and the page says why.
- **Everything**: ignore it entirely for the period.

Health is never rewritten. An ignored VPG still shows its real state in an *Ignored* list.
It's only taken out of the counts that demand attention, out of the SNMP failure/warning
figures and out of alerting. A zORG whose only problems are ignored stands down quietly,
without a false "all healthy again" email. Every ignore and removal is logged in the alert log.

### Ignoring a Zerto alert code everywhere (admins)
Admin → *Ignores* → **Ignored Zerto alert codes**, for a code that is known and accepted across
the estate (e.g. `VPG0035` for an accepted zORG mapping).
- **Covers a VPG only when** every live alert on it has an ignored code **and** its
  replication is otherwise healthy. A second alert, an RPO breach or a sync problem still
  raises it.
- **What happens:** covered VPGs stay visible with an *ignored: CODE (global)* badge, and drop
  out of the counts, the alert emails and the SNMP figures.
- **Each code shows** how many VPGs it hides right now and why, and can be set for 7, 30 or 90
  days or until removed.
- **Picking a code:** the codes on unhealthy VPGs right now are listed to choose from.
- **Who:** admins only. Every change is in the alert log.

## VRA sizing and resizing
`/vras/{site}` lists VRAs grouped and sorted by **vSphere cluster** (read from the ZVM's
`hostclusters`). Each VRA's target size is the most specific of these that applies:

1. a **pin** on that VRA (keep it exactly as it is),
2. its **cluster override**, or
3. the **site standard**.

The page offers the most common existing size as a starting point for each. Every VRA is
marked *at target*, *below*, *above* or *mixed*, plus flags for anything that rules a
resize out. Rules only ever **raise** a VRA, per dimension: a 32 GB / 2 vCPU VRA against a
16/4 standard is raised to 32/4, never lowered to 16. Bounds are 1–64 GB and 1–8 vCPU,
the largest sizes already running. Beyond Zerto's 16 GB / 4 vCPU guidance, a rule needs
a Zerto case reference. More than 2 vCPUs is "only per Zerto Support recommendation".
Pins follow the **host**, because a VRA's identifier changes when it's reinstalled.

### Resizing a VRA

**A resize is a planned replication outage, not a settings change.** Zerto applies a
memory or vCPU change by **powering the VRA off**:

- every VPG with a VM or a recovery volume on that host stops replicating (VRA0028);
- VPGs recovering to it can't fail over until it's back;
- a Bitmap Sync follows, or on the protected side possibly a Delta Sync that reads whole disks;
- raising memory needs host headroom, because VRA memory is fully reserved.

The design comes from a research pass over Zerto's 10.9 docs, KBs and API spec, against
this estate's data (2026-10-05).

- **Armed in five places, all off by default:**
  - Admin → VRA resizing switch;
  - the site armed;
  - the source's credential granted **ManageVRA** in the ZVM's Keycloak (the source card
    shows the roles it actually holds);
  - a **pinned** TLS certificate;
  - the hosts' connection method recorded as public key (VIB). The edit has to send it,
    and it can't be read back. Password-mode hosts are out of scope.
- **Engineers preview; only an admin starts.** The preview shows:
  - every check (G1–G12);
  - the exact request body;
  - the blast radius: each VPG on that host with its state and alerts, and which
    customers' own ZVMs will alert.

  Starting needs a ticket and acknowledgements: the outage, the connection method, host
  headroom for a memory raise, and a maintenance window when the change crosses the
  4/6/8 GB driver-cache boundary. **Lowering** is never automatic. An admin chooses it on
  the preview and types the host name.
- **Checked again on a fresh poll, just before the one write**:
  - the VRA is healthy (status *and* alert status, not ghost, no alert naming it);
  - its version matches the ZVM's;
  - the live VRA still matches the preview;
  - the blast radius agrees with Zerto's own counts;
  - every affected VPG is Meeting SLA with nothing syncing;
  - no Zerto task touches the host or those VPGs.

  Any change since the preview means nothing is sent.
- **One PUT, never retried.** The VRA's group and network are echoed exactly as read. The
  client can make no other write. The task is followed, then the VRA must come back at the
  new size with status and alerts clear and nothing else changed. Then every affected VPG
  must recover.
- **Holds**: the affected VPGs show as *planned* and stay out of alerting while it runs.
  Each hold ends when that VPG recovers or the resize ends, and after 155 minutes at most
  (the runner's own limits plus slack). Holds are never stored as ignores.
- **It always ends**:
  - An unexpected error before the PUT refuses the resize, because nothing was sent.
  - An error after the PUT ends it as *unknown* and halts resizing.
  - A failed token refresh mid-run counts as an unreadable answer, not a crash.
  - VPG recovery is judged only on a good poll taken after the VRA came back, never on the
    pre-outage snapshot.
  - A go that waited more than 10 minutes is refused rather than sent late.
  - Zerto tasks *waiting for user input* count as work in flight.
- **Paced**: one resize at a time across the appliance, a 30-minute cooldown, 24 hours apart
  until five have succeeded, and at most 4 a day per site. There are no cluster-wide runs
  yet; those come after five clean resizes.
- **Halts**: any outcome but *done* halts all resizing until an admin acknowledges it with
  a note. The task may have failed, the VRA may not be back, a VPG may not recover, or the
  monitor may have restarted mid-resize. Everything is in the site's **Resizes** history
  and the alert log.

**Suggested first resize:** an idle VRA (0 VPGs, no volumes), lowered rather than raised:
lowering frees reserved memory, so headroom can't block the power-on. Open items to confirm
with Zerto Support before resizing loaded VRAs:
- the size range the 10.9 PUT accepts;
- whether Edit VRA powers the VRA back on and sets the reservation;
- what omitted fields mean;
- whether VRA upgrades keep RAM and vCPU.

## Suggested fixes and the playbook
Each failing or warning VPG, and each alert on the zORG and VRA pages, carries up to three
suggested fixes. Entries are keyed by Zerto alert code (`VPG0035`) or by replication
condition (`cond:rpo-over-target`, `sub:<Substatus>`, `status:<Status>`). The specifics
(VM, host, datastore, peer site, zORG) are filled in from the alert text. Anything that can
trigger a resync, lose checkpoints or fail over carries a ⚠ caution. Where there's no
entry, the page says so rather than guessing. There are two kinds of entry:

- **Researched**: `app/playbook.json`, written from Zerto's alert reference and reviewed
  for safety. It ships with the app and is re-read when it changes.
- **Team fixes**: written by engineers when they find what actually fixed an error here.
  Use the **+ team fix** link in any Suggested-fix cell (pre-filled with that row's codes),
  or the **Playbook** page in the nav, which lists every entry and lets engineers edit and
  delete them. Team fixes are stored in the database, so upgrades keep them. They show
  *first*, with the author and date. Links in them are clickable, and everything else is
  shown as plain text.

## Trends, timeline and hot spots
- **RPO and journal trends.** After every full poll, each VPG is folded into an hourly bucket
  (kept 35 days) and a daily one (kept 400 days):
  - worst and average RPO, and how many samples breached the target;
  - the shortest journal history against the configured one;
  - journal size;
  - healthy, warning and failure counts.

  Only live sources count: a ZVM that stopped answering never replays its last good poll as
  new data. Charts are server-side SVG, so the pages and PDFs need no JavaScript library.
- **Timeline.** Zerto's events are collected every poll: changes, pauses and resumes, tests,
  failovers and moves, VRA and site operations. Sign-ins and alert flapping are left out.
  - `/v1/events` returns only the latest 1000 events and filters after that cap, so the
    monitor reads a short window each poll.
  - A busy ZVM keeps only a few days of events at all (about 3 on a large site), so the monitor's own copy, kept 400 days, is the history.
  - On first start it reads back what the ZVM still holds (up to 7 days), in 1-hour windows to stay under the cap.
  - Both ZVMs of a pair report the same event: it's stored once.

  Failover-test results (RTO, verdict, who, notes, steps) come from Zerto's recovery reports.
- **VRA hot spots** (`/vras/{site}`). Zerto's per-VM counters (`/v1/statistics/vms`) are
  cumulative. Each poll adds the difference to the VM's hourly traffic, and a counter that
  goes backwards (VRA restart) adds nothing. A VM's write volume is credited to the VRA doing
  the work: the protected-side VRA for outbound VPGs, the recovery-side VRA for inbound ones.
  - Flagged: one VM at 30% or more of a VRA that has 3 or more VMs and 20+ GB in 24 h.
  - Flagged: one VM at 20% or more of a site's inbound or outbound total of 100+ GB.

  The second rule catches the case where a single busy VM is a large share of a whole
  site's replication and makes the site look slow.

## VPG settings backups and restore
Every Zerto 10 ZVM already writes a full export of its VPGs' settings once a day and keeps about
30. Reading one back is a POST with read semantics that the read-only polling client may make,
so **backups need no write access**.
- **Collection.** Each hour the monitor stores any new export, per VPG. Each one is compressed
  and Fernet-encrypted, because pre/post-recovery script parameters can carry credentials.
  Backups are kept `backup_days` (default 7, Admin → Changes to Zerto), off the ZVM.
- **Compare (engineers).** Any backup can be compared field by field with another: VMs,
  volumes and NICs are matched by identifier, and script parameters show only as *set* or
  *empty*.
- **Back up now.** On an armed site this asks the ZVM for a fresh export; otherwise it stores
  the newest daily one.
- **Restore** re-creates a VPG that **no longer exists**, with Zerto's own import
  (`POST /v1/vpgSettings/import`) on the ZVM the backup came from. It is gated like a resize:
  - the restore switch on and the site armed;
  - the source's credential over the pinned certificate;
  - admin only, with a ticket, the VPG name typed in full, and an acknowledgement of the
    initial sync;
  - re-checked on a fresh poll, sent once, and its Zerto task followed to the end.

  A VPG that still exists is never imported over. A restored VPG starts with an initial sync
  and no journal history.

## DR failover (recovery) plans
Zerto 10.9 recovery plans are ordered blocks: VPGs started together, *wait until recovered*,
*delay*, and *script* (from the ZVM's repository).
- **On the zORG page**, every plan covering the zORG's VPGs is shown with its status, last run,
  last successful run and its tiers. Any zORG VPG **left out of the plan** is flagged: a VPG
  added after the plan was built is otherwise silently left behind in a real failover.
- **The builder** (engineers) puts VPGs into numbered tiers. After each tier it can wait, run a
  script, and pause. It previews the order and the exact request, then creates or updates the
  plan on the ZVM of the site the VPGs recover to.

Plan changes need the plans switch and an armed site. Saving replaces the whole plan, so the
builder only edits plans it can reproduce exactly: a plan that also holds another zORG's VPGs,
or steps the builder can't model, must be edited in Zerto. A plan id is only ever written or
deleted from the zORG page whose VPGs it covers. Deleting a plan is admin-only. The monitor
never *runs* a plan.

## Monthly reports
`/reports/{zORG}/{YYYY-MM}`, and `/pdf` for the PDF. Each report has:
- a branded header;
- the month's RPO-met, history-met and healthy percentages;
- RPO and daily-health charts;
- per-VPG compliance;
- failover tests with RTO, and VPGs never tested or tested over 90 days ago;
- the recovery plan and its gaps;
- changes and pauses, alerts, open issues, and backup coverage.

The PDF is rendered from the same HTML by WeasyPrint (pango on the appliance). Without it,
the page prints to PDF from the browser. Compliance needs the monitor's own samples, so
months before it began recording show tests and events only, and the report says so.

## Changes to Zerto: the model
The monitor is read-only on every ZVM until an admin allows a kind of change and arms the
site:
- the kinds are VRA resizes, VPG restores and recovery-plan changes;
- **one read/write credential per ZVM** (since 1.4.2): the credential the source was added
  with also makes changes, once the ZVM's Keycloak grants it the rights (for a registered
  client: *Clients → its client → Service account roles → zerto-client*). The source card
  shows the roles its token carries;
- changes go over the pinned certificate (the polling pin is reused unless one is pinned
  explicitly, and a fresh capture must match it).

Each kind of change is made by a client built with exactly that one write (`zerto.WRITES_*`).
The polling client can make none. Every restore and plan change is logged with its request
and response.

## Adding a source
Admin → *Add a source*. For a Zerto 10 appliance the best option is a **Keycloak
initial access token**, because then no password is stored:

1. Open the ZVM's Keycloak console (`https://<zvm>/auth/admin`), realm **zerto**.
2. *Clients → Client registration → Initial access token → Create* (count 1, a few
   minutes' expiry). Copy the long token from the dialog: it is shown **once**.
3. In the monitor, choose auth *Keycloak initial access token* and paste it as the secret.

The monitor spends the token registering its own confidential API client (OpenID Dynamic
Client Registration) and keeps only that client's id and secret, Fernet-encrypted.
Removing the source deletes the client from Keycloak again. On Zerto 10.9 the new client
gets read access automatically (verified on a 10.9 ZVM: VPGs, VRAs, alerts, zORGs,
events), so it lights up straight away. If a ZVM ever refuses it, the source card names
the one role to grant (`zerto-client` → `ZertoPrivilege_Viewer`).

Two Keycloak behaviours the monitor handles for you:
- This Keycloak takes its issuer from whatever hostname each request used. A token created
  with the console open at the **IP** is rejected at the **FQDN** with a bare
  `401 Failed decode token`. The monitor reads the token's issuer, confirms both names
  reach the same server, and registers there.
- A mistaken paste — the token's *ID* instead of the token, a token from another realm,
  an expired one, or a different token type — gets a message saying exactly which.

Username + password still works (Keycloak `scope=openid` is handled), as does a
pre-made API client id + secret. Legacy Windows ZVMs on 9669 and the ZCM on 9989 are
auto-detected. The source is polled immediately and lights up on `/`.

## Alerting (email + SNMP)
Admin → *Alerting*. Each zORG is judged by its worst VPG against two clocks: how long it
has been **continuously failing**, and how long **continuously not healthy**. A rule
fires *failure* once the first passes its error threshold, and *warning* once the second
passes its warning threshold. Defaults are 15 and 60 minutes, set per zORG or with a
`*` default. A zORG flapping between warning and failure can't reset its own warning
timer.

- **Email: one per VPG.** The subject is `[Zerto Monitor] <zORG> - <VPG> - Failure`,
  `Warning` or `Recovered`.
  - **Body:** what's wrong, status, RPO against its target, journal history, path, VMs, the
    Zerto alerts, the suggested fix, and links to the VPG's page and the zORG in the monitor.
  - **When:** a VPG is emailed once it has been unhealthy past its zORG rule's threshold for
    its level, when it gets worse, every *Remind every* hours while it holds (default 24), and
    once when it recovers. Easing from failure to warning is not announced. A VPG that is
    ignored mid-alert sends no "Recovered".
  - **Recipients:** the zORG rule's, else the defaults.
  - **Storm guard:** more than 25 VPG emails in one poll (setting `alert_vpg_email_cap`)
    sends the rest as one roll-up.
  - **Not a VPG:** a ZVM that stops answering gets its own `[source]` email.
- **SNMP traps** (v2c): one per event under a configurable base OID. The default sits
  in net-snmp's experimental arc, so swap in your enterprise number if you have one.
- **SNMP polling** for your RMM / network monitoring system: the appliance can answer SNMP on udp/161 with
  per-metric OIDs (failing VPGs, disconnected VRAs, unreachable sources, zORGs alerting,
  worst RPO…), restricted to an allowed source network. The admin page lists every OID.
- A ZVM that stops answering is alerted the same way, so a dead source can't silently
  mute every zORG behind it.
- With alerting off the clocks still run, and the page shows what *would* fire, so
  switching it on reports what is genuinely wrong rather than starting from zero.

**ZCM (Windows auth)**: there is no API key. The ZCM API (`POST :9989/v1/session/add`,
Basic auth, `{"AuthenticationMethod": 0}` = Windows, the default) validates the account
against the **ZCM server's local Administrators group** — the documented rule is
*"only members of the Administrators group under a specified domain can log in"*, using
`DOMAIN\username`. An account outside that group gets `"Provide Administrator
credentials"`. So: put the service account (or a domain group containing it) in the
ZCM host's local Administrators group, then add the ZCM as a `zcm` source with auth
*basic* and `DOMAIN\svc-zerto-monitor` (UPN also works). Sessions idle-expire after 30 min;
the client re-logs on every poll.

## Updating the appliance (signed self-update)
**Admin → Updates** installs a published release or an uploaded `.zmupdate` bundle. A
**deploy token** does the same over `POST /api/update/apply`, so no SSH key or appliance
password is needed.
- **Signed releases only:** every bundle is signed with the release key from the release
  workstation. The appliance checks it as root against its pinned public key, then backs up,
  installs, health-checks and **rolls back automatically** on failure.
- **Where releases come from:** set an update source under Admin → Updates. It can be a
  Gitea/Forgejo generic-package base URL, or a full `releases.json` index URL such as
  `https://github.com/OWNER/REPO/releases/latest/download/releases.json`. With none set,
  upload a `.zmupdate` from a release page.
- **Releases from this repository** are signed with the key whose public half ships in the
  OVA (`deploy/appliance/release-signing.pub`). If you build your own releases, create your
  own key (`deploy/new_release_key.ps1`) and deploy your own OVA.
- **Version rule:** newer versions only, unless an admin explicitly allows a reinstall or
  downgrade.

Full procedure: [deploy/UPDATING.md](deploy/UPDATING.md).

## Run locally
```
.\run_local.ps1      # http://127.0.0.1:8000  — first visit creates the admin
```

## Deploy
**Preferred: the vSphere appliance** (`deploy/appliance/`, see its README). Deploy the
OVA, fill in *Customize template*, power on.

Upgrade a running appliance in place without redeploying:
```
python deploy\appliance\build_ova.py --payload-only    # -> ~\ZertoMonitor-build\payload.tar.xz
# copy payload.tar.xz to /tmp/zm-payload.tar.xz on the box, then as root:
tar -xJf /tmp/zm-payload.tar.xz -C /opt/zerto-monitor && python3 /opt/zerto-monitor/firstboot.py --upgrade
```
`--upgrade` never touches network, accounts or data, and keeps the certificate, the
Fernet key, the database and the SNMP setting.

**HTTPS only.** Port 80 answers solely with a redirect to 443. A self-signed
certificate (covering the name, short name and every IP) is created at first boot.
Replace it from Admin → *Hostname & TLS*, using PEM files or a `.pfx`, or regenerate it
there. Session cookies are `Secure` + `HttpOnly` + `SameSite=Lax`, and HSTS is sent;
browsers honour HSTS only once the certificate is trusted, so a self-signed cert stays
click-through.

## Storage and security
**Admin → Security** shows all of the following live, including what is *not* protected.

- **Nothing sensitive is stored in plaintext.** Source usernames/client-ids and
  secrets, Keycloak registration tokens, the SMTP password, SNMP communities and the
  Entra client secret are Fernet-encrypted at rest. Local passwords are bcrypt hashes.
  Secrets are never rendered back into any page or API, never put on a command line or in
  an environment variable, and error text is scrubbed of credentials before it's stored,
  shown or logged. Client ids are kept out of messages, and access logs omit query
  strings. Any value found stored unencrypted is re-encrypted at the next start, and the
  Security card shows the live count. The trap community reaches `snmptrap`
  through a private config file. The one at-rest exception is inherent to SNMP: when the
  agent is enabled, snmpd needs its community in `/etc/snmp/snmpd.conf`, which is
  root-only `0600` (as is the TLS private key). This was verified on a production
  appliance with a byte-level search of every file, the journal, every process,
  guestinfo and then the **whole raw disk**, free space included, for every stored
  credential (each decrypted on the box) and the deploy-time password. It found 0 copies
  once old residue was wiped (see `BACKLOG.md`, *Disk residue*).
- **In motion**: browser ↔ appliance is HTTPS only. ZVM/ZCM calls are HTTPS with the
  server's identity checked on every connection: against a CA when "verify TLS" is ticked,
  otherwise against the certificate **pinned on first use**. A changed certificate stops
  polling with nothing sent, until an admin re-pins it. Redirects are refused on every call
  that carries a credential, and a stored secret is never sent to a changed host, SMTP
  server or trap receiver: it has to be re-entered. The SMTP password is only sent after
  STARTTLS or over SSL. SNMP v2c is unencrypted by design, so keep it on the management
  network. The agent answers only for system identity and the monitor's metrics, from one
  named network.
- **Writes to Zerto**: none unless an admin allows a kind of change and arms the site (see
  *Changes to Zerto: the model*). The source's credential is Fernet-encrypted and is used
  for changes only over a pinned certificate. Because it can write once Keycloak allows it,
  the Fernet key and the database must never be kept together. Each change is made by a
  client that permits exactly that one request (e.g. `PUT /v1/vras/{id}` for a resize) and
  refuses any other path. Pinned sessions ignore proxy environment variables, which would
  otherwise bypass the pin.
- **Deploy-time passwords** typed into the OVA wizard stay in the VM's vApp properties
  in vCenter until you blank them. The appliance removes its own copies at every boot and
  shows what vCenter still holds (see `deploy/appliance/README.md`).
- **Privilege separation.** The web app runs sandboxed (`NoNewPrivileges`,
  `ProtectSystem=strict`). The few root actions — installing a certificate, setting the
  hostname, configuring snmpd — go through `/usr/local/sbin/zerto-monitor-admin`. That
  helper is socket-activated by systemd *outside* the sandbox, accepts a whitelist of
  verbs, takes no file paths, and pattern-checks every argument. Application code is
  root-owned; only `data/` is writable by the service.
- **Keys**: production reads the Fernet key and the session-signing key via systemd
  `LoadCredential` from `/etc/zerto-monitor/fernet.key` and `session.key` (root-only,
  generated once, exposed to the service under `$CREDENTIALS_DIRECTORY`, never in the
  writable data dir or the upgrade backups). Dev falls back to files in `DATA_DIR`.
  `FERNET_KEY` / `SECRET_KEY` env override both. **Back the Fernet key up separately from
  the DB**, because losing it means re-entering every credential. Never keep the two
  together: a key beside its database is the same as plaintext. `/healthz` reports which
  key source is active.
- **Local development** (`run_local.ps1`) keeps its data in `%LOCALAPPDATA%\ZertoMonitor`,
  deliberately outside any synced folder, because that folder holds a key next to its
  database.
- **Pages never poll a ZVM.** The background collector writes the latest snapshot per
  source into SQLite (`DATA_DIR/monitor.db`, WAL mode) on the poll interval; every page and
  API reads from there. Each poll also appends a compact counts-only `history` row
  (retained `history_days`, default 30) powering the dashboard's "vs 24h ago" trend and
  `/api/history?source=&hours=`. SQLite is deliberate at this size (a few MB per poll);
  swap in Postgres only if you outgrow it.
- Service hardening: `UMask=0077`, `ProtectSystem=strict`, `ProtectHome`, `NoNewPrivileges`,
  data dir 0700, service user `zertomon` with `nologin`.

## Hard-won API notes baked in
- Keycloak password grant **must** include `scope=openid` or every `/v1/*` call is 401.
- Zerto 9.7 omits `StatusDescription`/`SubStatusDescription` and only sends numeric
  `Status`/`SubStatus`; the maps in `zerto.py` were derived from 10.x sites.
- A VPG between two of your own sites appears on **both** ZVMs — dedupe by VpgIdentifier (name + site pair only if an ID is missing); the worse side's health wins.
- `ZVM0002` alerts = ZVM cannot reach a VRA (ports 4006/4009). `ZVM0003` = peer down.
- VRA subnet-mask drift (a /24 on a /23 network) silently kills ZVM↔VRA; the VRAs
  page flags any VRA whose mask differs from the majority on its gateway.
