# Zerto Monitor — vSphere appliance (OVA)

A self-configuring virtual appliance. Deploy the OVA, fill in the **Customize template**
page, power it on, and the appliance sets its own address, credentials and services and
comes up as a working dashboard. No SSH step, no manual cloud-init.

Base image is Canonical's official **Ubuntu 26.04 LTS cloud image OVA**, reused with its
virtual disk **byte-for-byte unmodified** — only the OVF descriptor is rewritten. The disk
still hashes to Canonical's published value, so provenance stays verifiable.

---

## What you get

| | |
|---|---|
| Guest OS | Ubuntu 26.04 LTS (server cloud image) |
| Sizing | 2 vCPU, 4 GB RAM, 10 GB thin disk |
| Hardware | vmx-10, VMXNET3, PVSCSI, BIOS firmware |
| Web | **HTTPS only** on :443 (port 80 just redirects); self-signed until you install a certificate in Admin |
| Services | nginx proxying uvicorn on 127.0.0.1:8000; socket-activated root helper; snmpd (off until enabled) |
| Accounts | `root`, your named admin (sudo, `zmconsole`), `zertomon` (service, nologin) |
| Console | A DCUI-style menu at the admin's login, on the VM console and over SSH (see [Console menu](#console-menu)) |

Until you turn on **Admin → Users & access → Require sign-in**, the dashboards are
readable without signing in. Changing anything always needs a sign-in. There are three roles:
**viewer** (read-only), **engineer** (also ignores, VRA sizing, resize previews, team
playbook fixes) and **admin** (also everything on `/admin`, and starting a VRA resize). Roles
are set per local user, or come from two Entra ID groups. The monitor never changes anything
on a ZVM unless an admin has armed VRA resizing for that site: the switch, the site's own
ManageVRA credential, a pinned certificate and an attested host connection method.

**Payload size (1.3):** the application archive is about 207 KB of tar.xz, which is about
276,000 base64 characters across 12 properties. The console menu accounts for about 28 KB
of that; the researched playbook is the largest single file. Each property is under the
65,535 limit. The bootstrap falls back to the ISO transport if guestinfo can't deliver the
whole environment. A fresh deploy of 1.3 hasn't been run yet.

---

## Before you deploy

**First boot needs outbound access** to `archive.ubuntu.com` and `pypi.org`. This is the
one hard requirement, and it is not negotiable on this base image: Ubuntu's 26.04 cloud
image ships **no pip, no venv and no ensurepip**, and none of FastAPI, uvicorn,
python-multipart, python-jose or msal. There is no installer of any kind in the image
until apt brings one in.

Without that access the appliance still boots and applies its network, hostname and
accounts, but the web service will not start. The log says so in as many words rather
than failing silently.

If you need a genuinely offline deployment, drop a wheelhouse into
`/opt/zerto-monitor/wheels` before first boot and the installer will use it with
`--no-index`. The wheels must be **cp314 or abi3** manylinux x86_64, because the image's
interpreter is Python 3.14.

Everything else is optional. Leaving a field blank is safe: blank network means DHCP,
blank passwords means that account stays locked, blank Zerto site means you add sites
later from the admin page.

---

## Deploying

1. **Hosts and Clusters → right-click a cluster → Deploy OVF Template**
2. Select `ZertoMonitor-1.3.ova` as a local file
3. Pick a name, folder, compute resource, storage and network as usual
4. On **Customize template**, fill in the fields below
5. Finish, then power on
6. **Once it's up, blank the password fields in vCenter** (Edit Settings → vApp Options →
   Properties). vCenter otherwise keeps them. **Admin → Security** shows whether any remain.

The appliance is reachable roughly two to four minutes after power-on, depending on how
fast the package mirrors respond.

### Customize template fields

**1. Networking**

| Field | Notes |
|---|---|
| Hostname | Short name. Defaults to `zertomon`. |
| Use DHCP | Tick to get an address automatically; the static fields are then ignored. |
| IPv4 address | e.g. `192.0.2.10`. `192.0.2.10/24` also works; the prefix written here wins. |
| Subnet prefix or mask | Prefix (`24`) or dotted mask (`255.255.255.0`). Both accepted. |
| Default gateway | |
| DNS server 1 / 2 | Second is optional. |
| DNS search domain | Optional, e.g. `example.com`. |

**2. Appliance credentials**

| Field | Notes |
|---|---|
| Root password | Masked. Blank leaves root locked, which is the safer default. |
| Admin username | Linux account with sudo. Defaults to `zmadmin`. |
| Admin password | Masked. |
| SSH public key | Optional. One OpenSSH key added to the admin account. |

SSH password authentication is enabled only if you set a password. If you supply only a
key, the appliance stays key-only. A key-only admin can still use the console menu over
SSH (see [the sudo model](#the-sudo-model)). To use the VM console, they first set a
password from the menu: **Break-glass → Set this account's Linux password**.

**3. Web console**

| Field | Notes |
|---|---|
| Web admin username | Defaults to `admin`. |
| Web admin password | Masked, 10+ characters. Stored as a bcrypt hash. Leave blank to be prompted at `/setup` on first visit. |

**4. Regional** — timezone (IANA, e.g. `America/New_York`) and an NTP server.

**5. First Zerto site (optional)** — a display name, ZVM hostname, username and password.
Supply them and the dashboard has data on its first poll. The password is stored
Fernet-encrypted, never in clear. Leave blank and add sites from `/admin` instead.

---

## What first boot actually does

Ordered, and logged to `/var/log/zerto-monitor-firstboot.log`:

1. Reads the OVF environment (guestinfo first, then any `/dev/sr*`, then cloud-init's cache)
2. Validates every network value with Python's `ipaddress`. A bad address falls back to
   DHCP; a bad gateway, DNS server or search domain is dropped. Each case is logged. It
   renders one netplan file that matches the NIC **by MAC**, never by interface name or
   driver (a driver match would also catch a hot-added second vNIC and give it the same
   address and default route). It checks that file with
   `netplan generate` in a scratch root before anything moves. Then it backs up
   `/etc/netplan`, moves every other file out of the `*.yaml` glob, and applies. If
   anything fails, the previous files go back.
3. Sets hostname and timezone, and points **chrony** at your NTP server
4. Sets root and admin passwords via `chpasswd` on stdin, installs the SSH key
5. Unpacks the application from the OVF properties
6. Installs the [console menu](#console-menu). This needs no download, so the menu is
   there to fix the network even if the next step fails.
7. `apt-get install` whatever is missing: python3-venv, nginx, snmp, snmpd, chrony, whiptail,
   cloud-guest-utils and WeasyPrint's runtime libraries. Builds the venv; installs and
   **verifies** the imports
8. Generates the Fernet key and the session-signing key in `/etc/zerto-monitor/`, both
   root-owned `0600`
9. Seeds the web admin and any Zerto site into the encrypted database (secrets passed on
   stdin, never in an environment variable)
10. Installs the privileged helper and its socket (see Security notes)
11. Creates a self-signed certificate for `<hostname>.<search domain>`, the short name and
    every IP, so HTTPS works from the first request
12. Installs the HTTPS-only nginx site and the systemd unit, enables both; leaves snmpd off
13. Checks that HTTPS answers **and** that port 80 only redirects
14. Empties the `cdrom` group and ejects the transport media (see Security notes)
15. Switches cloud-init off. Installs `zerto-monitor-ovfscrub` and runs it now, at every
    boot and every 30 minutes (see Security notes)
16. Writes the console banner and MOTD

Every script it installs is syntax-checked on the box first (`compile()` for Python,
`sh -n` for the helper). A broken file never replaces a working one.

A stamp file makes it run exactly once. With cloud-init off, later boots don't start it at all.

Three details that are easy to get wrong on this image, and are handled:

- **NTP is chrony, not systemd-timesyncd.** Writing `timesyncd` config would silently
  discard your NTP server. The installer writes `/etc/chrony/sources.d/` and disables
  Ubuntu's default NTS pools, which need outbound `4460/tcp` to Canonical and otherwise
  leave the clock unset on a closed network.
- **netplan concatenates sequences across files.** Layering a `99-` file over
  `50-cloud-init.yaml` produces two default routes and a DHCP/static hybrid, so the
  installer takes the others out of the glob rather than adding to them.
- **sshd applies the first value it sees.** The drop-in is `10-zerto-monitor.conf`, which
  sorts ahead of cloud-init's `50-cloud-init.conf` and the image's own
  `60-cloudimg-settings.conf` (which sets `PasswordAuthentication no`).

---

## Console menu

Sign in as the appliance admin (the account named in **Admin username**, `zmadmin` by
default), on the VM console or over SSH, and a menu opens instead of a bare prompt. It
works like vCenter's DCUI. Before sign-in, the VM console's login screen shows the web URL
and address (`/etc/issue`, agetty's `\4`).

```
Status            hostname, addresses, web URL, zerto-monitor/nginx/snmpd, HTTPS check,
                  disk, uptime, version, time and NTP sync (also the first screen)
Network           show | configure (DHCP/static, NIC matched by MAC, address/prefix,
                  gateway, DNS, search, MTU) | restore the previous config |
                  regenerate the self-signed certificate | keep a pending change
Hostname          validated; then offers a new certificate
Time and NTP      status | NTP servers (chrony) | timezone | synchronise now
Disk expansion    rescan, growpart + resize2fs, before/after sizes
Services and logs restart zerto-monitor / nginx | app log | nginx error log |
                  connectivity test (DNS + TCP, e.g. a ZVM on 443 9669 9989)
Upgrade           apply a signed /tmp/zm-update.zmupdate | repair (re-run the installer)
Break-glass       reset a web password or create a local admin | this account's Linux
                  password | SSH password sign-in on/off | security posture summary
Reboot / shut down
Shell (bash)      also Cancel/Esc on the main menu
Log out
```

It is a convenience, not a jail. The admin keeps exactly the rights they had before.

### Getting a plain shell

- Pick **Shell** (or press Esc) on the main menu. Run `zerto-monitor-console` to reopen it.
- The menu **never** opens for:
  - `ssh host command` (a non-login, non-interactive shell)
  - a session without a TTY
  - `TERM=dumb` (automation that opens an interactive shell with `TERM=dumb` gets a plain
    prompt)
  - a login shell started by hand (`bash -l`)
  - accounts outside the `zmconsole` group, including root
- To opt out per account, create `~/.zm-no-menu`. For one session, set `ZM_NO_MENU=1`, or
  send `LC_ZM_NO_MENU=1` over SSH (`ssh -o SendEnv=LC_ZM_NO_MENU`).
- `zerto-monitor-console --status` prints the status screen as plain text, which also works
  over `ssh host zerto-monitor-console --status`.

The hook is `/etc/profile.d/zz-zerto-monitor-console.sh`. It runs the menu only when all of
these hold:

- the shell is interactive
- it is a real login shell (`$0` starts with `-`)
- stdin and stdout are TTYs
- `TERM` is not `dumb`
- the user is in `zmconsole`

If the menu fails, you land at the prompt.

### The sudo model

The menu runs as the admin, not as root. Each root action goes through one script:

```
sudo -n /usr/local/sbin/zerto-monitor-console-ops <verb> <args>
```

The rule in `/etc/sudoers.d/zerto-monitor-console` is checked with `visudo -c` before and
after it is installed:

```
%zmconsole ALL=(root) NOPASSWD: /usr/local/sbin/zerto-monitor-console-ops
```

- **NOPASSWD for that one script** was chosen over "require an admin password when root has
  none". First boot allows a key-only admin, and for that admin sudo could never work: there
  is no password to type. Forcing a password would change the deploy contract and put one
  more secret into vCenter's vApp properties. Full `sudo` still needs the account's password.
  The menu can set one (**Break-glass → Linux password**).
- **What it can do.** The script has a fixed verb list and validates every argument itself.
  The menu's own checks are only a convenience. Commands are argument lists, never a shell.
  Secrets arrive on stdin only. Every action is logged, without secrets, to
  `/var/log/zerto-monitor-console.log` (root, 0600).
- **Membership is powerful.** **Upgrade** installs only releases signed with the pinned key
  (the same updater as Admin → Updates), but the group can still re-IP the box, reset web
  passwords and re-run the installer. Keep the group to the admin account.
- **Kept apart from the web app's helper.** None of this is in `zerto-monitor-admin`, the
  web app's socket-activated helper, so a compromised web app can't re-IP the box, grow the
  disk or reset passwords. The app's account `zertomon` isn't in `zmconsole`, and its unit
  sets `NoNewPrivileges`, which stops sudo outright. The menu does reuse two of the helper's
  verbs, `hostname` and `tls-selfsigned`, by running the helper directly as root.
- **Web password resets** run as `zertomon`
  (`runuser -u zertomon -- /opt/zerto-monitor/venv/bin/python`). That way SQLite's `-wal` and
  `-shm` files never become root-owned, which would break the service. The reset hashes with
  bcrypt like `app/auth.py` and updates `users` like `app/db.py` `set_password`. The password
  travels on stdin. Entra ID users have no local password; create a local admin instead.

### Changing the IP address safely

Use **Network → Configure**. Every value is validated, and the netplan file matches the NIC
by MAC. The appliance keeps one adapter's configuration: configuring a different adapter
than the one that has it is refused, because it would remove that adapter's address and
gateway. The sequence is:

1. The current `/etc/netplan` is copied to `/var/lib/zerto-monitor/netplan-backup/<UTC time>/`.
   The last 10 copies are kept.
2. The new file is checked with `netplan generate`. If that fails, the old files go back and
   nothing is applied.
3. The change is applied with `netplan try --timeout 120`. Press **ENTER** within 120 seconds
   to keep it. Ctrl-C or the timeout rolls it back, and the old files are restored too
   (`netplan try` alone only reverts the runtime state).
4. A systemd timer (`zm-netplan-rollback`) restores the backup at 165 seconds if nothing else
   ran. This covers a killed session, a killed sudo or a crash.

The best place to change the address is the **VM console** in vCenter, where you can press
ENTER on the new settings. Over SSH, the menu warns you when the change removes the address
you're connected to:

1. The old session freezes.
2. Within 120 seconds, connect to the **new** address (SSH or VM console) and sign in.
3. The menu asks whether to keep the pending change. **Network → Keep the pending change**
   does the same.

If nobody confirms, the appliance goes back to the old address by itself.

After a change, the menu offers a new self-signed certificate with the new IP in its SANs.
It reuses `zerto-monitor-admin tls-selfsigned`. If a CA-issued certificate is installed, it
says so and defaults to **No**, because regenerating would replace it.

**Network → Restore** puts back the configuration from before the last change, also through
`netplan try`. Running it twice toggles between the two.

### Growing the disk

1. In vCenter, enlarge **Hard disk 1** (Edit Settings). No reboot is needed.
2. Open **Disk expansion**. It rescans the SCSI device
   (`/sys/class/block/sda/device/rescan`) and shows the disk, partition and filesystem sizes
   and the unallocated space.
3. Confirm. It runs `growpart` on the root partition, then `resize2fs`, and shows before and
   after sizes.

It all happens online. Nothing else grows the disk any more, because cloud-init is off after
first boot.

---

## Security notes

**vApp properties are stored in vCenter.** vCenter keeps the passwords you type on the
Customize template page in the VM's vApp configuration. Anyone who can read that VM's
settings in vCenter can read them back. This is inherent to OVF property deployment, not
specific to this appliance, and nothing inside the guest can reach that copy. After first
boot, clear them: **Edit Settings → vApp Options → Properties**, blank the password fields.
The appliance has already applied them and never reads them again. Until they're blank,
**Admin → Security** names the ones still held and shows a banner on the admin page.

**Inside the guest there were three more copies. 1.2 removes all of them:**

- `guestinfo.ovfEnv`. vCenter hands the whole environment to the VM at every power-on, and
  *any* local account can read it back with `vmware-rpctool` (verified: even `nobody`).
  A compromised web app could therefore have read the root password. `zerto-monitor-ovfscrub`
  blanks every password property, and the bulky install payload, in the guest's runtime copy.
  It then re-parses the result as XML to prove nothing secret remains. It runs at boot (before
  any non-root login, the app or snmpd) and every 30 minutes. It records which properties
  vCenter still filled in, by name only, in `/var/lib/zerto-monitor/ovfenv.state`.
- cloud-init's cache. `/var/lib/cloud/instances/*/obj.pkl` pickles the environment, passwords
  included. It's deleted, and cloud-init is switched off (`/etc/cloud/cloud-init.disabled`),
  so it can't re-cache it. Everything cloud-init set up is owned by the appliance's own config
  by then. Switching it off also means a blanked environment can't make it think it's a new
  instance and regenerate the SSH host keys.
- The ISO transport. vSphere can also deliver the environment as a small ISO in the virtual
  CD-ROM. `udev` gives `/dev/sr0` to `root:cdrom` `0660`, and the stock image puts its
  default user in `cdrom`. First boot empties the group, and the scrub ejects the media at
  every boot because vCenter re-presents it at each power-on.

Once the guest copies are gone, the passwords still sit in vCenter until you clear them. So
change them after deployment too: they have been readable there since the deploy.

**The web app can't become root.** It runs sandboxed (`NoNewPrivileges`,
`ProtectSystem=strict`), so it can neither use sudo nor write `/etc`. The admin page's
certificate, hostname and SNMP controls instead talk to `/usr/local/sbin/zerto-monitor-admin`
over `/run/zerto-monitor-admin.sock` (`root:zertomon 0660`). systemd starts one helper per
request, outside the app's sandbox. The helper only knows a fixed list of verbs, takes no
file paths (staging locations are hard-coded, and must be regular files owned by the
service), and pattern-checks every argument. A certificate install is tested with
`nginx -t` and rolled back if refused. Application code is root-owned: only `data/` is
the service's to write.

Inside the appliance, nothing sensitive is in clear. This was verified on the live box with a
byte-level search of every file, the journal, every process's argv and environment, and
guestinfo, for every stored credential, each decrypted on the box:

- Zerto usernames, passwords, API client secrets and Keycloak registration tokens, the SMTP
  password, SNMP communities and the Entra client secret: Fernet-encrypted (AES-128-CBC +
  HMAC-SHA256) in SQLite with `secure_delete`, so overwritten values are zeroed
- Web passwords: bcrypt hashes. Entra ID users have none.
- The Fernet key and the session-signing key: root-owned `0600` in `/etc/zerto-monitor`,
  handed to the service by systemd `LoadCredential`, never in the service's writable `data/`
  and never in the upgrade backups
- Passwords never appear in a log, a command line or an environment variable. The SNMP trap
  community goes to `snmptrap` through a private `snmp.conf`, not `-c`.
- The SMTP password is only ever sent after STARTTLS or over SSL. The app refuses otherwise.

What is deliberately *not* encrypted, and why:

- **The two keys themselves** are plain files (root-only), because the service has to start
  unattended. Binding them to the VM would need a vTPM (`systemd-creds --with-key=tpm2`).
  This VM has none.
- **SNMP v2c** sends its community string unencrypted on the network. That's inherent to v2c,
  so keep traps and polling on the management network. **Admin → Security** says when either is on.
- **ZVM/ZCM connections** are always HTTPS. Without a CA-signed certificate, each source's
  certificate is pinned on first use and checked on every connection afterwards (re-pin
  after an expected renewal). That is trust on first use: the very first connection is the
  one that has to be right.
- **Not covered by the appliance itself:** a copy of the VMDK, its backups, replicas or
  snapshots, which hold the keys and the data together (use vSphere VM Encryption); and
  log lines written by builds before 1.2 that named API client ids (the binary journal
  can only be vacuumed as a whole).

---

## Troubleshooting

```bash
tail -f /var/log/zerto-monitor-firstboot.log   # first-boot progress and errors
systemctl status zerto-monitor                 # the app
journalctl -u zerto-monitor -n 100             # app logs
cloud-init status --long                       # stage 1 (first boot only; off afterwards)
curl -sk https://localhost/healthz             # liveness + which key source is in use
cat /var/lib/zerto-monitor/ovfenv.state        # what vCenter still holds (names only)
sudo tail /var/log/zerto-monitor-console.log   # what the console menu changed, and who
```

If the console banner never appears, the usual cause is no outbound network: check
`ip a`, `ip r`, and `getent hosts pypi.org`. The console menu is installed before the
download step, so you can:

1. Sign in on the VM console.
2. Fix the network under **Network**.
3. Finish the install with **Upgrade → Repair**.

To re-apply configuration, remove `/opt/zerto-monitor/.firstboot-done` and run
`sudo python3 /opt/zerto-monitor/firstboot.py`. cloud-init is off after first boot, so a
reboot alone no longer does it. Network and hostname are re-read from the environment.
Passwords are not, because the appliance has blanked them there. Existing data is preserved.

---

## Upgrading a running appliance

No redeploy needed. Build the payload, copy it over, and run the installer's upgrade mode:

```powershell
python build_ova.py --payload-only          # -> ~\ZertoMonitor-build\payload.tar.xz
```
```bash
# on the appliance, as root:
tar -xJf /tmp/zm-payload.tar.xz -C /opt/zerto-monitor --no-same-owner
python3 /opt/zerto-monitor/firstboot.py --upgrade
```

Those commands are the break-glass route: they skip the signature check, the downgrade
refusal and the backup. The normal routes are Admin → Updates and the update API
([UPDATING.md](../UPDATING.md)). With the web app down, the console menu does the same signed
update: copy the release's `zerto-monitor-<version>.zmupdate` to `/tmp/zm-update.zmupdate`
(a plain file, yours or root's, not writable by others), then **Upgrade → Apply a signed
update**. It hands the file to `zerto-monitor-update`, which checks the signature against
the pinned key, refuses an older or same version unless you allow it, backs up, installs,
health-checks and rolls back on failure. Upgrading a 1.2 appliance needs the manual commands
above once, because 1.2 has no menu.

`--upgrade` does the following:

- **apt:** installs any package the payload newly needs. For 1.3 that's whiptail,
  cloud-guest-utils, chrony and WeasyPrint's `libpango-1.0-0`, `libpangoft2-1.0-0`,
  `libharfbuzz-subset0` and `fonts-dejavu-core`. When nothing is missing, apt isn't called.
- **pip:** runs `pip install -r requirements.txt` into the venv. When `requirements.txt` lists
  `weasyprint`, the import check includes it, which also proves the Pango libraries load.
- **Install:** reinstalls the helper, the console menu (scripts, `zmconsole` group, sudo
  rule, login hook, `/etc/issue`), nginx and the service, then verifies HTTPS.
- **Console members:** the `zmconsole` group is seeded from the human members of `sudo`, not
  the image's `ubuntu` user. This happens only while the group is empty.

It never touches the network, accounts, database, Fernet key or certificate, and leaves an
SNMP agent you enabled running. From 1.2 it also moves an older
appliance's session key to a fresh `/etc/zerto-monitor/session.key` (everyone signs in once
more; the old one may live on in backups, so it's retired, not copied). It also switches
cloud-init off and installs and runs the vApp-environment scrub. For a one-step rollback,
back up `app/`, `templates/` and `static/` first, plus a `VACUUM INTO` copy of
`data/monitor.db` made in a 0700 directory. That compacts the copy, so it carries no free
pages.

## Rebuilding the OVA

Windows, Python 3 only. No ovftool, qemu-img, VirtualBox or WSL required. Large files live
in a work directory **outside any synced folder**: `$env:ZM_BUILD_DIR`, default
`~\ZertoMonitor-build`.

```powershell
# once: fetch Canonical's base image, check it, unpack it into the work dir
$w = "$env:USERPROFILE\ZertoMonitor-build"; mkdir "$w\src" -Force
curl.exe -L -o "$w\ubuntu-26.04-server-cloudimg-amd64.ova" `
  https://cloud-images.ubuntu.com/releases/26.04/release/ubuntu-26.04-server-cloudimg-amd64.ova
# compare (Get-FileHash ... -Algorithm SHA256) with the line in that folder's SHA256SUMS
cd "$w\src"; tar.exe -xf ..\ubuntu-26.04-server-cloudimg-amd64.ova; cd -

python build_ova.py        # writes ~\ZertoMonitor-build\ZertoMonitor-1.3.ova (+ payload.tar.xz)
python validate_ova.py     # structure, manifest, hardware, payload round-trip, guest scripts
python validate_ova.py --payload-only   # just payload.tar.xz: no base image or OVA needed
```

Both modes check that every guest script is present, has LF endings, and compiles. They
also unit-test the console's network validation and netplan rendering, the login hook's
bypass conditions, the sudo rule and the package list. The helper `zerto-monitor-admin` is
POSIX sh. With no shell on the Windows build host, its `sh -n` check is reported as
skipped there. It runs on the appliance, where `firstboot.py` won't install a helper that
fails it.

Canonical refreshes the image periodically. The builder reads the image's own names
(they carry a build date) instead of assuming one, and the validator checks the disk
against the hash in *that* image's manifest.

`build_ova.py` reads the app straight from the project, so any change to `app/`,
`templates/` or `static/` is picked up on the next build.

| Script | Role |
|---|---|
| `build_ova.py` | Builds the OVA: payload, descriptor, manifest, tar (`--payload-only` for upgrades) |
| `bootstrap.py` | Stage 1 in the guest, carried in the `user-data` property |
| `firstboot.py` | Stage 2 in the guest, carried in the payload; `--upgrade` for in-place upgrades |
| `zerto-monitor-admin` | Privileged helper (TLS, hostname, snmpd), installed to `/usr/local/sbin` |
| `zerto-monitor-snmp` | snmpd `extend` hook: one metric per call, 20 s cache, `-1` if the app is down |
| `zerto-monitor-ovfscrub` | Blanks deploy-time passwords from the guest's vApp environment and cloud-init's cache, installed to `/usr/local/sbin` |
| `zerto-monitor-console` | The login menu (whiptail, system python3, runs as the admin), installed to `/usr/local/bin` |
| `zerto-monitor-console-ops` | The menu's root operations, reached only via sudo; also the one implementation of network validation and netplan rendering, which `firstboot.py` imports. Installed to `/usr/local/sbin` |
| `validate_ova.py` | Verifies the result without ovftool |

### How the app gets in

The application is a solid `tar.xz` (about 59 KB in 1.1), base64-encoded and split
across hidden `zm-payload*` OVF properties of 24,000 characters each. `user-data`
carries only the small bootstrap. vSphere's limit is 65,535 characters **per property**,
and the environment as a whole (about 90 KB) is well inside what the guestInfo transport
carries. So no second disk or ISO member is needed, which matters: an extra file member
would need a second CD-ROM competing with the ISO transport the wizard depends on.

`validate_ova.py` reconstructs the guest's view of that environment and proves every file
arrives byte-identical. Constraints it enforces, each of which fails **silently** in
production if broken:

- `ovf:key` contains no `.` or `:` (DSP0243 §9.5; dots also collide with the
  `[class.]key[.instance]` grammar that composes the key the guest sees)
- No cloud-init reserved key (`hostname`, `password`, `public-keys`, `seedfrom`) is reused
  for an appliance setting — `password` in particular is force-expired by cloud-init
- The CD-ROM stays parented to the **IDE** controller and no `InstanceID` is renumbered.
  vSphere 7+ quietly drops a SCSI-parented CD-ROM; the deploy then succeeds and the
  appliance boots completely unconfigured, with no error anywhere
- `instance-id` is non-empty, or cloud-init's per-instance semantics collapse
- The manifest is regenerated after every descriptor edit, in the exact
  `SHA256(name)= hex` spelling, and never lists itself
