# Updating Zerto Monitor

How a change becomes a release, and how a release reaches an appliance, for engineers and
for AI agents.

## How updates work

Every release is published as a **signed update bundle**, `zerto-monitor-<version>.zmupdate`.
It holds the payload (the same code an OVA carries), a manifest with the payload's SHA-256,
and an **Ed25519 signature** over that manifest.

- **The private signing key** stays on your release workstation. It's in DPAPI storage at
  `$env:ZM_SIGNING_KEY`, or `~\.zerto-monitor\release-signing.xml` when that isn't set, and
  is never written in clear or printed.
- **The public key** ships in every payload. Appliances pin it at
  `/etc/zerto-monitor/release-signing.pub`.
- **Before installing anything, the appliance checks:**
  - the signature, as root, with OpenSSL;
  - that the payload matches the signed hash;
  - that every file lands only where code belongs;
  - that the version is **newer** than the one installed. A reinstall or downgrade needs an
    admin to tick a box in the portal.
- **Installing:** it backs up the code and database, installs, runs the installer and
  health-checks the site. **If the check fails it restores the previous version
  automatically.**

So deploying needs **no SSH key and no appliance password**. An admin can do it in the portal,
or anyone holding a short-lived **deploy token** can use the update API. Neither can install
code that wasn't signed with the release key.

| Role | Who | Needs |
|---|---|---|
| **Release owner** | builds and signs releases | the release workstation (DPAPI signing key, an upload token for your package registry or GitHub) |
| **Deployer** | puts a release on an appliance | an admin login, or a deploy token from an admin |

## 1. Making a release (release owner)

All commands run from the repository root on your release workstation.

1. **Change and document.**
   - Code changes go in `app/`, `templates/`, `static/` or `deploy/`.
   - Add a section at the top of `CHANGELOG.md`: `## x.y.z — YYYY-MM-DD`, written for engineers.
   - Update `README.md` for anything user-visible, and the version in the status table in
     `OVERVIEW.md`.
   - Update `BACKLOG.md` if an item is done or new.
2. **Version.** Bump `VERSION` in `deploy/appliance/build_ova.py`: patch (`1.4.1`) for
   fixes, minor (`1.5.0`) for features. Bundle same-day fixes into one version; every
   release publishes a ~790 MB OVA.
3. **Test.** Run `.\tests\run_all.ps1`. Every suite must say `ALL GOOD`. The tests are
   offline (temporary data, `.invalid` hosts) and never touch a real ZVM. Add tests for what
   you changed.
4. **Build and validate.**
   ```powershell
   .venv\Scripts\python.exe deploy\appliance\build_ova.py        # OVA + payload.tar.xz in ~\ZertoMonitor-build
   .venv\Scripts\python.exe deploy\appliance\validate_ova.py     # must end ALL GOOD
   Copy-Item ~\ZertoMonitor-build\ZertoMonitor-x.y.z.ova ~\Downloads\
   ```
   The build refuses anything secret-shaped and refuses to run without the public key.
5. **Sign.** The private key goes to the signer over stdin only, never on a command line:
   ```powershell
   $key = if ($env:ZM_SIGNING_KEY) { $env:ZM_SIGNING_KEY } else { "$HOME\.zerto-monitor\release-signing.xml" }
   $b = "$HOME\ZertoMonitor-build"
   (Import-Clixml $key).GetNetworkCredential().Password |
     .venv\Scripts\python.exe deploy\release_signing.py sign --payload "$b\payload.tar.xz" --version x.y.z --out $b
   .venv\Scripts\python.exe deploy\release_signing.py verify --bundle "$b\zerto-monitor-x.y.z.zmupdate" --pub deploy\appliance\release-signing.pub
   ```
   The signer refuses a payload whose `VERSION` isn't the version you name.
6. **Publish.** The release owner's publish script (kept outside the repository, because it
   holds your registry details) or you by hand puts these in place. Nothing is sent if a
   secret check trips: scan the source and every member of `payload.tar.xz` for secrets
   before signing, and re-hash the payload between that scan and signing.
   - The source, as one commit, tagged `vx.y.z`.
   - The OVA and its `.sha256`, and the signed bundle `zerto-monitor-x.y.z.zmupdate`.
   - The release index, `releases.json`, listing every signed release:
     `{"product": "zerto-monitor", "generated": "...", "releases": [{"version": "x.y.z",
     "bundle": "zerto-monitor-x.y.z.zmupdate", "sha256": "...", "size": 0, "published": "..."}]}`.
   - Release `vx.y.z`, with the changelog section as its notes.
   - A published version is never overwritten. Fix forward with a new version.

   Two layouts work:
   - **Your package registry (Gitea/Forgejo generic packages).** The OVA and bundle go to
     `{base}/zerto-monitor/x.y.z/`, the index to
     `{base}/zerto-monitor-index/current/releases.json`, where `{base}` is
     `https://<server>/api/packages/<owner>/generic`. The generic registry refuses to
     overwrite a file, so delete the old index before uploading the new one. Release
     attachments there are usually size-capped, which is why the OVA goes to the registry
     and the release notes link to it.
   - **GitHub releases.** Attach the OVA, the bundle and `releases.json` to release `vx.y.z`.
     Give each index entry the bundle's full download `"url"`, so older releases stay
     reachable from the newest index.

   An appliance's **update source** is set in **Admin → Updates**. It is either the
   Gitea/Forgejo generic-package base URL (`{base}` above), or the full URL of a
   `releases.json` index, such as
   `https://github.com/OWNER/REPO/releases/latest/download/releases.json`. None is set by
   default; without one, admins upload `.zmupdate` files instead.

## 2. Deploying a release (deployer)

Pick one route; A and B are normal, C and D are for when the web app itself is down.

### A. The portal (admin)
1. Go to **Admin → Updates**.
2. Under *Published releases*, click **Download & check** on the version you want. Or upload
   a `.zmupdate` file.
3. Check the staged line: the version, *newer than* the installed one, and the signing key id.
4. Type the version and click **Apply update**.
5. The page refreshes itself while the update runs: *verifying → installing → done*. The
   service restarts once, and signed-in sessions survive.

### B. The update API (deploy token: other engineers, scripts, other Claude instances)
An admin creates a token in **Admin → Updates → Deploy tokens**. Give it a name and a
lifetime (pick the shortest that works). The token is shown once. Pass it to the deployer
through a secret store, never in chat, a ticket or a URL. With it:

```bash
H="Authorization: Bearer zmd_...."           # from the secret store, not typed into history
B=https://zertomon.example.com
curl -sk -H "$H" $B/api/update/status        # installed version, last update, signing key id
curl -sk -H "$H" $B/api/update/available     # published releases, each marked newer/same/older
curl -sk -H "$H" -H 'Content-Type: application/json' -X POST -d '{"version":"1.4.1"}' $B/api/update/apply
# 202 = started. Poll /api/update/status until status.state is done, rolled_back, refused or failed.
```

```powershell
$H = @{ Authorization = "Bearer $token" }    # $token read from a SecureString/secret store
$B = "https://zertomon.example.com"
Invoke-RestMethod "$B/api/update/available" -Headers $H -SkipCertificateCheck
Invoke-RestMethod "$B/api/update/apply" -Method Post -Headers $H -ContentType application/json -Body '{"version":"1.4.1"}' -SkipCertificateCheck
do { Start-Sleep 15; $s = Invoke-RestMethod "$B/api/update/status" -Headers $H -SkipCertificateCheck; $s.status.state } until ($s.status.state -in 'done','rolled_back','refused','failed')
```

A token can only install a **newer** signed release; a reinstall or downgrade is refused with
409. Revoke the token in the portal when the job is done.

### C. The appliance console menu (web app down)
Copy the release's signed bundle, `zerto-monitor-<version>.zmupdate`, to
`/tmp/zm-update.zmupdate` on the appliance. It must be a plain file, yours or root's, and not
writable by others. Then sign in on the VM console (or SSH) as the appliance admin and choose
**Upgrade → Apply a signed update**. It runs the same signed updater as route A: signature,
downgrade refusal (the menu asks whether to allow a reinstall/downgrade; default no), backup,
health check and automatic rollback. **Upgrade → Repair** re-runs the installer for the
version already on disk.

### D. By hand (break-glass)
As root on the appliance:
```bash
tar -xJf /tmp/zm-payload.tar.xz -C /opt/zerto-monitor --no-same-owner && python3 /opt/zerto-monitor/firstboot.py --upgrade
```
Route D skips the signature check, the downgrade refusal and the backup, because a person
with root is doing the install. Use it only for payloads you built or downloaded from the
release yourself, and only when C can't work (no updater yet, or a lost signing key).

### New appliance
Deploy the release's OVA; see [appliance/README.md](appliance/README.md). Its first boot
installs the pinned key, so every later update can use A or B.

## 3. After every deploy
- **Version and outcome:** `GET /api/update/status`, or Admin → Updates, shows the new version
  and `done`.
- **The site works:** the dashboard, a zORG page and the VRA page load; `/healthz` returns
  `{"ok": true}` and the new `version`. The updater's health check only accepts that version,
  so an old process still answering can't pass for the new one.
- **No new problems:** Admin → Security has nothing new in red, and the console menu's
  *Services → app log* has no tracebacks.
- **Close the loop:** if you used a token, revoke it. Note the deploy in the ticket.

## 4. Rollback
- **Automatic:** if the installed version fails its health check, the previous version is
  restored and the status says `rolled_back`.
- **Manual:** Admin → Updates → *Download & check* on the earlier version, tick **Reinstall /
  downgrade**, type its version and apply. Or use route C with the older release's
  `.zmupdate`, allowing the downgrade when the menu asks.
- **Backups:** the code and a compacted copy of the database are in
  `/var/backups/zerto-monitor/pre-update-*`, root-only. The newest three are kept.
- **Database changes are additive** (new tables and columns), so older code runs on a newer
  database.

## 5. The signing key
- **Where:** on your release workstation, as DPAPI: `$env:ZM_SIGNING_KEY` if set, else
  `~\.zerto-monitor\release-signing.xml`. `new_release_key.ps1 -KeyFile <path>` names
  another file. It is readable only by that Windows user on that machine. Never copy it into
  the repository, chat, email or a ticket. Your publish script's secret check should refuse
  to publish any file containing it.
- **If the release workstation is lost:**
  1. Create a new key on the new workstation (`.\deploy\new_release_key.ps1`).
  2. Put the new public key on each appliance by hand, as root: write
     `deploy/appliance/release-signing.pub` to `/etc/zerto-monitor/release-signing.pub`,
     mode 0644.
  3. Or deploy the next release by route D; its installer pins the key it carries. (Route C
     checks the signature, so it refuses a release signed with the new key.)
- **Rotating it, or handing releases to someone else:** two steps, so appliances never
  stop trusting.
  1. On the current release workstation, run `.\deploy\new_release_key.ps1 -Rotate`. The new
     public key goes into the repo; the new private key waits beside the current one as
     `<name>-next.xml`. Build and
     publish **one** release. It is signed with the current key, which appliances trust, and
     it carries the new public key, which they then pin.
  2. Run `.\deploy\new_release_key.ps1 -Promote`. Every later release is signed with the new
     key. To hand over, the new owner runs the rotation on *their* workstation, and the
     current owner publishes step 1's release.

## 6. Troubleshooting
| Symptom | Meaning / fix |
|---|---|
| "SIGNATURE INVALID" | Not signed with this appliance's release key: a tampered file, or a bundle from another key. Download it again from the release. |
| "not newer than the installed" | Working as designed. Use the portal's *Reinstall / downgrade* box (admin) if you really mean it. |
| "Couldn't read the release index" / "no release index configured" | The appliance can't reach the update source set in Admin → Updates, none is set, or the index wasn't published. Upload the `.zmupdate` file instead. |
| status `rolled_back` | The new version failed its health check and the old one is running. See `/var/log/zerto-monitor-update.log` on the appliance (root) and the console menu's app log. |
| status `failed` | The new version failed and so did the restore. Use the console menu: Upgrade → Repair, or route D with a known-good payload. |
| status `refused`, "the backup failed" | Nothing was installed and the running version is untouched. Usually a full disk: free space (or grow the disk from the console menu) and retry. |
| "the privileged helper is not installed" | The appliance predates 1.4. Install 1.4 by route D once; after that A, B and C work. |
