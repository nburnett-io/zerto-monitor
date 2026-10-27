<#
.SYNOPSIS
  Create, rotate or promote Zerto Monitor's release signing key.

.DESCRIPTION
  The PUBLIC key lives in deploy/appliance/release-signing.pub, ships in every payload, and
  appliances pin it at /etc/zerto-monitor/release-signing.pub. The PRIVATE key lives only in
  DPAPI storage at -KeyFile (readable only by this Windows user on this machine). It is
  never written to disk in clear and never printed. -KeyFile defaults to $env:ZM_SIGNING_KEY
  if set, else ~\.zerto-monitor\release-signing.xml.

  First key:    .\deploy\new_release_key.ps1
  Rotation:     .\deploy\new_release_key.ps1 -Rotate    # new key -> <key file>-next.xml;
                                                         # NEW public key written to release-signing.pub
                build + publish ONE release (it is signed with the CURRENT key, which appliances
                trust, and carries the new public key, which they then pin)
                .\deploy\new_release_key.ps1 -Promote   # the next key becomes the current one
  See deploy/UPDATING.md.
#>
param([switch]$Rotate, [switch]$Promote,
      [string]$KeyFile = $(if ($env:ZM_SIGNING_KEY) { $env:ZM_SIGNING_KEY } else { "$HOME\.zerto-monitor\release-signing.xml" }))
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$store = $KeyFile
$next = Join-Path (Split-Path $store) ([IO.Path]::GetFileNameWithoutExtension($store) + '-next' + [IO.Path]::GetExtension($store))
$pub = "$Root\deploy\appliance\release-signing.pub"
if ($Promote) {
  if (-not (Test-Path $next)) { throw "no rotated key waiting ($next)" }
  Move-Item -Force $store "$store.retired-$(Get-Date -Format yyyyMMdd)"
  Move-Item $next $store
  "promoted: releases are now signed with the new key; the old one is kept as $store.retired-*"
  return
}
$target = if ($Rotate) { $next } else { $store }
if (-not $Rotate -and (Test-Path $store)) { throw "a signing key already exists ($store) - use -Rotate deliberately" }
# a first key must never replace a public key appliances already pin (its private half may live at another -KeyFile)
if (-not $Rotate -and (Test-Path $pub)) { throw "$pub exists, so a release key is already in use: pass -KeyFile <its file> or set ZM_SIGNING_KEY. Delete release-signing.pub only if you really mean to start a new key (your own fork)." }
if ($Rotate -and -not (Test-Path $store)) { throw "nothing to rotate: create the first key without -Rotate" }
if ($Rotate -and (Test-Path $next)) { throw "a rotated key is already waiting ($next) - run -Promote first, or delete it deliberately" }
$py = "$Root\.venv\Scripts\python.exe"
$psi = New-Object System.Diagnostics.ProcessStartInfo $py, "`"$Root\deploy\release_signing.py`" genkey --pub `"$pub.new`""
$psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.UseShellExecute = $false
$p = [System.Diagnostics.Process]::Start($psi)
$pem = $p.StandardOutput.ReadToEnd(); $err = $p.StandardError.ReadToEnd(); $p.WaitForExit()
if ($p.ExitCode -ne 0 -or $pem -notmatch 'BEGIN PRIVATE KEY') { throw "key generation failed: $err" }
$sec = ConvertTo-SecureString $pem -AsPlainText -Force
$pem = $null
New-Item -ItemType Directory -Force (Split-Path $target) | Out-Null
New-Object System.Management.Automation.PSCredential('zm-release-signing', $sec) | Export-Clixml $target
Move-Item -Force "$pub.new" $pub
"signing key stored in $target (DPAPI); public key -> $pub ($($err.Trim()))"
