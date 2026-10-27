# Run Zerto Monitor locally on Windows for development/testing.
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
if (-not (Test-Path "$root\.venv")) { python -m venv "$root\.venv" }
& "$root\.venv\Scripts\pip.exe" install -q -r "$root\requirements.txt"
# Outside any synced folder on purpose: the database must never sync anywhere.
$env:DATA_DIR = "$env:LOCALAPPDATA\ZertoMonitor\data"
# The dev keys never sit in a file beside the database either: they're kept
# DPAPI-protected (readable only by this Windows account) and handed over in the
# environment. crypto.py refuses to create key files inside a synced folder regardless.
$kf = if ($env:ZM_DEV_KEYS) { $env:ZM_DEV_KEYS } else { "$HOME\.zerto-monitor\dev-keys.xml" }
New-Item -ItemType Directory -Force (Split-Path $kf) | Out-Null
if (-not (Test-Path $kf)) {
  $py = "$root\.venv\Scripts\python.exe"
  $f = & $py -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())"
  $s = & $py -c "import secrets;print(secrets.token_urlsafe(48))"
  @([pscredential]::new('fernet', (ConvertTo-SecureString $f -AsPlainText -Force)),
    [pscredential]::new('session', (ConvertTo-SecureString $s -AsPlainText -Force))) | Export-Clixml $kf
}
$k = Import-Clixml $kf
$env:FERNET_KEY = $k[0].GetNetworkCredential().Password
$env:SECRET_KEY = $k[1].GetNetworkCredential().Password
$env:PORT = "8000"
Set-Location "$root\app"
& "$root\.venv\Scripts\python.exe" -m uvicorn main:app --host 127.0.0.1 --port 8000
