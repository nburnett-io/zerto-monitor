# Run every test suite. Offline: temporary data dirs, .invalid hosts, no ZVM is contacted.
$py = Join-Path (Split-Path -Parent $PSScriptRoot) ".venv\Scripts\python.exe"
$failed = 0
foreach ($t in Get-ChildItem $PSScriptRoot -Filter "smoke_v*.py" | Sort-Object Name) {
  $out = & $py $t.FullName 2>&1
  $ok = ($out | Select-String -SimpleMatch "ALL GOOD") -ne $null
  if (-not $ok) { $failed++; $out | Select-String -Pattern '\[FAIL\]|Traceback|Error' | Select-Object -First 15 | ForEach-Object { "    $_" } }
  "{0,-16} {1}" -f $t.BaseName, ($(if ($ok) { "ALL GOOD" } else { "FAILED" }))
}
if ($failed) { throw "$failed suite(s) failed" }
