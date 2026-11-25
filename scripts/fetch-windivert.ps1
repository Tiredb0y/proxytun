<#
 Verifies (or re-downloads) the WinDivert 2.2.2-A x64 binaries bundled in third_party\WinDivert\x64.
   -VerifyOnly : only check SHA-256 of the files already present (used by build.bat)
   (no switch)  : download the official release zip from GitHub, check its hash, and extract the x64 files
#>
param([switch]$VerifyOnly)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dir  = Join-Path $root 'third_party\WinDivert\x64'
$expected = @{
  'WinDivert.dll'   = 'c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2'
  'WinDivert64.sys' = '8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2'
}
$zipHash = '63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15'
$url = 'https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip'

function Test-Files {
  foreach ($k in $expected.Keys) {
    $p = Join-Path $dir $k
    if (-not (Test-Path $p)) { return "missing: $k" }
    if ((Get-FileHash $p -Algorithm SHA256).Hash.ToLower() -ne $expected[$k]) { return "hash mismatch: $k" }
  }
  return $null
}

$err = Test-Files
if (-not $err) { Write-Host 'WinDivert 2.2.2 binaries OK (SHA-256 verified).'; exit 0 }
if ($VerifyOnly) { Write-Host "[ERROR] $err. Run scripts\fetch-windivert.ps1 without -VerifyOnly."; exit 1 }

$tmp = Join-Path $env:TEMP 'windivert-2.2.2.zip'
Invoke-WebRequest $url -OutFile $tmp
if ((Get-FileHash $tmp -Algorithm SHA256).Hash.ToLower() -ne $zipHash) { throw 'Downloaded archive hash mismatch - aborting.' }
$x = Join-Path $env:TEMP 'windivert-2.2.2'
Expand-Archive $tmp -DestinationPath $x -Force
New-Item -ItemType Directory -Force $dir | Out-Null
Copy-Item (Join-Path $x 'WinDivert-2.2.2-A\x64\WinDivert.dll'),(Join-Path $x 'WinDivert-2.2.2-A\x64\WinDivert64.sys') $dir -Force
$err = Test-Files
if ($err) { throw $err }
Write-Host 'WinDivert 2.2.2 binaries downloaded and verified.'
