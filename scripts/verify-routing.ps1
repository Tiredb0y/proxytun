<#
 End-to-end proof that ONLY listed applications are proxied (spec rule 5).

 It uses two different executables that behave identically:
   * C:\Windows\System32\curl.exe                 -> stays DIRECT (not in the list)
   * %TEMP%\apm-verify\curl-proxied.exe (a copy)  -> the one you ADD to App Proxy Manager

 Steps
   1. Make sure routing is STOPPED, then:      powershell -File scripts\verify-routing.ps1 -Phase Baseline
   2. In App Proxy Manager: Add Application -> %TEMP%\apm-verify\curl-proxied.exe, then Start Routing
      (Hiddify must be connected, with its SOCKS5 inbound on 127.0.0.1:12334).
   3. Run:                                      powershell -File scripts\verify-routing.ps1 -Phase Verify
   PASS = the direct curl still shows your real IP, the proxied copy shows a different (Hiddify exit) IP.
#>
param([ValidateSet('Baseline','Verify')][string]$Phase = 'Verify')
$ErrorActionPreference = 'Stop'
$dir = Join-Path $env:TEMP 'apm-verify'
New-Item -ItemType Directory -Force $dir | Out-Null
$direct  = "$env:SystemRoot\System32\curl.exe"
$proxied = Join-Path $dir 'curl-proxied.exe'
if (-not (Test-Path $proxied)) { Copy-Item $direct $proxied }
$baselineFile = Join-Path $dir 'baseline-ip.txt'
$url = 'https://api.ipify.org'

function Get-Ip($exe) { (& $exe -s --max-time 20 $url).Trim() }

if ($Phase -eq 'Baseline') {
  $ip = Get-Ip $direct
  Set-Content $baselineFile $ip
  Write-Host "Baseline (no routing) public IP: $ip"
  Write-Host "Now add this file in App Proxy Manager and start routing:`n  $proxied"
  exit 0
}
if (-not (Test-Path $baselineFile)) { throw 'Run -Phase Baseline first (with routing stopped).' }
$base = (Get-Content $baselineFile).Trim()
$d = Get-Ip $direct
$p = Get-Ip $proxied
Write-Host "Baseline IP          : $base"
Write-Host "Direct   curl.exe    : $d"
Write-Host "Proxied  curl-proxied: $p"
if ($d -eq $base -and $p -ne $base -and $p) { Write-Host 'PASS: only the listed application uses the proxy.' -ForegroundColor Green; exit 0 }
Write-Host 'FAIL: expected direct == baseline and proxied != baseline. See README > Troubleshooting.' -ForegroundColor Red
exit 1
