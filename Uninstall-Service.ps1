$ErrorActionPreference = 'Stop'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'Run this script as Administrator.' }
$svc = Get-Service -Name 'SentinelAgent' -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -ne 'Stopped') { Stop-Service -Name SentinelAgent -Force }
    & sc.exe delete SentinelAgent
    Write-Host 'Service registration removed. The evidence log and binaries were kept for review.'
}
else { Write-Host 'Service is not installed.' }
