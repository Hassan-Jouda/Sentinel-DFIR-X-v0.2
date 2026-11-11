# Use only after validating the new desktop/agent on a test VM.
$ErrorActionPreference = 'Stop'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'Open PowerShell as Administrator.' }
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$source = Join-Path $root 'dist\agent'
$exe = Join-Path $source 'Sentinel.Agent.exe'
$destination = Join-Path $env:ProgramFiles 'SentinelDFIR'
if (-not (Test-Path $exe)) { throw 'Run Publish.ps1 first.' }
$service = Get-Service SentinelAgent -ErrorAction Stop
$backup = Join-Path $env:ProgramFiles ('SentinelDFIR-backup-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
if (Test-Path $destination) {
    Write-Host "Backing up previous installed binaries to $backup"
    Copy-Item $destination $backup -Recurse -Force
}
try {
    if ($service.Status -ne 'Stopped') {
        Stop-Service SentinelAgent -ErrorAction Stop
        (Get-Service SentinelAgent).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    New-Item $destination -ItemType Directory -Force | Out-Null
    Copy-Item (Join-Path $source '*') $destination -Recurse -Force
    Start-Service SentinelAgent -ErrorAction Stop
    (Get-Service SentinelAgent).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    Write-Host 'SentinelAgent upgraded and running.' -ForegroundColor Green
    Write-Host 'Existing forensic data under C:\ProgramData\SentinelDFIR is untouched.'
}
catch {
    Write-Warning 'Upgrade failed; attempting to restore previous installed binaries.'
    try {
        Stop-Service SentinelAgent -ErrorAction SilentlyContinue
        if (Test-Path $backup) { Copy-Item (Join-Path $backup '*') $destination -Recurse -Force }
        Start-Service SentinelAgent -ErrorAction Stop
    }
    catch { Write-Warning ('Manual recovery needed from ' + $backup) }
    throw
}
