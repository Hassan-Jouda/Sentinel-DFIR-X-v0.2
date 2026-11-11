$ErrorActionPreference = 'Stop'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'Run this script as Administrator.' }
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$agent = Join-Path $root 'dist\agent\Sentinel.Agent.exe'
if (-not (Test-Path $agent)) { throw 'Agent not published. Run Publish.ps1 first.' }
$install = Join-Path $env:ProgramFiles 'SentinelDFIR'
New-Item -ItemType Directory -Path $install -Force | Out-Null
Copy-Item (Join-Path $root 'dist\agent\*') $install -Recurse -Force
$exe = Join-Path $install 'Sentinel.Agent.exe'
if (Get-Service -Name 'SentinelAgent' -ErrorAction SilentlyContinue) { throw 'SentinelAgent already installed.' }
New-Service -Name 'SentinelAgent' -BinaryPathName ('"' + $exe + '"') -DisplayName 'Sentinel DFIR Agent' -StartupType Automatic
Start-Service -Name 'SentinelAgent'
Write-Host 'Service installed and started. Review services.msc.' -ForegroundColor Green
