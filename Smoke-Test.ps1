$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$agent = Join-Path $root 'dist\agent\Sentinel.Agent.exe'
$desktop = Join-Path $root 'dist\desktop\Sentinel.Desktop.exe'
Write-Host '== Sentinel DFIR v0.2 smoke checks =='
if (-not (Test-Path $agent)) { throw "Not found: $agent" }
if (-not (Test-Path $desktop)) { throw "Not found: $desktop" }
Write-Host 'Published executables exist.' -ForegroundColor Green
$service = Get-Service SentinelAgent -ErrorAction SilentlyContinue
if ($service) { $service | Select-Object Name,Status,StartType | Format-Table }
else { Write-Warning 'Agent is not installed as a Windows Service yet.' }
$data = Join-Path $env:ProgramData 'SentinelDFIR'
$eventPath = Join-Path $data 'events.jsonl'
$snapshot = Join-Path $data 'snapshot.json'
if (Test-Path $eventPath) {
  Get-Content $eventPath -Tail 3 | ForEach-Object { try { $_ | ConvertFrom-Json | Select-Object TimestampUtc,Source,Category,Title,Severity,RiskScore } catch { Write-Warning 'Malformed event line' } }
}
else { Write-Warning "No event file yet: $eventPath" }
if (Test-Path $snapshot) {
  Get-Content $snapshot -Raw | ConvertFrom-Json | Select-Object TimestampUtc,ProcessCount,SysmonActive,DroppedEvents
}
else { Write-Warning "No snapshot yet: $snapshot" }
Write-Host 'For application crashes, check Event Viewer > Windows Logs > Application (.NET Runtime 1026).'
