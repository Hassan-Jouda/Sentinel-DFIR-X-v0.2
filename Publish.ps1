$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $root
try {
    # IMPORTANT: WPF multi-file avoids known single-file startup regressions on .NET 10.
    dotnet publish .\src\Sentinel.Agent\Sentinel.Agent.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false -p:PublishTrimmed=false -o .\dist\agent
    if ($LASTEXITCODE -ne 0) { throw 'Agent publish failed' }
    dotnet publish .\src\Sentinel.Desktop\Sentinel.Desktop.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false -p:PublishTrimmed=false -o .\dist\desktop
    if ($LASTEXITCODE -ne 0) { throw 'Desktop publish failed' }
    Write-Host 'Published dist\agent\Sentinel.Agent.exe and dist\desktop\Sentinel.Desktop.exe.' -ForegroundColor Green
    Write-Host 'Keep all DLL and runtime files next to each EXE. Do not move just the EXE.'
}
finally { Pop-Location }
