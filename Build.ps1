$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $root
try {
    dotnet build .\src\Sentinel.Agent\Sentinel.Agent.csproj -c Release
    if ($LASTEXITCODE -ne 0) { throw 'Agent build failed' }
    dotnet build .\src\Sentinel.Desktop\Sentinel.Desktop.csproj -c Release
    if ($LASTEXITCODE -ne 0) { throw 'Desktop build failed' }
    Write-Host 'Build successful.' -ForegroundColor Green
}
finally { Pop-Location }
