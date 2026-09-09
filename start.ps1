# Local development launcher. Run -Help for options; no admin rights required.
[CmdletBinding()]
param(
    [Alias('b')][ValidateRange(1, 65535)][int]$BackendPort = 8000,
    [Alias('f')][ValidateRange(1, 65535)][int]$FrontendPort = 5173,
    [ValidateRange(10, 600)][int]$StartupTimeout = 120,
    [switch]$InstallDependencies,
    [switch]$NoBrowser,
    [switch]$Check,
    [switch]$Stop,
    [switch]$Help
)

$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
$Backend = Join-Path $Root 'backend'
$LocalPython = Join-Path $Backend '.venv\Scripts\python.exe'
$StatePath = Join-Path $Root 'tmp\launcher.json'
$Started = @()

function Stop-OwnedProcess($Record) {
    $process = Get-Process -Id $Record.pid -ErrorAction SilentlyContinue
    # A stored PID may have been reused since the last launch.
    if ($process -and $process.StartTime.ToUniversalTime().Ticks.ToString() -eq $Record.startTicks) {
        # Windows venv Python may launch a child interpreter; stop that tree too.
        & "$env:SystemRoot\System32\taskkill.exe" /PID "$($process.Id)" /T /F | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Could not stop $($Record.name) (PID $($process.Id))." }
        Write-Host "Stopped $($Record.name) (PID $($process.Id))."
    }
}

function Test-FreePort([int]$Port) {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
    try { $listener.Start() } catch { throw "Port $Port is already in use. Choose another port; existing servers were not stopped." }
    finally { $listener.Stop() }
}

function Wait-Service($Process, [string]$Url, [string]$Log, [switch]$Api) {
    $deadline = (Get-Date).AddSeconds($StartupTimeout)
    do {
        $Process.Refresh()
        if ($Process.HasExited) { throw "Server exited with code $($Process.ExitCode). Read $Log" }
        try {
            if ($Api) {
                $health = Invoke-RestMethod -Uri $Url -TimeoutSec 2
                if ($health.status -eq 'ok' -and $health.version -eq '2.3.2') { return }
            } else {
                $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 2
                if ($response.StatusCode -eq 200) { return }
            }
        } catch { }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    throw "Timed out waiting for $Url. Read $Log or increase -StartupTimeout."
}

function Start-ServiceProcess([string]$Name, [string]$Executable, [string[]]$Arguments, [string]$Directory) {
    $logDirectory = Join-Path $Root 'logs'
    New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
    $log = Join-Path $logDirectory "$Name-$stamp.err.log"
    $process = Start-Process -FilePath $Executable -ArgumentList $Arguments -WorkingDirectory $Directory `
        -WindowStyle Hidden -PassThru -RedirectStandardError $log `
        -RedirectStandardOutput (Join-Path $logDirectory "$Name-$stamp.out.log")
    return @{ process = $process; log = $log; record = @{
        name = $Name; pid = $process.Id; startTicks = $process.StartTime.ToUniversalTime().Ticks.ToString()
    } }
}

if ($Help) {
    Write-Host @'
Aegis Threat 2.3.2 - Windows local launcher

PowerShell: .\start.ps1 [-BackendPort 8000] [-FrontendPort 5173]
             [-InstallDependencies] [-NoBrowser] [-StartupTimeout 120]
             [-Check] [-Stop] [-Help]
Batch:      start.bat [--backend-port PORT] [--frontend-port PORT]
             [--install] [--no-browser] [--check] [--stop] [--help]

First start creates backend/.venv and installs missing dependencies.
--install refreshes dependencies from the manifests (npm ci and pip install).
--check validates installed dependencies without installing or starting servers.
--stop stops only processes recorded by this launcher's latest run.
Servers bind to 127.0.0.1; logs are in logs/ and process state in tmp/launcher.json.
Python 3.10+ (3.12 recommended) and Node 22.13+ on an even-numbered LTS line required.
Models are not downloaded during startup. Use backend/tools/prefetch_models.py separately.
'@
    exit 0
}

try {
    if ($Check -and $InstallDependencies) { throw '-Check cannot be combined with -InstallDependencies; no dependencies were changed.' }
    if ($Stop) {
        if (Test-Path -LiteralPath $StatePath) {
            $state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
            foreach ($record in $state.processes) { Stop-OwnedProcess $record }
            Remove-Item -LiteralPath $StatePath
        } else { Write-Host 'No launcher-managed processes were recorded.' }
        exit 0
    }
    if ($BackendPort -eq $FrontendPort) { throw 'Backend and frontend ports must differ.' }
    if (Test-Path -LiteralPath $StatePath) {
        $state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
        foreach ($record in $state.processes) {
            $process = Get-Process -Id $record.pid -ErrorAction SilentlyContinue
            if (-not $Check -and $process -and $process.StartTime.ToUniversalTime().Ticks.ToString() -eq $record.startTicks) {
                throw 'This launcher already has running servers. Use -Stop first, or use the printed URLs.'
            }
        }
    }
    $node = (Get-Command node.exe -ErrorAction Stop).Source
    $npm = (Get-Command npm.cmd -ErrorAction Stop).Source
    & $node -e "const [major,minor]=process.versions.node.split('.').map(Number); process.exit((major===22&&minor>=13)||(major>=24&&major%2===0)?0:1)"
    if ($LASTEXITCODE -ne 0) { throw 'Install Node.js 22.13+ or a newer even-numbered LTS version.' }
    $env:PYTHONUTF8 = '1'
    if (-not (Test-Path -LiteralPath $LocalPython)) {
        if ($Check) { throw 'backend/.venv is missing. Run the launcher without -Check to create it.' }
        $python = $env:AEGIS_PYTHON
        $pythonArgs = @()
        if (-not $python) {
            if (Get-Command py.exe -ErrorAction SilentlyContinue) { $python = 'py.exe'; $pythonArgs = @('-3') }
            else { $python = (Get-Command python.exe -ErrorAction Stop).Source }
        }
        & $python @pythonArgs -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)'
        if ($LASTEXITCODE -ne 0) { throw 'Python 3.10+ is required; Python 3.12 is recommended.' }
        & $python @pythonArgs -m venv (Join-Path $Backend '.venv')
        if ($LASTEXITCODE -ne 0) { throw 'Could not create backend/.venv.' }
    }
    & $LocalPython -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)'
    if ($LASTEXITCODE -ne 0) { throw 'backend/.venv requires Python 3.10+.' }

    Push-Location $Root
    try {
        & $LocalPython 'scripts/check-backend-dependencies.py' --quiet
        $missingDependencies = $LASTEXITCODE -ne 0
        if ($Check -and $missingDependencies) { throw 'Backend dependencies need installation. Run with -InstallDependencies.' }
        if ($InstallDependencies -or $missingDependencies) {
            & $LocalPython -m pip install -r requirements.txt
            if ($LASTEXITCODE -ne 0) { throw 'Backend dependency installation failed.' }
        }
        & $LocalPython -m pip check
        if ($LASTEXITCODE -ne 0) { throw 'Backend dependency constraints are inconsistent.' }
        $vite = Join-Path $Root 'node_modules\vite\bin\vite.js'
        $nodeModulesMissing = -not (Test-Path -LiteralPath $vite)
        if (-not $nodeModulesMissing) {
            & $npm ls --depth=0 --json 1>$null 2>$null
            $nodeModulesMissing = $LASTEXITCODE -ne 0
        }
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        try {
            $lockBytes = [System.IO.File]::ReadAllBytes((Join-Path $Root 'package-lock.json'))
            $lockHash = [System.BitConverter]::ToString($sha256.ComputeHash($lockBytes)).Replace('-', '')
        } finally { $sha256.Dispose() }
        $stampPath = Join-Path $Root 'node_modules\.aegis-package-lock.sha256'
        $lockChanged = (Test-Path -LiteralPath $stampPath) -and ((Get-Content -LiteralPath $stampPath -Raw).Trim() -ne $lockHash)
        if ($Check -and ($nodeModulesMissing -or $lockChanged)) { throw 'Frontend dependencies need installation. Run with -InstallDependencies.' }
        if (-not $Check -and ($InstallDependencies -or $nodeModulesMissing -or $lockChanged)) {
            & $npm ci
            if ($LASTEXITCODE -ne 0) { throw 'Frontend dependency installation failed.' }
            Set-Content -LiteralPath $stampPath -Value $lockHash -Encoding ASCII
        }
    } finally { Pop-Location }

    Write-Host 'Aegis Threat 2.3.2 - dependencies ready.'
    if ($Check) { Write-Host 'Check passed; no servers were started.'; exit 0 }
    Test-FreePort $BackendPort
    Test-FreePort $FrontendPort
    $env:AEGIS_THREAT_ALLOW_MODEL_DOWNLOAD = '0'
    $env:VITE_API_URL = "http://127.0.0.1:$BackendPort"
    $env:VITE_WS_URL = "ws://127.0.0.1:$BackendPort"
    $apiArguments = @('-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', "$BackendPort")
    $envFile = Join-Path $Root '.env'
    if (Test-Path -LiteralPath $envFile) { $apiArguments += @('--env-file', ('"' + $envFile + '"')) }
    $api = Start-ServiceProcess 'backend' $LocalPython $apiArguments $Backend
    $Started += $api.record
    Wait-Service $api.process "http://127.0.0.1:$BackendPort/health" $api.log -Api
    $ui = Start-ServiceProcess 'frontend' $node @(('"' + $vite + '"'), '--host', '127.0.0.1', '--port', "$FrontendPort", '--strictPort') $Root
    $Started += $ui.record
    Wait-Service $ui.process "http://127.0.0.1:$FrontendPort/" $ui.log
    New-Item -ItemType Directory -Path (Split-Path $StatePath) -Force | Out-Null
    @{ processes = $Started; backendPort = $BackendPort; frontendPort = $FrontendPort } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $StatePath -Encoding UTF8
    Write-Host "Frontend: http://localhost:$FrontendPort"
    Write-Host "Backend:  http://127.0.0.1:$BackendPort"
    Write-Host "API docs: http://127.0.0.1:$BackendPort/docs"
    Write-Host "Logs:     $(Join-Path $Root 'logs')"
    Write-Host 'Stop with .\start.ps1 -Stop or start.bat --stop.'
    if (-not $NoBrowser) { Start-Process "http://localhost:$FrontendPort" }
} catch {
    foreach ($record in $Started) { Stop-OwnedProcess $record }
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
