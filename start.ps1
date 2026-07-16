$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

function Resolve-BasePython {
    if ($env:PROGROK_PYTHON -and (Test-Path -LiteralPath $env:PROGROK_PYTHON)) {
        return $env:PROGROK_PYTHON
    }
    foreach ($candidate in @("python", "python3")) {
        $command = Get-Command $candidate -ErrorAction SilentlyContinue
        if ($command) {
            try {
                $version = & $command.Source -c "import sys; print(sys.version_info.major * 100 + sys.version_info.minor)"
                if ([int]$version -ge 310) { return $command.Source }
            } catch {}
        }
    }
    $launcher = Get-Command "py" -ErrorAction SilentlyContinue
    if ($launcher) {
        foreach ($minor in @("3.13", "3.12", "3.11", "3.10")) {
            try {
                $resolved = & $launcher.Source "-$minor" -c "import sys; print(sys.executable)" 2>$null
                if ($LASTEXITCODE -eq 0 -and $resolved -and (Test-Path -LiteralPath $resolved.Trim())) {
                    return $resolved.Trim()
                }
            } catch {}
        }
    }
    throw "Python 3.10 or newer was not found. Run install_and_start.cmd first."
}

function Ensure-Venv([string]$Path, [string]$Requirements, [string]$BasePython) {
    $Python = Join-Path $Path "Scripts\python.exe"
    if (-not (Test-Path -LiteralPath $Python)) {
        & $BasePython -m venv $Path | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "Failed to create venv: $Path" }
    }
    & $Python -m pip install -q --disable-pip-version-check -r $Requirements | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Failed to install: $Requirements" }
    return $Python
}

$BasePython = Resolve-BasePython
$MainPython = Ensure-Venv (Join-Path $Root ".venv") (Join-Path $Root "requirements.txt") $BasePython
$SolverRoot = Join-Path $Root "turnstile-solver"
$SolverPython = Ensure-Venv (Join-Path $SolverRoot ".venv") (Join-Path $SolverRoot "requirements.txt") $BasePython

$SolverUp = $false
try {
    $health = Invoke-RestMethod -Uri "http://127.0.0.1:5072/health" -TimeoutSec 2
    $SolverUp = $null -ne $health
} catch {}

if (-not $SolverUp) {
    & $SolverPython -m camoufox fetch
    $solver = Start-Process -FilePath $SolverPython -ArgumentList @(
        "api_solver.py", "--browser_type", "camoufox", "--thread", "1",
        "--host", "127.0.0.1", "--port", "5072"
    ) -WorkingDirectory $SolverRoot -WindowStyle Hidden -PassThru
    $solver.Id | Set-Content -LiteralPath (Join-Path $Root ".solver.pid") -Encoding ascii
    Write-Host "Turnstile Solver started: PID=$($solver.Id), port=5072"
} else {
    Write-Host "Turnstile Solver already available on port 5072"
}

$AppUp = $false
try {
    $health = Invoke-RestMethod -Uri "http://127.0.0.1:3080/api/health" -TimeoutSec 2
    $AppUp = $health.service -eq "progrok-registration"
} catch {}

if (-not $AppUp) {
    $LogDir = Join-Path $Root "logs"
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
    $app = Start-Process -FilePath $MainPython -ArgumentList @(
        "-m", "uvicorn", "app:app", "--host", "127.0.0.1", "--port", "3080", "--workers", "1"
    ) -WorkingDirectory $Root -WindowStyle Hidden -RedirectStandardOutput (Join-Path $LogDir "app.out.log") -RedirectStandardError (Join-Path $LogDir "app.err.log") -PassThru
    $app.Id | Set-Content -LiteralPath (Join-Path $Root ".app.pid") -Encoding ascii
    Write-Host "ProGrok started: PID=$($app.Id), http://127.0.0.1:3080"
} else {
    Write-Host "ProGrok already available: http://127.0.0.1:3080"
}
