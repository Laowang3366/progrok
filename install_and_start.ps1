$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Test-Python([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $false }
    try {
        $version = & $Path -c "import sys; print(sys.version_info.major * 100 + sys.version_info.minor)" 2>$null
        return $LASTEXITCODE -eq 0 -and [int]$version -ge 310
    } catch {
        return $false
    }
}

function Find-Python {
    if (Test-Python $env:PROGROK_PYTHON) { return $env:PROGROK_PYTHON }
    foreach ($name in @("python", "python3")) {
        $command = Get-Command $name -ErrorAction SilentlyContinue
        if ($command -and (Test-Python $command.Source)) { return $command.Source }
    }
    $launcher = Get-Command "py" -ErrorAction SilentlyContinue
    if ($launcher) {
        foreach ($minor in @("3.14", "3.13", "3.12", "3.11", "3.10")) {
            try {
                $path = & $launcher.Source "-$minor" -c "import sys; print(sys.executable)" 2>$null
                if ($LASTEXITCODE -eq 0 -and (Test-Python $path.Trim())) { return $path.Trim() }
            } catch {}
        }
    }
    foreach ($path in @(
        "$env:LocalAppData\Programs\Python\Python312\python.exe",
        "$env:ProgramFiles\Python312\python.exe"
    )) {
        if (Test-Python $path) { return $path }
    }
    return $null
}

$Python = Find-Python
if (-not $Python) {
    Write-Host "未检测到 Python 3.10+，正在安装 Python 3.12..."
    $winget = Get-Command "winget" -ErrorAction SilentlyContinue
    if ($winget) {
        & $winget.Source install --id Python.Python.3.12 --exact --scope user --silent --accept-package-agreements --accept-source-agreements
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "winget 安装失败，将尝试 Python 官方安装程序。"
        }
    }
    $Python = Find-Python
    if (-not $Python) {
        $Installer = Join-Path $env:TEMP "python-3.12.10-amd64.exe"
        $Url = "https://www.python.org/ftp/python/3.12.10/python-3.12.10-amd64.exe"
        Write-Host "正在从 Python 官网下载安装程序..."
        Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $Installer
        $process = Start-Process -FilePath $Installer -ArgumentList @(
            "/quiet", "InstallAllUsers=0", "PrependPath=1", "Include_pip=1",
            "Include_launcher=1", "Include_test=0", "Shortcuts=0"
        ) -Wait -PassThru
        if ($process.ExitCode -ne 0) {
            throw "Python 安装失败，退出代码：$($process.ExitCode)"
        }
        $Python = Find-Python
    }
}

if (-not $Python) {
    throw "Python 已执行安装但仍无法定位，请重新打开终端后再次运行。"
}

$env:PROGROK_PYTHON = $Python
Write-Host "使用 Python：$Python"
& (Join-Path $Root "start.ps1")
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host ""
Write-Host "启动完成，请访问：http://127.0.0.1:3080"
