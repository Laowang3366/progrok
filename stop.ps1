$Root = Split-Path -Parent $MyInvocation.MyCommand.Path

function Stop-ProcessTree([int]$ProcessId) {
    $children = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.ParentProcessId -eq $ProcessId } |
        Select-Object -ExpandProperty ProcessId)
    foreach ($child in $children) {
        Stop-ProcessTree ([int]$child)
    }
    Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue
}

foreach ($name in @(".app.pid", ".solver.pid")) {
    $path = Join-Path $Root $name
    if (Test-Path -LiteralPath $path) {
        $raw = (Get-Content -LiteralPath $path -Raw).Trim()
        if ($raw -match '^\d+$') {
            Stop-ProcessTree ([int]$raw)
        }
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    }
}
Write-Host "Stopped ProGrok background processes recorded by this project."
