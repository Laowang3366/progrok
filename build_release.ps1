$ErrorActionPreference = "Stop"
$Root = [IO.Path]::GetFullPath((Split-Path -Parent $MyInvocation.MyCommand.Path))
$ReleaseRoot = [IO.Path]::GetFullPath((Join-Path $Root "release"))
$Stage = [IO.Path]::GetFullPath((Join-Path $ReleaseRoot "progrok-windows"))
$Zip = Join-Path $ReleaseRoot ("progrok-windows-{0}.zip" -f (Get-Date -Format "yyyyMMdd"))

function Assert-ChildPath([string]$Path, [string]$Parent) {
    $prefix = $Parent.TrimEnd('\') + '\'
    if (-not $Path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Unsafe release path: $Path"
    }
}

Assert-ChildPath $Stage $ReleaseRoot
New-Item -ItemType Directory -Force -Path $ReleaseRoot | Out-Null
if (Test-Path -LiteralPath $Stage) {
    Remove-Item -LiteralPath $Stage -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $Stage | Out-Null

$TopFiles = @(
    ".env.example", ".gitignore", "README.md", "requirements.txt",
    "account_pipeline.py", "accounts.py", "app.py", "config.py",
    "export_formats.py", "grok_build_adapter.py", "model_health.py",
    "moemail.py", "proxy_pool.py", "sso_to_auth_json.py",
    "install_and_start.cmd", "install_and_start.ps1",
    "start.cmd", "start.ps1", "stop.cmd", "stop.ps1",
    "build_release.ps1"
)

foreach ($name in $TopFiles) {
    $source = Join-Path $Root $name
    if (-not (Test-Path -LiteralPath $source)) { throw "Missing release file: $name" }
    Copy-Item -LiteralPath $source -Destination (Join-Path $Stage $name)
}

$DirectoryFiles = [ordered]@{
    "static" = @("app.js", "index.html", "style.css")
    "turnstile-solver" = @("api_solver.py", "browser_configs.py", "db_results.py", "requirements.txt")
    "grok-build-auth" = @("LICENSE", "NOTICE", "requirements.txt", "run.py")
    "grok-build-auth\alias_mail" = @("alias_mail.py")
    "grok-build-auth\xconsole_client" = @(
        "__init__.py", "client.py", "config.py", "fingerprint.py", "grpcweb.py",
        "mailbox.py", "models.py", "oauth_protocol.py", "solver.py", "sso.py",
        "tempmail_transport.py", "xai_oauth.py"
    )
}

foreach ($entry in $DirectoryFiles.GetEnumerator()) {
    $destination = Join-Path $Stage $entry.Key
    New-Item -ItemType Directory -Force -Path $destination | Out-Null
    foreach ($name in $entry.Value) {
        $source = Join-Path (Join-Path $Root $entry.Key) $name
        if (-not (Test-Path -LiteralPath $source)) { throw "Missing release file: $($entry.Key)\$name" }
        Copy-Item -LiteralPath $source -Destination (Join-Path $destination $name)
    }
}

$ForbiddenFiles = @(Get-ChildItem -LiteralPath $Stage -File -Recurse | Where-Object {
    $_.Name -match '(?i)^(config\.json|\.env)$' -or
    $_.Name -match '(?i)(credential|secret)' -or
    $_.FullName -match '(?i)\\(data|logs|output|\.venv|__pycache__)\\'
})
if ($ForbiddenFiles.Count -gt 0) {
    throw "Release contains forbidden local files."
}

$TextFiles = @(Get-ChildItem -LiteralPath $Stage -File -Recurse | Where-Object {
    $_.Extension -in @('.py', '.js', '.html', '.css', '.md', '.ps1', '.cmd', '.txt', '.json', '.example')
})
$LocalConfig = Join-Path $Root "config.json"
if (Test-Path -LiteralPath $LocalConfig) {
    $SensitiveKeys = @(
        "mail_api_key", "mail_base_url", "mail_domain", "yescaptcha_key",
        "proxy", "proxy_username", "proxy_password", "cpa_base_url",
        "cpa_management_key", "sub2api_base_url", "sub2api_admin_email",
        "sub2api_admin_password", "sub2api_api_key"
    )
    $LocalValues = Get-Content -LiteralPath $LocalConfig -Raw | ConvertFrom-Json
    foreach ($key in $SensitiveKeys) {
        $value = [string]$LocalValues.$key
        if (-not $value -or $value.Length -lt 5) { continue }
        if ($key -eq "mail_base_url" -and $value -eq "https://maliapi.215.im") { continue }
        if ($key -eq "mail_domain" -and -not $value.Trim()) { continue }
        if (Select-String -LiteralPath $TextFiles.FullName -SimpleMatch -Pattern $value -Quiet) {
            throw "Release security scan found a value from the local private configuration."
        }
    }
}

if (Test-Path -LiteralPath $Zip) { Remove-Item -LiteralPath $Zip -Force }
Compress-Archive -LiteralPath $Stage -DestinationPath $Zip -CompressionLevel Optimal
Remove-Item -LiteralPath $Stage -Recurse -Force
$Hash = (Get-FileHash -LiteralPath $Zip -Algorithm SHA256).Hash
Write-Host "Release created: $Zip"
Write-Host "SHA256: $Hash"
