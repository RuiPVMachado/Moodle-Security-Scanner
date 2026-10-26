param(
    [switch]$Safe,
    [switch]$Active,
    [switch]$Offline,
    [string]$Output = "",
    [string]$Target = "https://moodle.ensinolusofona.pt/login/index.php"
)

$ErrorActionPreference = "Stop"
$repo = $PSScriptRoot
$scanner = Join-Path $repo "moodle_scanner.py"
$target = $Target

if (-not (Test-Path -LiteralPath $scanner)) {
    Write-Error "moodle_scanner.py not found next to this script."
    exit 1
}

if ([string]::IsNullOrWhiteSpace($Output)) {
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $Output = Join-Path $repo "moodle-scan-ensinolusofona-$stamp.html"
}

$scanArgs = @(
    $scanner,
    "-t", $target,
    "-o", $Output
)

if ($Safe) {
    # Read-only option: version/CVE/MSA, passive checks, auth form and API.
    $scanArgs += @("--profile", "fast")
}
elseif ($Active) {
    # Only use this switch when you have written authorization.
    $scanArgs += @(
        "--profile", "auto",
        "--authorized",
        "--validate-cves",
        "--crawl-pages", "5"
    )
}
else {
    # Default: auto profile. The scanner asks once for authorization and
    # optionally for credentials, then writes the report below.
    $scanArgs += @("--profile", "auto")
}

if ($Offline) {
    $scanArgs += "--offline"
}

Write-Host ""
Write-Host "Target : $target"
Write-Host "Report : $Output"
Write-Host ""

& python @scanArgs
$code = $LASTEXITCODE

if (Test-Path -LiteralPath $Output) {
    Write-Host ""
    Write-Host "Report saved to: $Output"
}

exit $code
