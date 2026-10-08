param(
    [int]$MaxLines = 2000,
    [int]$RedLine = 1500
)

$ErrorActionPreference = "Stop"
$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$redline = @(
    "crates\pangu-boundary\src\sandbox.rs",
    "crates\pangu-agent\src\lib.rs"
)

Get-ChildItem -Path (Join-Path $root "crates") -Recurse -Filter *.rs | ForEach-Object {
    $count = @(Get-Content -LiteralPath $_.FullName).Count
    $relative = $_.FullName.Substring($root.Length).TrimStart("\", "/")
    $limit = if ($redline -contains $relative) { $RedLine } else { $MaxLines }
    if ($count -gt $limit) {
        Write-Warning "$relative has $count lines; threshold is $limit (warning only)"
    }
}

exit 0
