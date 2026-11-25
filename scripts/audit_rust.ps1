[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$LockFile,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [Parameter(Mandatory)][ValidateSet('report','block')][string]$Policy
)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$out = [IO.Path]::GetFullPath($OutputDirectory)
$lock = (Get-Item -LiteralPath $LockFile -ErrorAction Stop).FullName
New-Item -ItemType Directory -Path $out -Force | Out-Null
$toolRoot = Join-Path $env:RUNNER_TEMP ('caesium-rust-audit-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $toolRoot -Force | Out-Null
Push-Location $toolRoot
try {
  # Official RustSec release asset; digest recorded from GitHub release metadata.
  $url = 'https://github.com/rustsec/rustsec/releases/download/cargo-audit/v0.23.0/cargo-audit-x86_64-pc-windows-msvc-v0.23.0.zip'
  $expectedDigest = 'aafeb61206730029601a72e669a12231f8674427e6248d02f6cb382cb36d56b4'
  $archive = Join-Path $toolRoot 'cargo-audit.zip'
  Invoke-WebRequest -Uri $url -OutFile $archive -MaximumRetryCount 3 -RetryIntervalSec 2 -TimeoutSec 120
  $actualDigest = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
  [ordered]@{url=$url;expected_sha256=$expectedDigest;actual_sha256=$actualDigest} | ConvertTo-Json | Set-Content "$out/cargo-audit-download.json"
  if ($actualDigest -ne $expectedDigest) { throw 'RustSec tool download hash mismatch' }
  Expand-Archive -LiteralPath $archive -DestinationPath "$toolRoot/extracted"
  $tools = @(Get-ChildItem -LiteralPath "$toolRoot/extracted" -Recurse -File -Filter 'cargo-audit.exe')
  if ($tools.Count -ne 1) { throw 'Expected exactly one cargo-audit executable' }
  $audit = $tools[0].FullName
  $actualVersion = (& $audit --version | Out-String).Trim()
  $actualVersion | Set-Content "$out/cargo-audit-version.txt"
  if ($LASTEXITCODE -ne 0 -or $actualVersion -notmatch '(?<![0-9.])0\.23\.0(?![0-9.])') { throw 'Unexpected cargo-audit version' }
  & $audit audit --json --file $lock 1> "$out/cargo-audit.json" 2> "$out/cargo-audit-stderr.log"
  $code = $LASTEXITCODE
  $report = Get-Content "$out/cargo-audit.json" -Raw | ConvertFrom-Json -ErrorAction Stop
  if ($null -eq $report.vulnerabilities.count -or $null -eq $report.vulnerabilities.found -or $code -notin @(0,1)) { throw 'RustSec audit unavailable or invalid' }
  if ($null -eq $report.settings -or $null -eq $report.vulnerabilities.list -or $null -eq $report.settings.ignore -or $null -eq $report.settings.target_os -or $null -eq $report.settings.target_arch) { throw 'Incomplete RustSec audit schema' }
  if ($report.database.'last-commit' -notmatch '^[0-9a-f]{40}$' -or !$report.database.'last-updated') { throw 'RustSec advisory database identity missing' }
  if (@($report.settings.ignore).Count -gt 0 -or @($report.settings.target_os).Count -gt 0 -or @($report.settings.target_arch).Count -gt 0) { throw 'Unexpected RustSec advisory exclusions' }
  $count = [int]$report.vulnerabilities.count
  if ($count -ne @($report.vulnerabilities.list).Count) { throw 'RustSec advisory count mismatch' }
  if (($count -gt 0) -ne [bool]$report.vulnerabilities.found -or ($count -gt 0 -and $code -ne 1) -or ($count -eq 0 -and $code -ne 0)) { throw 'RustSec audit status inconsistent' }
  $warnings = 0
  if ($report.warnings) { foreach ($p in $report.warnings.PSObject.Properties) { if ($p.Value -is [array]) { $warnings += $p.Value.Count } } }
  [ordered]@{policy=$Policy;vulnerabilities=$count;informational_warnings=$warnings;exit_code=$code} | ConvertTo-Json | Set-Content "$out/cargo-audit-status.json"
  "### RustSec (entire Cargo.lock)`n- Known vulnerabilities: $count`n- Informational warnings: $warnings`n- Policy: $Policy" | Add-Content $env:GITHUB_STEP_SUMMARY
  if ($count -gt 0) {
    if ($Policy -eq 'block') { throw 'RustSec vulnerabilities found; installer blocked' }
    Write-Warning 'RustSec vulnerabilities reported; inspect diagnostics before installation.'
  }
} finally {
  Pop-Location
  Remove-Item -LiteralPath $toolRoot -Recurse -Force -ErrorAction SilentlyContinue
}

