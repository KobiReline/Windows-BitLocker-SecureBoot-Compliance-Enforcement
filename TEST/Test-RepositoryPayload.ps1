[CmdletBinding()]
param([string]$RepositoryPath = (Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference = 'Stop'
$failed = $false
Get-ChildItem -LiteralPath $RepositoryPath -Filter '*.ps1' -Recurse -File | ForEach-Object {
    $tokens = $null
    $errors = $null
    [Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$errors) | Out-Null
    if ($errors.Count) {
        $failed = $true
        Write-Host "FAIL syntax: $($_.Name)" -ForegroundColor Red
        $errors | ForEach-Object { Write-Host "Line $($_.Extent.StartLineNumber): $($_.Message)" -ForegroundColor Red }
    } else { Write-Host "PASS syntax: $($_.Name)" -ForegroundColor Green }
    $bytes = [IO.File]::ReadAllBytes($_.FullName)
    $hasNonAscii = @($bytes | Where-Object { $_ -gt 127 }).Count -gt 0
    if ($hasNonAscii -and -not ($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191)) {
        $failed = $true
        Write-Host "FAIL encoding: $($_.Name) needs UTF-8 BOM for Windows PowerShell 5.1." -ForegroundColor Red
    }
}
$manifest = Get-Content -LiteralPath (Join-Path $RepositoryPath 'manifest.json') -Raw | ConvertFrom-Json
foreach ($entry in $manifest.Files) {
    $path = Join-Path $RepositoryPath $entry.Source
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $entry.Sha256) {
        $failed = $true
        Write-Host "FAIL hash: $($entry.Source)" -ForegroundColor Red
    } else { Write-Host "PASS hash: $($entry.Source)" -ForegroundColor Green }
}
if ($failed) { throw 'Repository payload validation failed.' }

# Load only pure decision functions, never the backend pipeline or scheduled tasks.
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $RepositoryPath 'SecurityFeatureMonitor-Backend.ps1'), [ref]$tokens, [ref]$errors)
foreach ($name in @('Get-ComplianceZone', 'Get-NextIntervalMinutes', 'Save-ComplianceState')) {
    $definitions = @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true))
    if ($definitions.Count -ne 1) { throw "Expected one function definition: $name" }
    . ([scriptblock]::Create($definitions[0].Extent.Text))
}
foreach ($case in @(@('Healthy',1440), @('Excluded',1440), @('Warning',60), @('Critical',5), @('EncryptionInProgress',60))) {
    if ((Get-NextIntervalMinutes -Zone $case[0]) -ne $case[1]) { throw "Wrong interval: $($case[0])" }
}
if ((Get-ComplianceZone -HoursElapsed 23.99) -ne 'Warning' -or (Get-ComplianceZone -HoursElapsed 24) -ne 'Critical') { throw 'Wrong 24-hour boundary.' }
function Save-StateAtomically { param($State) $script:CapturedState = $State }
function Set-ItemProperty { param($Path, $Name, $Value, [switch]$Force) }
$stamp = [datetime]::UtcNow.AddHours(-25)
Save-ComplianceState -Zone Critical -SecureBoot $false -BitLocker $false -FirstFailureTime $stamp
if (-not $script:CapturedState.PlayAudio -or -not $script:CapturedState.FirstFailureUtc) { throw 'Critical state serialization failed.' }
Save-ComplianceState -Zone EncryptionInProgress -SecureBoot $false -BitLocker $false -FirstFailureTime $stamp -SuppressAlerts $true
if ($script:CapturedState.PlayAudio -or -not $script:CapturedState.SuppressAlerts) { throw 'Encryption suppression failed.' }
Write-Host 'PASS cadence, 24-hour boundary, failure timestamp and encryption suppression.' -ForegroundColor Green
