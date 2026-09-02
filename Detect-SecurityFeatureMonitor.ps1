[CmdletBinding()]
param(
    [string]$RepositoryRawBaseUrl = 'https://raw.githubusercontent.com/KobiReline/Windows-BitLocker-SecureBoot-Compliance-Enforcement/main',
    [string]$InstallDirectory = 'C:\ProgramData\SecurityFeatureMonitor',
    [string]$StateDirectory = 'C:\ProgramData\SecurityFeatureMonitor\State',
    [string]$ManifestName = 'manifest.json'
)

$ErrorActionPreference = 'Stop'
$remediationResultPath = Join-Path $InstallDirectory 'RemediationResult.json'

function Add-Issue {
    param([Parameter(Mandatory)][Collections.Generic.List[string]]$Issues, [Parameter(Mandatory)][string]$Value)
    if ($Issues.Contains($Value)) { return }
    $Issues.Add($Value)
}

function Get-TargetPath {
    param([Parameter(Mandatory)]$File)
    if ([string]$File.Target -eq 'Install') { return Join-Path $InstallDirectory ([string]$File.Destination) }
    if ([string]$File.Target -eq 'Media') { return Join-Path (Join-Path $InstallDirectory 'media') ([string]$File.Destination) }
    if ([string]$File.Target -eq 'Staging') { return Join-Path (Join-Path $InstallDirectory 'Staging') ([string]$File.Destination) }
    return $null
}

function Test-TaskDefinitions {
    param([Parameter(Mandatory)][Collections.Generic.List[string]]$Issues)
    $backend = Get-ScheduledTask -TaskName 'Intune-SecurityFeatureMonitor' -ErrorAction SilentlyContinue
    if ($null -eq $backend) { Add-Issue -Issues $Issues -Value 'MissingTask:Backend' }
    if ($null -ne $backend -and [string]$backend.Principal.UserId -notin @('SYSTEM', 'NT AUTHORITY\SYSTEM')) { Add-Issue -Issues $Issues -Value 'InvalidTaskPrincipal:Backend' }
    if ($null -ne $backend -and [string]$backend.Actions.Arguments -notmatch 'SecurityFeatureMonitor-Backend\.cached\.ps1') { Add-Issue -Issues $Issues -Value 'InvalidTaskAction:Backend' }

    $ui = Get-ScheduledTask -TaskName 'SecurityFeatureMonitor-UI' -ErrorAction SilentlyContinue
    if ($null -eq $ui) { Add-Issue -Issues $Issues -Value 'MissingTask:UI' }
    $uiIdentity = if ($null -eq $ui) { '' } elseif (-not [string]::IsNullOrWhiteSpace([string]$ui.Principal.GroupId)) { [string]$ui.Principal.GroupId } else { [string]$ui.Principal.UserId }
    if ($null -ne $ui -and $uiIdentity -notmatch '(?i)^(BUILTIN\\Users|Users|S-1-5-32-545)$') { Add-Issue -Issues $Issues -Value 'InvalidTaskPrincipal:UI' }
    if ($null -ne $ui -and ([string]$ui.Actions.Execute -notmatch '(?i)wscript\.exe$' -or [string]$ui.Actions.Arguments -notmatch 'SecurityFeatureMonitor-UI-Launcher\.vbs')) { Add-Issue -Issues $Issues -Value 'InvalidTaskAction:UI' }
}

function Get-RemediationResult {
    if (-not (Test-Path -LiteralPath $remediationResultPath -PathType Leaf)) { return $null }
    try { return Get-Content -LiteralPath $remediationResultPath -Raw | ConvertFrom-Json }
    catch { return [PSCustomObject]@{ Status = 'UnreadableRemediationResult' } }
    finally { Remove-Item -LiteralPath $remediationResultPath -Force -ErrorAction SilentlyContinue }
}

function Write-DetectionResult {
    param(
        [Parameter(Mandatory)][string]$Status,
        [Parameter(Mandatory)][Collections.Generic.List[string]]$Issues,
        [AllowNull()]$Manifest,
        [AllowNull()]$Remediation
    )
    $result = [ordered]@{
        Schema = 1
        Utc = (Get-Date).ToUniversalTime().ToString('o')
        Status = $Status
        Version = if ($null -eq $Manifest) { $null } else { [string]$Manifest.Version }
        Issues = @($Issues)
    }
    if ($null -ne $Remediation) { $result.Remediation = [string]$Remediation.Status }
    Write-Output ($result | ConvertTo-Json -Compress -Depth 5)
}

$issues = [Collections.Generic.List[string]]::new()
$manifest = $null
try {
    $manifest = Invoke-RestMethod -Uri "$($RepositoryRawBaseUrl.TrimEnd('/'))/$ManifestName" -UseBasicParsing -ErrorAction Stop
}
catch {
    Add-Issue -Issues $issues -Value 'ManifestUnavailable'
}

$requiredFallback = @(
    (Join-Path $InstallDirectory 'SecurityFeatureMonitor-Backend.cached.ps1'),
    (Join-Path $InstallDirectory 'Staging\Install-SecurityFeatureMonitor.ps1'),
    (Join-Path $InstallDirectory 'SecurityFeatureMonitor-UI.ps1'),
    (Join-Path $InstallDirectory 'SecurityFeatureMonitor-UI-Launcher.vbs'),
    (Join-Path $InstallDirectory 'Set-SecurityFeatureMonitorTestMode.ps1'),
    (Join-Path $InstallDirectory 'Version.txt'),
    (Join-Path $InstallDirectory 'manifest.json'),
    (Join-Path $InstallDirectory 'media\bip.wav'),
    (Join-Path $InstallDirectory 'media\alarm.mp3')
)
foreach ($path in $requiredFallback) {
    if (Test-Path -LiteralPath $path -PathType Leaf) { continue }
    Add-Issue -Issues $issues -Value "MissingFile:$([IO.Path]::GetFileName($path))"
}

if ($null -ne $manifest) {
    foreach ($file in $manifest.Files) {
        $targetPath = Get-TargetPath -File $file
        if ($null -eq $targetPath) { continue }
        if (-not (Test-Path -LiteralPath $targetPath -PathType Leaf)) { continue }
        if ((Get-FileHash -LiteralPath $targetPath -Algorithm SHA256).Hash -eq [string]$file.Sha256) { continue }
        Add-Issue -Issues $issues -Value "HashMismatch:$([string]$file.Destination)"
    }
}

Test-TaskDefinitions -Issues $issues
$remediation = Get-RemediationResult
$actionableIssues = @($issues | Where-Object { $_ -ne 'ManifestUnavailable' })

if ($actionableIssues.Count -gt 0) {
    $status = if ($null -ne $remediation -and [string]$remediation.Status -eq 'RepairFailed') { 'RepairFailed' } else { 'IssueDetected' }
    Write-DetectionResult -Status $status -Issues $issues -Manifest $manifest -Remediation $remediation
    exit 1
}

$status = if ($null -ne $remediation -and [string]$remediation.Status -eq 'RepairCompleted') { 'RepairVerified' } elseif ($issues.Contains('ManifestUnavailable')) { 'HealthyOffline' } else { 'Healthy' }
Write-DetectionResult -Status $status -Issues $issues -Manifest $manifest -Remediation $remediation
exit 0
