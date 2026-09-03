[CmdletBinding()]
param(
    [string]$RepositoryRawBaseUrl = 'https://raw.githubusercontent.com/KobiReline/Windows-BitLocker-SecureBoot-Compliance-Enforcement/main',
    [string]$StagingDirectory = 'C:\ProgramData\SecurityFeatureMonitor\Staging',
    [string]$ManifestName = 'manifest.json'
)

$ErrorActionPreference = 'Stop'
$resultPath = 'C:\ProgramData\SecurityFeatureMonitor\RemediationResult.json'

function Assert-SystemAccount {
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18') { return }
    throw 'This remediation must run as NT AUTHORITY\SYSTEM.'
}

function Test-HashMatch {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Sha256)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -eq $Sha256
}

function Save-VerifiedRepositoryFile {
    param(
        [Parameter(Mandatory)][string]$RelativePath,
        [Parameter(Mandatory)][string]$ExpectedSha256
    )
    $destination = Join-Path $StagingDirectory $RelativePath
    $parent = Split-Path -Path $destination -Parent
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
    $url = "$($RepositoryRawBaseUrl.TrimEnd('/'))/$($RelativePath.Replace('\', '/'))"
    $temporaryPath = "$destination.download"
    try {
        Invoke-WebRequest -Uri $url -OutFile $temporaryPath -UseBasicParsing -ErrorAction Stop
        if (-not (Test-HashMatch -Path $temporaryPath -Sha256 $ExpectedSha256)) { throw "SHA-256 mismatch: $RelativePath" }
        Move-Item -LiteralPath $temporaryPath -Destination $destination -Force
    }
    finally {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
    }
}

function Get-InstalledTargetPath {
    param([Parameter(Mandatory)]$File)
    $installDirectory = 'C:\ProgramData\SecurityFeatureMonitor'
    if ([string]$File.Target -eq 'Install') { return Join-Path $installDirectory ([string]$File.Destination) }
    if ([string]$File.Target -eq 'Media') { return Join-Path (Join-Path $installDirectory 'media') ([string]$File.Destination) }
    if ([string]$File.Target -eq 'Staging') { return Join-Path (Join-Path $installDirectory 'Staging') ([string]$File.Destination) }
    return $null
}

function Assert-InstalledState {
    param([Parameter(Mandatory)]$Manifest)

    foreach ($file in $Manifest.Files) {
        $targetPath = Get-InstalledTargetPath -File $file
        if ($null -eq $targetPath) { continue }
        if (Test-HashMatch -Path $targetPath -Sha256 ([string]$file.Sha256)) { continue }
        throw "Post-install hash verification failed: $targetPath"
    }

    $backend = Get-ScheduledTask -TaskName 'Intune-SecurityFeatureMonitor' -ErrorAction SilentlyContinue
    if ($null -eq $backend -or [string]$backend.State -eq 'Disabled') { throw 'Post-install backend task verification failed.' }
    if ([string]$backend.Principal.UserId -notin @('SYSTEM', 'NT AUTHORITY\SYSTEM')) { throw 'Post-install backend principal verification failed.' }
    if ([string]$backend.Principal.RunLevel -ne 'Highest') { throw 'Post-install backend run-level verification failed.' }
    if ([string]$backend.Actions.Arguments -notmatch 'SecurityFeatureMonitor-Backend\.cached\.ps1' -or [string]$backend.Actions.Arguments -notmatch 'InstallScheduledTask') { throw 'Post-install backend action verification failed.' }
    if ([string]$backend.Settings.MultipleInstances -ne 'StopExisting') { throw 'Post-install backend instance policy verification failed.' }

    $logonTriggers = @($backend.Triggers | Where-Object { $_.CimClass.CimClassName -match 'LogonTrigger' })
    $timeTriggers = @($backend.Triggers | Where-Object { $_.CimClass.CimClassName -notmatch 'LogonTrigger' })
    if ($logonTriggers.Count -ne 1) { throw 'Post-install backend logon trigger verification failed.' }
    if (@($backend.Triggers | Where-Object { -not [bool]$_.Enabled }).Count -gt 0) { throw 'Post-install backend trigger is disabled.' }

    $statePath = 'C:\ProgramData\SecurityFeatureMonitor\State\State.json'
    if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) { throw 'Post-install state file is missing.' }
    $zone = [string](Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json -ErrorAction Stop).Zone
    if ($zone -in @('Healthy', 'Excluded')) {
        $dailyTriggers = @($timeTriggers | Where-Object { $_.CimClass.CimClassName -match 'DailyTrigger' })
        if ($timeTriggers.Count -ne 1 -or $dailyTriggers.Count -ne 1) { throw 'Post-install backend daily schedule verification failed.' }
    }
    else {
        $expectedInterval = if ($zone -eq 'Critical') { 'PT5M' } else { 'PT1H' }
        $matchingTriggers = @($timeTriggers | Where-Object { [string]$_.Repetition.Interval -eq $expectedInterval })
        if ($timeTriggers.Count -ne 1 -or $matchingTriggers.Count -ne 1) { throw "Post-install backend interval verification failed: $expectedInterval" }
    }

    $ui = Get-ScheduledTask -TaskName 'SecurityFeatureMonitor-UI' -ErrorAction SilentlyContinue
    if ($null -eq $ui -or [string]$ui.State -eq 'Disabled') { throw 'Post-install UI task verification failed.' }
    $uiIdentity = if ([string]::IsNullOrWhiteSpace([string]$ui.Principal.GroupId)) { [string]$ui.Principal.UserId } else { [string]$ui.Principal.GroupId }
    if ($uiIdentity -notmatch '(?i)^(BUILTIN\\Users|Users|S-1-5-32-545)$') { throw 'Post-install UI principal verification failed.' }
    if ([string]$ui.Principal.RunLevel -ne 'Limited') { throw 'Post-install UI run-level verification failed.' }
    if ([string]$ui.Actions.Execute -notmatch '(?i)wscript\.exe$' -or [string]$ui.Actions.Arguments -notmatch 'SecurityFeatureMonitor-UI-Launcher\.vbs') { throw 'Post-install UI action verification failed.' }
    if ([string]$ui.Settings.MultipleInstances -ne 'StopExisting') { throw 'Post-install UI instance policy verification failed.' }
    if (@($ui.Triggers).Count -ne 0) { throw 'Post-install UI trigger verification failed.' }
}

function Write-RemediationResult {
    param([Parameter(Mandatory)][hashtable]$Result)
    $parent = Split-Path -Path $resultPath -Parent
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
    $Result | ConvertTo-Json -Compress -Depth 5 | Set-Content -LiteralPath $resultPath -Encoding UTF8 -Force
}

Assert-SystemAccount
$manifestPath = Join-Path $StagingDirectory $ManifestName
$manifestUrl = "$($RepositoryRawBaseUrl.TrimEnd('/'))/$ManifestName"
if (-not (Test-Path -LiteralPath $StagingDirectory -PathType Container)) { New-Item -Path $StagingDirectory -ItemType Directory -Force | Out-Null }

try {
    Invoke-WebRequest -Uri $manifestUrl -OutFile $manifestPath -UseBasicParsing -ErrorAction Stop
    $manifest = Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    foreach ($file in $manifest.Files) {
        Save-VerifiedRepositoryFile -RelativePath ([string]$file.Source) -ExpectedSha256 ([string]$file.Sha256)
    }
    $installer = Join-Path $StagingDirectory 'Install-SecurityFeatureMonitor.ps1'
    $installerArguments = @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', $installer,
        '-SourceDirectory', $StagingDirectory,
        '-Version', [string]$manifest.Version,
        '-RecoveryMode'
    )
    $installerProcess = Start-Process -FilePath 'powershell.exe' -ArgumentList $installerArguments -WindowStyle Hidden -Wait -PassThru
    if ($installerProcess.ExitCode -ne 0) { throw "Installer exit code: $($installerProcess.ExitCode)" }
    Assert-InstalledState -Manifest $manifest

    Write-RemediationResult -Result @{
        Schema = 1
        Utc = (Get-Date).ToUniversalTime().ToString('o')
        Status = 'RepairCompleted'
        Version = [string]$manifest.Version
    }
    Write-Output (@{ Schema = 1; Status = 'RepairCompleted'; Version = [string]$manifest.Version } | ConvertTo-Json -Compress)
    exit 0
}
catch {
    Write-RemediationResult -Result @{
        Schema = 1
        Utc = (Get-Date).ToUniversalTime().ToString('o')
        Status = 'RepairFailed'
        Error = $_.Exception.Message
    }
    Write-Error $_.Exception.Message
    exit 1
}
