[CmdletBinding()]
param(
    [string]$RootPath = 'C:\Windows\Logs\SecurityCheck',
    [string]$RegistryPath = 'HKLM:\SOFTWARE\CustomSecurityCheck',
    [string]$BackendTaskName = 'Intune-SecurityFeatureMonitor',
    [string]$RepositoryRawBaseUrl = 'https://raw.githubusercontent.com/KobiReline/Windows-BitLocker-SecureBoot-Compliance-Enforcement/main',
    [string]$BootstrapPath = 'C:\ProgramData\SecurityFeatureMonitor\Invoke-SecurityFeatureMonitor.ps1',
    [string]$TrustedSignerThumbprint = '0000000000000000000000000000000000000000',
    [switch]$InstallScheduledTask
)

$ErrorActionPreference = 'Stop'
$script:ExclusionKeys = @('ManualManagement', 'VIP_Device', 'AdminException', 'LabMachine')
$script:StatePath = Join-Path $RootPath 'State.json'
$script:FailureTimePath = Join-Path $RootPath 'FirstFailureTime.txt'
$script:BeepPath = Join-Path $RootPath 'bip.wav'
$script:AlarmPath = Join-Path $RootPath 'alarm.mp3'
$script:BeepSha256 = 'B4C3B580A90E8796B869C07767D82D02F4C273729EBF131806042C2BA7BC4470'
$script:AlarmSha256 = '6043D5644C97CB14AA457F9AC7988139F34F43EACA9ECB192B835239A1A70FC9'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { return }
    throw 'The backend requires an elevated administrator token.'
}

function Initialize-BackendStorage {
    if (-not (Test-Path -LiteralPath $RootPath)) { New-Item -Path $RootPath -ItemType Directory -Force | Out-Null }
    if (-not (Test-Path -LiteralPath $RegistryPath)) { New-Item -Path $RegistryPath -Force | Out-Null }
}

function Test-DeviceExcluded {
    foreach ($name in $script:ExclusionKeys) {
        $value = Get-ItemPropertyValue -Path $RegistryPath -Name $name -ErrorAction SilentlyContinue
        if ([string]$value -ieq 'True') { return $true }
    }
    return $false
}

function Get-SecureBootState {
    try { return [bool](Confirm-SecureBootUEFI -ErrorAction Stop) }
    catch { return $false }
}

function Get-BitLockerState {
    try {
        $volume = Get-BitLockerVolume -MountPoint 'C:' -ErrorAction Stop
        if ($volume.ProtectionStatus -eq 'On') { return $true }
        return $volume.VolumeStatus -eq 'EncryptionInProgress'
    }
    catch { return $false }
}

function Get-FailureTimestamp {
    $now = Get-Date
    if (-not (Test-Path -LiteralPath $script:FailureTimePath -PathType Leaf)) {
        $now.ToString('o') | Set-Content -LiteralPath $script:FailureTimePath -Encoding ASCII -Force
        return $now
    }

    $raw = Get-Content -LiteralPath $script:FailureTimePath -Raw -ErrorAction SilentlyContinue
    $parsed = [datetime]::MinValue
    if (-not [datetime]::TryParse($raw, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$parsed)) {
        $now.ToString('o') | Set-Content -LiteralPath $script:FailureTimePath -Encoding ASCII -Force
        return $now
    }

    if ($parsed -le $now) { return $parsed }
    $now.ToString('o') | Set-Content -LiteralPath $script:FailureTimePath -Encoding ASCII -Force
    return $now
}

function Remove-FailureTracking {
    if (-not (Test-Path -LiteralPath $script:FailureTimePath)) { return }
    Remove-Item -LiteralPath $script:FailureTimePath -Force
}

function Get-ComplianceZone {
    param([Parameter(Mandatory)][double]$HoursElapsed)
    if ($HoursElapsed -ge 48) { return 'Critical' }
    if ($HoursElapsed -ge 24) { return 'Warning' }
    return 'Grace'
}

function Get-NextIntervalMinutes {
    param([Parameter(Mandatory)][string]$Zone)
    if ($Zone -eq 'Critical') { return 5 }
    if ($Zone -eq 'Healthy' -or $Zone -eq 'Excluded') { return 1440 }
    return 60
}

function Save-StateAtomically {
    param([Parameter(Mandatory)][hashtable]$State)

    $temporaryPath = "$script:StatePath.tmp"
    $State | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $temporaryPath -Encoding UTF8 -Force
    Move-Item -LiteralPath $temporaryPath -Destination $script:StatePath -Force
}

function Save-ComplianceState {
    param(
        [Parameter(Mandatory)][string]$Zone,
        [Parameter(Mandatory)][bool]$SecureBoot,
        [Parameter(Mandatory)][bool]$BitLocker,
        [AllowNull()][Nullable[datetime]]$FirstFailureTime
    )

    $interval = Get-NextIntervalMinutes -Zone $Zone
    $state = @{
        SchemaVersion = 1
        GeneratedUtc = (Get-Date).ToUniversalTime().ToString('o')
        Zone = $Zone
        IsCompliant = ($Zone -in @('Healthy', 'Excluded'))
        SecureBoot = $SecureBoot
        BitLocker = $BitLocker
        FirstFailureUtc = if ($null -eq $FirstFailureTime) { $null } else { $FirstFailureTime.Value.ToUniversalTime().ToString('o') }
        AlertIntervalMinutes = $interval
        MinimizeWindows = ($Zone -in @('Warning', 'Critical'))
        MaximizeVolume = ($Zone -eq 'Critical')
        PlayAudio = ($Zone -eq 'Critical')
        BeepPath = $script:BeepPath
        AlarmPath = $script:AlarmPath
        BeepRepeatCount = 2
        AlarmRepeatCount = 3
        BeepSha256 = $script:BeepSha256
        AlarmSha256 = $script:AlarmSha256
        AlertTitle = 'SECURITY ALERT: Action Required'
        AlertMessage = 'Your device is missing critical security configurations (BitLocker or Secure Boot). Please enable them immediately to protect corporate data.'
    }
    Save-StateAtomically -State $state
    $registryStatus = switch ($Zone) {
        'Excluded' { 'Compliant_Excluded' }
        'Healthy' { 'Compliant' }
        'Grace' { 'Missing_Grace' }
        'Warning' { 'Missing_24h' }
        'Critical' { 'Missing_48h' }
    }
    Set-ItemProperty -Path $RegistryPath -Name ComplianceStatus -Value $registryStatus -Force
}

function Test-FileHashMatch {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$ExpectedSha256)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -eq $ExpectedSha256
}

function Invoke-AssetDownload {
    param([Parameter(Mandatory)][string]$Url, [Parameter(Mandatory)][string]$Destination, [Parameter(Mandatory)][string]$ExpectedSha256)
    if (Test-FileHashMatch -Path $Destination -ExpectedSha256 $ExpectedSha256) { return $true }
    $temporaryPath = "$Destination.download"
    try {
        Invoke-WebRequest -Uri $Url -OutFile $temporaryPath -UseBasicParsing -ErrorAction Stop
        if (-not (Test-FileHashMatch -Path $temporaryPath -ExpectedSha256 $ExpectedSha256)) { throw 'Downloaded asset hash validation failed.' }
        Move-Item -LiteralPath $temporaryPath -Destination $Destination -Force
        return $true
    }
    catch {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        Write-Warning "Asset download failed; cached local assets remain available. $($_.Exception.Message)"
        return $false
    }
}

function Initialize-AudioAssets {
    $baseUrl = $RepositoryRawBaseUrl.TrimEnd('/')
    [void](Invoke-AssetDownload -Url "$baseUrl/media/bip.wav" -Destination $script:BeepPath -ExpectedSha256 $script:BeepSha256)
    [void](Invoke-AssetDownload -Url "$baseUrl/media/alarm.mp3" -Destination $script:AlarmPath -ExpectedSha256 $script:AlarmSha256)
}

function Set-BackendScheduledTask {
    param([Parameter(Mandatory)][string]$Zone)

    $backendUrl = "$($RepositoryRawBaseUrl.TrimEnd('/'))/SecurityFeatureMonitor-Backend.ps1"
    $arguments = "-NoProfile -NonInteractive -ExecutionPolicy AllSigned -File `"$BootstrapPath`" -BackendScriptUrl `"$backendUrl`" -RepositoryRawBaseUrl `"$RepositoryRawBaseUrl`" -TrustedSignerThumbprint `"$TrustedSignerThumbprint`""
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
    $principal = New-ScheduledTaskPrincipal -GroupId 'BUILTIN\Administrators' -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew
    $triggers = if ($Zone -in @('Healthy', 'Excluded')) {
        @((New-ScheduledTaskTrigger -Daily -At '12:00'), (New-ScheduledTaskTrigger -AtLogOn))
    } else {
        $minutes = Get-NextIntervalMinutes -Zone $Zone
        @(New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $minutes))
    }
    Register-ScheduledTask -TaskName $BackendTaskName -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Force | Out-Null
}

function Invoke-BackendPipeline {
    Assert-Administrator
    Initialize-BackendStorage
    Initialize-AudioAssets

    if (Test-DeviceExcluded) {
        Remove-FailureTracking
        Save-ComplianceState -Zone Excluded -SecureBoot $true -BitLocker $true -FirstFailureTime $null
        if ($InstallScheduledTask) { Set-BackendScheduledTask -Zone Excluded }
        return 0
    }

    $secureBoot = Get-SecureBootState
    $bitLocker = Get-BitLockerState
    if ($secureBoot -and $bitLocker) {
        Remove-FailureTracking
        Save-ComplianceState -Zone Healthy -SecureBoot $secureBoot -BitLocker $bitLocker -FirstFailureTime $null
        if ($InstallScheduledTask) { Set-BackendScheduledTask -Zone Healthy }
        return 0
    }

    $firstFailure = Get-FailureTimestamp
    $zone = Get-ComplianceZone -HoursElapsed ((Get-Date) - $firstFailure).TotalHours
    Save-ComplianceState -Zone $zone -SecureBoot $secureBoot -BitLocker $bitLocker -FirstFailureTime $firstFailure
    if ($InstallScheduledTask) { Set-BackendScheduledTask -Zone $zone }
    return 1
}

exit (Invoke-BackendPipeline)
