[CmdletBinding()]
param(
    [string]$RootPath = 'C:\ProgramData\SecurityFeatureMonitor\State',
    [string]$InstallPath = 'C:\ProgramData\SecurityFeatureMonitor',
    [string]$RegistryPath = 'HKLM:\SOFTWARE\CustomSecurityCheck',
    [string]$BackendTaskName = 'Intune-SecurityFeatureMonitor',
    [string]$RepositoryRawBaseUrl = 'https://raw.githubusercontent.com/KobiReline/Windows-BitLocker-SecureBoot-Compliance-Enforcement/main',
    [ValidateSet('None', 'Healthy', 'Warning', 'Critical')]
    [string]$TestScenario = 'None',
    [ValidateRange(1, 1440)][int]$TestAlertIntervalMinutes = 1,
    [switch]$SuppressAudioOnce,
    [switch]$InstallScheduledTask
)

$ErrorActionPreference = 'Stop'
$script:ExclusionKeys = @('ManualManagement', 'VIP_Device', 'AdminException', 'LabMachine')
$script:StatePath = Join-Path $RootPath 'State.json'
$script:FailureTimePath = Join-Path $RootPath 'FirstFailureTime.txt'
$script:EncryptionPausePath = Join-Path $RootPath 'EncryptionPause.json'
$script:ManifestPath = Join-Path $InstallPath 'manifest.json'
$script:BeepPath = Join-Path $InstallPath 'media\bip.wav'
$script:AlarmPath = Join-Path $InstallPath 'media\alarm.mp3'
$script:BeepSha256 = $null
$script:AlarmSha256 = $null

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { return }
    throw 'The backend requires an elevated administrator token.'
}

function Initialize-BackendStorage {
    if (-not (Test-Path -LiteralPath $RootPath)) { New-Item -Path $RootPath -ItemType Directory -Force | Out-Null }
    $mediaPath = Join-Path $InstallPath 'media'
    if (-not (Test-Path -LiteralPath $mediaPath)) { New-Item -Path $mediaPath -ItemType Directory -Force | Out-Null }
    if (-not (Test-Path -LiteralPath $RegistryPath)) { New-Item -Path $RegistryPath -Force | Out-Null }
}

function Get-RegistryValueOrNull {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )

    $item = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $null }
    $property = $item.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Test-DeviceExcluded {
    foreach ($name in $script:ExclusionKeys) {
        $value = Get-RegistryValueOrNull -Path $RegistryPath -Name $name
        if ([string]$value -ieq 'True') { return $true }
    }
    return $false
}

function Import-TestConfiguration {
    if ($TestScenario -ne 'None') { return }
    $enabled = Get-RegistryValueOrNull -Path $RegistryPath -Name TestModeEnabled
    if ([string]$enabled -ne '1') { return }
    $configuredScenario = [string](Get-RegistryValueOrNull -Path $RegistryPath -Name TestScenario)
    if ($configuredScenario -notin @('Healthy', 'Warning', 'Critical')) { return }
    $script:EffectiveTestScenario = $configuredScenario
    $script:EffectiveTestActivationId = [string](Get-RegistryValueOrNull -Path $RegistryPath -Name TestActivationId)
    $configuredInterval = Get-RegistryValueOrNull -Path $RegistryPath -Name TestAlertIntervalMinutes
    if ($null -eq $configuredInterval) { return }
    if ([int]$configuredInterval -lt 1 -or [int]$configuredInterval -gt 1440) { return }
    $script:EffectiveTestAlertIntervalMinutes = [int]$configuredInterval
}

function Get-SecureBootState {
    try { return [bool](Confirm-SecureBootUEFI -ErrorAction Stop) }
    catch { return $false }
}

function Get-BitLockerStatus {
    try {
        $volume = Get-BitLockerVolume -MountPoint 'C:' -ErrorAction Stop
        if ([string]$volume.VolumeStatus -eq 'EncryptionInProgress') { return 'EncryptionInProgress' }
        if ([string]$volume.ProtectionStatus -eq 'On') { return 'Protected' }
        return 'NotProtected'
    }
    catch { return 'NotProtected' }
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
    if ($HoursElapsed -ge 24) { return 'Critical' }
    return 'Warning'
}

function Get-NextIntervalMinutes {
    param([Parameter(Mandatory)][string]$Zone)
    if ($Zone -in @('Critical', 'EncryptionInProgress')) { return 5 }
    if ($Zone -eq 'Healthy' -or $Zone -eq 'Excluded') { return 1440 }
    return 60
}

function Start-UserInterfaceTask {
    Start-ScheduledTask -TaskName 'SecurityFeatureMonitor-UI' -ErrorAction SilentlyContinue
}

function Get-EncryptionPause {
    if (-not (Test-Path -LiteralPath $script:EncryptionPausePath -PathType Leaf)) { return $null }
    try { return Get-Content -LiteralPath $script:EncryptionPausePath -Raw | ConvertFrom-Json -ErrorAction Stop }
    catch { Remove-Item -LiteralPath $script:EncryptionPausePath -Force -ErrorAction SilentlyContinue; return $null }
}

function Start-EncryptionPause {
    $existingPause = Get-EncryptionPause
    if ($null -ne $existingPause) { return $existingPause }

    $resumeZone = 'Warning'
    if (Test-Path -LiteralPath $script:StatePath -PathType Leaf) {
        try {
            $existingState = Get-Content -LiteralPath $script:StatePath -Raw | ConvertFrom-Json -ErrorAction Stop
            if ([string]$existingState.Zone -in @('Warning', 'Critical')) { $resumeZone = [string]$existingState.Zone }
        }
        catch { }
    }

    $pause = [ordered]@{
        StartedUtc = (Get-Date).ToUniversalTime().ToString('o')
        ResumeZone = $resumeZone
    }
    $pause | ConvertTo-Json | Set-Content -LiteralPath $script:EncryptionPausePath -Encoding UTF8 -Force
    return [PSCustomObject]$pause
}

function Resume-FailureClockAfterEncryption {
    $pause = Get-EncryptionPause
    if ($null -eq $pause) { return }

    try {
        $pauseStarted = [datetime]::Parse([string]$pause.StartedUtc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)
        $failureStarted = [datetime]::Parse((Get-Content -LiteralPath $script:FailureTimePath -Raw), [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)
        $adjustedFailureTime = $failureStarted.Add((Get-Date).ToUniversalTime() - $pauseStarted.ToUniversalTime())
        $adjustedFailureTime.ToString('o') | Set-Content -LiteralPath $script:FailureTimePath -Encoding ASCII -Force
    }
    catch { }
    finally { Remove-Item -LiteralPath $script:EncryptionPausePath -Force -ErrorAction SilentlyContinue }
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
        [AllowNull()][Nullable[datetime]]$FirstFailureTime,
        [bool]$IsTestMode = $false,
        [bool]$IsRecoveryAlert = $false,
        [bool]$SuppressAlerts = $false,
        [AllowNull()][string]$ResumeZone = $null
    )

    $interval = if ($IsTestMode) { $script:EffectiveTestAlertIntervalMinutes } else { Get-NextIntervalMinutes -Zone $Zone }
    $state = @{
        SchemaVersion = 1
        IsTestMode = $IsTestMode
        TestActivationId = if ($IsTestMode) { $script:EffectiveTestActivationId } else { $null }
        RecoveryAlertId = if ($IsRecoveryAlert) { [guid]::NewGuid().ToString() } else { $null }
        GeneratedUtc = (Get-Date).ToUniversalTime().ToString('o')
        Zone = $Zone
        IsCompliant = ($Zone -in @('Healthy', 'Excluded'))
        SuppressAlerts = $SuppressAlerts
        ResumeZone = $ResumeZone
        SecureBoot = $SecureBoot
        BitLocker = $BitLocker
        FirstFailureUtc = if ($null -eq $FirstFailureTime) { $null } else { $FirstFailureTime.Value.ToUniversalTime().ToString('o') }
        AlertIntervalMinutes = $interval
        MinimizeWindows = (($Zone -in @('Warning', 'Critical')) -and -not $SuppressAlerts)
        MaximizeVolume = ($Zone -eq 'Critical')
        PlayAudio = (($Zone -eq 'Critical') -and -not $IsRecoveryAlert -and -not $SuppressAlerts)
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
        'Warning' { 'Missing_Under24h' }
        'Critical' { 'Missing_24hOrMore' }
        'EncryptionInProgress' { 'EncryptionInProgress_AlertsSuspended' }
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
    if (-not (Test-Path -LiteralPath $script:ManifestPath -PathType Leaf)) {
        Write-Warning 'Local manifest is unavailable; audio validation and download were skipped.'
        return
    }
    try { $manifest = Get-Content -LiteralPath $script:ManifestPath -Raw | ConvertFrom-Json -ErrorAction Stop }
    catch { Write-Warning "Local manifest is invalid; audio validation and download were skipped. $($_.Exception.Message)"; return }
    $beepEntry = @($manifest.Files | Where-Object { [string]$_.Source -eq 'media/bip.wav' }) | Select-Object -First 1
    $alarmEntry = @($manifest.Files | Where-Object { [string]$_.Source -eq 'media/alarm.mp3' }) | Select-Object -First 1
    if ($null -eq $beepEntry -or $null -eq $alarmEntry) { Write-Warning 'Audio entries are missing from the local manifest.'; return }
    $script:BeepSha256 = [string]$beepEntry.Sha256
    $script:AlarmSha256 = [string]$alarmEntry.Sha256
    $baseUrl = $RepositoryRawBaseUrl.TrimEnd('/')
    [void](Invoke-AssetDownload -Url "$baseUrl/media/bip.wav" -Destination $script:BeepPath -ExpectedSha256 $script:BeepSha256)
    [void](Invoke-AssetDownload -Url "$baseUrl/media/alarm.mp3" -Destination $script:AlarmPath -ExpectedSha256 $script:AlarmSha256)
}

function Set-BackendScheduledTask {
    param([Parameter(Mandatory)][string]$Zone)

    $backendPath = $PSCommandPath
    $arguments = "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$backendPath`" -RepositoryRawBaseUrl `"$RepositoryRawBaseUrl`" -InstallScheduledTask"
    if ($TestScenario -ne 'None') { $arguments += " -TestScenario $TestScenario -TestAlertIntervalMinutes $TestAlertIntervalMinutes" }
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew
    $logonTrigger = New-ScheduledTaskTrigger -AtLogOn
    $triggers = if ($Zone -in @('Healthy', 'Excluded')) {
        @((New-ScheduledTaskTrigger -Daily -At '12:00'), $logonTrigger)
    } else {
        $minutes = Get-NextIntervalMinutes -Zone $Zone
        @((New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $minutes)), $logonTrigger)
    }
    Register-ScheduledTask -TaskName $BackendTaskName -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Force | Out-Null
}

function Invoke-BackendPipeline {
    Assert-Administrator
    Initialize-BackendStorage
    $script:EffectiveTestScenario = $TestScenario
    $script:EffectiveTestAlertIntervalMinutes = $TestAlertIntervalMinutes
    $script:EffectiveTestActivationId = [guid]::NewGuid().ToString()
    Import-TestConfiguration
    Initialize-AudioAssets

    if ($script:EffectiveTestScenario -ne 'None') {
        $testSecureBoot = $script:EffectiveTestScenario -eq 'Healthy'
        $testBitLocker = $script:EffectiveTestScenario -eq 'Healthy'
        $testFailureTime = if ($script:EffectiveTestScenario -in @('Warning', 'Critical')) { Get-Date } else { $null }
        Save-ComplianceState -Zone $script:EffectiveTestScenario -SecureBoot $testSecureBoot -BitLocker $testBitLocker -FirstFailureTime $testFailureTime -IsTestMode $true
        if ($InstallScheduledTask) { Set-BackendScheduledTask -Zone $script:EffectiveTestScenario }
        Start-UserInterfaceTask
        return 0
    }

    if (Test-DeviceExcluded) {
        Remove-FailureTracking
        Save-ComplianceState -Zone Excluded -SecureBoot $true -BitLocker $true -FirstFailureTime $null
        if ($InstallScheduledTask) { Set-BackendScheduledTask -Zone Excluded }
        Start-UserInterfaceTask
        return 0
    }

    $secureBoot = Get-SecureBootState
    $bitLockerStatus = Get-BitLockerStatus
    if ($bitLockerStatus -eq 'EncryptionInProgress') {
        $pause = Start-EncryptionPause
        $firstFailure = if (Test-Path -LiteralPath $script:FailureTimePath -PathType Leaf) { Get-FailureTimestamp } else { $null }
        Save-ComplianceState -Zone EncryptionInProgress -SecureBoot $secureBoot -BitLocker $false -FirstFailureTime $firstFailure -SuppressAlerts $true -ResumeZone ([string]$pause.ResumeZone)
        if ($InstallScheduledTask) { Set-BackendScheduledTask -Zone EncryptionInProgress }
        Start-UserInterfaceTask
        return 0
    }

    Resume-FailureClockAfterEncryption
    $bitLocker = $bitLockerStatus -eq 'Protected'
    if ($secureBoot -and $bitLocker) {
        Remove-FailureTracking
        Save-ComplianceState -Zone Healthy -SecureBoot $secureBoot -BitLocker $bitLocker -FirstFailureTime $null
        if ($InstallScheduledTask) { Set-BackendScheduledTask -Zone Healthy }
        Start-UserInterfaceTask
        return 0
    }

    $firstFailure = Get-FailureTimestamp
    $zone = Get-ComplianceZone -HoursElapsed ((Get-Date) - $firstFailure).TotalHours
    Save-ComplianceState -Zone $zone -SecureBoot $secureBoot -BitLocker $bitLocker -FirstFailureTime $firstFailure -IsRecoveryAlert ([bool]$SuppressAudioOnce)
    if ($InstallScheduledTask) { Set-BackendScheduledTask -Zone $zone }
    Start-UserInterfaceTask
    return 0
}

exit (Invoke-BackendPipeline)
