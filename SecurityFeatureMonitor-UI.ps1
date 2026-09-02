[CmdletBinding()]
param(
    [string]$RootPath = 'C:\ProgramData\SecurityFeatureMonitor\State',
    [switch]$ForceDisplay,
    [switch]$ForceAudio
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName System.Windows.Forms
$statePath = Join-Path $RootPath 'State.json'
$userDataPath = Join-Path $env:LOCALAPPDATA 'SecurityFeatureMonitor'
$lastAlertPath = Join-Path $userDataPath 'LastAlertUtc.txt'
$lastTestActivationPath = Join-Path $userDataPath 'LastTestActivationId.txt'
$lastRecoveryAlertPath = Join-Path $userDataPath 'LastRecoveryAlertId.txt'

function Get-MonitorState {
    if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) { return $null }
    try {
        $state = Get-Content -LiteralPath $statePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if ([int]$state.SchemaVersion -ne 1) { return $null }
        if ([string]$state.Zone -notin @('Healthy', 'Excluded', 'Warning', 'Critical', 'EncryptionInProgress')) { return $null }
        return $state
    }
    catch {
        Write-Warning "State file could not be read: $($_.Exception.Message)"
        return $null
    }
}

function Test-AlertDue {
    param([Parameter(Mandatory)]$State)
    if ($ForceDisplay) { return $true }
    if ([bool]$State.SuppressAlerts) { return $false }
    if ([bool]$State.IsCompliant) { return $false }
    if (-not [string]::IsNullOrWhiteSpace([string]$State.RecoveryAlertId)) {
        $lastRecoveryAlert = Get-Content -LiteralPath $lastRecoveryAlertPath -Raw -ErrorAction SilentlyContinue
        if ([string]$lastRecoveryAlert -ne [string]$State.RecoveryAlertId) { return $true }
    }
    if ([bool]$State.IsTestMode -and -not [string]::IsNullOrWhiteSpace([string]$State.TestActivationId)) {
        $lastActivation = Get-Content -LiteralPath $lastTestActivationPath -Raw -ErrorAction SilentlyContinue
        if ([string]$lastActivation -ne [string]$State.TestActivationId) { return $true }
    }
    if (-not (Test-Path -LiteralPath $lastAlertPath -PathType Leaf)) { return $true }

    $lastAlertUtc = [datetime]::MinValue
    $rawTimestamp = Get-Content -LiteralPath $lastAlertPath -Raw -ErrorAction SilentlyContinue
    $isValid = [datetime]::TryParse($rawTimestamp, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$lastAlertUtc)
    if (-not $isValid) { return $true }
    return ((Get-Date).ToUniversalTime() - $lastAlertUtc.ToUniversalTime()).TotalMinutes -ge [int]$State.AlertIntervalMinutes
}

function Set-LastAlertTime {
    param([Parameter(Mandatory)]$State)
    if (-not (Test-Path -LiteralPath $userDataPath -PathType Container)) { New-Item -Path $userDataPath -ItemType Directory -Force | Out-Null }
    (Get-Date).ToUniversalTime().ToString('o') | Set-Content -LiteralPath $lastAlertPath -Encoding ASCII -Force
    if ([bool]$State.IsTestMode -and -not [string]::IsNullOrWhiteSpace([string]$State.TestActivationId)) {
        [string]$State.TestActivationId | Set-Content -LiteralPath $lastTestActivationPath -Encoding ASCII -Force
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$State.RecoveryAlertId)) {
        [string]$State.RecoveryAlertId | Set-Content -LiteralPath $lastRecoveryAlertPath -Encoding ASCII -Force
    }
}

function Invoke-MinimizeAllWindows {
    try { (New-Object -ComObject Shell.Application).MinimizeAll() }
    catch { Write-Warning "Windows could not be minimized: $($_.Exception.Message)" }
}

function Set-MaximumVolume {
    try {
        $wshShell = New-Object -ComObject WScript.Shell
        for ($i = 0; $i -lt 50; $i++) { $wshShell.SendKeys([char]::ToString(175)) }
    }
    catch { Write-Warning "Volume could not be changed: $($_.Exception.Message)" }
}

function Wait-MediaPlayerReady {
    param(
        [Parameter(Mandatory)][System.Windows.Media.MediaPlayer]$Player,
        [Parameter(Mandatory)][string]$AudioPath,
        [int]$TimeoutSeconds = 10
    )

    $signal = [PSCustomObject]@{ Opened = $false; Failed = $false }
    $openedHandler = { $signal.Opened = $true }.GetNewClosure()
    $failedHandler = { $signal.Failed = $true }.GetNewClosure()
    try {
        $Player.add_MediaOpened($openedHandler)
        $Player.add_MediaFailed($failedHandler)
        $Player.Open([Uri]::new($AudioPath, [UriKind]::Absolute))
        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        while ((Get-Date) -lt $deadline) {
            [Windows.Forms.Application]::DoEvents()
            if ($signal.Opened) { return $true }
            if ($signal.Failed) { return $false }
            Start-Sleep -Milliseconds 25
        }
        return $false
    }
    finally {
        $Player.remove_MediaOpened($openedHandler)
        $Player.remove_MediaFailed($failedHandler)
    }
}

function New-PreparedAudioItem {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][ValidateRange(1, 100)][int]$RepeatCount,
        [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedSha256
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Write-Warning "Audio file was not found and will be skipped: $Path"
        return $null
    }

    if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ne $ExpectedSha256) {
        Write-Warning "Audio file hash validation failed and will be skipped: $Path"
        return $null
    }

    $player = [System.Windows.Media.MediaPlayer]::new()
    if (Wait-MediaPlayerReady -Player $player -AudioPath $Path) {
        $player.Volume = 1.0
        return [PSCustomObject]@{ Name = $Name; Path = $Path; RepeatCount = $RepeatCount; PlayedCount = 0; Player = $player }
    }

    $player.Close()
    Write-Warning "Audio file could not be prepared and will be skipped: $Path"
    return $null
}

function New-AudioSequence {
    param([Parameter(Mandatory)]$State)
    $items = [Collections.Generic.List[object]]::new()
    $beep = New-PreparedAudioItem -Name 'Beep' -Path ([string]$State.BeepPath) -RepeatCount ([int]$State.BeepRepeatCount) -ExpectedSha256 ([string]$State.BeepSha256)
    if ($null -ne $beep) { $items.Add($beep) }
    $alarm = New-PreparedAudioItem -Name 'Alarm' -Path ([string]$State.AlarmPath) -RepeatCount ([int]$State.AlarmRepeatCount) -ExpectedSha256 ([string]$State.AlarmSha256)
    if ($null -ne $alarm) { $items.Add($alarm) }
    return [PSCustomObject]@{ Items = $items; CurrentIndex = 0; EndedHandler = $null; IsDisposed = $false }
}

function Close-AudioSequence {
    param([AllowNull()]$Sequence)
    if ($null -eq $Sequence) { return }
    if ($Sequence.IsDisposed) { return }
    $Sequence.IsDisposed = $true
    foreach ($item in $Sequence.Items) {
        try {
            if ($null -ne $Sequence.EndedHandler) { $item.Player.remove_MediaEnded($Sequence.EndedHandler) }
            $item.Player.Stop()
            $item.Player.Close()
        }
        catch { Write-Warning "Audio resource could not be released: $($_.Exception.Message)" }
    }
    $Sequence.Items.Clear()
}

function Start-AudioSequence {
    param([AllowNull()]$Sequence)
    if ($null -eq $Sequence) { return }
    if ($Sequence.Items.Count -eq 0) { Close-AudioSequence -Sequence $Sequence; return }

    $endedHandler = {
        $current = $Sequence.Items[$Sequence.CurrentIndex]
        $current.PlayedCount++
        if ($current.PlayedCount -lt $current.RepeatCount) {
            $current.Player.Position = [TimeSpan]::Zero
            $current.Player.Play()
            return
        }
        $Sequence.CurrentIndex++
        if ($Sequence.CurrentIndex -ge $Sequence.Items.Count) {
            Close-AudioSequence -Sequence $Sequence
            return
        }
        $next = $Sequence.Items[$Sequence.CurrentIndex]
        $next.Player.Position = [TimeSpan]::Zero
        $next.Player.Play()
    }.GetNewClosure()
    $Sequence.EndedHandler = $endedHandler
    foreach ($item in $Sequence.Items) { $item.Player.add_MediaEnded($endedHandler) }
    $Sequence.Items[0].Player.Position = [TimeSpan]::Zero
    $Sequence.Items[0].Player.Play()
}

function Show-ComplianceDialog {
    param([Parameter(Mandatory)]$State, [AllowNull()]$AudioSequence)
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $form = [Windows.Forms.Form]::new()
    $form.Text = [string]$State.AlertTitle
    $form.Size = [Drawing.Size]::new(500, 220)
    $form.StartPosition = 'CenterScreen'
    $form.TopMost = $true
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false

    $label = [Windows.Forms.Label]::new()
    $label.Text = [string]$State.AlertMessage
    $label.Location = [Drawing.Point]::new(20, 20)
    $label.Size = [Drawing.Size]::new(440, 80)
    $form.Controls.Add($label)

    $laterButton = [Windows.Forms.Button]::new()
    $laterButton.Text = 'OK אני אפעיל מאוחר יותר'
    $laterButton.Location = [Drawing.Point]::new(40, 120)
    $laterButton.Size = [Drawing.Size]::new(190, 35)
    $laterButton.DialogResult = [Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $laterButton
    $form.Controls.Add($laterButton)

    $nowButton = [Windows.Forms.Button]::new()
    $nowButton.Text = 'נכנע אני יפעיל עכשיו'
    $nowButton.Location = [Drawing.Point]::new(250, 120)
    $nowButton.Size = [Drawing.Size]::new(190, 35)
    $nowButton.DialogResult = [Windows.Forms.DialogResult]::Cancel
    $form.Controls.Add($nowButton)

    $shownHandler = { Start-AudioSequence -Sequence $AudioSequence }.GetNewClosure()
    $complianceTimer = [Windows.Forms.Timer]::new()
    $complianceTimer.Interval = 2000
    $complianceHandler = {
        $latestState = Get-MonitorState
        if ($null -eq $latestState) { return }
        if (-not [bool]$latestState.IsCompliant -and -not [bool]$latestState.SuppressAlerts) { return }
        Close-AudioSequence -Sequence $AudioSequence
        $form.Close()
    }.GetNewClosure()
    $form.add_Shown($shownHandler)
    $complianceTimer.add_Tick($complianceHandler)
    $complianceTimer.Start()
    try { $result = $form.ShowDialog() }
    finally {
        $complianceTimer.Stop()
        $complianceTimer.remove_Tick($complianceHandler)
        $complianceTimer.Dispose()
        $form.remove_Shown($shownHandler)
        $form.Dispose()
    }
    while ($null -ne $AudioSequence -and -not $AudioSequence.IsDisposed) {
        [Windows.Forms.Application]::DoEvents()
        Start-Sleep -Milliseconds 25
    }
    if ($result -ne [Windows.Forms.DialogResult]::OK) { return }
    $intervalText = if ([string]$State.Zone -eq 'Critical') { '5 דקות' } else { 'שעה' }
    [void][Windows.Forms.MessageBox]::Show("אל תדאג אני אזכיר לך במקרה ותשכח בעוד $intervalText", 'Reminder Set', 'OK', 'Information')
}

function Invoke-UiPipeline {
    $state = Get-MonitorState
    if ($null -eq $state) { return 0 }
    if (-not (Test-AlertDue -State $state)) { return 0 }
    Set-LastAlertTime -State $state
    if ([bool]$state.MinimizeWindows) { Invoke-MinimizeAllWindows }
    if ([bool]$state.MaximizeVolume) { Set-MaximumVolume }
    $audioSequence = if ([bool]$state.PlayAudio -or $ForceAudio) { New-AudioSequence -State $state } else { $null }
    Show-ComplianceDialog -State $state -AudioSequence $audioSequence
    return 0
}

exit (Invoke-UiPipeline)
