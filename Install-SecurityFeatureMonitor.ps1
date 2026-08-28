[CmdletBinding()]
param(
    [string]$SourceDirectory = $PSScriptRoot,
    [string]$InstallDirectory = 'C:\ProgramData\SecurityFeatureMonitor',
    [string]$StateDirectory = 'C:\Windows\Logs\SecurityCheck'
)

$ErrorActionPreference = 'Stop'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { return }
    throw 'Installation requires an elevated administrator token.'
}

function Install-ScriptFiles {
    foreach ($directory in @($InstallDirectory, $StateDirectory)) {
        if (Test-Path -LiteralPath $directory) { continue }
        New-Item -Path $directory -ItemType Directory -Force | Out-Null
    }
    Copy-Item -LiteralPath (Join-Path $SourceDirectory 'SecurityFeatureMonitor-UI.ps1') -Destination $InstallDirectory -Force
    Copy-Item -LiteralPath (Join-Path $SourceDirectory 'Set-SecurityFeatureMonitorTestMode.ps1') -Destination $InstallDirectory -Force
    Copy-Item -LiteralPath (Join-Path $SourceDirectory 'SecurityFeatureMonitor-Backend.ps1') -Destination (Join-Path $InstallDirectory 'SecurityFeatureMonitor-Backend.cached.ps1') -Force
    $mediaSource = Join-Path $SourceDirectory 'media'
    if (-not (Test-Path -LiteralPath $mediaSource -PathType Container)) { return }
    $beepDestination = Join-Path $StateDirectory 'bip.wav'
    $alarmDestination = Join-Path $StateDirectory 'alarm.mp3'
    $expectedBeepHash = 'B4C3B580A90E8796B869C07767D82D02F4C273729EBF131806042C2BA7BC4470'
    $expectedAlarmHash = '6043D5644C97CB14AA457F9AC7988139F34F43EACA9ECB192B835239A1A70FC9'
    $beepIsValid = (Test-Path -LiteralPath $beepDestination -PathType Leaf) -and ((Get-FileHash -LiteralPath $beepDestination -Algorithm SHA256).Hash -eq $expectedBeepHash)
    $alarmIsValid = (Test-Path -LiteralPath $alarmDestination -PathType Leaf) -and ((Get-FileHash -LiteralPath $alarmDestination -Algorithm SHA256).Hash -eq $expectedAlarmHash)
    if (-not $beepIsValid) {
        Copy-Item -LiteralPath (Join-Path $mediaSource 'bip.wav') -Destination $beepDestination -Force
    }
    if (-not $alarmIsValid) {
        Copy-Item -LiteralPath (Join-Path $mediaSource 'alarm.mp3') -Destination $alarmDestination -Force
    }
}

function Set-SecureAcls {
    & icacls.exe $InstallDirectory /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
    & icacls.exe $StateDirectory /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
}

function Register-UserInterfaceTask {
    $uiPath = Join-Path $InstallDirectory 'SecurityFeatureMonitor-UI.ps1'
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$uiPath`""
    $principal = New-ScheduledTaskPrincipal -GroupId 'BUILTIN\Users' -RunLevel Limited
    $trigger = @((New-ScheduledTaskTrigger -AtLogOn), (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5)))
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances Parallel -ExecutionTimeLimit (New-TimeSpan -Hours 24)
    Register-ScheduledTask -TaskName 'SecurityFeatureMonitor-UI' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
}

function Register-BackendTask {
    $backendPath = Join-Path $InstallDirectory 'SecurityFeatureMonitor-Backend.cached.ps1'
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$backendPath`""
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $trigger = @(
        (New-ScheduledTaskTrigger -AtStartup),
        (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Hours 1))
    )
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName 'Intune-SecurityFeatureMonitor' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
}

Assert-Administrator
Install-ScriptFiles
Set-SecureAcls
Register-BackendTask
Register-UserInterfaceTask
Start-ScheduledTask -TaskName 'Intune-SecurityFeatureMonitor'
Write-Output 'Security Feature Monitor installed successfully.'
