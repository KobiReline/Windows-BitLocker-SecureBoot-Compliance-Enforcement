[CmdletBinding()]
param(
    [string]$SourceDirectory = $PSScriptRoot,
    [string]$InstallDirectory = 'C:\ProgramData\SecurityFeatureMonitor',
    [string]$StateDirectory = 'C:\ProgramData\SecurityFeatureMonitor\State',
    [string]$Version = '0.0.0',
    [switch]$RecoveryMode
)

$ErrorActionPreference = 'Stop'

function Assert-SystemOrAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($identity.User.Value -eq 'S-1-5-18') { return }
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { return }
    throw 'Installation requires SYSTEM or an elevated administrator token.'
}

function Initialize-Directories {
    foreach ($directory in @($InstallDirectory, $StateDirectory, (Join-Path $InstallDirectory 'media'), (Join-Path $InstallDirectory 'Staging'))) {
        if (Test-Path -LiteralPath $directory -PathType Container) { continue }
        New-Item -Path $directory -ItemType Directory -Force | Out-Null
    }
}

function Install-Files {
    $mapping = @(
        @{ Source = 'SecurityFeatureMonitor-UI.ps1'; Destination = (Join-Path $InstallDirectory 'SecurityFeatureMonitor-UI.ps1') },
        @{ Source = 'Set-SecurityFeatureMonitorTestMode.ps1'; Destination = (Join-Path $InstallDirectory 'Set-SecurityFeatureMonitorTestMode.ps1') },
        @{ Source = 'SecurityFeatureMonitor-Backend.ps1'; Destination = (Join-Path $InstallDirectory 'SecurityFeatureMonitor-Backend.cached.ps1') },
        @{ Source = 'manifest.json'; Destination = (Join-Path $InstallDirectory 'manifest.json') },
        @{ Source = 'media\bip.wav'; Destination = (Join-Path $InstallDirectory 'media\bip.wav') },
        @{ Source = 'media\alarm.mp3'; Destination = (Join-Path $InstallDirectory 'media\alarm.mp3') }
    )
    foreach ($item in $mapping) {
        $sourcePath = Join-Path $SourceDirectory $item.Source
        if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) { throw "Required source file is missing: $($item.Source)" }
        Copy-Item -LiteralPath $sourcePath -Destination $item.Destination -Force
    }
    $Version | Set-Content -LiteralPath (Join-Path $InstallDirectory 'Version.txt') -Encoding ASCII -Force
}

function Set-SecureAcls {
    & icacls.exe $InstallDirectory /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to secure the installation directory.' }
}

function Register-UserInterfaceTask {
    $uiPath = Join-Path $InstallDirectory 'SecurityFeatureMonitor-UI.ps1'
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$uiPath`""
    $principal = New-ScheduledTaskPrincipal -GroupId 'BUILTIN\Users' -RunLevel Limited
    $triggers = @(
        (New-ScheduledTaskTrigger -AtLogOn),
        (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5))
    )
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 1)
    Register-ScheduledTask -TaskName 'SecurityFeatureMonitor-UI' -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Force | Out-Null
}

function Register-BackendTask {
    $backendPath = Join-Path $InstallDirectory 'SecurityFeatureMonitor-Backend.cached.ps1'
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$backendPath`""
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $triggers = @(
        (New-ScheduledTaskTrigger -AtStartup),
        (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Hours 1))
    )
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName 'Intune-SecurityFeatureMonitor' -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Force | Out-Null
}

function Invoke-ImmediateComplianceCheck {
    $backendPath = Join-Path $InstallDirectory 'SecurityFeatureMonitor-Backend.cached.ps1'
    $arguments = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $backendPath)
    if ($RecoveryMode) { $arguments += '-SuppressAudioOnce' }
    $process = Start-Process -FilePath 'powershell.exe' -ArgumentList $arguments -WindowStyle Hidden -Wait -PassThru
    if ($process.ExitCode -notin @(0, 1)) { throw "Backend immediate check failed with exit code $($process.ExitCode)." }
}

Assert-SystemOrAdministrator
Initialize-Directories
Install-Files
Set-SecureAcls
Register-BackendTask
Register-UserInterfaceTask
Invoke-ImmediateComplianceCheck
Start-ScheduledTask -TaskName 'SecurityFeatureMonitor-UI' -ErrorAction SilentlyContinue
Write-Output "Security Feature Monitor version $Version installed successfully."
exit 0
