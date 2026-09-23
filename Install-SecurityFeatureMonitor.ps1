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

function Assert-SourcePayload {
    $manifest = Get-Content -LiteralPath (Join-Path $SourceDirectory 'manifest.json') -Raw | ConvertFrom-Json
    foreach ($entry in $manifest.Files) {
        $path = Join-Path $SourceDirectory ([string]$entry.Source)
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing payload: $($entry.Source)" }
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne [string]$entry.Sha256) {
            throw "Payload hash mismatch: $($entry.Source)"
        }
        if ([IO.Path]::GetExtension($path) -ne '.ps1') { continue }
        $tokens = $null
        $parseErrors = $null
        [Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$parseErrors) | Out-Null
        if ($parseErrors.Count -gt 0) {
            $details = ($parseErrors | ForEach-Object { "Line $($_.Extent.StartLineNumber): $($_.Message)" }) -join '; '
            throw "Payload syntax error in $($entry.Source): $details"
        }
    }
}

function Install-Files {
    $mapping = @(
        @{ Source = 'SecurityFeatureMonitor-UI.ps1'; Destination = (Join-Path $InstallDirectory 'SecurityFeatureMonitor-UI.ps1') },
        @{ Source = 'SecurityFeatureMonitor-UI-Launcher.vbs'; Destination = (Join-Path $InstallDirectory 'SecurityFeatureMonitor-UI-Launcher.vbs') },
        @{ Source = 'Deploy-FromIntune.ps1'; Destination = (Join-Path $InstallDirectory 'Update-SecurityFeatureMonitor.ps1') },
        @{ Source = 'Set-SecurityFeatureMonitorTestMode.ps1'; Destination = (Join-Path $InstallDirectory 'Set-SecurityFeatureMonitorTestMode.ps1') },
        @{ Source = 'SecurityFeatureMonitor-Backend.ps1'; Destination = (Join-Path $InstallDirectory 'SecurityFeatureMonitor-Backend.cached.ps1') },
        @{ Source = 'manifest.json'; Destination = (Join-Path $InstallDirectory 'manifest.json') },
        @{ Source = 'media\bip.wav'; Destination = (Join-Path $InstallDirectory 'media\bip.wav') },
        @{ Source = 'media\alarm.mp3'; Destination = (Join-Path $InstallDirectory 'media\alarm.mp3') }
    )
    foreach ($item in $mapping) {
        $sourcePath = Join-Path $SourceDirectory $item.Source
        if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) { throw "Required source file is missing: $($item.Source)" }
        $temporaryDestination = "$($item.Destination).installing"
        try {
            Copy-Item -LiteralPath $sourcePath -Destination $temporaryDestination -Force
            Move-Item -LiteralPath $temporaryDestination -Destination $item.Destination -Force
        }
        finally { Remove-Item -LiteralPath $temporaryDestination -Force -ErrorAction SilentlyContinue }
    }
    $Version | Set-Content -LiteralPath (Join-Path $InstallDirectory 'Version.txt') -Encoding ASCII -Force
}

function Set-SecureAcls {
    & icacls.exe $InstallDirectory /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to secure the installation directory.' }
}

function Register-UserInterfaceTask {
    $launcherPath = Join-Path $InstallDirectory 'SecurityFeatureMonitor-UI-Launcher.vbs'
    $action = New-ScheduledTaskAction -Execute 'wscript.exe' -Argument "//B //NoLogo `"$launcherPath`""
    $principal = New-ScheduledTaskPrincipal -GroupId 'BUILTIN\Users' -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances StopExisting -ExecutionTimeLimit (New-TimeSpan -Hours 1)
    $task = New-ScheduledTask -Action $action -Principal $principal -Settings $settings
    Register-ScheduledTask -TaskName 'SecurityFeatureMonitor-UI' -InputObject $task -Force | Out-Null
}

function Register-BackendTask {
    $backendPath = Join-Path $InstallDirectory 'SecurityFeatureMonitor-Backend.cached.ps1'
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$backendPath`" -InstallScheduledTask"
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $triggers = @(
        (New-ScheduledTaskTrigger -AtStartup),
        (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Hours 1))
    )
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances StopExisting
    Register-ScheduledTask -TaskName 'Intune-SecurityFeatureMonitor' -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Force | Out-Null
}

function Invoke-ImmediateComplianceCheck {
    $backendPath = Join-Path $InstallDirectory 'SecurityFeatureMonitor-Backend.cached.ps1'
    $arguments = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $backendPath), '-InstallScheduledTask', '-SkipSelfUpdate')
    if ($RecoveryMode) { $arguments += '-SuppressAudioOnce' }
    $stdout = Join-Path $StateDirectory 'Backend-install.stdout.log'
    $stderr = Join-Path $StateDirectory 'Backend-install.stderr.log'
    $process = Start-Process -FilePath 'powershell.exe' -ArgumentList $arguments -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    if ($process.ExitCode -ne 0) {
        $details = Get-Content -LiteralPath $stderr -Raw -ErrorAction SilentlyContinue
        throw "Backend immediate check failed with exit code $($process.ExitCode). $details"
    }
}

try {
    Assert-SystemOrAdministrator
    Assert-SourcePayload
    Initialize-Directories
    Install-Files
    Set-SecureAcls
    Register-BackendTask
    Register-UserInterfaceTask
    Invoke-ImmediateComplianceCheck
    Remove-Item -LiteralPath (Join-Path $StateDirectory 'Installer-error.log') -Force -ErrorAction SilentlyContinue
    Write-Output "Security Feature Monitor version $Version installed successfully."
    exit 0
}
catch {
    $failure = "$( [datetime]::UtcNow.ToString('o') )`r`n$($_ | Out-String)"
    if (Test-Path -LiteralPath $StateDirectory -PathType Container) {
        $failure | Set-Content -LiteralPath (Join-Path $StateDirectory 'Installer-error.log') -Encoding UTF8
    }
    [Console]::Error.WriteLine($failure)
    exit 1
}
