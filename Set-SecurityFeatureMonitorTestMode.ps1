[CmdletBinding(DefaultParameterSetName = 'Enable')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Enable')]
    [ValidateSet('Healthy', 'Warning', 'Critical')]
    [string]$Scenario,
    [Parameter(ParameterSetName = 'Enable')]
    [ValidateRange(1, 1440)]
    [int]$AlertIntervalMinutes = 1,
    [Parameter(Mandatory, ParameterSetName = 'Disable')]
    [switch]$Disable,
    [string]$RegistryPath = 'HKLM:\SOFTWARE\CustomSecurityCheck'
)

$ErrorActionPreference = 'Stop'

function Assert-SystemOrAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($identity.User.Value -eq 'S-1-5-18') { return }
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { return }
    throw 'Changing test mode requires SYSTEM or an elevated administrator token.'
}

Assert-SystemOrAdministrator
if (-not (Test-Path -LiteralPath $RegistryPath)) { New-Item -Path $RegistryPath -Force | Out-Null }

if ($Disable) {
    Set-ItemProperty -Path $RegistryPath -Name TestModeEnabled -Value 0 -Type DWord -Force
}
else {
    Set-ItemProperty -Path $RegistryPath -Name TestModeEnabled -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $RegistryPath -Name TestScenario -Value $Scenario -Type String -Force
    Set-ItemProperty -Path $RegistryPath -Name TestAlertIntervalMinutes -Value $AlertIntervalMinutes -Type DWord -Force
    Set-ItemProperty -Path $RegistryPath -Name TestActivationId -Value ([guid]::NewGuid().ToString()) -Type String -Force
}

Start-ScheduledTask -TaskName 'Intune-SecurityFeatureMonitor'
Start-Sleep -Seconds 3
Start-ScheduledTask -TaskName 'SecurityFeatureMonitor-UI'
