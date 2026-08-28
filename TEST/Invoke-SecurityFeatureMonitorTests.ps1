<#
.SYNOPSIS
Runs read-only post-deployment tests for Security Feature Monitor.

.DESCRIPTION
Run in 64-bit Windows PowerShell as Administrator. The script does not change
BitLocker, Secure Boot, scheduled tasks, files, ACLs, Registry, or test mode.
It prints PASS in green, WARN in yellow, and FAIL in red, followed by a summary
and an exit code: 0 = all required checks passed, 1 = one or more checks failed.

PASS means the observed value matches the expected installed configuration.
WARN means the result is informative or could not be fully validated offline.
FAIL means Intune Remediation should be run and its post-remediation output checked.

.EXAMPLE
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\TEST\Invoke-SecurityFeatureMonitorTests.ps1

Expected healthy summary:
PASS: <number>  WARN: 0 or more  FAIL: 0
OVERALL: PASS
#>
[CmdletBinding()]
param(
    [string]$InstallDirectory = 'C:\ProgramData\SecurityFeatureMonitor',
    [string]$BackendTaskName = 'Intune-SecurityFeatureMonitor',
    [string]$UiTaskName = 'SecurityFeatureMonitor-UI'
)

$ErrorActionPreference = 'Stop'
$script:Passed = 0
$script:Warned = 0
$script:Failed = 0

function Write-TestResult {
    param(
        [Parameter(Mandatory)][ValidateSet('PASS', 'WARN', 'FAIL')][string]$Status,
        [Parameter(Mandatory)][string]$Test,
        [Parameter(Mandatory)][string]$Observed,
        [Parameter(Mandatory)][string]$Expected
    )
    $colour = switch ($Status) { 'PASS' { 'Green' } 'WARN' { 'Yellow' } 'FAIL' { 'Red' } }
    switch ($Status) { 'PASS' { $script:Passed++ } 'WARN' { $script:Warned++ } 'FAIL' { $script:Failed++ } }
    Write-Host "[$Status] $Test" -ForegroundColor $colour
    Write-Host "       Received: $Observed" -ForegroundColor $colour
    Write-Host "       Expected: $Expected" -ForegroundColor DarkGray
}

function Test-Condition {
    param([bool]$Condition, [string]$Test, [string]$Observed, [string]$Expected, [switch]$Warning)
    if ($Condition) { Write-TestResult PASS $Test $Observed $Expected }
    elseif ($Warning) { Write-TestResult WARN $Test $Observed $Expected }
    else { Write-TestResult FAIL $Test $Observed $Expected }
}

function Get-InstalledPath {
    param($Entry)
    switch ([string]$Entry.Target) {
        'Install' { Join-Path $InstallDirectory ([string]$Entry.Destination) }
        'Media' { Join-Path (Join-Path $InstallDirectory 'media') ([string]$Entry.Destination) }
        default { $null }
    }
}

Write-Host 'Security Feature Monitor - post-deployment tests' -ForegroundColor Cyan
Write-Host "Computer: $env:COMPUTERNAME  UTC: $((Get-Date).ToUniversalTime().ToString('o'))" -ForegroundColor DarkGray

$isWindows = $env:OS -eq 'Windows_NT'
Test-Condition $isWindows 'Operating system' ([string]$env:OS) 'Windows_NT'
if (-not $isWindows) { exit 1 }

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$isElevated = $identity.User.Value -eq 'S-1-5-18' -or $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Test-Condition $isElevated 'Execution privilege' $identity.Name 'SYSTEM or elevated Administrator'

Test-Condition (Test-Path -LiteralPath $InstallDirectory -PathType Container) 'Installation directory' $InstallDirectory 'Directory exists'
$manifestPath = Join-Path $InstallDirectory 'manifest.json'
$manifest = $null
try { $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -ErrorAction Stop }
catch { Write-TestResult FAIL 'Local manifest' $_.Exception.Message 'Readable valid JSON at the installed path' }
if ($null -ne $manifest) {
    Write-TestResult PASS 'Local manifest' "Schema=$($manifest.Schema); Version=$($manifest.Version)" 'Readable manifest with file hashes'
    foreach ($entry in $manifest.Files) {
        $path = Get-InstalledPath $entry
        if ($null -eq $path) { continue }
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            Write-TestResult FAIL "File $($entry.Destination)" 'Missing' "Present; SHA-256=$($entry.Sha256)"
            continue
        }
        $actualHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        Test-Condition ($actualHash -eq [string]$entry.Sha256) "Hash $($entry.Destination)" $actualHash ([string]$entry.Sha256)
    }
    $versionPath = Join-Path $InstallDirectory 'Version.txt'
    $installedVersion = if (Test-Path $versionPath) { (Get-Content $versionPath -Raw).Trim() } else { '<missing>' }
    Test-Condition ($installedVersion -eq [string]$manifest.Version) 'Installed version label' $installedVersion ([string]$manifest.Version) -Warning
}

foreach ($definition in @(
    @{ Name = $BackendTaskName; Identity = '(?i)^(SYSTEM|NT AUTHORITY\\SYSTEM)$'; Script = 'SecurityFeatureMonitor-Backend\.cached\.ps1'; Label = 'Backend task' },
    @{ Name = $UiTaskName; Identity = '(?i)^(BUILTIN\\Users|S-1-5-32-545)$'; Script = 'SecurityFeatureMonitor-UI\.ps1'; Label = 'UI task' }
)) {
    $task = Get-ScheduledTask -TaskName $definition.Name -ErrorAction SilentlyContinue
    if ($null -eq $task) { Write-TestResult FAIL $definition.Label 'Missing' "Scheduled task '$($definition.Name)' exists"; continue }
    Write-TestResult PASS $definition.Label $task.TaskName "Scheduled task '$($definition.Name)' exists"
    $taskIdentity = if ([string]::IsNullOrWhiteSpace([string]$task.Principal.GroupId)) { [string]$task.Principal.UserId } else { [string]$task.Principal.GroupId }
    Test-Condition ($taskIdentity -match $definition.Identity) "$($definition.Label) identity" $taskIdentity $definition.Identity
    Test-Condition ([string]$task.Actions.Arguments -match $definition.Script) "$($definition.Label) action" ([string]$task.Actions.Arguments) $definition.Script
    $taskInfo = Get-ScheduledTaskInfo -TaskName $definition.Name -ErrorAction SilentlyContinue
    if ($null -ne $taskInfo) {
        $resultText = "Last=$($taskInfo.LastRunTime); Result=$($taskInfo.LastTaskResult); Next=$($taskInfo.NextRunTime)"
        Test-Condition ($taskInfo.LastTaskResult -in @(0, 267011)) "$($definition.Label) last result" $resultText '0 after a completed run; 267011 means never run' -Warning
    }
}

$acl = Get-Acl -LiteralPath $InstallDirectory -ErrorAction SilentlyContinue
if ($null -eq $acl) { Write-TestResult FAIL 'NTFS ACL' 'Could not read ACL' 'Protected ACL readable' }
else {
    Test-Condition $acl.AreAccessRulesProtected 'NTFS inheritance' ([string]$acl.AreAccessRulesProtected) 'True (parent ACEs are not inherited)'
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-32-545')) {
        $rule = @($acl.Access | Where-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq $sid -and $_.AccessControlType -eq 'Allow' })
        Test-Condition ($rule.Count -gt 0) "NTFS rule $sid" (($rule.FileSystemRights -join ', ')) 'SYSTEM/Admins FullControl or Users ReadAndExecute'
    }
}

$statePath = Join-Path $InstallDirectory 'State\State.json'
try {
    $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json -ErrorAction Stop
    Test-Condition ([int]$state.SchemaVersion -eq 1) 'State schema' ([string]$state.SchemaVersion) '1'
    Test-Condition ([string]$state.Zone -in @('Healthy','Excluded','Grace','Warning','Critical')) 'State zone' ([string]$state.Zone) 'Healthy, Excluded, Grace, Warning, or Critical'
    $colour = if ([bool]$state.IsCompliant) { 'Green' } else { 'Yellow' }
    Write-Host "[INFO] Backend state: Zone=$($state.Zone); SecureBoot=$($state.SecureBoot); BitLocker=$($state.BitLocker); GeneratedUtc=$($state.GeneratedUtc)" -ForegroundColor $colour
}
catch { Write-TestResult FAIL 'Backend state' $_.Exception.Message 'Readable State\State.json created by an immediate backend run' }

Write-Host ''
Write-Host "PASS: $script:Passed  WARN: $script:Warned  FAIL: $script:Failed" -ForegroundColor $(if ($script:Failed) { 'Red' } elseif ($script:Warned) { 'Yellow' } else { 'Green' })
if ($script:Failed) { Write-Host 'OVERALL: FAIL - run Intune Remediation and repeat this test.' -ForegroundColor Red; exit 1 }
Write-Host 'OVERALL: PASS' -ForegroundColor Green
exit 0
