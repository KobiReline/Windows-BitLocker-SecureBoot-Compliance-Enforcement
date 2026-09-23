[CmdletBinding()]
param([string]$RepositoryPath = (Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'Run this integration test only on the disposable GitHub Actions Windows runner.' }

# Load registration functions without executing the installer or backend pipeline.
foreach ($source in @(
    @{ File = 'Install-SecurityFeatureMonitor.ps1'; Names = @('Register-BackendTask', 'Register-UserInterfaceTask', 'Set-StopExistingTaskPolicy') },
    @{ File = 'SecurityFeatureMonitor-Backend.ps1'; Names = @('Set-BackendScheduledTask', 'Get-NextIntervalMinutes', 'Test-TaskRepairRequired') }
)) {
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $RepositoryPath $source.File), [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw "Invalid source: $($source.File)" }
    foreach ($name in $source.Names) {
        $definition = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
        . ([scriptblock]::Create($definition.Extent.Text))
    }
}

$InstallDirectory = Join-Path $env:TEMP 'SecurityFeatureMonitor-Test'
$BackendTaskName = 'Intune-SecurityFeatureMonitor'
$RepositoryRawBaseUrl = 'https://example.invalid'
$TestScenario = 'None'
$taskNames = @('Intune-SecurityFeatureMonitor', 'SecurityFeatureMonitor-UI')
foreach ($name in $taskNames) {
    if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) { throw "Refusing to overwrite an existing task: $name" }
}

function Assert-RegisteredTask {
    param([string]$Name)
    $task = Get-ScheduledTask -TaskName $Name -ErrorAction Stop
    Write-Host "Instance value: $($task.Settings.MultipleInstances); numeric: $([int]$task.Settings.MultipleInstances)"
    if ([int]$task.Settings.MultipleInstances -ne 3) { throw "Wrong instance policy: $Name" }
    if ([string]$task.State -eq 'Disabled') { throw "Task remains disabled: $Name" }
    [xml]$xml = Export-ScheduledTask -TaskName $Name
    if ($xml.Task.Settings.MultipleInstancesPolicy -ne 'StopExisting') { throw "Wrong XML instance policy: $Name" }
    Write-Host "PASS registration: $Name, enabled, StopExisting (3)." -ForegroundColor Green
}

try {
    Register-BackendTask
    Register-UserInterfaceTask
    foreach ($name in $taskNames) {
        Assert-RegisteredTask -Name $name
        Disable-ScheduledTask -TaskName $name | Out-Null
    }
    Register-BackendTask
    Register-UserInterfaceTask
    foreach ($name in $taskNames) { Assert-RegisteredTask -Name $name }
    if (Test-TaskRepairRequired) { throw 'Backend rejects freshly registered tasks.' }
    foreach ($zone in @('Healthy', 'Excluded', 'Warning', 'Critical', 'EncryptionInProgress')) {
        Set-BackendScheduledTask -Zone $zone
        Assert-RegisteredTask -Name $BackendTaskName
        $task = Get-ScheduledTask -TaskName $BackendTaskName
        $timeTriggers = @($task.Triggers | Where-Object { $_.CimClass.CimClassName -notmatch 'LogonTrigger' })
        if ($timeTriggers.Count -ne 1) { throw "Wrong trigger count: $zone" }
        if ($zone -in @('Healthy', 'Excluded')) {
            if ($timeTriggers[0].CimClass.CimClassName -notmatch 'DailyTrigger') { throw "Not daily: $zone" }
        } else {
            $expected = if ($zone -eq 'Critical') { 'PT5M' } else { 'PT1H' }
            if ($timeTriggers[0].Repetition.Interval -ne $expected) { throw "Wrong schedule: $zone" }
        }
        Write-Host "PASS real scheduler cadence: $zone" -ForegroundColor Green
    }
}
finally {
    foreach ($name in $taskNames) {
        Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
    }
}
