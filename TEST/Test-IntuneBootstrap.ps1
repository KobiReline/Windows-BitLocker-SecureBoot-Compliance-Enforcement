[CmdletBinding()]
param([string]$RepositoryPath = (Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference = 'Stop'
$testRoot = Join-Path $env:TEMP ('BootstrapTests-' + [guid]::NewGuid().ToString('N'))
New-Item -Path $testRoot -ItemType Directory | Out-Null
try {
    foreach ($role in @('Detection', 'Remediation')) {
        $wrapper = Join-Path $RepositoryPath "Intune\Invoke-$role.ps1"
        $tokens = $null
        $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile($wrapper, [ref]$tokens, [ref]$errors)
        if ($errors.Count) { throw 'Wrapper syntax failed.' }
        $definitions = $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $false)
        $functions = ($definitions | ForEach-Object { $_.Extent.Text }) -join "`r`n"
        foreach ($scenario in @('Exit0', 'Exit1', 'Exit2', 'Throw', 'HashFailure', 'SyntaxFailure', 'Offline', 'MissingEntry')) {
            $caseRoot = Join-Path $testRoot "$role-$scenario"
            New-Item -Path $caseRoot -ItemType Directory | Out-Null
            $payloadPath = Join-Path $caseRoot 'payload.ps1'
            $markerPath = Join-Path $caseRoot 'executed.txt'
            $exitCode = if ($scenario -match '^Exit(\d)$') { [int]$Matches[1] } else { 0 }
            $payload = @'
param([string]$RepositoryRawBaseUrl)
if ($RepositoryRawBaseUrl -notmatch '/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa$') { throw 'Snapshot not forwarded.' }
$acl = Get-Acl -LiteralPath $PSScriptRoot
if (-not $acl.AreAccessRulesProtected) { throw 'Bootstrap directory ACL is not protected.' }
if (@($acl.Access | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18', 'S-1-5-32-544') }).Count) { throw 'Unexpected staging access.' }
[Console]::Out.WriteLine('fixture-output-' + [char]0x05D0)
[Console]::Error.WriteLine('fixture-error')
'@
            $payload += "`r`n[IO.File]::WriteAllText('$($markerPath.Replace("'", "''"))', 'executed')`r`nexit $exitCode`r`n"
            if ($scenario -eq 'Throw') { $payload = $payload.Replace("exit $exitCode", "throw 'Fixture terminating exception'") }
            if ($scenario -eq 'SyntaxFailure') { $payload += "`r`nif (" }
            [IO.File]::WriteAllText($payloadPath, $payload, [Text.UTF8Encoding]::new($false))
            $sha = (Get-FileHash -LiteralPath $payloadPath -Algorithm SHA256).Hash
            if ($scenario -eq 'HashFailure') { $sha = '0' * 64 }
            $source = if ($role -eq 'Detection') { 'Detect-SecurityFeatureMonitor.ps1' } else { 'Deploy-FromIntune.ps1' }
            $fixture = @{ Role = $role; Scenario = $scenario; Payload = $payloadPath; Manifest = @{ Schema = 1; EntryPoints = @{ $role = @{ Source = $source; Sha256 = $sha } } } }
            if ($scenario -eq 'MissingEntry') { $fixture.Manifest.EntryPoints = @{} }
            $fixturePath = Join-Path $caseRoot 'fixture.json'
            $fixture | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $fixturePath -Encoding UTF8
            $mocks = @'
function Assert-BootstrapContext { }
function Invoke-RestMethod {
    param($Uri, $Headers, $TimeoutSec, [switch]$UseBasicParsing)
    if ($script:Fixture.Scenario -eq 'Offline') { throw 'Fixture offline.' }
    if ($Uri -match '/git/ref/heads/main$') { return @{ object = @{ sha = ('a' * 40) } } }
    if ($Uri -notmatch '/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/manifest.json$') { throw 'Manifest not pinned.' }
    return $script:Fixture.Manifest
}
function Invoke-WebRequest {
    param($Uri, $OutFile, $TimeoutSec, [switch]$UseBasicParsing)
    if ($Uri -notmatch '/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/') { throw 'Payload not pinned.' }
    Copy-Item -LiteralPath $script:Fixture.Payload -Destination $OutFile
}
'@
            $harness = "[Console]::OutputEncoding = [Text.UTF8Encoding]::new()`r`n$functions`r`n$mocks`r`n"
            $harness += "`$script:Fixture = Get-Content -LiteralPath '$($fixturePath.Replace("'", "''"))' -Raw | ConvertFrom-Json`r`n"
            $harness += "exit (Invoke-IntuneBootstrap -Role $role -WorkingRoot '$($caseRoot.Replace("'", "''"))')`r`n"
            $harnessPath = Join-Path $caseRoot 'harness.ps1'
            [IO.File]::WriteAllText($harnessPath, $harness, [Text.UTF8Encoding]::new($false))
            $outPath = Join-Path $caseRoot 'output.txt'
            $errPath = Join-Path $caseRoot 'error.txt'
            $process = Start-Process -FilePath "$PSHOME\powershell.exe" -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $harnessPath)) -Wait -PassThru -RedirectStandardOutput $outPath -RedirectStandardError $errPath
            $output = [IO.File]::ReadAllText($outPath, [Text.Encoding]::UTF8).Trim()
            $errorOutput = [IO.File]::ReadAllText($errPath, [Text.Encoding]::UTF8).Trim()
            if ($scenario -like 'Exit*') {
                if ($process.ExitCode -ne $exitCode -or $output -ne ('fixture-output-' + [char]0x05D0) -or $errorOutput -ne 'fixture-error' -or -not (Test-Path $markerPath)) {
                    throw "$role/$scenario forwarding failed: exit=$($process.ExitCode); out=$output; err=$errorOutput"
                }
            } elseif ($scenario -eq 'Throw') {
                if ($process.ExitCode -ne 2 -or $errorOutput -notmatch 'Fixture terminating exception') { throw 'Uncaught exception was not reported as failure.' }
            } else {
                $result = $output | ConvertFrom-Json
                $expectedStage = @{ HashFailure = 'Hash'; SyntaxFailure = 'Syntax'; Offline = 'ResolveCommit'; MissingEntry = 'Manifest' }[$scenario]
                if ($process.ExitCode -ne 2 -or $result.Status -ne 'BootstrapFailed' -or $result.Stage -ne $expectedStage -or (Test-Path $markerPath)) {
                    throw "$role/$scenario did not fail closed: $output $errorOutput"
                }
            }
            if (@(Get-ChildItem $caseRoot -Directory -Filter 'Bootstrap-*').Count) { throw 'Temporary execution folder was not cleaned.' }
            Write-Host "PASS bootstrap $role/$scenario" -ForegroundColor Green
        }
    }
}
finally { Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue }
