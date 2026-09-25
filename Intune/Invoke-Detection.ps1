# Stable Intune entry point. Business logic and its hashes are maintained in GitHub.
function Assert-BootstrapContext {
    if (-not [Environment]::Is64BitProcess) { throw 'Configure Intune to use 64-bit PowerShell.' }
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') {
        throw 'Configure Intune to run as SYSTEM, not the logged-on user.'
    }
}

function Invoke-IntuneBootstrap {
    param(
        [ValidateSet('Detection', 'Remediation')][string]$Role,
        [string]$WorkingRoot = 'C:\ProgramData\SecurityFeatureMonitor\Staging'
    )
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    $runDirectory = $null
    $commit = $null
    $stage = 'Context'
    try {
        Assert-BootstrapContext
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $repository = 'KobiReline/Windows-BitLocker-SecureBoot-Compliance-Enforcement'
        $stage = 'ResolveCommit'
        $headers = @{ 'User-Agent' = 'SecurityFeatureMonitor-Intune'; 'Cache-Control' = 'no-cache' }
        $reference = Invoke-RestMethod -Uri "https://api.github.com/repos/$repository/git/ref/heads/main" -Headers $headers -TimeoutSec 30 -UseBasicParsing
        $commit = [string]$reference.object.sha
        if ($commit -notmatch '^[0-9a-fA-F]{40}$') { throw 'Invalid repository commit.' }
        $baseUrl = "https://raw.githubusercontent.com/$repository/$commit"
        $stage = 'Manifest'
        $manifest = Invoke-RestMethod -Uri "$baseUrl/manifest.json" -TimeoutSec 30 -UseBasicParsing
        $entry = $manifest.EntryPoints.$Role
        $fileName = if ($Role -eq 'Detection') { 'Detect-SecurityFeatureMonitor.ps1' } else { 'Deploy-FromIntune.ps1' }
        if ($manifest.Schema -ne 1 -or $entry.Source -ne $fileName -or [string]$entry.Sha256 -notmatch '^[0-9a-fA-F]{64}$') {
            throw 'Invalid or missing manifest entry point.'
        }
        $stage = 'Staging'
        $runDirectory = Join-Path $WorkingRoot ('Bootstrap-' + [guid]::NewGuid().ToString('N'))
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
            $identity = [Security.Principal.SecurityIdentifier]::new($sid)
            $rule = [Security.AccessControl.FileSystemAccessRule]::new($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            $acl.AddAccessRule($rule)
        }
        [IO.Directory]::CreateDirectory($runDirectory, $acl) | Out-Null
        $path = Join-Path $runDirectory $fileName
        $stage = 'Download'
        Invoke-WebRequest -Uri "$baseUrl/$fileName" -OutFile $path -TimeoutSec 30 -UseBasicParsing | Out-Null
        $stage = 'Hash'
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $entry.Sha256) { throw 'SHA-256 mismatch; execution refused.' }
        $stage = 'Syntax'
        $tokens = $null
        $parseErrors = $null
        [Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$parseErrors) | Out-Null
        if ($parseErrors.Count) { throw "Invalid PowerShell syntax: $($parseErrors[0].Message)" }
        $stage = 'Execute'
        $stdout = Join-Path $runDirectory 'stdout.txt'
        $stderr = Join-Path $runDirectory 'stderr.txt'
        $command = "[Console]::OutputEncoding = [Text.UTF8Encoding]::new(); `$ErrorActionPreference = 'Stop'; `$ProgressPreference = 'SilentlyContinue'; `$global:LASTEXITCODE = 0; try { & '$($path.Replace("'", "''"))' -RepositoryRawBaseUrl '$baseUrl'; exit `$LASTEXITCODE } catch { [Console]::Error.WriteLine((`$_ | Out-String)); exit 2 }"
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
        $hostPath = Join-Path $PSHOME 'powershell.exe'
        $process = Start-Process -FilePath $hostPath -ArgumentList @('-NoProfile', '-NonInteractive', '-OutputFormat', 'Text', '-InputFormat', 'Text', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encoded) -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        [Console]::Out.Write([IO.File]::ReadAllText($stdout, [Text.Encoding]::UTF8))
        [Console]::Error.Write([IO.File]::ReadAllText($stderr, [Text.Encoding]::UTF8))
        return [int]$process.ExitCode
    }
    catch {
        $message = $_.Exception.Message
        if ($message.Length -gt 700) { $message = $message.Substring(0, 700) }
        $result = @{ Schema = 1; Status = 'BootstrapFailed'; Role = $Role; Stage = $stage; Commit = $commit; Error = $message; Utc = [datetime]::UtcNow.ToString('o') }
        [Console]::Out.WriteLine(($result | ConvertTo-Json -Compress))
        return 2
    }
    finally {
        if ($runDirectory -and (Test-Path -LiteralPath $runDirectory)) {
            Remove-Item -LiteralPath $runDirectory -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

exit (Invoke-IntuneBootstrap -Role Detection)
