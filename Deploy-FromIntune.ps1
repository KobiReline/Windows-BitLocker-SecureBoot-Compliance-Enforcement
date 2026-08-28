[CmdletBinding()]
param(
    [string]$RepositoryRawBaseUrl = 'https://raw.githubusercontent.com/KobiReline/Windows-BitLocker-SecureBoot-Compliance-Enforcement/main',
    [string]$StagingDirectory = 'C:\ProgramData\SecurityFeatureMonitor-Staging',
    [string]$ManifestName = 'manifest.json'
)

$ErrorActionPreference = 'Stop'
$resultPath = 'C:\ProgramData\SecurityFeatureMonitor\RemediationResult.json'

function Assert-SystemAccount {
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18') { return }
    throw 'This remediation must run as NT AUTHORITY\SYSTEM.'
}

function Test-HashMatch {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Sha256)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -eq $Sha256
}

function Save-VerifiedRepositoryFile {
    param(
        [Parameter(Mandatory)][string]$RelativePath,
        [Parameter(Mandatory)][string]$ExpectedSha256
    )
    $destination = Join-Path $StagingDirectory $RelativePath
    $parent = Split-Path -Path $destination -Parent
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
    $url = "$($RepositoryRawBaseUrl.TrimEnd('/'))/$($RelativePath.Replace('\', '/'))"
    $temporaryPath = "$destination.download"
    try {
        Invoke-WebRequest -Uri $url -OutFile $temporaryPath -UseBasicParsing -ErrorAction Stop
        if (-not (Test-HashMatch -Path $temporaryPath -Sha256 $ExpectedSha256)) { throw "SHA-256 mismatch: $RelativePath" }
        Move-Item -LiteralPath $temporaryPath -Destination $destination -Force
    }
    finally {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
    }
}

function Write-RemediationResult {
    param([Parameter(Mandatory)][hashtable]$Result)
    $parent = Split-Path -Path $resultPath -Parent
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
    $Result | ConvertTo-Json -Compress -Depth 5 | Set-Content -LiteralPath $resultPath -Encoding UTF8 -Force
}

Assert-SystemAccount
$manifestPath = Join-Path $StagingDirectory $ManifestName
$manifestUrl = "$($RepositoryRawBaseUrl.TrimEnd('/'))/$ManifestName"
if (-not (Test-Path -LiteralPath $StagingDirectory -PathType Container)) { New-Item -Path $StagingDirectory -ItemType Directory -Force | Out-Null }

try {
    Invoke-WebRequest -Uri $manifestUrl -OutFile $manifestPath -UseBasicParsing -ErrorAction Stop
    $manifest = Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    foreach ($file in $manifest.Files) {
        Save-VerifiedRepositoryFile -RelativePath ([string]$file.Source) -ExpectedSha256 ([string]$file.Sha256)
    }

    $installer = Join-Path $StagingDirectory 'Install-SecurityFeatureMonitor.ps1'
    $installerArguments = @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', $installer,
        '-SourceDirectory', $StagingDirectory,
        '-Version', [string]$manifest.Version,
        '-RecoveryMode'
    )
    $installerProcess = Start-Process -FilePath 'powershell.exe' -ArgumentList $installerArguments -WindowStyle Hidden -Wait -PassThru
    if ($installerProcess.ExitCode -ne 0) { throw "Installer exit code: $($installerProcess.ExitCode)" }

    Write-RemediationResult -Result @{
        Schema = 1
        Utc = (Get-Date).ToUniversalTime().ToString('o')
        Status = 'RepairCompleted'
        Version = [string]$manifest.Version
    }
    Write-Output (@{ Schema = 1; Status = 'RepairCompleted'; Version = [string]$manifest.Version } | ConvertTo-Json -Compress)
    exit 0
}
catch {
    Write-RemediationResult -Result @{
        Schema = 1
        Utc = (Get-Date).ToUniversalTime().ToString('o')
        Status = 'RepairFailed'
        Error = $_.Exception.Message
    }
    Write-Error $_.Exception.Message
    exit 1
}
