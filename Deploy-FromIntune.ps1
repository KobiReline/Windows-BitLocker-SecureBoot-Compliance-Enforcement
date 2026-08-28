[CmdletBinding()]
param(
    [string]$RepositoryRawBaseUrl = 'https://raw.githubusercontent.com/KobiReline/Windows-BitLocker-SecureBoot-Compliance-Enforcement/main',
    [string]$StagingDirectory = 'C:\ProgramData\SecurityFeatureMonitor-Staging'
)

$ErrorActionPreference = 'Stop'

function Assert-SystemAccount {
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18') { return }
    throw 'This deployment script must run as NT AUTHORITY\SYSTEM.'
}

function Save-RepositoryFile {
    param([Parameter(Mandatory)][string]$RelativePath)
    $destination = Join-Path $StagingDirectory $RelativePath
    $parent = Split-Path -Path $destination -Parent
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
    $url = "$($RepositoryRawBaseUrl.TrimEnd('/'))/$($RelativePath.Replace('\', '/'))"
    $temporaryPath = "$destination.download"
    try {
        Invoke-WebRequest -Uri $url -OutFile $temporaryPath -UseBasicParsing -ErrorAction Stop
        Move-Item -LiteralPath $temporaryPath -Destination $destination -Force
    }
    finally {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
    }
}

Assert-SystemAccount
foreach ($relativePath in @(
    'Install-SecurityFeatureMonitor.ps1',
    'SecurityFeatureMonitor-Backend.ps1',
    'SecurityFeatureMonitor-UI.ps1',
    'Set-SecurityFeatureMonitorTestMode.ps1',
    'media\bip.wav',
    'media\alarm.mp3'
)) {
    Save-RepositoryFile -RelativePath $relativePath
}

& (Join-Path $StagingDirectory 'Install-SecurityFeatureMonitor.ps1') -SourceDirectory $StagingDirectory
exit $LASTEXITCODE
