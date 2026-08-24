[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^https://raw\.githubusercontent\.com/')][string]$BackendScriptUrl,
    [Parameter(Mandatory)][ValidatePattern('^https://raw\.githubusercontent\.com/')][string]$RepositoryRawBaseUrl,
    [string]$CachePath = 'C:\ProgramData\SecurityFeatureMonitor\SecurityFeatureMonitor-Backend.cached.ps1',
    [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$TrustedSignerThumbprint
)

$ErrorActionPreference = 'Stop'

function Test-TrustedPowerShellSignature {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Thumbprint)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid') { return $false }
    if ($null -eq $signature.SignerCertificate) { return $false }
    return $signature.SignerCertificate.Thumbprint -eq $Thumbprint
}

function Save-LatestTrustedBackend {
    param([Parameter(Mandatory)][string]$Url, [Parameter(Mandatory)][string]$Destination, [Parameter(Mandatory)][string]$Thumbprint)
    $temporaryPath = "$Destination.download"
    try {
        Invoke-WebRequest -Uri $Url -OutFile $temporaryPath -UseBasicParsing -ErrorAction Stop
        if (-not (Test-TrustedPowerShellSignature -Path $temporaryPath -Thumbprint $Thumbprint)) { throw 'Downloaded backend signature validation failed.' }
        Move-Item -LiteralPath $temporaryPath -Destination $Destination -Force
        return $true
    }
    catch {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        Write-Warning "Latest backend could not be cached: $($_.Exception.Message)"
        return $false
    }
}

function Invoke-CachedBackend {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Thumbprint,
        [Parameter(Mandatory)][string]$RawBaseUrl
    )
    if (-not (Test-TrustedPowerShellSignature -Path $Path -Thumbprint $Thumbprint)) { throw 'No trusted cached backend is available.' }
    & $Path -InstallScheduledTask -RepositoryRawBaseUrl $RawBaseUrl -TrustedSignerThumbprint $Thumbprint
    return $LASTEXITCODE
}

$cacheDirectory = Split-Path -Path $CachePath -Parent
if (-not (Test-Path -LiteralPath $cacheDirectory -PathType Container)) { New-Item -Path $cacheDirectory -ItemType Directory -Force | Out-Null }
[void](Save-LatestTrustedBackend -Url $BackendScriptUrl -Destination $CachePath -Thumbprint $TrustedSignerThumbprint)
exit (Invoke-CachedBackend -Path $CachePath -Thumbprint $TrustedSignerThumbprint -RawBaseUrl $RepositoryRawBaseUrl)
