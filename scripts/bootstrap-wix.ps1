param()

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$wixRoot = Join-Path $root ".tools\wix314"
$wixBin = Join-Path $wixRoot "bin"
$wixZip = Join-Path $wixRoot "wix314-binaries.zip"
$wixExe = Join-Path $wixBin "candle.exe"
$downloadUrl = "https://github.com/wixtoolset/wix3/releases/download/wix3141rtm/wix314-binaries.zip"

if (Test-Path $wixExe) {
    Write-Host "WIX_HOME=$wixBin"
    return
}

New-Item -ItemType Directory -Force -Path $wixRoot | Out-Null

if (-not (Test-Path $wixZip)) {
    $ProgressPreference = "SilentlyContinue"
    Invoke-WebRequest -Uri $downloadUrl -OutFile $wixZip
}

Expand-Archive -Path $wixZip -DestinationPath $wixBin -Force

if (-not (Test-Path $wixExe)) {
    throw "WiX bootstrap failed. candle.exe was not found in $wixBin"
}

Write-Host "WIX_HOME=$wixBin"
