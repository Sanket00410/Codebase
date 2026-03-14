$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$toolsRoot = Join-Path $root ".tools\java-desktop"
$downloadsRoot = Join-Path $toolsRoot "downloads"
$jdkRoot = Join-Path $toolsRoot "jdk"
$gradleRoot = Join-Path $toolsRoot "gradle"

New-Item -ItemType Directory -Force -Path $downloadsRoot | Out-Null

function Expand-SingleDirectoryZip {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ZipPath,
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath
    )

    $extractRoot = Join-Path $downloadsRoot ([System.IO.Path]::GetFileNameWithoutExtension($ZipPath))
    if (Test-Path $extractRoot) {
        Remove-Item -Recurse -Force $extractRoot
    }

    Expand-Archive -Path $ZipPath -DestinationPath $extractRoot -Force
    $childDirectory = Get-ChildItem -Path $extractRoot -Directory | Select-Object -First 1
    if (-not $childDirectory) {
        throw "Archive $ZipPath did not contain a top-level directory."
    }

    if (Test-Path $DestinationPath) {
        Remove-Item -Recurse -Force $DestinationPath
    }

    Move-Item -Path $childDirectory.FullName -Destination $DestinationPath
    Remove-Item -Recurse -Force $extractRoot
}

if (-not (Test-Path (Join-Path $jdkRoot "bin\java.exe"))) {
    $jdkZip = Join-Path $downloadsRoot "temurin-jdk21.zip"
    Write-Host "Downloading Temurin JDK 21..."
    Invoke-WebRequest `
        -Uri "https://api.adoptium.net/v3/binary/latest/21/ga/windows/x64/jdk/hotspot/normal/eclipse" `
        -OutFile $jdkZip
    Expand-SingleDirectoryZip -ZipPath $jdkZip -DestinationPath $jdkRoot
}

if (-not (Test-Path (Join-Path $gradleRoot "bin\gradle.bat"))) {
    $gradleZip = Join-Path $downloadsRoot "gradle-8.10.2-bin.zip"
    Write-Host "Downloading Gradle 8.10.2..."
    Invoke-WebRequest `
        -Uri "https://services.gradle.org/distributions/gradle-8.10.2-bin.zip" `
        -OutFile $gradleZip
    Expand-SingleDirectoryZip -ZipPath $gradleZip -DestinationPath $gradleRoot
}

Write-Host "JAVA_HOME=$jdkRoot"
Write-Host "GRADLE_HOME=$gradleRoot"
