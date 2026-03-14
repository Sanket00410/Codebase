param(
    [ValidateSet("build", "runSwing", "runJavaFx", "smokeTestSwing", "smokeTestJavaFx")]
    [string]$Task = "build"
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$javaProject = Join-Path $root "apps\desktop-java"

& "$PSScriptRoot\bootstrap-java-desktop.ps1"

$env:JAVA_HOME = Join-Path $root ".tools\java-desktop\jdk"
$env:Path = "$(Join-Path $env:JAVA_HOME 'bin');$env:Path"

$gradle = Join-Path $root ".tools\java-desktop\gradle\bin\gradle.bat"
& $gradle -p $javaProject $Task
