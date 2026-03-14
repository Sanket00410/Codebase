param(
    [ValidateSet("swing", "javafx", "both")]
    [string]$Flavor = "both",
    [ValidateSet("app-image", "exe", "msi")]
    [string]$Type = "app-image"
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$javaProject = Join-Path $root "apps\desktop-java"

& "$PSScriptRoot\bootstrap-java-desktop.ps1"

$env:JAVA_HOME = Join-Path $root ".tools\java-desktop\jdk"
$env:Path = "$(Join-Path $env:JAVA_HOME 'bin');$env:Path"

$gradle = Join-Path $root ".tools\java-desktop\gradle\bin\gradle.bat"

switch ($Flavor) {
    "swing" {
        switch ($Type) {
            "app-image" { & $gradle -p $javaProject packageSwingAppImage }
            "exe" { & $gradle -p $javaProject packageSwingExe }
            "msi" { & $gradle -p $javaProject packageSwingMsi }
        }
    }
    "javafx" {
        switch ($Type) {
            "app-image" { & $gradle -p $javaProject packageJavaFxAppImage }
            "exe" { & $gradle -p $javaProject packageJavaFxExe }
            "msi" { & $gradle -p $javaProject packageJavaFxMsi }
        }
    }
    "both" {
        switch ($Type) {
            "app-image" {
                & $gradle -p $javaProject packageSwingAppImage
                & $gradle -p $javaProject packageJavaFxAppImage
            }
            "exe" {
                & $gradle -p $javaProject packageSwingExe
                & $gradle -p $javaProject packageJavaFxExe
            }
            "msi" {
                & $gradle -p $javaProject packageSwingMsi
                & $gradle -p $javaProject packageJavaFxMsi
            }
        }
    }
}
