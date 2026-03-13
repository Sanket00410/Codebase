param(
  [string]$PythonCommand = ""
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$venvPython = Join-Path $root ".venv\Scripts\python.exe"
if ([string]::IsNullOrWhiteSpace($PythonCommand)) {
  if (Test-Path $venvPython) {
    $PythonCommand = $venvPython
  } else {
    $PythonCommand = "py -3.12"
  }
}
$backendDir = Join-Path $root "services\scanner-core"
$desktopBackendDir = Join-Path $root "apps\desktop\src-tauri\backend"

Push-Location $backendDir
Invoke-Expression "& `"$PythonCommand`" -m pip install --upgrade pip setuptools wheel pyinstaller"
Invoke-Expression "& `"$PythonCommand`" -m pip install ."
Invoke-Expression "& `"$PythonCommand`" -m PyInstaller --noconfirm security-platform-backend.spec"
Pop-Location

New-Item -ItemType Directory -Force -Path $desktopBackendDir | Out-Null
$sourceExe = Join-Path $backendDir "dist\security-platform-backend.exe"
$sourceBin = Join-Path $backendDir "dist\security-platform-backend"

if (Test-Path $sourceExe) {
  Copy-Item $sourceExe (Join-Path $desktopBackendDir "security-platform-backend.exe") -Force
} elseif (Test-Path $sourceBin) {
  Copy-Item $sourceBin (Join-Path $desktopBackendDir "security-platform-backend") -Force
} else {
  throw "Backend artifact was not generated."
}
