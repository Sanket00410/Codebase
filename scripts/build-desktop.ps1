$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
Push-Location $root

& "$PSScriptRoot\build-backend.ps1"
npm install
npm --workspace apps/desktop run tauri build

Pop-Location

