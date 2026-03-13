# Build And Packaging

## Prerequisites

- Node.js 20+
- Rust toolchain with Cargo
- Python 3.11+ available as `python` on Windows or `python3` on macOS/Linux
- Platform packaging prerequisites for Tauri

Linux packages typically required for Tauri:

- `libwebkit2gtk-4.1-dev`
- `build-essential`
- `curl`
- `wget`
- `file`
- `libxdo-dev`
- `libssl-dev`
- `libayatana-appindicator3-dev`
- `librsvg2-dev`

## Development

Backend only:

```powershell
cd services\scanner-core
python -m pip install -e .
python -m security_platform.cli serve --host 127.0.0.1 --port 8686
```

Desktop in development mode:

```powershell
npm install
npm --workspace apps/desktop run tauri dev
```

The desktop host will launch the backend automatically. If you want to point it at a prebuilt backend, set `SCANNER_PLATFORM_BACKEND` to the backend executable path.

## Packaging

Build the backend sidecar:

```powershell
.\scripts\build-backend.ps1
```

Build native desktop installers:

```powershell
.\scripts\build-desktop.ps1
```

Equivalent shell scripts are provided for macOS/Linux:

```bash
./scripts/build-backend.sh
./scripts/build-desktop.sh
```

## Backend packaging

The PyInstaller spec at [security-platform-backend.spec](/C:/Users/DarkWorld/Documents/CODE_BASE_SCANNER/services/scanner-core/security-platform-backend.spec) creates a standalone backend executable. The build scripts copy the artifact into [backend](/C:/Users/DarkWorld/Documents/CODE_BASE_SCANNER/apps/desktop/src-tauri/backend) so Tauri can bundle it as a resource.

## Production notes

- Replace the generated icon assets with signed production artwork before release.
- Sign Windows and macOS artifacts in CI for trusted distribution.
- Cache Python wheels, Cargo dependencies, and npm modules in CI to reduce build time.
- For offline deployments, pre-install required scanners and refresh advisory databases before packaging or imaging the workstation.

