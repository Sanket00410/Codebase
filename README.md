# Code Base Scanner

Code Base Scanner is a local-first desktop security scanning platform built as a cross-platform monorepo. The product uses a native desktop host, an embedded local API, and a plugin-based scanning core that executes real security tools against local repositories.

## Monorepo layout

- `apps/desktop`: Tauri desktop application and React frontend.
- `services/scanner-core`: FastAPI backend, scanner runtime, report generation, binary management, and CLI.
- `docs`: architecture, packaging, operational guidance.
- `ci`: CI/CD templates and automation assets.

## Primary design choices

- Desktop host: Tauri + Rust for low-overhead native packaging on Windows, macOS, and Linux.
- Backend: Python for scanner integration breadth, report generation, and AI/knowledge workflows.
- Execution model: local process orchestration with OS-aware binary management and offline-capable storage.
- Data model: normalized findings with CVE/CWE/CVSS, SARIF export, HTML/PDF reporting, and SQLite persistence.

## Status

The repository contains a production-oriented baseline that is ready to extend with more scanner plugins, richer desktop UX, and distribution automation. All implemented plugins execute real external tools and parse their native output formats.

## Implemented scanner integrations

- SAST: `semgrep`, `bandit`
- Secrets: `gitleaks`
- IaC: `checkov`, `trivy` misconfiguration parsing
- SCA: `osv-scanner`, `grype`, `trivy` vulnerability parsing
- SBOM: `syft`

The runtime also supports dynamic Python plugin loading from the user plugin directory.

## Quick start

1. Install Node.js, Rust, and Python 3.11+.
2. Run `npm install`.
3. Install backend dependencies with `python -m pip install ./services/scanner-core`.
4. Start the API with `python services/scanner-core/launcher.py serve`.
5. Start the desktop shell with `npm --workspace apps/desktop run tauri dev`.

## Build outputs

- Desktop packages: `apps/desktop/src-tauri/target/release/bundle`
- Scan reports: `~/.code-base-scanner/reports`
- Advisory cache and scanner tool store: `~/.code-base-scanner`

See [docs/architecture.md](/C:/Users/DarkWorld/Documents/CODE_BASE_SCANNER/docs/architecture.md) and [docs/build-and-packaging.md](/C:/Users/DarkWorld/Documents/CODE_BASE_SCANNER/docs/build-and-packaging.md) for the packaging and deployment flow.
