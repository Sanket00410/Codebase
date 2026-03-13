# Architecture

## Runtime model

The product is split into three layers:

1. `apps/desktop`
   Native Tauri shell responsible for windowing, native filesystem access, backend lifecycle, packaging, and installer generation.
2. `services/scanner-core`
   Local FastAPI service that performs repository analysis, scanner orchestration, advisory updates, report generation, and CLI execution.
3. External scanner binaries
   Security tools installed per OS and architecture, resolved from PATH or the managed local tool store in `SCANNER_PLATFORM_DATA_DIR/tools`.

## Scan pipeline

1. Repository inventory and language detection
2. Dependency graph extraction from lockfiles and manifests
3. Plugin selection by category, repository contents, and binary availability
4. Parallel scanner execution with phase ordering
5. Finding normalization and vulnerability correlation
6. Advisory enrichment from GitHub Advisory Database and NVD
7. AI triage and zero-day candidate clustering when an LLM provider is configured
8. Report generation in JSON, SARIF, HTML, Markdown, and PDF
9. Persistence into local SQLite storage

## Plugin lifecycle

Built-in plugins live in [services/scanner-core/security_platform/plugins](/C:/Users/DarkWorld/Documents/CODE_BASE_SCANNER/services/scanner-core/security_platform/plugins). External plugins are loaded dynamically from `SCANNER_PLATFORM_PLUGIN_DIR` or the default user plugin directory at `~/.code-base-scanner/plugins`.

Every plugin:

- resolves its binary through the binary manager
- executes the real underlying scanner
- parses the scanner’s native output
- normalizes findings into the shared schema
- emits artifacts such as raw outputs or SBOMs

## Desktop packaging strategy

- Windows: Tauri bundle targets `nsis` and `msi`
- macOS: Tauri bundle target `dmg`
- Linux: Tauri bundle targets `appimage`, `deb`, and `rpm`

The backend is packaged as a standalone executable with PyInstaller and embedded into the desktop app as a bundle resource under `src-tauri/backend`.

## Update strategy

- Desktop updates: Tauri updater artifacts
- Scanner binary updates: binary manager install/update endpoints
- Vulnerability data updates: GitHub Advisory Database sync, NVD modified feed sync, and scanner database refresh commands
- Offline mode: use previously cached databases and installed binaries

