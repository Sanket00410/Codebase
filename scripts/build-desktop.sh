#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

"$ROOT_DIR/scripts/build-backend.sh"
pushd "$ROOT_DIR" >/dev/null
npm install
npm --workspace apps/desktop run tauri build
popd >/dev/null
