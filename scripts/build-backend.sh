#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_DIR="$ROOT_DIR/services/scanner-core"
DESKTOP_BACKEND_DIR="$ROOT_DIR/apps/desktop/src-tauri/backend"
if [[ -z "${PYTHON_BIN:-}" ]]; then
  if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
    PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
  else
    PYTHON_BIN="python3"
  fi
fi

pushd "$BACKEND_DIR" >/dev/null
"$PYTHON_BIN" -m pip install --upgrade pip setuptools wheel pyinstaller
"$PYTHON_BIN" -m pip install .
"$PYTHON_BIN" -m PyInstaller --noconfirm security-platform-backend.spec
popd >/dev/null

mkdir -p "$DESKTOP_BACKEND_DIR"
if [[ -f "$BACKEND_DIR/dist/security-platform-backend" ]]; then
  cp "$BACKEND_DIR/dist/security-platform-backend" "$DESKTOP_BACKEND_DIR/security-platform-backend"
elif [[ -f "$BACKEND_DIR/dist/security-platform-backend.exe" ]]; then
  cp "$BACKEND_DIR/dist/security-platform-backend.exe" "$DESKTOP_BACKEND_DIR/security-platform-backend.exe"
else
  echo "Backend artifact was not generated." >&2
  exit 1
fi
