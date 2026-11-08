#!/usr/bin/env sh
# CTF-Toolkit v4.0 Apex - Linux / macOS / WSL2 Launcher
set -e

export PYTHONIOENCODING="utf-8"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

if [ -x "$SCRIPT_DIR/.venv/bin/python" ]; then
    exec "$SCRIPT_DIR/.venv/bin/python" "$SCRIPT_DIR/main.py" "$@"
elif command -v python3 >/dev/null 2>&1; then
    exec python3 "$SCRIPT_DIR/main.py" "$@"
elif command -v python >/dev/null 2>&1; then
    exec python "$SCRIPT_DIR/main.py" "$@"
else
    echo "[-] Error: Python 3.10+ not found in PATH." >&2
    exit 1
fi
