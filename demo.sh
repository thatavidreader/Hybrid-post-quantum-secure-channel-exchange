#!/usr/bin/env bash
# Linux / WSL2 / Git-Bash demo.  Usage: ./demo.sh [--setup]
set -euo pipefail
cd "$(dirname "$0")"
if [[ "${1:-}" == "--setup" || ! -d .venv ]]; then
  python3 -m venv .venv
  PIP=".venv/bin/pip"; [[ -x "$PIP" ]] || PIP=".venv/Scripts/pip"
  "$PIP" install -r requirements.txt
fi
PY=".venv/bin/python"; [[ -x "$PY" ]] || PY=".venv/Scripts/python"
"$PY" demo.py
