#!/usr/bin/env bash
set -e
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="$ROOT/src"
export HUNTERX_TOOL_BIN="$HOME/.hunterx/tools/bin"
export GOBIN="$HUNTERX_TOOL_BIN"
export VIRTUAL_ENV="$HOME/.hunterx/venv"
export PATH="$HUNTERX_TOOL_BIN:$(go env GOPATH 2>/dev/null)/bin:$HOME/.cargo/bin:$HOME/.local/bin:$HOME/.hunterx/venv/bin:$PATH"
export HUNTERX_DATA_DIR="$HOME/.hunterx/data"
cd /tmp
HX="$HOME/.hunterx/venv/bin/hunterx"
timeout 300 "$HX" tools matrix --json 2>/dev/null > $ROOT/artifacts/toolchain-audit/toolchain-matrix.json
echo "matrix rows: $(python3 -c "import json; print(len(json.load(open('$ROOT/artifacts/toolchain-audit/toolchain-matrix.json'))['tools']))")"
