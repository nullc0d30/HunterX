#!/usr/bin/env bash
set -e
export PYTHONUNBUFFERED=1
UVENV="$HOME/.hunterx/venv"
TOOLBIN="$HOME/.hunterx/tools/bin"
mkdir -p "$TOOLBIN"
echo "=== creating user venv at $UVENV ==="
if [ ! -x "$UVENV/bin/python" ]; then
  python3 -m venv "$UVENV"
  echo "venv created"
else
  echo "venv exists"
fi
echo "=== installing current repo source (editable) ==="
"$UVENV/bin/pip" install --quiet --upgrade pip 2>&1 | tail -n1
"$UVENV/bin/pip" install --quiet -e /home/nc/hunterx/HunterX 2>&1 | tail -n 5
echo "=== verify hunterx from user venv ==="
"$UVENV/bin/hunterx" help 2>&1 | grep -iE "tools check|tools matrix" | head -n 2
"$UVENV/bin/python" -c "import hunterx; print('source:', hunterx.__file__)"
