#!/usr/bin/env bash
set +e
export PATH="$HOME/.hunterx/tools/bin:$HOME/go/bin:$PATH"
echo "=== katana fixed argv ==="
timeout 60 katana -u http://localhost:3010 -d 2 -jc -silent 2>&1 | head -n 12
echo ""
echo "=== osv-scanner via ~/.hunterx/tools/bin? ==="
ls -la "$HOME/.hunterx/tools/bin/osv-scanner" 2>/dev/null || echo "NOT in HUNTERX_TOOL_BIN (only in ~/go/bin)"
echo "=== mission PATH has go bin? (simulate) ==="
env PATH="$HOME/.hunterx/tools/bin:$HOME/go/bin:$PATH" bash -c 'command -v osv-scanner && osv-scanner scan --format json /tmp 2>&1 | head -c 100; echo; echo "rc=$?"'
