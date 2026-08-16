#!/usr/bin/env bash
set +e
export PATH="$HOME/.hunterx/tools/bin:$HOME/go/bin:$PATH"
cd /tmp
echo "=== katana adapter-style argv ==="
timeout 30 katana -u http://localhost:3010 -d 3 -jc -silent -json 2>&1 | head -c 300
echo ""
echo "=== katana help (check flags) ==="
katana -h 2>&1 | grep -iE "\-jc|json|silent|depth" | head -n 6
echo "=== osv-scanner on PATH ==="
command -v osv-scanner
osv-scanner scan --format json /tmp 2>&1 | head -c 200
echo ""
echo "=== osv-scanner exit check ==="
osv-scanner scan --format json /tmp >/dev/null 2>&1; echo "osv rc=$?"
