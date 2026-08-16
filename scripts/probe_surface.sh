#!/usr/bin/env bash
set +e
export PATH="$HOME/.hunterx/tools/bin:$HOME/go/bin:$PATH"
T="http://localhost:3010"
echo "=== katana crawl ==="
timeout 90 katana -u "$T" -d 2 -silent -jc -kf all 2>/dev/null | head -n 30
echo "=== feroxbuster ==="
timeout 90 feroxbuster -u "$T" -k -q -n -C 404 -W 80 --depth 1 2>/dev/null | grep -oE "^\S+" | head -n 30
echo "=== httpx paths (root only) ==="
timeout 30 httpx -u "$T" -sc -title 2>/dev/null | head -n 3
echo "=== which tools available ==="
for t in katana feroxbuster ffuf gobuster dirsearch linkfinder arjun osv-scanner; do
  printf '%s=%s\n' "$t" "$(command -v $t 2>/dev/null || echo MISSING)"
done
