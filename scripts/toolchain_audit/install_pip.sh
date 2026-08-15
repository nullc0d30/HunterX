#!/usr/bin/env bash
# Install all manifest-declared pip tools in parallel via the base interpreter
# --user install (same trusted packages as the readiness manifest).
set -uo pipefail
export PATH="$HOME/.local/bin:$PATH"
mkdir -p /tmp/pipinstall

declare -A TOOLS=(
  [sqlmap]="sqlmap"
  [dirsearch]="dirsearch"
  [arjun]="arjun"
  [paramspider]="paramspider"
  [ghauri]="ghauri"
  [commix]="commix"
  [sstimap]="sstimap"
  [graphqlmap]="graphqlmap"
  [inql]="inql"
  [xssstrike]="xssstrike"
  [tplmap]="tplmap"
  [mitmproxy]="mitmproxy"
  [semgrep]="semgrep"
  [wapiti]="wapiti"
  [detect-secrets]="detect-secrets"
  [bbot]="bbot"
  [theharvester]="theHarvester"
  [spiderfoot]="spiderfoot"
  [wafw00f]="wafw00f"
  [prowler]="prowler"
  [scoutsuite]="scoutsuite"
)

install_one() {
  local tool="$1"
  local pkg="$2"
  if command -v "$tool" >/dev/null 2>&1; then
    echo "[SKIP] $tool already installed"
    return 0
  fi
  local log="/tmp/pipinstall/${tool}.log"
  if /usr/bin/python3 -m pip install --user --quiet "$pkg" >"$log" 2>&1; then
    echo "[OK] $tool"
  else
    echo "[FAIL] $tool (see $log)"
  fi
}
export -f install_one

i=0
for tool in "${!TOOLS[@]}"; do
  pkg="${TOOLS[$tool]}"
  install_one "$tool" "$pkg" &
  i=$((i + 1))
  if [ $((i % 3)) -eq 0 ]; then
    wait
  fi
done
wait
echo "ALL DONE"
