#!/usr/bin/env bash
# Install all manifest-declared go tools in parallel batches.
# Uses only the exact module paths from the readiness manifest.
set -uo pipefail

mkdir -p /tmp/goinstall
export PATH="$HOME/go/bin:$PATH"

declare -A TOOLS=(
  [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  [urlfinder]="github.com/projectdiscovery/urlfinder@latest"
  [amass]="github.com/owasp-amass/amass/v4/cmd/amass@master"
  [assetfinder]="github.com/tomnomnom/assetfinder@latest"
  [dnsx]="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  [shuffledns]="github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
  [httpx]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
  [katana]="github.com/projectdiscovery/katana/cmd/katana@latest"
  [gospider]="github.com/jaeles-project/gospider@latest"
  [hakrawler]="github.com/hakluke/hakrawler@latest"
  [gau]="github.com/lc/gau/v2/cmd/gau@latest"
  [waybackurls]="github.com/tomnomnom/waybackurls@latest"
  [ffuf]="github.com/ffuf/ffuf/v2@latest"
  [nuclei]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  [dalfox]="github.com/hahwul/dalfox/v2@latest"
  [gitleaks]="github.com/gitleaks/gitleaks/v8@latest"
  [trufflehog]="github.com/trufflesecurity/trufflehog/v3@latest"
  [interactsh]="github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
  [naabu]="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  [gobuster]="github.com/OJ/gobuster/v3@latest"
  [osv-scanner]="github.com/google/osv-scanner/cmd/osv-scanner@latest"
)

install_one() {
  local tool="$1"
  local mod="$2"
  if command -v "$tool" >/dev/null 2>&1; then
    echo "[SKIP] $tool already installed"
    return 0
  fi
  local log="/tmp/goinstall/${tool}.log"
  if go install -v "$mod" >"$log" 2>&1; then
    echo "[OK] $tool"
  else
    echo "[FAIL] $tool (see $log)"
  fi
}
export -f install_one

i=0
for tool in "${!TOOLS[@]}"; do
  mod="${TOOLS[$tool]}"
  install_one "$tool" "$mod" &
  i=$((i + 1))
  if [ $((i % 4)) -eq 0 ]; then
    wait
  fi
done
wait
echo "ALL DONE"
