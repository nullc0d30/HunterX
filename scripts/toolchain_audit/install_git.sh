#!/usr/bin/env bash
# Install git-only manifest tools from their official repositories
# (all repo URLs are documented in README.md / the canonical tool manifest).
set -uo pipefail
export PATH="$HOME/.local/bin:$PATH"
mkdir -p /tmp/gitinstall /opt/hunterx-tools

# tool|repo|install-mode|binary
TOOLS=(
  "theharvester|https://github.com/laramies/theHarvester|pip|theHarvester"
  "spiderfoot|https://github.com/smicallef/spiderfoot|pip-req|sf"
  "paramspider|https://github.com/devanshbatham/ParamSpider|pip|paramspider"
  "sstimap|https://github.com/vladris/sstimap|pip|sstimap"
  "ghauri|https://github.com/r0oth3x49/ghauri|pip|ghauri"
  "graphqlmap|https://github.com/swisskyrepo/GraphQLmap|pip|graphqlmap"
  "tplmap|https://github.com/epinna/tplmap|pip|tplmap"
  "xssstrike|https://github.com/s0md3v/XSStrike|pip|xstrike"
)

install_one() {
  IFS='|' read -r tool repo mode binary <<<"$1"
  if command -v "$binary" >/dev/null 2>&1; then
    echo "[SKIP] $tool already installed"
    return 0
  fi
  local dir="/opt/hunterx-tools/${tool}"
  local log="/tmp/gitinstall/${tool}.log"
  {
    rm -rf "$dir"
    git clone --depth 1 "$repo" "$dir" || { echo "[FAIL] $tool clone"; exit 1; }
    if [ "$mode" = "pip" ]; then
      /usr/bin/python3 -m pip install --quiet --user "$dir" 2>/dev/null || \
        ( cd "$dir" && /usr/bin/python3 -m pip install --quiet --user . )
    else
      /usr/bin/python3 -m pip install --quiet --user -r "$dir/requirements.txt"
    fi
    echo "[OK] $tool"
  } >"$log" 2>&1
  grep -q "\[OK\]" "$log" && tail -1 "$log" || { echo "[FAIL] $tool (see $log)"; tail -3 "$log"; }
}
export -f install_one

for entry in "${TOOLS[@]}"; do
  install_one "$entry" &
done
wait
echo "ALL DONE"
