#!/usr/bin/env bash
# Install git-only tools into a shared dedicated venv and link binaries to ~/.local/bin.
set -uo pipefail
export PATH="$HOME/.local/bin:$PATH"
VENV="/opt/hunterx-tools/venv"
mkdir -p /tmp/gitvenv

if [ ! -x "$VENV/bin/python" ]; then
  /usr/bin/python3 -m venv "$VENV"
fi

install_one() {
  local tool="$1"
  local bin="$2"
  local log="/tmp/gitvenv/${tool}.log"
  if command -v "$bin" >/dev/null 2>&1; then
    echo "[SKIP] $tool already installed"
    return 0
  fi
  if [ ! -d "/opt/hunterx-tools/${tool}" ]; then
    echo "[FAIL] $tool not cloned"
    return 0
  fi
  if "$VENV/bin/pip" install --quiet --upgrade "/opt/hunterx-tools/${tool}" >"$log" 2>&1; then
    # Link console scripts (or create wrapper for script-style tools)
    local found=0
    for cand in "$VENV/bin/${bin}" "$VENV/bin/${tool}" "$VENV/bin/${tool}.py"; do
      if [ -f "$cand" ]; then
        ln -sf "$cand" "$HOME/.local/bin/${bin}"
        found=1
        break
      fi
    done
    if [ "$found" = "0" ]; then
      # wrapper for tools run via `python script.py`
      cat > "$HOME/.local/bin/${bin}" <<WRAP
#!/usr/bin/env bash
exec "$VENV/bin/python" "/opt/hunterx-tools/${tool}/${bin}.py" "\$@"
WRAP
      chmod +x "$HOME/.local/bin/${bin}"
      found=1
    fi
    echo "[OK] $tool (bin=$bin)"
  else
    echo "[FAIL] $tool (see $log)"; tail -3 "$log"
  fi
}
export -f install_one

install_one theharvester theHarvester &
install_one spiderfoot sf &
install_one paramspider paramspider &
install_one sstimap sstimap &
install_one ghauri ghauri &
install_one graphqlmap graphqlmap &
install_one tplmap tplmap &
install_one xssstrike xsstrike &
wait
echo "ALL DONE"
