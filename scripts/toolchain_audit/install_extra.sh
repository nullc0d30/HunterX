#!/usr/bin/env bash
# Install remaining legitimately-installable tools (go + git python).
set -uo pipefail
export PATH="$HOME/go/bin:$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
mkdir -p /tmp/extra

install_go() {
  local tool="$1" mod="$2" bin="${3:-$1}"
  if command -v "$bin" >/dev/null 2>&1; then echo "[SKIP] $tool"; return 0; fi
  if go install -v "$mod" >"/tmp/extra/${tool}.log" 2>&1; then echo "[OK] $tool"; else echo "[FAIL] $tool"; tail -2 "/tmp/extra/${tool}.log"; fi
}

install_git_py() {
  local tool="$1" repo="$2" bin="$3" script="$4"
  if command -v "$bin" >/dev/null 2>&1; then echo "[SKIP] $tool"; return 0; fi
  local dir="/opt/hunterx-tools/${tool}"
  if [ ! -d "$dir" ]; then
    git clone --depth 1 "$repo" "$dir" >"/tmp/extra/${tool}.log" 2>&1 || { echo "[FAIL] $tool clone"; return 0; }
  fi
  cat > "$HOME/.local/bin/${bin}" <<WRAP
#!/usr/bin/env bash
cd "${dir}" || exit 1
exec /opt/hunterx-tools/venv/bin/python "${script}" "\$@"
WRAP
  chmod +x "$HOME/.local/bin/${bin}"
  echo "[OK] $tool (wrapper)"
}

install_go gauplus github.com/bp0lr/gauplus@latest &
install_go jsluice github.com/BishopFox/jsluice/cmd/jsluice@latest &
install_git_py linkfinder https://github.com/GerbenJavado/LinkFinder linkfinder linkfinder.py &
install_git_py secretfinder https://github.com/m4ll0k/SecretFinder secretfinder SecretFinder.py &
install_git_py xnlinkfinder https://github.com/xnl-h4ck3r/xnLinkFinder xnlinkfinder xnLinkFinder.py &
install_git_py xxeinjector https://github.com/enjoiz/XXEinjector xxeinjector XXEinjector.rb &
install_git_py jwt-tool https://github.com/ticarpi/jwt_tool jwt_tool jwt_tool.py &
wait
echo "DONE"
