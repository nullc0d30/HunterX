#!/usr/bin/env bash
# Create ~/.local/bin wrappers for script-style git tools in /opt/hunterx-tools.
set -uo pipefail
export PATH="$HOME/.local/bin:$PATH"
VENV="/opt/hunterx-tools/venv"

make_wrapper() {
  local bin="$1"
  local script="$2"
  local dir="${script%/*}"
  cat > "$HOME/.local/bin/${bin}" <<WRAP
#!/usr/bin/env bash
cd "${dir}" || exit 1
exec "${VENV}/bin/python" "${script}" "\$@"
WRAP
  chmod +x "$HOME/.local/bin/${bin}"
  echo "[OK] wrapper ${bin} -> ${script}"
}

make_wrapper tplmap   /opt/hunterx-tools/tplmap/tplmap.py
make_wrapper xsstrike /opt/hunterx-tools/xssstrike/xsstrike.py
make_wrapper sf       /opt/hunterx-tools/spiderfoot/sf.py
make_wrapper spiderfoot /opt/hunterx-tools/spiderfoot/sf.py

# sstimap retry clone + wrapper (may already be cloned by now)
if [ -d /opt/hunterx-tools/sstimap ] && [ -f /opt/hunterx-tools/sstimap/sstimap.py ]; then
  make_wrapper sstimap /opt/hunterx-tools/sstimap/sstimap.py
else
  git clone --depth 1 https://github.com/vladris/sstimap.git /opt/hunterx-tools/sstimap 2>/dev/null || true
  if [ -f /opt/hunterx-tools/sstimap/sstimap.py ]; then
    make_wrapper sstimap /opt/hunterx-tools/sstimap/sstimap.py
  else
    echo "[FAIL] sstimap clone did not complete"
  fi
fi
echo "DONE"
