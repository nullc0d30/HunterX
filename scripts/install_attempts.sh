#!/usr/bin/env bash
# Real installation attempts for the required 43-tool CLI toolchain.
# Usage: install_attempts.sh <tool_id> [tool_id ...]
set +e
export PYTHONPATH=/home/nc/hunterx/HunterX/src
export HUNTERX_TOOL_BIN="${HUNTERX_TOOL_BIN:-/home/nc/.hunterx/tools/bin}"
mkdir -p "$HUNTERX_TOOL_BIN"
# Launcher precedence: managed tools dir first, then go bin, cargo bin, user bin.
export GOBIN="$HUNTERX_TOOL_BIN"
GO_BIN="$(go env GOPATH 2>/dev/null)/bin"
export PATH="$HUNTERX_TOOL_BIN:$GO_BIN:$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
export HUNTERX_HOME="$HOME/.hunterx"
cd /tmp
HX="${HX:-/opt/hunterx/venv/bin/hunterx}"
if [ -x "$HOME/.hunterx/venv/bin/hunterx" ]; then
  HX="$HOME/.hunterx/venv/bin/hunterx"
fi
OUT=/home/nc/hunterx/HunterX/artifacts/toolchain-audit/install-attempts.jsonl
mkdir -p "$(dirname "$OUT")"
: > "$OUT"
for tool in "$@"; do
  echo "[$tool] attempting..."
  start=$(date +%s)
  RESULT=$(timeout 1500 "$HX" tools install "$tool" --json 2>/tmp/hx_install_err.txt)
  rc=$?
  end=$(date +%s)
  elapsed=$((end-start))
  if [ $rc -ne 0 ]; then
    # timeout or CLI crash
    echo "{\"tool_id\":\"$tool\",\"attempted\":true,\"success\":false,\"status\":\"install_failed\",\"error\":\"installer run failed rc=$rc: $(head -c 300 /tmp/hx_install_err.txt | tr -d '\"\\')\",\"elapsed_s\":$elapsed}" >> "$OUT"
    echo "[$tool] FAILED (rc=$rc, ${elapsed}s)"
  else
    # RESULT is a JSON list of outcomes; unwrap into the record
    echo "$RESULT" | python3 -c "
import sys, json
try:
    outcomes = json.load(sys.stdin)
except Exception as e:
    print(json.dumps({'tool_id':'$tool','attempted':True,'success':False,'status':'parse_failed','error':str(e),'raw': sys.stdin.read()[:200] if False else ''}))
    sys.exit(0)
for o in outcomes:
    print(json.dumps({'tool_id':o.get('tool_id'),'attempted':True,'success':o.get('success'),'status':o.get('status'),'version':o.get('version'),'method':(o.get('method') or {}).get('kind') if isinstance(o.get('method'),dict) else o.get('method'),'skipped':o.get('skipped'),'error':o.get('error'),'elapsed_s':$elapsed}, default=str))
" >> "$OUT"
    echo "[$tool] done (${elapsed}s)"
  fi
done
echo "=== install attempts complete ==="
