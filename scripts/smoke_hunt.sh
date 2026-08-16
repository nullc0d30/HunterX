#!/usr/bin/env bash
set +e
export PYTHONPATH=/home/nc/hunterx/HunterX/src
export HUNTERX_TOOL_BIN="$HOME/.hunterx/tools/bin"
export GOBIN="$HUNTERX_TOOL_BIN"
export VIRTUAL_ENV="$HOME/.hunterx/venv"
export PATH="$HUNTERX_TOOL_BIN:$(go env GOPATH 2>/dev/null)/bin:$HOME/.cargo/bin:$HOME/.local/bin:$HOME/.hunterx/venv/bin:$PATH"
export HUNTERX_DATA_DIR="$HOME/.hunterx/data"
mkdir -p "$HUNTERX_DATA_DIR"
cd /tmp
HX="$HOME/.hunterx/venv/bin/hunterx"
echo "=== smoke hunt vs http://localhost:3010 (toolchain-only) ==="
timeout 300 "$HX" hunt full_security_assessment http://localhost:3010 --output "$HOME/.hunterx/data/smoke-run" 2>/tmp/smoke_err.txt > /tmp/smoke_out.json
rc=$?
echo "hunt rc=$rc"
echo "--- stdout (overview) head ---"
head -c 900 /tmp/smoke_out.json
echo ""
echo "--- tool executions observed (stderr progress) ---"
grep -oE ">> run [a-zA-Z0-9_.-]+" /tmp/smoke_err.txt | sort | uniq -c | sort -rn | head -n 30
echo "--- events recorded ---"
EV="$HOME/.hunterx/data/smoke-run/events.jsonl"
if [ -f "$EV" ]; then
  echo "events: $(wc -l < "$EV")"
  python3 -c "
import json
from collections import Counter
c=Counter()
tools=Counter()
for line in open('$EV'):
    line=line.strip()
    if not line: continue
    e=json.loads(line)
    c[e['event_type']]+=1
    p=e.get('payload') or {}
    if e['event_type']=='mission.tool.started': tools[p.get('tool_id')]+=1
print('event types:', dict(c))
print('tools executed:', dict(tools))
"
else
  echo "NO events file: $EV"
fi
