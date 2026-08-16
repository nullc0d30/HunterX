#!/usr/bin/env bash
set +e
export PYTHONPATH=/home/nc/hunterx/HunterX/src
export HUNTERX_TOOL_BIN="$HOME/.hunterx/tools/bin"
export GOBIN="$HUNTERX_TOOL_BIN"
export VIRTUAL_ENV="$HOME/.hunterx/venv"
export PATH="$HUNTERX_TOOL_BIN:$(go env GOPATH 2>/dev/null)/bin:$HOME/.cargo/bin:$HOME/.local/bin:$HOME/.hunterx/venv/bin:$PATH"
export HUNTERX_DATA_DIR="$HOME/.hunterx/data"
cd /tmp
HX="$HOME/.hunterx/venv/bin/hunterx"
TARGET="http://localhost:3010"
BASE=/home/nc/hunterx/HunterX/artifacts/hunterx-results/juice-shop
mkdir -p "$BASE"
OBJECTIVE="$1"
OUT="$BASE/$OBJECTIVE"
mkdir -p "$OUT"
rm -f "$OUT/events.jsonl" "$OUT/results.json" "$OUT/report.txt" "$OUT/cli.out" "$OUT/cli.err"
echo "=== HUNT $OBJECTIVE -> $TARGET ==="
timeout 540 "$HX" hunt "$OBJECTIVE" "$TARGET" --output "$OUT" >"$OUT/cli.out" 2>"$OUT/cli.err"
rc=$?
echo "rc=$rc"
echo "artifacts:"
ls -la "$OUT" | grep -E "events|results|report"
echo "--- results stats ---"
python3 -c "
import json
p='$OUT/results.json'
try:
    d=json.load(open(p))
    c=d.get('counts',{})
    print('status:', d.get('status'), '| planning:', d.get('planning_state'), '| phase:', d.get('current_phase'))
    print('counts:', {k:c.get(k) for k in ('observations','hypotheses','decisions','findings','validated_findings','negative_evidence','tool_executions','endpoints','parameters','technologies','services','attack_paths')})
    print('coverage:', d.get('coverage_ratio'), '| outcome:', (d.get('outcome') or {}).get('stop_condition') if d.get('outcome') else None)
except Exception as e:
    print('no results.json:', e)
"
echo "--- live cli reasoning markers ---"
grep -oE "\[HYPOTHESIS\]|\[PROBE\]|\[ANALYSIS\]|\[REASSESS\]|\[FINDING\]|\[MODEL\]|\[DECISION\]|\[CONTINUE\]|\[VALIDATION\]|hypothesis \[|>> decide|>> run" "$OUT/cli.err" | sort | uniq -c | sort -rn | head -n 12
echo "--- events summary ---"
python3 -c "
import json
from collections import Counter
p='$OUT/events.jsonl'
try:
    c=Counter()
    for line in open(p):
        line=line.strip()
        if line: c[json.loads(line)['event_type']]+=1
    print(dict(c))
except Exception as e:
    print('no events:', e)
"
