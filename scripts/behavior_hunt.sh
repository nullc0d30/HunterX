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
echo "=== hunter behavior hunt vs http://localhost:3010 ==="
timeout 420 "$HX" hunt full_security_assessment http://localhost:3010 --output "$HOME/.hunterx/data/behavior-run" 2>/tmp/beh_err.txt > /tmp/beh_out.json
rc=$?
echo "hunt rc=$rc"
echo "--- overview summary ---"
python3 -c "
import json
d=json.load(open('/tmp/beh_out.json'))
print('state:', d.get('planning_state'), '| phase:', d.get('current_phase'))
print('counts:', {k:d['counts'][k] for k in ('observations','hypotheses','decisions','findings','validated_findings','tool_executions','negative_evidence') if k in d['counts']})
print('coverage:', d.get('coverage_ratio'))
"
echo "--- live reasoning events on stderr ---"
grep -oE "\[[A-Z]+|hypothesis|observation|>> decide|>> run|coverage:" /tmp/beh_err.txt | sort | uniq -c | sort -rn | head -n 15
echo "--- event stream (reasoning chain) ---"
EV="$HOME/.hunterx/data/behavior-run/events.jsonl"
if [ -f "$EV" ]; then
  python3 -c "
import json
for line in open('$EV'):
    line=line.strip()
    if not line: continue
    e=json.loads(line)
    t=e['event_type']
    p=e.get('payload') or {}
    if t in ('mission.phase.started','mission.tool.started','mission.observation.created','mission.hypothesis.created','mission.hypothesis.updated','mission.action.selected','mission.finding.created','mission.finding.validated','mission.tool.completed','mission.tool.failed','mission.completed'):
        print(t, '|', {k:p.get(k) for k in ('phase','tool_id','observation_type','hypothesis_id','statement','state','capability','finding_id','outcome') if p.get(k)})
" | head -n 60
fi
