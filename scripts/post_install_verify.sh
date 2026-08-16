#!/usr/bin/env bash
set +e
export PYTHONPATH=/home/nc/hunterx/HunterX/src
export HUNTERX_TOOL_BIN="$HOME/.hunterx/tools/bin"
export GOBIN="$HUNTERX_TOOL_BIN"
export VIRTUAL_ENV="$HOME/.hunterx/venv"
export PATH="$HUNTERX_TOOL_BIN:$(go env GOPATH 2>/dev/null)/bin:$HOME/.cargo/bin:$HOME/.local/bin:$HOME/.hunterx/venv/bin:$PATH"
cd /tmp
HX="$HOME/.hunterx/venv/bin/hunterx"
REQ='findomain theharvester massdns rustscan linkfinder secretfinder xnlinkfinder paramspider kiterunner spiderfoot crt-sh unicornscan crobat gauplus feroxbuster graphqlmap jwt-tool openapi-parser postman-parser jsluice xssstrike ghauri tplmap sstimap xxeinjector trufflehog codeql zap netexec impacket enum4linux-ng trivy syft grype kube-bench metasploit searchsploit exploitdb'

echo "===== TOOLS CHECK --JSON ====="
timeout 300 "$HX" tools check --json 2>/dev/null > /tmp/check.json
python3 - <<'PY'
import json
d=json.load(open('/tmp/check.json'))
print('summary:', json.dumps(d['summary']))
req='''findomain theharvester massdns rustscan linkfinder secretfinder xnlinkfinder paramspider kiterunner spiderfoot crt-sh unicornscan crobat gauplus feroxbuster graphqlmap jwt-tool openapi-parser postman-parser jsluice xssstrike ghauri tplmap sstimap xxeinjector trufflehog codeql zap netexec impacket enum4linux-ng trivy syft grype kube-bench metasploit searchsploit exploitdb'''.split()
tools={t['tool_id']:t for t in d['tools']}
print('--- required 43 ---')
for t in req:
    r=tools.get(t)
    print(f"{t:<16} {r['status'] if r else 'NO ROW'}")
PY
echo ""
echo "===== TOOLS MATRIX --JSON (43 required only) ====="
timeout 300 "$HX" tools matrix --json 2>/dev/null > /tmp/matrix.json
python3 - <<'PY'
import json
d=json.load(open('/tmp/matrix.json'))
req='''findomain theharvester massdns rustscan linkfinder secretfinder xnlinkfinder paramspider kiterunner spiderfoot crt-sh unicornscan crobat gauplus feroxbuster graphqlmap jwt-tool openapi-parser postman-parser jsluice xssstrike ghauri tplmap sstimap xxeinjector trufflehog codeql zap netexec impacket enum4linux-ng trivy syft grype kube-bench metasploit searchsploit exploitdb'''.split()
rows={r['tool']:r for r in d['tools']}
from collections import Counter
c=Counter(rows[t]['final_status'] for t in req)
print('required-43 counts:', dict(c))
# full catalog counts
fc=Counter(r['final_status'] for r in d['tools'])
print('full-106 counts:', dict(fc))
print('total rows:', len(d['tools']))
PY
echo ""
echo "===== HTTPX IDENTITY (ProjectDiscovery vs Python) ====="
command -v httpx >/dev/null 2>&1 && echo "httpx on PATH: $(command -v httpx)"
python3 - <<'PY'
import json
d=json.load(open('/tmp/check.json'))
for t in d['tools']:
    if t['tool_id']=='httpx':
        print('httpx:', json.dumps({k:t.get(k) for k in ('status','resolved_path','version','expected_identity','health','shadowed_by')}, default=str))
PY
echo ""
echo "===== IDEMPOTENCY (reinstall an installed tool) ====="
timeout 120 "$HX" tools install trufflehog --json 2>/dev/null | python3 -c "import sys,json; [print(json.dumps({k:o.get(k) for k in ('tool_id','success','status','version','skipped')})) for o in json.load(sys.stdin)]"
