#!/usr/bin/env bash
set +e
python3 - <<'PY'
import json
from collections import Counter
p = "/home/nc/hunterx/HunterX/artifacts/hunterx-results/juice-shop/vulnerability_discovery/events.jsonl"
classes = Counter()
for line in open(p):
    line = line.strip()
    if not line:
        continue
    e = json.loads(line)
    if e["event_type"] == "mission.hypothesis.updated":
        pl = e.get("payload") or {}
        # hypothesis statements carry the class in the text
        st = pl.get("statement") or ""
        if "may be susceptible to" in st:
            cls = st.split("may be susceptible to")[1].strip()
            classes[cls] += 1
        elif "may be affected by" in st:
            cls = st.split("may be affected by")[1].strip()
            classes[cls] += 1
print("class hypothesis updates:", dict(classes))
print("probe events:", sum(1 for line in open(p) if '"vulnerability.probe' in line))
# sample some hypothesis statements from report
report = open("/home/nc/hunterx/HunterX/artifacts/hunterx-results/juice-shop/vulnerability_discovery/report.txt").read()
for line in report.splitlines():
    if "may be susceptible to" in line:
        print("  HYP:", line.strip()[:110])
PY
