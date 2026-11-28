#!/usr/bin/env bash
# Summarize the hypothesis/probe events of one archived mission run.
# Usage: inspect_chain.sh [run-name]   (default: juice-shop)
set +e
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export ROOT
RUN="${1:-juice-shop}"
export RUN
python3 - <<'PY'
import json
import os
from collections import Counter

base = os.path.join(os.environ["ROOT"], "artifacts", "hunterx-results", os.environ.get("RUN") or "juice-shop")
events_path = os.path.join(base, "vulnerability_discovery", "events.jsonl")
report_path = os.path.join(base, "vulnerability_discovery", "report.txt")

classes = Counter()
for line in open(events_path):
    line = line.strip()
    if not line:
        continue
    e = json.loads(line)
    if e["event_type"] != "mission.hypothesis.updated":
        continue
    statement = (e.get("payload") or {}).get("statement") or ""
    for marker in ("may be susceptible to", "may be affected by"):
        if marker in statement:
            classes[statement.split(marker)[1].strip()] += 1
            break

print("class hypothesis updates:", dict(classes))
print("probe events:", sum(1 for line in open(events_path) if '"vulnerability.probe' in line))

for line in open(report_path).read().splitlines():
    if "may be susceptible to" in line:
        print("  HYP:", line.strip()[:110])
PY
