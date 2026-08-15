"""Generate the tool-knowledge-audit.json artifact.

Combines the real integration audit (knowledge dimensions per tool) with the
readiness verdict (runtime availability) so the report classifies every tool.
"""
from __future__ import annotations

import json

from hunterx.platform import build_platform

OUT = "/home/nc/hunterx/HunterX/artifacts/toolchain-audit/tool-knowledge-audit.json"


def main() -> None:
    plat = build_platform()
    svc = plat.tool_readiness_service

    audit_report = svc.audit()
    readiness = svc.check()

    by_id = {a.tool_id: a for a in audit_report.audits}
    status = {t.tool_id: t.status.value for t in readiness.tools}
    version = {t.tool_id: t.version for t in readiness.tools}
    path = {t.tool_id: t.path for t in readiness.tools}

    rows = []
    for tool_id, audit in sorted(by_id.items()):
        rows.append({
            "tool_id": tool_id,
            "level": audit.level.value,
            "dimensions": audit.dimensions,
            "missing_dimensions": list(audit.missing),
            "runtime_adapter": audit.runtime,
            "available": audit.available,
            "readiness_status": status.get(tool_id, "unknown"),
            "version": version.get(tool_id, ""),
            "path": path.get(tool_id, ""),
            "reasons": list(audit.reasons),
        })

    payload = {
        "summary": audit_report.summary,
        "tool_count": len(rows),
        "tools": rows,
    }
    json.dump(payload, open(OUT, "w"), indent=2)
    print("wrote", OUT)
    print("summary:", json.dumps(audit_report.summary))
    # selected executable providers: check FULLY_INTEGRATED + parser presence
    fully = [r for r in rows if r["level"] == "fully_integrated" and r["available"]]
    print("fully_integrated AND available:", len(fully))
    missing_parser = [r for r in rows if r["level"] == "fully_integrated" and "parser" in r["missing_dimensions"]]
    print("fully_integrated but missing parser dimension:", [r["tool_id"] for r in missing_parser])


if __name__ == "__main__":
    main()
