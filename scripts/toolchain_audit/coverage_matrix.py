"""Build the CATEGORY|TOOL|INSTALLED|EXECUTABLE|VERSION|KNOWLEDGE|PARSER|SMOKE|STATUS matrix."""
from __future__ import annotations

import json

from hunterx.platform import build_platform

OUT = "/home/nc/hunterx/HunterX/artifacts/toolchain-audit/coverage-matrix.md"


def main() -> None:
    plat = build_platform()
    svc = plat.tool_readiness_service
    readiness = svc.check()
    audit = svc.audit()

    by_audit = {a.tool_id: a for a in audit.audits}
    by_status = {t.tool_id: t for t in readiness.tools}

    smoke = {s["tool"]: s["smoke"] for s in json.load(open("/home/nc/hunterx/HunterX/artifacts/toolchain-audit/smoke-tests.json"))}

    rows = []
    for t in sorted(readiness.tools, key=lambda x: x.tool_id):
        a = by_audit.get(t.tool_id)
        level = a.level.value if a else "unknown"
        has_knowledge = bool(a and a.dimensions.get("commands"))
        has_parser = bool(a and a.dimensions.get("parser"))
        rows.append({
            "tool": t.tool_id,
            "status": t.status.value,
            "version": t.version,
            "level": level,
            "knowledge": "yes" if has_knowledge else "no",
            "parser": "yes" if has_parser else "no",
            "smoke": smoke.get(t.tool_id, "-"),
        })

    lines = ["# HunterX Toolchain Coverage Matrix", ""]
    lines.append("| TOOL | STATUS | VERSION | KNOWLEDGE | PARSER | SMOKE TEST | MATURITY |")
    lines.append("|---|---|---|---|---|---|---|")
    for r in rows:
        lines.append(
            f"| {r['tool']} | {r['status']} | {r['version'] or '-'} | {r['knowledge']} | "
            f"{r['parser']} | {r['smoke']} | {r['level']} |"
        )
    open(OUT, "w").write("\n".join(lines))
    print("wrote", OUT, f"({len(rows)} rows)")


if __name__ == "__main__":
    main()
