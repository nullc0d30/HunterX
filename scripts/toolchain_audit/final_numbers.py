"""Compute the exact final numbers for the readiness report (section 23)."""
from __future__ import annotations

import json

from hunterx.platform import build_platform

OUT = "/home/nc/hunterx/HunterX/artifacts/toolchain-audit"


def main() -> None:
    plat = build_platform()
    svc = plat.tool_readiness_service
    report = svc.check()
    audit = svc.audit()

    by_status = {t.tool_id: t.status.value for t in report.tools}
    by_audit = {a.tool_id: a.level.value for a in audit.audits}

    counts = {
        "total_tools": report.summary["total"],
        "available": report.summary["available"],
        "missing": report.summary["missing"],
        "broken": report.summary["broken"],
        "outdated": report.summary["outdated"],
        "unsupported": report.summary["unsupported"],
        "capabilities_ready": report.summary["capabilities_ready"],
        "capabilities_missing": report.summary["capabilities_missing"],
    }

    # maturity levels
    from collections import Counter
    levels = Counter(by_audit.values())

    # categories with >=2 executable providers
    cap_data = {}
    for c in report.capabilities:
        cap_data[c.capability] = {
            "level": c.level.value,
            "available": list(c.available),
            "providers": list(c.providers),
            "ready": c.ready,
            "exec_count": len(c.available),
        }

    ge2 = sum(1 for c in cap_data.values() if c["exec_count"] >= 2)
    ge3 = sum(1 for c in cap_data.values() if c["exec_count"] >= 3)
    one = sum(1 for c in cap_data.values() if c["exec_count"] == 1)
    zero = sum(1 for c in cap_data.values() if c["exec_count"] == 0)

    result = {
        "counts": counts,
        "maturity_levels": dict(levels),
        "category_coverage": {
            "total_capabilities": len(cap_data),
            "with_2_or_more_providers": ge2,
            "with_3_or_more_providers": ge3,
            "with_exactly_1_provider": one,
            "with_zero_providers": zero,
        },
        "capabilities": cap_data,
    }
    json.dump(result, open(f"{OUT}/final-numbers.json", "w"), indent=2)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
