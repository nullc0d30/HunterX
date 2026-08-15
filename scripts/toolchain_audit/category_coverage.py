import json
import sys

from hunterx.platform import build_platform
from hunterx.tools.readiness.manifest import CAPABILITY_PROVIDERS, CAPABILITY_LEVELS

plat = build_platform()
svc = plat.tool_readiness_service
report = svc.check()

available = {t.tool_id for t in report.tools if t.status.value == "available"}
status_map = {t.tool_id: t.status.value for t in report.tools}

rows = []
for cap, providers in CAPABILITY_PROVIDERS.items():
    avail = [p for p in providers if p in available]
    missing = [p for p in providers if p not in available]
    rows.append({
        "capability": cap,
        "level": CAPABILITY_LEVELS.get(cap, "").value if hasattr(CAPABILITY_LEVELS.get(cap), "value") else str(CAPABILITY_LEVELS.get(cap, "")),
        "providers": list(providers),
        "available": avail,
        "missing": missing,
        "executable_provider_count": len(avail),
        "status": "ready" if avail else "missing",
    })

out = {
    "total_capabilities": len(CAPABILITY_PROVIDERS),
    "ready_capabilities": sum(1 for r in rows if r["status"] == "ready"),
    "missing_capabilities": sum(1 for r in rows if r["status"] == "missing"),
    "capabilities": rows,
}
json.dump(out, open("/home/nc/hunterx/HunterX/artifacts/toolchain-audit/category-coverage.json", "w"), indent=2)
print(json.dumps(out, indent=2))
