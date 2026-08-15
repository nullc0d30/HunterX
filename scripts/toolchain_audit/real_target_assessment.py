"""Real-target assessment against https://juice-shop.herokuapp.com.

Drives HunterX's canonical capability->provider->tool->execute->parse pipeline
(which grants sandbox permissions) against the real target. Every step is
recorded with command, exit status, output preview and parsed result.
"""
from __future__ import annotations

import json
import os

os.environ.pop("HUNTERX_DATABASE_URL", None)
os.environ.pop("HUNTERX_DB_URL", None)

from hunterx.platform import build_platform  # noqa: E402

TARGET = "https://juice-shop.herokuapp.com"
HOST = "juice-shop.herokuapp.com"


def main() -> None:
    plat = build_platform()
    svc = plat.tool_readiness_service
    svc.check(sync_engine=True)
    toolchain = plat.toolchain_service
    engine = plat.execution_engine

    results = []
    steps = [
        # (label, capability, tool, target, params)
        ("subdomain-enumeration", "asset_discovery", "subfinder", HOST, {"silent": True}),
        ("dns-records", "dns_enumeration", "dnsx", HOST, {"a": True, "cname": True}),
        ("port-discovery", "port_discovery", "nmap", HOST, {"top_ports": "100"}),
        ("http-probing", "technology_fingerprint", "httpx", TARGET, {"tech_detect": True}),
        ("tech-fingerprint", "technology_fingerprint", "whatweb", TARGET, {}),
        ("crawl-endpoints", "endpoint_enumeration", "katana", TARGET, {"depth": 2}),
        ("parameter-discovery", "parameter_discovery", "arjun", TARGET, {}),
        ("template-scan", "vulnerability_scanning", "nuclei", TARGET, {"severity": "medium"}),
    ]

    for label, cap, tool, target, params in steps:
        rec = {"label": label, "capability": cap, "tool": tool, "target": target}
        try:
            result = toolchain.execute(tool, target, parameters=params)
            rec["status"] = result.get("status")
            rec["error"] = (result.get("error") or "")[:200]
            rec["execution_id"] = result.get("execution_id")
            if result.get("execution_id"):
                detail = toolchain.inspect_result(result["execution_id"])
                rec["parsed_status"] = detail.get("status")
                rec["stdout_preview"] = (detail.get("stdout_preview") or "")[:400]
        except Exception as exc:  # noqa: BLE001
            rec["status"] = "exception"
            rec["error"] = f"{type(exc).__name__}: {str(exc)[:200]}"
        results.append(rec)
        print(f"[{rec['status']}] {label} ({tool}): {rec.get('error', '')[:80]}")

    out = {"target": TARGET, "steps": results}
    base = "/home/nc/hunterx/HunterX/artifacts/final-rollout"
    import glob
    ts = sorted(glob.glob(f"{base}/*/"))[-1].split("/")[-2]
    json.dump(out, open(f"{base}/{ts}/telemetry/target-assessment.json", "w"), indent=2, default=str)
    print("WROTE target-assessment.json")


if __name__ == "__main__":
    main()
