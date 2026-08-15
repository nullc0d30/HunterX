"""End-to-end execution cycle via toolchain_service.execute_chain (safe localhost).

Proves capability -> provider resolution -> tool selection -> command
knowledge -> construction -> validation -> execution -> output -> parser ->
observation for a real target we own.
"""
from __future__ import annotations

import json

from hunterx.platform import build_platform


def main() -> None:
    plat = build_platform()
    service = plat.toolchain_service
    svc = plat.tool_readiness_service

    # Preflight sync so engine health passes.
    svc.check(sync_engine=True)

    target = "http://127.0.0.1:18080"
    capabilities = ["technology-fingerprinting", "directory-discovery"]

    print("=== CHAIN PLAN ===")
    plan = service.chain("toolchain-cycle", capabilities, scope="127.0.0.1")
    print("steps:", [(s["tool_id"], s["capability"]) for s in plan["steps"]])

    print("\n=== CHAIN EXECUTION (safe localhost) ===")
    report = service.execute_chain(
        "toolchain-cycle", capabilities, target,
        target_type="url", scope="127.0.0.1",
    )
    print("status:", report.get("status"))
    print("observation_count:", report.get("observation_count"))
    for step in report.get("steps", []):
        print(f"  step {step.get('tool_id')}: status={step.get('status')} observations={len(step.get('observations', []))}")
        for obs in step.get("observations", [])[:2]:
            print(f"    obs: source={obs.get('provenance', {}).get('source')} kind={obs.get('kind')}")


if __name__ == "__main__":
    main()
