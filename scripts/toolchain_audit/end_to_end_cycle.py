"""Prove the full execution cycle against a SAFE local target (localhost).

Shows: capability -> provider resolution -> tool selection -> command
knowledge -> command construction -> validation -> execution -> output ->
parser -> observation. Uses only localhost (owned target), never the external
Juice Shop target.
"""
from __future__ import annotations

import json

from hunterx.platform import build_platform


def main() -> None:
    plat = build_platform()
    toolchain = plat.toolchain_service
    engine = plat.execution_engine

    # Sync readiness first (as the mission preflight does) so engine health passes.
    svc = plat.tool_readiness_service
    svc.check(sync_engine=True)

    target = "http://127.0.0.1:18080"

    scenarios = [
        ("technology_fingerprint", "httpx", {"url": target, "tech_detect": True}),
        ("port_discovery", "nmap", {"host": "127.0.0.1", "ports": "18080"}),
        ("content_discovery", "ffuf", {"url": target, "wordlist": "/dev/null", "match_codes": "200"}),
    ]

    for cap, tool, params in scenarios:
        print(f"=== {cap} via {tool} ===")
        # 1. provider resolution (readiness knows available providers)
        # 2. command knowledge + construction + validation + execution
        try:
            result = toolchain.execute(tool, target, parameters=params)
        except Exception as exc:  # noqa: BLE001
            print(f"  EXECUTE ERROR: {exc}")
            continue
        print("  execution_id:", result.get("execution_id"))
        print("  status:", result.get("status"))
        print("  semantics:", result.get("semantics"))
        print("  error:", (result.get("error") or "")[:120])
        print("  stdout_preview:", (result.get("stdout_preview") or "")[:150])
        # 3. parse
        try:
            parsed = toolchain.inspect_result(result["execution_id"])
            print("  parsed_status:", parsed.get("status"))
        except Exception as exc:  # noqa: BLE001
            print("  parse error:", exc)
        print()


if __name__ == "__main__":
    main()
