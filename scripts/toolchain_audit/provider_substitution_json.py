"""Emit structured provider-substitution results + preflight gating checks."""
from __future__ import annotations

import json

from hunterx.tools.readiness.models import ToolReadinessStatus

from provider_substitution_test import StubDiscovery


def run(service, statuses):  # noqa: ANN001
    service._discovery = StubDiscovery(statuses)
    report = service.check()
    return {c.capability: c.to_dict() for c in report.capabilities}


def main() -> None:
    from hunterx.platform import build_platform

    plat = build_platform()
    svc = plat.tool_readiness_service

    scenarios = [
        ("all_providers_available", "port_discovery",
         {"nmap": ToolReadinessStatus.AVAILABLE, "rustscan": ToolReadinessStatus.AVAILABLE,
          "naabu": ToolReadinessStatus.AVAILABLE, "masscan": ToolReadinessStatus.AVAILABLE}),
        ("nmap_unavailable", "port_discovery",
         {"nmap": ToolReadinessStatus.MISSING, "rustscan": ToolReadinessStatus.AVAILABLE,
          "naabu": ToolReadinessStatus.AVAILABLE, "masscan": ToolReadinessStatus.AVAILABLE}),
        ("nmap_rustscan_unavailable", "port_discovery",
         {"nmap": ToolReadinessStatus.MISSING, "rustscan": ToolReadinessStatus.MISSING,
          "naabu": ToolReadinessStatus.AVAILABLE, "masscan": ToolReadinessStatus.AVAILABLE}),
        ("only_last_provider", "port_discovery",
         {"nmap": ToolReadinessStatus.MISSING, "rustscan": ToolReadinessStatus.MISSING,
          "naabu": ToolReadinessStatus.MISSING, "masscan": ToolReadinessStatus.AVAILABLE}),
        ("no_executable_provider", "port_discovery",
         {"nmap": ToolReadinessStatus.MISSING, "rustscan": ToolReadinessStatus.MISSING,
          "naabu": ToolReadinessStatus.MISSING, "masscan": ToolReadinessStatus.MISSING}),
        ("content_substitution_ffuf_to_gobuster", "content_discovery",
         {"ffuf": ToolReadinessStatus.MISSING, "gobuster": ToolReadinessStatus.AVAILABLE,
          "feroxbuster": ToolReadinessStatus.MISSING, "dirsearch": ToolReadinessStatus.MISSING}),
        ("broken_provider_is_not_available", "xss",
         {"dalfox": ToolReadinessStatus.BROKEN, "xssstrike": ToolReadinessStatus.AVAILABLE}),
        ("wrong_binary_is_not_available", "service_detection",
         {"nmap": ToolReadinessStatus.BROKEN, "httpx": ToolReadinessStatus.AVAILABLE}),
    ]

    results = []
    for name, cap, st in scenarios:
        res = run(svc, {k: v for k, v in st.items()})
        results.append({"scenario": name, "capability": cap, **res[cap]})

    json.dump(results, open("/home/nc/hunterx/HunterX/artifacts/toolchain-audit/provider-substitution-results.json", "w"), indent=2)
    for r in results:
        print(f"{r['scenario']:44} status={r['status']:8} available={r['available']}")


if __name__ == "__main__":
    main()
