"""Provider substitution tests for the capability resolver.

Simulates provider availability (AVAILABLE / MISSING / BROKEN) and verifies
that the readiness capability resolver picks the first available provider in
declaration order and reports NO_EXECUTABLE_PROVIDER when all are unavailable.
Uses the real readiness service with a stub discovery, never the live system.
"""
from __future__ import annotations

import sys

from hunterx.tools.readiness.discovery import ToolDiscovery
from hunterx.tools.readiness.models import ToolReadiness, ToolReadinessStatus
from hunterx.tools.readiness.platform import PlatformInfo
from hunterx.tools.readiness.service import ToolReadinessService


class StubDiscovery(ToolDiscovery):
    """Discovery whose probe() returns canned verdicts per tool id."""

    def __init__(self, statuses: dict[str, ToolReadinessStatus]) -> None:
        super().__init__(engine=None)
        self._statuses = statuses

    def probe(self, definition, platform) -> ToolReadiness:  # noqa: ANN001
        status = self._statuses.get(definition.tool_id, ToolReadinessStatus.MISSING)
        version = "9.9.9" if status is ToolReadinessStatus.AVAILABLE else ""
        return ToolReadiness(
            tool_id=definition.tool_id,
            status=status,
            version=version,
            definition=definition,
            platform=platform.os,
        )


def run(service: ToolReadinessService, statuses: dict[str, ToolReadinessStatus]) -> dict:
    service._discovery = StubDiscovery(statuses)
    report = service.check()
    caps = {c.capability: c for c in report.capabilities}
    return {name: caps[name].to_dict() for name in ("port_discovery", "content_discovery", "xss", "sql_injection")}


def main() -> None:
    from hunterx.platform import build_platform

    plat = build_platform()
    svc = plat.tool_readiness_service

    scenarios = [
        ("all providers available",
         {"nmap": "available", "rustscan": "available", "naabu": "available", "masscan": "available"}),
        ("nmap missing -> rustscan",
         {"nmap": "missing", "rustscan": "available", "naabu": "available", "masscan": "available"}),
        ("nmap+rustscan missing -> naabu",
         {"nmap": "missing", "rustscan": "missing", "naabu": "available", "masscan": "available"}),
        ("nmap+rustscan+naabu missing -> masscan",
         {"nmap": "missing", "rustscan": "missing", "naabu": "missing", "masscan": "available"}),
        ("all port providers unavailable -> NO_EXECUTABLE_PROVIDER",
         {"nmap": "missing", "rustscan": "missing", "naabu": "missing", "masscan": "missing"}),
        ("port ok, content substitution ffuf->gobuster",
         {"nmap": "available", "rustscan": "missing", "naabu": "missing", "masscan": "missing",
          "ffuf": "missing", "gobuster": "available", "feroxbuster": "missing", "dirsearch": "missing"}),
    ]

    for name, st in scenarios:
        statuses = {k: ToolReadinessStatus(v) for k, v in st.items()}
        res = run(svc, statuses)
        print(f"=== {name} ===")
        for cap, data in res.items():
            print(f"  {cap:22} status={data['status']:8} available={data['available']}")
        print()


if __name__ == "__main__":
    main()
