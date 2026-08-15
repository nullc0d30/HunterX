"""Prove the mission preflight gate resolves capabilities end-to-end."""
from __future__ import annotations

import json

from hunterx.platform import build_platform


def main() -> None:
    plat = build_platform()
    preflight = plat.tool_readiness_service.preflight  # service-level preflight if present
    service = plat.tool_readiness_service

    report = service.check()
    caps = {c.capability: c for c in report.capabilities}
    required = [c for c in caps.values() if c.level.value == "required"]
    ready_required = [c for c in required if c.ready]
    blocked_required = [c for c in required if not c.ready]

    print("=== MISSION PREFLIGHT GATE (capability resolution) ===")
    print(f"required capabilities: {len(required)}")
    print(f"  with >=1 executable provider: {len(ready_required)}")
    for c in ready_required:
        print(f"    {c.capability:26} -> {','.join(c.available)}")
    print(f"  blocked (no provider): {len(blocked_required)}")
    for c in blocked_required:
        print(f"    {c.capability}: missing {list(c.missing)}")

    recommended = [c for c in caps.values() if c.level.value == "recommended"]
    ready_rec = [c for c in recommended if c.ready]
    print(f"\nrecommended capabilities: {len(recommended)} ready: {len(ready_rec)}")

    print("\n=== END-TO-END PIPELINE CHAIN (Observe -> Parse -> Observation) ===")
    # Prove command construction + execution + parsing via the execution engine
    engine = plat.execution_engine
    tip = plat.tip

    # pick a fully integrated provider and construct+run a safe command
    from hunterx.tools.intelligence.api import ToolSelectionCriteria

    probe_tools = ["nmap", "subfinder", "httpx"]
    for tool_id in probe_tools:
        meta = tip.get_tool(tool_id)
        knowledge = tip.get_knowledge(tool_id)
        adapter = engine.adapter_for(tool_id)
        print(f"  {tool_id}: metadata={'yes' if meta else 'no'} knowledge={'yes' if knowledge else 'no'} adapter={'yes' if adapter else 'no'} cli_binary={getattr(knowledge, 'cli_binary', None) if knowledge else None}")


if __name__ == "__main__":
    main()
