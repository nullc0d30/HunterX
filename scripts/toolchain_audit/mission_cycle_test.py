"""Full Observe -> Hypothesize -> Probe -> Verify cycle via MissionExecutor.

Runs a real plan against a SAFE local target (127.0.0.1:18080, owned).
Proves: capability -> provider resolution -> tool selection -> command
knowledge -> construction -> validation -> execution -> output -> parser ->
observation, with scope/safety guards active.
"""
from __future__ import annotations

import json

from hunterx.engines.orchestration.executor import MissionExecutor
from hunterx.engines.orchestration.plan import ExecutionPlan
from hunterx.engines.orchestration.step import MissionStep, SafetyClass
from hunterx.platform import build_platform


def main() -> None:
    plat = build_platform()
    engine = plat.execution_engine
    tip = plat.tip

    # Sync readiness (what preflight does) so engine health passes.
    plat.tool_readiness_service.check(sync_engine=True)

    steps = [
        MissionStep(step_id="s1", capability="port_discovery", target="127.0.0.1",
                    parameters={"ports": "18080"}, tool_id="nmap", safety_class=SafetyClass.DISCOVERY),
        MissionStep(step_id="s2", capability="technology_fingerprint", target="http://127.0.0.1:18080",
                    parameters={"tech_detect": True}, tool_id="httpx", safety_class=SafetyClass.DISCOVERY),
        MissionStep(step_id="s3", capability="content_discovery", target="http://127.0.0.1:18080",
                    parameters={"wordlist": "/dev/null", "match_codes": "200"}, tool_id="ffuf",
                    safety_class=SafetyClass.DISCOVERY),
    ]
    plan = ExecutionPlan(plan_id="plan-cycle-1", scope="127.0.0.1", steps=steps)

    executor = MissionExecutor(engine=engine, tip=tip)
    result = executor.run(mission_id="mission-cycle-1", plan=plan)

    print("=== MISSION CYCLE RESULT ===")
    print("all_completed:", getattr(result, "all_completed", "n/a"))
    for key in ("completed", "skipped", "failed", "gaps", "fallbacks", "deduplicated"):
        value = getattr(result, key, None)
        if value is not None:
            print(f"  {key}: {value}")
    if getattr(result, "outcomes", None):
        for step_id, outcome in result.outcomes.items():
            status = getattr(outcome, "status", "n/a")
            error = getattr(outcome, "error", "") or ""
            print(f"  step {step_id}: {status} {error[:100]}")


if __name__ == "__main__":
    main()
