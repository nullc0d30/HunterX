"""Complete single-process full hunt with full tool-execution capture."""
from __future__ import annotations

import json
import os

os.environ.pop("HUNTERX_DATABASE_URL", None)
os.environ.pop("HUNTERX_DB_URL", None)

from hunterx.platform import build_platform  # noqa: E402


def main() -> None:
    plat = build_platform()
    mission_service = plat.mission_orchestration_service
    execution = plat.mission_execution_service
    dashboard = plat.mission_dashboard_service

    target = "https://juice-shop.herokuapp.com"
    objective = "full_security_assessment"

    mission = mission_service.create_mission(objective=objective, target=target)
    mid = mission.mission_id
    print("MISSION_ID:", mid)

    try:
        mission_service.start(mid)
    except Exception as exc:  # noqa: BLE001
        print("start:", type(exc).__name__, str(exc)[:100])

    run = execution.run(mid, max_cycles=16, max_idle_cycles=3)
    print("initial run:", run["cycles_run"], "executions", run["tool_executions"], "obs", run["observations"], "cov", run["coverage_ratio"])

    # reassessment cycles
    for i in range(2, 8):
        again = execution.run(mid, max_cycles=4, max_idle_cycles=2)
        if again["tool_executions"] == 0 and again["observations"] == 0:
            print(f"reassess {i}: idle -> stop")
            break
        print(f"reassess {i}: exec={again['tool_executions']} obs={again['observations']} decisions={again['decisions']} cov={again['coverage_ratio']}")

    # Pull the live orchestrated mission object for detailed records
    om = mission_service.get(mid)
    mission_obj = om.mission
    ctx = om.context

    payload = {
        "mission_id": mid,
        "target": target,
        "objective": objective,
        "state": mission_obj.state.value,
        "phase": getattr(mission_obj, "phase", ""),
        "coverage_ratio": om.coverage_ratio(),
        "observations": [o.to_dict() if hasattr(o, "to_dict") else o for o in ctx.observations],
        "decisions": [d.to_dict() if hasattr(d, "to_dict") else d for d in ctx.decisions],
        "tool_executions": list(ctx.tool_executions),
        "hypotheses": [h.to_dict() if hasattr(h, "to_dict") else h for h in getattr(ctx, "hypotheses", [])],
        "evidence": [e.to_dict() if hasattr(e, "to_dict") else e for e in getattr(ctx, "evidence", [])],
        "findings": [f.to_dict() if hasattr(f, "to_dict") else f for f in getattr(ctx, "findings", [])],
        "attack_paths": [p.to_dict() if hasattr(p, "to_dict") else p for p in getattr(ctx, "attack_paths", [])],
        "negative_evidence": list(getattr(ctx, "negative_evidence", [])),
    }

    import glob
    base = "/home/nc/hunterx/HunterX/artifacts/final-rollout"
    ts_dirs = sorted(glob.glob(f"{base}/*/"))
    ts = ts_dirs[-1].split("/")[-2]
    tele = f"{base}/{ts}/telemetry"
    json.dump(payload, open(f"{tele}/mission-full.json", "w"), indent=2, default=str)
    print("WROTE mission-full.json")

    # print summary
    print("\n=== TOOL EXECUTIONS ===")
    for te in ctx.tool_executions:
        print(f"  {te.get('tool_id')}: {te.get('executed_at')} asset={te.get('asset_key')}")
    print("\n=== OBSERVATIONS ===")
    for o in ctx.observations[:20]:
        print(f"  {getattr(o,'tool_id','?')} {getattr(o,'observation_type','?')}: {str(getattr(o,'content',''))[:70]}")
    print("\n=== DECISIONS ===")
    for d in ctx.decisions[:20]:
        print(f"  {getattr(d,'kind','?')}: {str(getattr(d,'reason',''))[:70]}")


if __name__ == "__main__":
    main()
