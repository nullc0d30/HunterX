"""Extract full mission execution detail (tool runs, observations, decisions) from a fresh process."""
from __future__ import annotations

import json
import os

os.environ.pop("HUNTERX_DATABASE_URL", None)
os.environ.pop("HUNTERX_DB_URL", None)

from hunterx.platform import build_platform  # noqa: E402


def main() -> None:
    plat = build_platform()
    dashboard = plat.mission_dashboard_service
    mission = plat.mission_orchestration_service
    execution = plat.mission_execution_service

    # Find the latest mission
    mids = [m.mission_id for m in mission.list_missions()] if hasattr(mission, "list_missions") else []
    print("missions found:", len(mids))

    # Read from the persisted overview
    import glob
    base = "/home/nc/hunterx/HunterX/artifacts/final-rollout"
    ts_dirs = sorted(glob.glob(f"{base}/*/"))
    ts = ts_dirs[-1].split("/")[-2]
    data = json.load(open(f"{base}/{ts}/telemetry/mission.json"))
    mid = data["mission_id"]
    print("using mission:", mid)

    overview = dashboard.overview(mid)
    print(json.dumps({
        "counts": overview.get("counts"),
        "coverage_ratio": overview.get("coverage_ratio"),
        "state": overview.get("state"),
    }, indent=1))


if __name__ == "__main__":
    main()
