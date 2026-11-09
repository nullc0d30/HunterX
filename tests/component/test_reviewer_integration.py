import pytest
from hunterx.domain.orchestration.enums import MissionState, MissionType
from hunterx.engines.orchestration.mock_reviewer import SimpleMockReviewer
from tests.component.test_orchestration_engine import _make_api

def test_mission_with_reviewer_rejects_empty_results() -> None:
    api, _, _, _ = _make_api()
    reviewer = SimpleMockReviewer()
    # Inject the reviewer into the engine
    api.engine._reviewer = reviewer
    
    mission = api.create_mission(
        objective="assess example.com",
        mission_type=MissionType.WEB_PENTEST,
        targets=("example.com",),
    ).value
    api.plan_mission(mission.mission_id)
    
    # Run mission. With no tool outputs, evidence_count should be 0, 
    # so the reviewer should reject it.
    run_result = api.engine.run_mission(mission.mission_id)
    
    assert not run_result.ok
    assert isinstance(run_result.error, Exception)
