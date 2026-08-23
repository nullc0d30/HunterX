# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Regression tests: JSON persistence boundary survives arbitrary objects.

Reproduces the v7.1.3 production incident:

    TypeError: Object of type JSToken is not JSON serializable
    (sqlalchemy.exc.StatementError on ``tidb_audit_logs.after``)

A JavaScript-analysis observation whose ``content`` carried raw
:class:`~hunterx.domain.javascript.tokenizer.JSToken` objects crashed the
SQLAlchemy commit because the versioning listener snapshots every column of
the observation row into ``AuditLogModel.after`` (a JSON column), whose
serializer received the non-JSON-native dataclass.

The contract under test: any value entering a JSON-backed persistence path —
observation rows, audit snapshots, timeline payloads, legacy JSON-text
columns — must already be JSON-compatible. These tests fail (StatementError)
on a codebase without the canonical :func:`to_json_safe` boundary.
"""

from __future__ import annotations

import dataclasses

import pytest

from hunterx.config.settings import DatabaseSettings
from hunterx.domain.entities.tidb.mission_orchestration import MissionObservationRecord
from hunterx.domain.javascript.tokenizer import JSToken, JSTokenType
from hunterx.domain.mission_orchestration.enums import StopCondition
from hunterx.infrastructure.db.sql.crud import SqlCrudRepository, SqlTidbRepositoryFactory
from hunterx.infrastructure.db.sql.factory import SessionFactory
from hunterx.infrastructure.db.sql.tidb_models import AuditLogModel
from hunterx.infrastructure.db.sql.versioning import install_versioning

sqlalchemy = pytest.importorskip("sqlalchemy")

from hunterx.application.mission_execution import MissionExecutionService  # noqa: E402
from hunterx.application.mission_orchestration import MissionOrchestrationService  # noqa: E402
from hunterx.domain.adaptive_mission_planning.toolchain import ToolSelectionEngine  # noqa: E402
from hunterx.domain.mission_orchestration.orchestrator import MissionOrchestrator  # noqa: E402
from hunterx.engines.adaptive_mission_planning.engine import AdaptiveMissionPlanningEngine  # noqa: E402
from hunterx.engines.mission_orchestration import MissionOrchestrationEngine  # noqa: E402
from tests.framework.fakes import FakeExecutionEngine  # noqa: E402


def _token(value: str = "/api/login", line: int = 3) -> JSToken:
    return JSToken(
        token_type=JSTokenType.STRING,
        value=value,
        line=line,
        column=9,
        offset=40,
        raw=f'"{value}"',
    )


@pytest.fixture()
def session_factory() -> SessionFactory:
    factory = SessionFactory(DatabaseSettings(url="sqlite:///:memory:"))
    factory.create_all()
    install_versioning(factory, actor="pytest", source="json-boundary-test")
    yield factory
    factory.dispose()


@pytest.fixture()
def observation_repo(session_factory: SessionFactory) -> SqlCrudRepository:
    return SqlCrudRepository(session_factory, MissionObservationRecord)


def _js_observation_payload() -> dict[str, object]:
    """A realistic JS-analysis observation content embedding raw tokens."""
    return {
        "javascript": {
            "analyses": [
                {
                    "asset": {"url": "http://target.test/app.js"},
                    "endpoints": [{"url": "/api/login", "evidence": [_token()]}],
                    "tokens": [_token("/api/search", 11), _token("Bearer ${t}", 12)],
                }
            ]
        }
    }


def test_observation_with_nested_js_token_persists(
    session_factory: SessionFactory, observation_repo: SqlCrudRepository
) -> None:
    record = MissionObservationRecord(
        observation_id="obs-js-1",
        mission_id="mission-js",
        action_id="action-1",
        tool_id="javascript",
        asset_key="http://target.test/app.js",
        observation_type="javascript_analysis",
        content=_js_observation_payload(),
        provenance={"source": "javascript", "correlation_id": "c-1"},
        confidence=0.7,
    )
    observation_repo.save(record)  # must not raise StatementError

    with session_factory.session() as session:
        logs = session.query(AuditLogModel).filter_by(action="create").all()
        assert len(logs) == 1
        after = logs[0].after
        analyses = after["content"]["javascript"]["analyses"]
        evidence_token = analyses[0]["endpoints"][0]["evidence"][0]
        assert evidence_token["__type__"] == "JSToken"
        assert evidence_token["value"] == "/api/login"
        assert evidence_token["line"] == 3
        assert evidence_token["token_type"] == "string"
        list_tokens = analyses[0]["tokens"]
        assert [t["value"] for t in list_tokens] == ["/api/search", "Bearer ${t}"]


def test_persisted_observation_round_trips_as_json_native(
    session_factory: SessionFactory, observation_repo: SqlCrudRepository
) -> None:
    record = MissionObservationRecord(
        observation_id="obs-js-2",
        mission_id="mission-js",
        content={"tokens": [_token()]},
    )
    observation_repo.save(record)

    restored = observation_repo.get(record.id)
    assert restored is not None
    leaf = restored.content["tokens"][0]
    assert isinstance(restored.content, dict)
    assert leaf["__type__"] == "JSToken" and leaf["value"] == "/api/login"


def test_audit_log_row_with_nested_js_token_commits(session_factory: SessionFactory) -> None:
    from hunterx.shared.ids import generate_id
    from hunterx.shared.time import utcnow_iso

    now = utcnow_iso()
    row = AuditLogModel(
        id=generate_id(),
        actor="pytest",
        action="create",
        object_type="observation",
        object_id="obs-js-3",
        before=None,
        after={
            "content": {
                "endpoint": "/api/login",
                "tokens": [_token(), {"nested": {"deep": [_token("secret-ish", 99)]}}],
            }
        },
        occurred_at=now,
        created_at=now,
    )
    with session_factory.session() as session:
        session.add(row)
        session.commit()  # must not raise TypeError/StatementError

    with session_factory.session() as session:
        stored = session.get(AuditLogModel, row.id)
        assert stored is not None
        deep = stored.after["content"]["tokens"][1]["nested"]["deep"][0]
        assert deep["__type__"] == "JSToken"
        assert deep["column"] == 9


def test_circular_reference_content_persists(
    session_factory: SessionFactory, observation_repo: SqlCrudRepository
) -> None:
    payload: dict[str, object] = {"name": "cycle"}
    payload["self"] = payload
    record = MissionObservationRecord(
        observation_id="obs-cycle",
        mission_id="mission-cycle",
        content=payload,
    )
    observation_repo.save(record)

    restored = observation_repo.get(record.id)
    assert restored.content["name"] == "cycle"
    assert restored.content["self"] == {"__circular__": True}


def test_non_finite_floats_persist_as_valid_json(
    session_factory: SessionFactory, observation_repo: SqlCrudRepository
) -> None:
    import json

    record = MissionObservationRecord(
        observation_id="obs-nan",
        mission_id="mission-nan",
        content={"score": float("nan"), "ceiling": float("inf")},
    )
    observation_repo.save(record)
    restored = observation_repo.get(record.id)
    text = json.dumps(restored.content)  # strict dumps: NaN would raise ValueError
    assert json.loads(text) == {"score": "NaN", "ceiling": "Infinity"}


# -- exact incident reproduction through the real mission runner ---------------


_DEFAULT_CANDIDATES: dict[str, tuple[str, ...]] = {
    "technology_fingerprint": ("whatweb",),
    "endpoint_enumeration": ("httpx",),
    "parameter_discovery": ("arjun",),
    "vulnerability_scanning": ("nuclei",),
}


def _token_bearing_outputs() -> dict[str, dict[str, object]]:
    """Every fake tool emits token-bearing payloads like real JS analysis."""
    def payload(kind: str) -> dict[str, object]:
        return {
            kind: [
                {
                    "url": "http://127.0.0.1:3010/app.js",
                    "findings": [_token("/rest/products/search?q=", 42)],
                    "tokens": [_token()],
                }
            ]
        }

    return {
        "whatweb": payload("technologies"),
        "httpx": payload("endpoints"),
        "arjun": payload("parameters"),
        "nuclei": payload("findings"),
    }


def test_full_mission_with_js_token_observations_never_crashes(tmp_path) -> None:
    """The v7.1.3 incident, end to end.

    A full_security_assessment mission persists every tool observation through
    the real SQL repository + versioning listener while each payload carries
    raw ``JSToken`` objects. Pre-fix this raises
    ``sqlalchemy.exc.StatementError`` on ``tidb_audit_logs.after``; post-fix
    the mission reaches an honest terminal state with everything persisted.
    """
    db_path = tmp_path / "incident.db"
    factory = SessionFactory(DatabaseSettings(url=f"sqlite:///{db_path}"))
    factory.create_all()
    install_versioning(factory, actor="pytest", source="incident-repro")
    try:
        planning = AdaptiveMissionPlanningEngine(
            tool_selection_engine=ToolSelectionEngine(
                mission_type="bug-bounty", default_candidates=_DEFAULT_CANDIDATES
            )
        )
        orchestrator = MissionOrchestrator(planning=planning)
        orchestration = MissionOrchestrationService(
            engine=MissionOrchestrationEngine(orchestrator=orchestrator),
            stores=SqlTidbRepositoryFactory(factory),
        )
        runner = MissionExecutionService(
            orchestration=orchestration,
            planning=planning,
            execution_engine=FakeExecutionEngine(outputs=_token_bearing_outputs()),
        )
        mission = orchestration.create_mission(
            objective="full_security_assessment", target="http://127.0.0.1:3010"
        )
        mission.policy = dataclasses.replace(
            mission.policy,
            stop_conditions=(
                StopCondition.COVERAGE_TARGET_ACHIEVED,
                StopCondition.RESOURCE_BUDGET_EXHAUSTED,
                StopCondition.OBJECTIVES_COMPLETE,
            ),
        )
        orchestration.start(mission.mission_id)
        result = runner.run(mission.mission_id, max_cycles=12, max_idle_cycles=4)

        # The mission reached a truthful terminal state without a persistence
        # crash. With fake tool outputs, the mission hits the cycle ceiling
        # (max_cycles=12) which is an operational ceiling, not resource exhaustion.
        # This correctly maps to 'degraded' status.
        assert result["status"] in ("completed", "stopped", "blocked", "degraded")

        # Observations carrying tokens were persisted.
        with factory.session() as session:
            from hunterx.infrastructure.db.sql.tidb_models import (
                MissionObservationRecordModel,
            )

            rows = (
                session.query(MissionObservationRecordModel)
                .filter_by(mission_id=mission.mission_id)
                .all()
            )
            assert rows, "expected observations to be persisted"
            token_rows = [row for row in rows if "JSToken" in str(row.content)]
            assert token_rows, "expected at least one token-bearing observation"

            # Every audit snapshot is valid JSON with semantic tokens preserved.
            audit_rows = (
                session.query(AuditLogModel)
                .filter_by(object_type="missionobservationrecord")
                .all()
            )
            assert audit_rows
            found_token_in_audit = any(
                "JSToken" in str(log.after) for log in audit_rows
            )
            assert found_token_in_audit, "audit snapshots should preserve typed tokens"
    finally:
        factory.dispose()
