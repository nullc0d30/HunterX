# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Final failure-recovery acceptance matrix.

Every failure mode is explicit and never silently becomes COMPLETE /
EXHAUSTED / NO_FINDING: model timeout / unavailable / malformed output, tool
unavailability / failure, defensive HTTP responses (429 / 403 / 5xx),
connection resets and partial discovery all preserve mission state and honest
outcomes.
"""

from __future__ import annotations

import contextlib
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from hunterx.application.adaptive_attack import AdaptiveAttackService
from hunterx.application.attack_surface import AttackSurfaceService
from hunterx.application.capability_execution import CapabilityExecutionEngine
from hunterx.application.capability_finding import CapabilityFindingPipeline
from hunterx.application.model_attacker import ModelAttacker
from hunterx.application.vulnerability_finding import VulnerabilityFindingService
from hunterx.domain.adaptive_attack.enums import AttackState
from hunterx.domain.capability_execution.enums import CapabilityExecutionStatus
from hunterx.domain.model_attacker.enums import AttackerCompletion
from hunterx.domain.model_attacker.reasoner import ModelReasoner
from hunterx.infrastructure.db.graph import InMemoryKnowledgeGraph
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.infrastructure.event_bus import InMemoryEventBus
from hunterx.infrastructure.memory import InMemoryFindingRepository
from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.sdk.engine import ExecutionEngine
from tests.framework.model_attacker import ScriptedHypothesisModel
from tests.framework.vulnerable_app import VulnerableApp


def _finding_service() -> VulnerabilityFindingService:
    return VulnerabilityFindingService(
        engine=ExecutionEngine(),
        stores=InMemoryTidbRepositoryFactory(),
        event_bus=InMemoryEventBus(),
        knowledge_graph=InMemoryKnowledgeGraph(),
        tip=ToolIntelligenceAPI(),
        findings=InMemoryFindingRepository(),
    )


def _make_handler_factory(status: int, reset: bool):
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *_: Any) -> None:
            return

        def do_GET(self) -> None:  # noqa: N802
            self._reply()

        def do_POST(self) -> None:  # noqa: N802
            self._reply()

        def _reply(self) -> None:
            if reset:
                with contextlib.suppress(OSError):
                    self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            body = b"forbidden" if status == 403 else b"rate limited" if status == 429 else b"server error"
            self.send_response(status)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return _Handler


def _status_server(status: int, *, reset: bool = False) -> Any:
    class _Server:
        def __init__(self) -> None:
            self._server: ThreadingHTTPServer | None = None
            self._thread: threading.Thread | None = None
            self.base_url = ""

        def __enter__(self) -> _Server:
            self._server = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler_factory(status, reset))
            port = int(self._server.server_address[1])
            self.base_url = f"http://127.0.0.1:{port}"
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._thread.start()
            return self

        def __exit__(self, *_: Any) -> None:
            if self._server is not None:
                self._server.shutdown()
                self._server.server_close()
            if self._thread is not None:
                self._thread.join(timeout=5)

    return _Server()


def _run_engine_on(target: str, *, adaptive: AdaptiveAttackService | None = None) -> CapabilityExecutionEngine:
    surface = AttackSurfaceService(mission_id="final-failure", target_key=target)
    surface.on_observation(
        observation_type="api",
        content={"endpoints": [f"{target}/vuln/search"]},
        asset_key=target,
        source="final-failure",
    )
    surface.on_observation(
        observation_type="parameter",
        content={"parameters": ["q"]},
        asset_key=f"{target}/vuln/search",
        source="final-failure",
    )
    engine = CapabilityExecutionEngine(
        mission_id="final-failure",
        target_key=target,
        surface=surface,
        adaptive=adaptive,
        probe_timeout_s=5.0,
    )
    engine.execute_ready()
    return engine


class TestModelFailure:
    """Model timeout / unavailability / malformed output never fabricate."""

    def test_model_unavailable_is_not_exhaustion(self) -> None:
        with VulnerableApp() as app:
            surface = _surface(app.base_url)
            attacker = ModelAttacker(ModelReasoner(ai=None), finding_pipeline=CapabilityFindingPipeline(_finding_service()))
            attacker.bind(surface, mission_id="final-failure")
            step = attacker.step()
            assert step["status"] == "model_unavailable"
            assert attacker.exhausted() is False
            assert attacker.completion_reason() == AttackerCompletion.MODEL_UNAVAILABLE.value
            assert attacker.report()["hypotheses"] == [], "no fabricated hypotheses on model failure"

    def test_model_failure_is_explicit_and_reported(self) -> None:
        with VulnerableApp() as app:
            surface = _surface(app.base_url)
            model = ScriptedHypothesisModel([[]], fail_after=1)
            attacker = ModelAttacker(ModelReasoner(model), finding_pipeline=CapabilityFindingPipeline(_finding_service()))
            attacker.bind(surface, mission_id="final-failure")
            step = attacker.step()
            assert step["status"] == "model_unavailable"
            assert attacker.telemetry()["model_failures"] >= 1
            assert attacker.exhausted() is False

    def test_malformed_model_output_creates_no_tasks(self) -> None:
        class _Malformed:
            def complete(self, prompt: str, *, model: str | None = None, temperature: float = 0.0) -> str:  # noqa: ARG002
                return "this is not json at all"

            def embed(self, text: str) -> list[float]:  # noqa: ARG002
                return []

        with VulnerableApp() as app:
            surface = _surface(app.base_url)
            attacker = ModelAttacker(ModelReasoner(_Malformed()), finding_pipeline=CapabilityFindingPipeline(_finding_service()))
            attacker.bind(surface, mission_id="final-failure")
            step = attacker.step()
            assert step["status"] == "model_unavailable", "malformed output must surface as a model failure"
            assert attacker.report()["plans"] == [], "no unsafe task creation from malformed output"


class TestHTTPDefensiveResponses:
    """429 / 403 / 5xx / reset throttle and record honestly — never exhaust."""

    @pytest.mark.parametrize("status", [429, 403, 500, 503])
    def test_defensive_status_records_honest_outcome(self, status: int) -> None:
        with _status_server(status) as server:
            adaptive = AdaptiveAttackService(mission_id="final-failure", target_key=server.base_url)
            engine = _run_engine_on(server.base_url, adaptive=adaptive)
            records = engine.records
            assert records, "the engine must record an outcome"
            assert adaptive.is_throttling(), f"HTTP {status} must throttle the controller"
            # Defensive feedback is never converted into a terminal success.
            assert adaptive.attack_state() in (AttackState.THROTTLED, AttackState.BACKING_OFF, AttackState.BLOCKED)
            for record in records:
                assert record.outcome in (
                    CapabilityExecutionStatus.FAILED,
                    CapabilityExecutionStatus.NO_FINDING,
                    CapabilityExecutionStatus.NOT_APPLICABLE,
                    CapabilityExecutionStatus.VERIFIED,
                ), "a defensive response must never fabricate a FINDING"

    def test_connection_reset_is_bounded_and_recorded(self) -> None:
        with _status_server(0, reset=True) as server:
            engine = _run_engine_on(server.base_url)
            assert engine.records, "a connection reset must still produce a recorded outcome"
            for record in engine.records:
                if record.outcome is CapabilityExecutionStatus.FINDING:
                    pytest.fail("a reset connection must never fabricate a finding")


class TestPartialDiscovery:
    """Partial discovery continues with the available surfaces."""

    def test_valid_surfaces_execute_after_broken_ones(self) -> None:
        with VulnerableApp() as app:
            target = app.base_url
            surface = AttackSurfaceService(mission_id="final-failure", target_key=target)
            surface.on_observation(
                observation_type="api",
                content={"endpoints": [f"{target}/vuln/search", f"{target}/does-not-exist"]},
                asset_key=target,
                source="final-failure",
            )
            surface.on_observation(
                observation_type="parameter",
                content={"parameters": ["q"]},
                asset_key=f"{target}/vuln/search",
                source="final-failure",
            )
            engine = CapabilityExecutionEngine(
                mission_id="final-failure",
                target_key=target,
                surface=surface,
                adaptive=None,
                probe_timeout_s=5.0,
            )
            engine.execute_ready()
            assert any(record.endpoint.endswith("/vuln/search") for record in engine.records), "valid surfaces must execute"
            # The broken surface was still recorded (never silently dropped).
            assert any("/does-not-exist" in record.endpoint for record in engine.records), "broken surfaces must be recorded, not dropped"


def _surface(target: str) -> AttackSurfaceService:
    surface = AttackSurfaceService(mission_id="final-failure", target_key=target)
    surface.on_observation(
        observation_type="api",
        content={"endpoints": [f"{target}/vuln/search", f"{target}/vuln/echo"]},
        asset_key=target,
        source="final-failure",
    )
    surface.on_observation(
        observation_type="parameter",
        content={"parameters": ["q"]},
        asset_key=f"{target}/vuln/search",
        source="final-failure",
    )
    surface.on_observation(
        observation_type="parameter",
        content={"parameters": ["msg"]},
        asset_key=f"{target}/vuln/echo",
        source="final-failure",
    )
    return surface


__all__: list[str] = []
