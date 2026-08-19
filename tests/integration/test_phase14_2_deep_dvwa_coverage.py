# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Phase 14.2 — deep DVWA-style authenticated coverage regressions.

Focused regression tests for the root causes found while diagnosing why the
Phase 14.1 deep run missed the DVWA-low SQLi / LFI / RCE surfaces:

1. Multi-candidate parameter→class derivation (``id`` → IDOR *and* SQL
   injection; ``page`` → LFI; ``ip``/``host`` → command injection) with
   token-boundary matching (an ``api``/``skip`` parameter must NOT derive a
   command-injection hypothesis).
2. Arjun-shaped parameter observations (``{"findings": [{"name", "endpoint",
   "method"}]}``) and structured crawler endpoint records ingest cleanly into
   the context model, preserving POST methods in provenance.
3. POST-discovered form fields produce body-carrying probes that genuinely
   reach body-only handlers (DVWA exec is a POST-only form) — and are
   honestly refuted on safe surfaces.
4. Per-endpoint parameter discovery replanning (deduplicated by
   capability+asset) instead of a single mission-level arjun run.
5. Deep path-traversal payloads reach DVWA's six-level traversal depth.
6. Authenticated session lifecycle: a probe whose session died mid-mission
   (an authenticated crawl can touch a logout endpoint) must never evaluate
   the login wall — the mission re-establishes the session and retries the
   probe once, so walled probes are inconclusive, never refuted/validated.

The capabilities, evidence gates and completion policy are untouched: these
tests only pin the discovery/hypothesis/probe plumbing fixes.
"""

from __future__ import annotations

from typing import Any

import pytest

from hunterx.application.mission_execution import MissionExecutionService
from hunterx.application.mission_orchestration import MissionOrchestrationService
from hunterx.domain.adaptive_mission_planning.toolchain import ToolSelectionEngine
from hunterx.domain.mission_orchestration.orchestrator import (
    MissionOrchestrator,
    _classes_for_surface,
)
from hunterx.engines.adaptive_mission_planning.engine import AdaptiveMissionPlanningEngine
from hunterx.engines.mission_orchestration import MissionOrchestrationEngine
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.domain.vulnerability_capability.capabilities.injection import (
    CommandInjectionCapability,
    PathTraversalCapability,
)
from hunterx.domain.vulnerability_capability.engine import VulnerabilityCapabilityEngine
from hunterx.domain.vulnerability_capability.probe_executor import ProbeExecutor
from hunterx.infrastructure.db.graph import InMemoryKnowledgeGraph
from hunterx.infrastructure.event_bus import InMemoryEventBus
from hunterx.infrastructure.memory import InMemoryFindingRepository
from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.sdk.engine import ExecutionEngine
from tests.framework.fakes import FakeExecutionEngine
from tests.framework.vulnerable_app import VulnerableApp


@pytest.fixture(scope="module")
def app() -> VulnerableApp:
    with VulnerableApp() as server:
        yield server


class TestMultiCandidateParameterDerivation:
    def test_ambiguous_id_derives_idor_and_sql_injection(self) -> None:
        classes = [class_id for class_id, _ in _classes_for_surface("id")]
        assert "idor" in classes
        assert "sql-injection" in classes

    def test_id_tokens_keep_secondary_class(self) -> None:
        classes = [class_id for class_id, _ in _classes_for_surface("user_id")]
        assert classes == ["idor", "sql-injection"]

    def test_page_implies_lfi(self) -> None:
        classes = [class_id for class_id, _ in _classes_for_surface("page")]
        assert "lfi" in classes

    def test_ip_and_host_imply_command_injection(self) -> None:
        assert "command-injection" in [c for c, _ in _classes_for_surface("ip")]
        assert "command-injection" in [c for c, _ in _classes_for_surface("host")]

    def test_token_boundary_prevents_substring_false_positives(self) -> None:
        # ``ip`` is a substring of ``api``/``skip``; ``id`` of ``ids`` —
        # none of these may fabricate a command-injection/IDOR hypothesis.
        assert [c for c, _ in _classes_for_surface("api")] == ["xss"]
        assert [c for c, _ in _classes_for_surface("skip")] == ["xss"]
        assert [c for c, _ in _classes_for_surface("ids")] == ["xss"]

    def test_unclassified_falls_back_to_reflection_xss(self) -> None:
        assert [c for c, _ in _classes_for_surface("random_param")] == ["xss"]


class TestParameterIngestion:
    def _service(self) -> tuple[MissionOrchestrationService, str]:
        planning = AdaptiveMissionPlanningEngine(
            tool_selection_engine=ToolSelectionEngine(default_candidates={}),
        )
        orchestration = MissionOrchestrationService(
            engine=MissionOrchestrationEngine(orchestrator=MissionOrchestrator(planning=planning)),
            stores=InMemoryTidbRepositoryFactory(),
        )
        mission = orchestration.create_mission(
            objective="web_security_assessment", target="http://localhost:3010"
        )
        return orchestration, mission.mission_id

    def test_arjun_findings_shape_ingests_with_method(self) -> None:
        orchestration, mission_id = self._service()
        orchestration.ingest_result(
            mission_id,
            tool_id="arjun",
            asset_key="http://localhost:3010/",
            raw={
                "observation_type": "parameter",
                "content": {
                    "parameters": {
                        "findings": [
                            {"name": "q", "endpoint": "http://localhost:3010/search", "method": "GET"},
                            {"name": "ip", "endpoint": "http://localhost:3010/exec", "method": "POST"},
                        ]
                    },
                    "count": 2,
                },
            },
        )
        mission = orchestration.get(mission_id)
        param_keys = {key: entry for key, entry in mission.context.parameters.items()}
        assert "param:http://localhost:3010/search:q" in param_keys
        exec_entry = param_keys["param:http://localhost:3010/exec:ip"]
        assert exec_entry.get("method") == "POST"
        assert "method" not in param_keys["param:http://localhost:3010/search:q"]

    def test_structured_endpoint_record_ingests_post_form_field(self) -> None:
        orchestration, mission_id = self._service()
        orchestration.ingest_result(
            mission_id,
            tool_id="crawler",
            asset_key="http://localhost:3010/",
            raw={
                "observation_type": "endpoint",
                "content": {
                    "endpoints": [
                        {
                            "url": "http://localhost:3010/exec",
                            "method": "POST",
                            "parameters": [{"name": "ip"}, {"name": "submit"}],
                        }
                    ]
                },
            },
        )
        mission = orchestration.get(mission_id)
        entry = mission.context.parameters["param:http://localhost:3010/exec:ip"]
        assert entry.get("method") == "POST"

    def test_post_form_field_derives_hypothesis_with_method(self) -> None:
        orchestration, mission_id = self._service()
        orchestration.ingest_result(
            mission_id,
            tool_id="crawler",
            asset_key="http://localhost:3010/",
            raw={
                "observation_type": "endpoint",
                "content": {
                    "endpoints": [
                        {
                            "url": "http://localhost:3010/exec",
                            "method": "POST",
                            "parameters": [{"name": "ip"}],
                        }
                    ]
                },
            },
        )
        mission = orchestration.get(mission_id)
        command = next(
            (
                h
                for h in mission.hypotheses
                if (h.provenance or {}).get("vulnerability_class") == "command-injection"
            ),
            None,
        )
        assert command is not None, "a POST 'ip' form field must derive a command-injection hypothesis"
        assert (command.provenance or {}).get("method") == "POST"


class TestPostProbeReachability:
    def test_post_probe_carries_body_and_form_encoding(self) -> None:
        probes = CommandInjectionCapability().build_probes(
            {
                "endpoint": "http://127.0.0.1:3010/exec",
                "parameter": "ip",
                "method": "POST",
            }
        )
        assert len(probes) == 1
        probe = probes[0]
        assert probe.method == "POST"
        assert probe.body_template == "ip={payload}"
        assert ("Content-Type", "application/x-www-form-urlencoded") in probe.headers

    def test_get_probe_unchanged_for_query_surfaces(self) -> None:
        probes = CommandInjectionCapability().build_probes(
            {"endpoint": "http://127.0.0.1:3010/run", "parameter": "cmd"}
        )
        assert probes[0].method == "GET"
        assert probes[0].body_template == ""

    def test_post_probe_reaches_body_only_handler(self, app: VulnerableApp) -> None:
        engine = VulnerabilityCapabilityEngine()
        probe = engine.build_probe(
            "command-injection",
            {"endpoint": f"{app.base_url}/vuln/run", "parameter": "ip", "method": "POST"},
        )
        assert probe is not None
        responses = ProbeExecutor().execute(probe, target=f"{app.base_url}/vuln/run")
        verdict = engine.analyze_probe("command-injection", probe, responses)
        assert verdict.supported, verdict.notes

    def test_post_probe_honestly_refutes_safe_body_handler(self, app: VulnerableApp) -> None:
        engine = VulnerabilityCapabilityEngine()
        probe = engine.build_probe(
            "command-injection",
            {"endpoint": f"{app.base_url}/safe/run", "parameter": "ip", "method": "POST"},
        )
        assert probe is not None
        responses = ProbeExecutor().execute(probe, target=f"{app.base_url}/safe/run")
        verdict = engine.analyze_probe("command-injection", probe, responses)
        assert verdict.contradicted, verdict.notes


class TestPerEndpointParameterDiscoveryReplan:
    def _runner(self) -> tuple[MissionExecutionService, AdaptiveMissionPlanningEngine, str]:
        planning = AdaptiveMissionPlanningEngine(
            tool_selection_engine=ToolSelectionEngine(default_candidates={}),
        )
        orchestration = MissionOrchestrationService(
            engine=MissionOrchestrationEngine(orchestrator=MissionOrchestrator(planning=planning)),
            stores=InMemoryTidbRepositoryFactory(),
        )
        mission = orchestration.create_mission(objective="bug_bounty_assessment", target="http://127.0.0.1:4280")
        orchestration.start(mission.mission_id)
        runner = MissionExecutionService(
            orchestration=orchestration,
            planning=planning,
            execution_engine=FakeExecutionEngine(outputs={}),
        )
        return runner, planning, mission.mission_id

    def test_each_discovered_endpoint_gets_its_own_parameter_discovery(self) -> None:
        runner, planning, mission_id = self._runner()
        for url in (
            "http://127.0.0.1:4280/sqli.php?id=1",
            "http://127.0.0.1:4280/exec.php",
        ):
            runner._replan_from_observation(  # noqa: SLF001
                mission_id,
                capability="endpoint_enumeration",
                raw={
                    "observation_type": "endpoint",
                    "content": {"urls": [url]},
                },
            )
        graph = planning.get_plan(mission_id)
        param_actions = [
            a for a in graph.actions.values() if a.capability == "parameter_discovery"
        ]
        assets = {a.asset for a in param_actions}
        assert "http://127.0.0.1:4280/sqli.php?id=1" in assets
        assert "http://127.0.0.1:4280/exec.php" in assets

    def test_identical_endpoint_never_schedules_twice(self) -> None:
        runner, planning, mission_id = self._runner()
        url = "http://127.0.0.1:4280/exec.php"
        for _ in range(2):
            runner._replan_from_observation(  # noqa: SLF001
                mission_id,
                capability="endpoint_enumeration",
                raw={"observation_type": "endpoint", "content": {"urls": [url]}},
            )
        graph = planning.get_plan(mission_id)
        param_actions = [
            a for a in graph.actions.values() if a.capability == "parameter_discovery"
        ]
        # The initial chain may already carry a target-root parameter_discovery
        # action; the regression point is that the endpoint itself is never
        # scheduled twice.
        assert len([a for a in param_actions if a.asset == url]) == 1


class TestDeepTraversalPayloads:
    def test_payloads_reach_six_levels(self) -> None:
        payloads = PathTraversalCapability.payloads
        assert "../../../../../etc/passwd" in payloads
        assert "../../../../../../etc/passwd" in payloads

    def test_deep_traversal_probe_validates_lfi(self, app: VulnerableApp) -> None:
        engine = VulnerabilityCapabilityEngine()
        probe = engine.build_probe(
            "lfi",
            {"endpoint": f"{app.base_url}/vuln/read", "parameter": "file"},
        )
        assert probe is not None
        responses = ProbeExecutor().execute(probe, target=f"{app.base_url}/vuln/read")
        verdict = engine.analyze_probe("lfi", probe, responses)
        assert verdict.supported, verdict.notes

    def test_deep_traversal_probe_honestly_refutes_safe_reader(self, app: VulnerableApp) -> None:
        engine = VulnerabilityCapabilityEngine()
        probe = engine.build_probe(
            "lfi",
            {"endpoint": f"{app.base_url}/safe/read", "parameter": "file"},
        )
        assert probe is not None
        responses = ProbeExecutor().execute(probe, target=f"{app.base_url}/safe/read")
        verdict = engine.analyze_probe("lfi", probe, responses)
        assert verdict.contradicted, verdict.notes


class TestInformationalCandidatesNeverBecomeVulnerabilitySignals:
    """A severity=info scanner result is intelligence even when its template
    canonicalizes to a real class (nuclei ``http-missing-security-headers``
    -> ``security-misconfiguration``): a generic per-page detection must never
    derive a hypothesis or a report-ready finding on its own.
    """

    def test_info_severity_missing_headers_is_not_a_signal(self) -> None:
        from hunterx.domain.mission_orchestration.orchestrator import _is_vulnerability_signal

        assert not _is_vulnerability_signal(
            {
                "template_id": "http-missing-security-headers",
                "template_name": "HTTP Missing Security Headers",
                "severity": "info",
                "matched_at": "http://localhost:3010/login.php",
            }
        )

    def test_medium_severity_class_candidate_still_signals(self) -> None:
        from hunterx.domain.mission_orchestration.orchestrator import _is_vulnerability_signal

        assert _is_vulnerability_signal(
            {
                "vulnerability_class": "security-misconfiguration",
                "severity": "medium",
                "endpoint": "http://localhost:3010/vuln/headers",
            }
        )

    def test_info_severity_nuclei_finding_never_creates_mission_finding(self, app: VulnerableApp) -> None:
        planning = AdaptiveMissionPlanningEngine(
            tool_selection_engine=ToolSelectionEngine(default_candidates={}),
        )
        orchestration = MissionOrchestrationService(
            engine=MissionOrchestrationEngine(orchestrator=MissionOrchestrator(planning=planning)),
            stores=InMemoryTidbRepositoryFactory(),
        )
        mission = orchestration.create_mission(objective="bug_bounty_assessment", target=app.base_url)
        orchestration.start(mission.mission_id)
        runner = MissionExecutionService(
            orchestration=orchestration,
            planning=planning,
            execution_engine=FakeExecutionEngine(
                outputs={
                    "nuclei": {
                        "findings": [
                            {
                                "template_id": "http-missing-security-headers",
                                "template_name": "HTTP Missing Security Headers",
                                "severity": "info",
                                "matched_at": f"{app.base_url}/login.php",
                            }
                        ]
                    }
                }
            ),
        )
        runner.run(mission.mission_id, max_cycles=12)
        mission = orchestration.get(mission.mission_id)
        assert not [h for h in mission.hypotheses if "security-misconfiguration" in h.statement]
        assert mission.context.findings == []


class TestArjunInvocationMatchesInstalledCli:
    """The installed arjun (2.2.7+) dropped ``-oJ``/``-H`` for ``-o``/
    ``--headers``; the adapter must emit the modern flags or every
    authenticated run exits with an argparse usage error.
    """

    def test_argv_uses_modern_json_and_header_flags(self) -> None:
        from hunterx.domain.execution import ExecutionContext
        from hunterx.tools.parameter.adapters import ArjunAdapter

        adapter = ArjunAdapter()
        context = ExecutionContext(
            tool_id="arjun",
            execution_id="exec-1",
            target="http://localhost:3010/search",
            parameters={
                "cookies": {"PHPSESSID": "abc", "security": "low"},
                "headers": {"X-Test": "1"},
            },
        )
        argv = adapter.build_argv(context)
        assert "-o" in argv
        assert "-oJ" not in argv
        assert "--headers" in argv
        assert "-H" not in argv
        assert "Cookie: PHPSESSID=abc; security=low" in argv
        assert "X-Test: 1" in argv

    def test_argv_without_session_has_no_header_flags(self) -> None:
        from hunterx.domain.execution import ExecutionContext
        from hunterx.tools.parameter.adapters import ArjunAdapter

        argv = ArjunAdapter().build_argv(
            ExecutionContext(tool_id="arjun", execution_id="exec-2", target="http://localhost:3010/search")
        )
        assert "--headers" not in argv
        assert "-H" not in argv


class TestProbeExecutorFollowsRedirects:
    """A real browser follows HTTP redirects; the probe executor must too, or
    Apache's directory-slash 301 (``/dir`` -> ``/dir/``) becomes the final
    response and turns a genuine finding into a false negative.
    """

    def test_directory_slash_redirect_reaches_final_resource(self) -> None:
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                if self.path.startswith("/dir") and not self.path.startswith("/dir/"):
                    self.send_response(301)
                    self.send_header("Location", f"/dir/{self.path[4:]}")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"root:x:0:0:root:/root:/bin/bash")

            def log_message(self, *args: Any) -> None:  # noqa: ANN401
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}"
            engine = VulnerabilityCapabilityEngine()
            probe = engine.build_probe("lfi", {"endpoint": f"{base}/dir?page=include.php", "parameter": "page"})
            assert probe is not None
            responses = ProbeExecutor().execute(probe, target=f"{base}/dir?page=include.php")
            for response in responses:
                assert response["status"] == 200, response
                assert "root:x:" in response["body"]
        finally:
            server.shutdown()
            server.server_close()


class TestClassSpecificHypothesesBlockPrematureStop:
    """The hunt never stops on a validated finding while a derived
    class-specific vulnerability hypothesis (sql-injection / xss / lfi / ...)
    is still open, even when its priority is below the 0.75 high-value bar.
    """

    def _mission(self, *, state: Any) -> Any:
        from hunterx.domain.mission_orchestration.enums import HypothesisState
        from hunterx.domain.mission_orchestration.mission import new_orchestrated_mission
        from hunterx.domain.mission_orchestration.models import MissionHypothesis
        from hunterx.domain.target_intelligence.enums import HypothesisType

        mission = new_orchestrated_mission()
        mission.context.remaining_objectives = ["bug_bounty_assessment"]
        mission.context.findings = [{"finding_id": "f1", "stage": "report_ready"}]
        mission.upsert_hypothesis(
            MissionHypothesis(
                mission_id=mission.mission_id,
                statement="The page parameter may be susceptible to lfi",
                category=HypothesisType.LFI,
                priority=0.65,
                state=state,
                provenance={"vulnerability_class": "lfi"},
            )
        )
        return mission

    def test_open_class_specific_hypothesis_blocks_findings_validated_stop(self) -> None:
        from hunterx.domain.mission_orchestration.enums import HypothesisState
        from hunterx.domain.mission_orchestration.policy import MissionPolicyEngine

        mission = self._mission(state=HypothesisState.PROPOSED)
        assert MissionPolicyEngine().evaluate_stop(mission) is None

    def test_resolved_class_specific_hypothesis_allows_stop(self) -> None:
        from hunterx.domain.mission_orchestration.enums import HypothesisState, StopCondition
        from hunterx.domain.mission_orchestration.policy import MissionPolicyEngine

        mission = self._mission(state=HypothesisState.REFUTED)
        assert MissionPolicyEngine().evaluate_stop(mission) is StopCondition.FINDINGS_VALIDATED

    def test_hypothesis_without_class_provenance_is_not_gated(self) -> None:
        from hunterx.domain.mission_orchestration.enums import HypothesisState, StopCondition
        from hunterx.domain.mission_orchestration.mission import new_orchestrated_mission
        from hunterx.domain.mission_orchestration.models import MissionHypothesis
        from hunterx.domain.mission_orchestration.policy import MissionPolicyEngine
        from hunterx.domain.target_intelligence.enums import HypothesisType

        mission = new_orchestrated_mission()
        mission.context.remaining_objectives = ["bug_bounty_assessment"]
        mission.context.findings = [{"finding_id": "f1", "stage": "report_ready"}]
        mission.upsert_hypothesis(
            MissionHypothesis(
                mission_id=mission.mission_id,
                statement="The endpoint may be affected by unknown behavior",
                category=HypothesisType.UNKNOWN_BEHAVIOR,
                priority=0.5,
                state=HypothesisState.PROPOSED,
            )
        )
        assert MissionPolicyEngine().evaluate_stop(mission) is StopCondition.FINDINGS_VALIDATED


class TestAuthenticatedProbesNeverEvaluateLoginWall:
    """An authenticated probe whose session died mid-mission must never be
    evaluated against the login wall (the wall is not target evidence): the
    executor reports the final URL, the mission re-establishes the session and
    retries the probe once, and a still-walled probe stays inconclusive —
    never refuted or validated.
    """

    @staticmethod
    def _authed_server() -> Any:
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        state: dict[str, Any] = {"sid": "live"}

        class _Handler(BaseHTTPRequestHandler):
            def _cookie(self) -> dict[str, str]:
                pairs = (self.headers.get("Cookie") or "").split(";")
                return dict(
                    pair.strip().split("=", 1) for pair in pairs if "=" in pair
                )

            def do_GET(self) -> None:  # noqa: N802
                if self.path.startswith("/login.php"):
                    self.send_response(200)
                    self.send_header("Set-Cookie", "security=low; Path=/")
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(
                        b'<form method="post" action="/login.php">'
                        b'<input type="text" name="username">'
                        b'<input type="password" name="password">'
                        b"</form>"
                    )
                    return
                if self.path.startswith("/protected"):
                    if self._cookie().get("sid") == state["sid"]:
                        self.send_response(200)
                        self.send_header("Content-Type", "text/plain")
                        self.end_headers()
                        if ".." in self.path or "etc/passwd" in self.path:
                            self.wfile.write(b"root:x:0:0:root:/root:/bin/bash")
                        else:
                            self.wfile.write(b"index page")
                    else:
                        self.send_response(302)
                        self.send_header("Location", "/login.php")
                        self.end_headers()
                    return
                self.send_response(404)
                self.end_headers()

            def do_POST(self) -> None:  # noqa: N802
                if self.path.startswith("/login.php"):
                    self.send_response(302)
                    self.send_header("Location", "/")
                    self.send_header("Set-Cookie", f"sid={state['sid']}; Path=/")
                    self.end_headers()
                    return
                self.send_response(404)
                self.end_headers()

            def log_message(self, *args: Any) -> None:  # noqa: ANN401
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread, state

    def test_probe_records_final_url_after_redirect(self) -> None:
        from dataclasses import replace

        server, thread, _state = self._authed_server()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}"
            engine = VulnerabilityCapabilityEngine()
            probe = engine.build_probe(
                "lfi", {"endpoint": f"{base}/protected?page=include.php", "parameter": "page"}
            )
            assert probe is not None
            walled = ProbeExecutor().execute(probe, target=f"{base}/protected?page=include.php")
            assert all(str(r["url"]).endswith("/login.php") for r in walled)
            authed = ProbeExecutor().execute(
                replace(probe, headers=(("Cookie", "sid=live"),)),
                target=f"{base}/protected?page=include.php",
            )
            for response in authed:
                assert response["status"] == 200
                assert str(response["url"]).endswith("/protected")
            assert "index page" in authed[0]["body"]
            assert any("root:x:" in r["body"] for r in authed[1:])
        finally:
            server.shutdown()
            server.server_close()

    def test_landed_on_auth_wall_helper(self) -> None:
        from hunterx.application.mission_execution import _landed_on_auth_wall

        assert _landed_on_auth_wall([{"url": "http://127.0.0.1:4280/login.php"}]) is True
        assert _landed_on_auth_wall([{"url": "http://127.0.0.1:4280/protected"}]) is False
        assert _landed_on_auth_wall([]) is False

    def test_mission_reattempts_session_and_retries_walled_probe(self) -> None:
        from hunterx.domain.mission_orchestration.enums import HypothesisState
        from hunterx.domain.mission_orchestration.models import MissionHypothesis
        from hunterx.domain.target_intelligence.enums import HypothesisType

        server, thread, state = self._authed_server()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}"
            stores = InMemoryTidbRepositoryFactory()
            planning = AdaptiveMissionPlanningEngine(
                tool_selection_engine=ToolSelectionEngine(mission_type="bug-bounty", default_candidates={})
            )
            orchestrator = MissionOrchestrator(planning=planning)
            orchestration = MissionOrchestrationService(
                engine=MissionOrchestrationEngine(orchestrator=orchestrator),
                stores=stores,
            )
            runner = MissionExecutionService(
                orchestration=orchestration,
                planning=planning,
                execution_engine=FakeExecutionEngine(outputs={}),
            )
            mission = orchestration.create_mission(objective="bug_bounty_assessment", target=base)
            orchestration.start(mission.mission_id)
            parameters = {
                "auth": {"login_url": f"{base}/login.php", "username": "admin", "password": "password"}
            }
            runner._parameters = parameters
            runner._establish_auth_session(mission.mission_id, parameters)
            assert runner._session is not None and runner._session.established
            assert dict(runner._session.cookies)["sid"] == "live"

            # The server-side session is revoked (an authenticated crawl
            # touched a logout endpoint): the probe must bounce to the login
            # wall, the mission re-logins and retries against the real page.
            state["sid"] = "live2"
            endpoint = f"{base}/protected?page=include.php"
            mission.upsert_hypothesis(
                MissionHypothesis(
                    mission_id=mission.mission_id,
                    statement=f"The 'page' parameter on {endpoint} may be susceptible to lfi",
                    category=HypothesisType.LFI,
                    priority=0.65,
                    state=HypothesisState.PROPOSED,
                    provenance={"vulnerability_class": "lfi", "endpoint": endpoint, "parameter": "page"},
                )
            )
            hypothesis = mission.hypotheses[-1]
            verdict = runner._differential_verdict(mission.mission_id, hypothesis)
            assert verdict is not None and verdict.supported
            assert "lfi" in verdict.notes
            assert dict(runner._session.cookies)["sid"] == "live2"
        finally:
            server.shutdown()
            server.server_close()


class TestFormFieldParameterDiscovery:
    """Arjun enumerates URL query parameters; HTML form fields (notably POST
    forms) are invisible to it, so form-only surfaces never produce a
    parameter hypothesis. The mission extracts form field names in-process so
    body-carrying probes can assess those surfaces (generic — any form-based
    endpoint benefits; nothing is DVWA-specific).
    """

    @staticmethod
    def _form_server() -> Any:
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                if self.path.startswith("/app"):
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(
                        b'<form method="post" action="/submit">'
                        b'<input type="text" name="id">'
                        b'<input type="submit" name="Submit" value="Submit">'
                        b"</form>"
                    )
                    return
                self.send_response(404)
                self.end_headers()

            def do_POST(self) -> None:  # noqa: N802
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args: Any) -> None:  # noqa: ANN401
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread

    def test_form_field_observation_extracts_post_fields(self) -> None:
        server, thread = self._form_server()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}"
            stores = InMemoryTidbRepositoryFactory()
            planning = AdaptiveMissionPlanningEngine(
                tool_selection_engine=ToolSelectionEngine(mission_type="bug-bounty", default_candidates={})
            )
            orchestrator = MissionOrchestrator(planning=planning)
            orchestration = MissionOrchestrationService(
                engine=MissionOrchestrationEngine(orchestrator=orchestrator),
                stores=stores,
            )
            runner = MissionExecutionService(
                orchestration=orchestration,
                planning=planning,
                execution_engine=FakeExecutionEngine(outputs={}),
            )
            mission = orchestration.create_mission(objective="bug_bounty_assessment", target=base)
            endpoint = f"{base}/app"
            observation, status = runner._form_field_observation(mission.mission_id, endpoint)
            assert observation is not None
            assert status == 200
            findings = observation["content"]["parameters"]["findings"]
            names = {f["name"]: f for f in findings}
            assert "id" in names
            assert names["id"]["method"] == "POST"
            assert names["id"]["endpoint"].endswith("/submit")
            assert "Submit" in names
        finally:
            server.shutdown()
            server.server_close()

    def test_parameter_discovery_negative_records_form_parameters(self) -> None:
        from hunterx.domain.execution import ExecutionContext

        server, thread = self._form_server()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}"
            endpoint = f"{base}/app"
            stores = InMemoryTidbRepositoryFactory()
            planning = AdaptiveMissionPlanningEngine(
                tool_selection_engine=ToolSelectionEngine(mission_type="bug-bounty", default_candidates={})
            )
            orchestrator = MissionOrchestrator(planning=planning)
            orchestration = MissionOrchestrationService(
                engine=MissionOrchestrationEngine(orchestrator=orchestrator),
                stores=stores,
            )
            fake = FakeExecutionEngine(outputs={"arjun": {"parameters": {"findings": []}}})
            runner = MissionExecutionService(
                orchestration=orchestration,
                planning=planning,
                execution_engine=fake,
            )
            mission = orchestration.create_mission(objective="bug_bounty_assessment", target=base)
            orchestration.start(mission.mission_id)
            from hunterx.domain.adaptive_mission_planning.enums import ReplanTrigger

            runner._planning.replan_for_change(
                mission.mission_id,
                trigger=ReplanTrigger.NEW_ENDPOINT_DISCOVERED,
                asset_key=endpoint,
                reason="test fixture",
            )
            action = next(
                a
                for a in runner._planning.get_plan(mission.mission_id).actions.values()
                if a.capability == "parameter_discovery" and a.asset == endpoint
            )
            context = ExecutionContext(tool_id="arjun", execution_id="exec-arjun-1", target=endpoint)
            pipeline = fake.execute(context)
            outcome = runner._handle_execution(
                mission.mission_id,
                action_id=action.action_id,
                capability="parameter_discovery",
                tool_id="arjun",
                target=endpoint,
                pipeline=pipeline,
            )
            mission = orchestration.get(mission.mission_id)
            params = [p for p in mission.context.parameters.values() if isinstance(p, dict)]
            assert params, "form fields must become context parameters"
            assert any(p.get("parameter") == "id" and p.get("method") == "POST" for p in params)
            assert any(
                (h.provenance or {}).get("vulnerability_class") == "sql-injection"
                for h in mission.hypotheses
            )
        finally:
            server.shutdown()
            server.server_close()