# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for the attack-surface completion gate.

- targeted parameter-name → vulnerability-class hypothesis mapping (so a
  discovered ``id`` implies IDOR, ``to`` implies open redirect, ``q`` implies
  SQL injection, ...) — evidence-driven, never "run every class".
- osv-scanner adapter: argv, parser, and mission integration.
"""

from __future__ import annotations

from hunterx.application.mission_orchestration import MissionOrchestrationService
from hunterx.domain.adaptive_mission_planning.toolchain import ToolSelectionEngine
from hunterx.domain.mission_orchestration.models import MissionObservation
from hunterx.domain.mission_orchestration.orchestrator import (
    MissionOrchestrator,
    _class_for_parameter,
)
from hunterx.engines.adaptive_mission_planning.engine import AdaptiveMissionPlanningEngine
from hunterx.engines.mission_orchestration import MissionOrchestrationEngine
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory


class TestTargetedParameterHypotheses:
    @staticmethod
    def _class_for(name: str) -> str:
        class_id, _ = _class_for_parameter(name)
        return class_id

    def test_parameter_name_maps_to_class(self) -> None:
        assert self._class_for("id") == "idor"
        assert self._class_for("to") == "open-redirect"
        assert self._class_for("url") == "ssrf"
        assert self._class_for("q") == "sql-injection"
        assert self._class_for("file") == "lfi"
        assert self._class_for("cmd") == "command-injection"
        assert self._class_for("password") == "authentication"
        assert self._class_for("username") == "authentication"
        assert self._class_for("name") == "ssti"
        assert self._class_for("random_param") == ""

    def test_parameter_observation_creates_targeted_hypotheses(self) -> None:
        planning = AdaptiveMissionPlanningEngine(
            tool_selection_engine=ToolSelectionEngine(default_candidates={}),
        )
        orchestrator = MissionOrchestrator(planning=planning)
        orchestration = MissionOrchestrationService(
            engine=MissionOrchestrationEngine(orchestrator=orchestrator),
            stores=InMemoryTidbRepositoryFactory(),
        )
        mission = orchestration.create_mission(objective="web_security_assessment", target="http://localhost:3010")
        observation = MissionObservation(
            observation_id="obs-param",
            mission_id=mission.mission_id,
            action_id="act-1",
            tool_id="arjun",
            asset_key="http://localhost:3010/search",
            observation_type="parameter",
            content={"parameters": ["q", "id", "to"]},
            confidence=0.6,
            provenance={"tool_id": "arjun"},
        )
        orchestrator._hypothesize_from_observation(mission, observation)

        classes = {
            str((h.provenance or {}).get("vulnerability_class"))
            for h in mission.hypotheses
            if (h.provenance or {}).get("vulnerability_class")
        }
        assert "sql-injection" in classes, "q must imply a SQL-injection hypothesis"
        assert "idor" in classes, "id must imply an IDOR hypothesis"
        assert "open-redirect" in classes, "to must imply an open-redirect hypothesis"
        for h in mission.hypotheses:
            assert h.supporting_evidence, "each hypothesis must carry provenance"

    def test_endpoint_query_param_drives_targeted_hypothesis(self) -> None:
        planning = AdaptiveMissionPlanningEngine(
            tool_selection_engine=ToolSelectionEngine(default_candidates={}),
        )
        orchestrator = MissionOrchestrator(planning=planning)
        orchestration = MissionOrchestrationService(
            engine=MissionOrchestrationEngine(orchestrator=orchestrator),
            stores=InMemoryTidbRepositoryFactory(),
        )
        mission = orchestration.create_mission(objective="web_security_assessment", target="http://localhost:3010")
        observation = MissionObservation(
            observation_id="obs-endpoint",
            mission_id=mission.mission_id,
            action_id="act-1",
            tool_id="katana",
            asset_key="http://localhost:3010/",
            observation_type="endpoint",
            content={"urls": ["http://localhost:3010/redirect?to=https://evil.example"]},
            confidence=0.6,
            provenance={"tool_id": "katana"},
        )
        orchestrator._hypothesize_from_observation(mission, observation)

        redirect = next(
            (h for h in mission.hypotheses if (h.provenance or {}).get("vulnerability_class") == "open-redirect"),
            None,
        )
        assert redirect is not None, "a URL ?to= parameter must imply an open-redirect hypothesis"
        assert (redirect.provenance or {}).get("parameter") == "to"
        assert (redirect.provenance or {}).get("endpoint") == "http://localhost:3010/redirect?to=https://evil.example"


class TestOsvScannerAdapter:
    def test_adapter_registered_and_builds_argv(self) -> None:
        from hunterx.tools.vuln.registry import VULNERABILITY_SCANNER_IDS, vulnerability_scanners

        assert "osv-scanner" in VULNERABILITY_SCANNER_IDS
        adapter = vulnerability_scanners()["osv-scanner"]
        context = _context(target="http://localhost:3010")
        argv = adapter.build_argv(context)
        assert argv[:4] == ["osv-scanner", "scan", "--format", "json"]

    def test_parser_extracts_dependency_candidates(self) -> None:
        from hunterx.tools.recon.runner import CommandResult
        from hunterx.tools.vuln.registry import vulnerability_scanners

        adapter = vulnerability_scanners()["osv-scanner"]
        sample = (
            '{"results": [{"source": {"path": "/tmp/lock", "type": "lockfile"}, "packages": ['
            '{"package": {"name": "lodash", "version": "4.17.11", "ecosystem": "npm"}, '
            '"vulnerabilities": [{"id": "GHSA-x", "aliases": ["CVE-2020-28500"], "summary": "ReDoS in lodash"}]}]}]}'
        )
        result = CommandResult(returncode=0, stdout=sample, stderr="", argv=[])
        records = adapter.parse_output(_context(target="http://localhost:3010"), result)
        assert len(records) == 1
        assert records[0]["vulnerability_class"] == "dependency-vulnerability"
        assert records[0]["dependency"] == "lodash"
        assert records[0]["cve"] == "CVE-2020-28500"

    def test_empty_output_parses_to_no_candidates(self) -> None:
        from hunterx.tools.recon.runner import CommandResult
        from hunterx.tools.vuln.registry import vulnerability_scanners

        adapter = vulnerability_scanners()["osv-scanner"]
        result = CommandResult(returncode=0, stdout="", stderr="", argv=[])
        assert adapter.parse_output(_context(target="http://localhost:3010"), result) == []

    def test_url_target_scans_temp_dir_not_host(self) -> None:
        from hunterx.tools.vuln.registry import vulnerability_scanners

        adapter = vulnerability_scanners()["osv-scanner"]
        argv = adapter.build_argv(_context(target="http://localhost:3010"))
        assert argv[:4] == ["osv-scanner", "scan", "--format", "json"]
        assert argv[4] != "localhost", "a URL target must not be scanned as a bare path"
        assert not argv[4].startswith("http"), "a URL target has no local lockfile"


class TestKatanaPlainUrlParser:
    def test_plain_url_lines_become_observations(self) -> None:
        from hunterx.tools.web.katana import KatanaAdapter

        adapter = KatanaAdapter()
        record = adapter._parse_line("http://localhost:3010/redirect?to=https")
        assert record is not None
        assert record.get("url") == "http://localhost:3010/redirect?to=https"

    def test_malformed_lines_are_skipped(self) -> None:
        from hunterx.tools.web.katana import KatanaAdapter

        adapter = KatanaAdapter()
        assert adapter._parse_line("") is None
        assert adapter._parse_line("not json { malformed") is None

    def test_argv_omits_unsupported_json_flag(self) -> None:
        from hunterx.tools.sdk.context import ExecutionContext
        from hunterx.tools.web.katana import KatanaAdapter

        # katana's `-json` flag was removed in current releases; the argv must
        # not include it or katana exits 2 and no surface is discovered.
        adapter = KatanaAdapter()
        context = ExecutionContext(tool_id="katana", target="http://localhost:3010")
        argv = adapter.build_argv(context)
        assert "-json" not in argv
        assert "-silent" in argv


def _context(target: str):
    from hunterx.tools.sdk.context import ExecutionContext

    return ExecutionContext(tool_id="osv-scanner", target=target)
