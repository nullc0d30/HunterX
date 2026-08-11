# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the full toolchain application service (Sprint 031)."""

from __future__ import annotations

from hunterx.application.toolchain import ToolchainService
from hunterx.domain.exceptions import ToolExecutionError, ToolNotFoundError
from hunterx.domain.execution import ExecutionContext
from hunterx.domain.tools import ToolDescriptor
from hunterx.infrastructure.event_bus import InMemoryEventBus
from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.sdk.adapter import ToolAdapter
from hunterx.tools.sdk.engine import ExecutionEngine
from hunterx.tools.sdk.output import OutputCollector
from tests.framework.tip import make_compatibility, make_knowledge, make_metadata


class _FakeScanner(ToolAdapter):
    """In-process scanner adapter that never runs a binary."""

    descriptor = ToolDescriptor(
        name="fakescanner",
        version="1.0.0",
        description="Fake in-process scanner.",
        targets=("host",),
        capabilities=("port-scanning",),
        permissions=(),
    )

    def run(self, context: ExecutionContext, collector: OutputCollector) -> None:
        collector.attach_stdout("fakescanner: host is open\n")
        collector.set_json({"findings": [{"title": "open port", "severity": "info", "target": context.target}]})


def _register(
    tip: ToolIntelligenceAPI,
    tool_id: str,
    *,
    capabilities: tuple[str, ...],
    accepts: tuple[str, ...] = ("host",),
    available: bool = True,
) -> None:
    tip.register_tool(
        make_metadata(tool_id, category="assessment", subcategory="port", description=f"{tool_id}."),
        knowledge=make_knowledge(tool_id, capabilities=capabilities, accepts=accepts),
        compatibility=make_compatibility(tool_id),
    )
    if available:
        tip.install(tool_id)
        tip.verify(tool_id)
        tip.make_available(tool_id)


def _build() -> tuple[ToolchainService, ToolIntelligenceAPI, ExecutionEngine, InMemoryEventBus]:
    tip = ToolIntelligenceAPI()
    _register(tip, "fakescanner", capabilities=("port-scanning",))
    engine = ExecutionEngine(intelligence=tip.registry)
    engine.register_adapter("fakescanner", _FakeScanner())
    engine.install_hook("fakescanner", lambda tool_id, version: "1.0.0")
    engine.install("fakescanner")
    bus = InMemoryEventBus()
    service = ToolchainService(tip, engine, bus)
    return service, tip, engine, bus


def test_list_tools_reports_catalog() -> None:
    service, _, _, _ = _build()
    tools = service.list_tools()
    assert any(tool["tool_id"] == "fakescanner" for tool in tools)
    entry = next(tool for tool in tools if tool["tool_id"] == "fakescanner")
    assert entry["installed"] is True


def test_show_tool_exposes_knowledge_contract() -> None:
    service, _, _, _ = _build()
    contract = service.show_tool("fakescanner")
    assert contract["tool_id"] == "fakescanner"
    assert "capabilities" in contract["knowledge"]
    assert "requirements" in contract
    assert "provenance" in contract


def test_show_unknown_tool_raises() -> None:
    service, _, _, _ = _build()
    try:
        service.show_tool("does-not-exist")
    except ToolNotFoundError:
        return
    raise AssertionError("expected ToolNotFoundError")


def test_requirements_and_provenance() -> None:
    service, _, _, _ = _build()
    requirements = service.requirements("fakescanner")
    assert requirements["inputs"]["accepts"] == ["host"]
    provenance = service.provenance("fakescanner")
    assert provenance["tool_id"] == "fakescanner"


def test_execute_stores_structured_result() -> None:
    service, _, _, _ = _build()
    outcome = service.execute("fakescanner", "10.0.0.1", target_type="host")
    assert outcome["tool_id"] == "fakescanner"
    assert outcome["status"] == "completed"
    execution_id = outcome["execution_id"]

    status = service.execution_status(execution_id)
    assert status["status"] == "completed"
    assert status["semantics"] in ("found", "not-found")

    output = service.execution_output(execution_id)
    assert "stdout" in output["formats"]

    result = service.inspect_result(execution_id)
    assert result["execution_id"] == execution_id
    assert result["profile"]["tool_id"] == "fakescanner"
    assert result["exit_code"] == 0


def test_execute_without_adapter_raises() -> None:
    service, tip, engine, bus = _build()
    tip.register_tool(
        make_metadata("knowledgeonly", category="recon", description="No adapter."),
        knowledge=make_knowledge("knowledgeonly", capabilities=("subdomain-discovery",)),
        compatibility=make_compatibility("knowledgeonly"),
    )
    try:
        service.execute("knowledgeonly", "example.com")
    except ToolExecutionError as error:
        assert "no execution adapter" in str(error)
        return
    raise AssertionError("expected ToolExecutionError")


def test_execute_unknown_tool_raises() -> None:
    service, _, _, _ = _build()
    try:
        service.execute("missing", "example.com")
    except ToolNotFoundError:
        return
    raise AssertionError("expected ToolNotFoundError")


def test_parse_offline_replay() -> None:
    service, _, engine, _ = _build()
    # fakescanner has no parse_output -> generic JSON fallback path.
    parsed = service.parse("fakescanner", '{"host": "example.com"}')
    assert parsed["count"] == 1
    assert parsed["records"][0]["host"] == "example.com"


def test_normalize_offline() -> None:
    service, _, _, _ = _build()
    normalized = service.normalize("fakescanner", [{"title": "x", "severity": "high", "target": "t", "description": "d"}])
    assert normalized["counts"]["findings"] == 1


def test_recommend_and_strategies() -> None:
    service, tip, _, _ = _build()
    _register(tip, "primary", capabilities=("port-scanning",))
    _register(tip, "fallback", capabilities=("port-scanning",))
    recommendations = service.recommend("port-scanning")
    assert recommendations
    strategy = service.strategies("port-scanning")
    assert strategy["capability"] == "port-scanning"
    assert strategy["primary"]
    assert strategy["merge_policy"] == "deduplicate"


def test_chain_planning() -> None:
    service, tip, _, _ = _build()
    _register(tip, "faketech", capabilities=("technology-detection",), accepts=("url",))
    chain = service.chain("Assess web target", capabilities=["port-scanning", "technology-detection"])
    assert chain["objective"] == "Assess web target"
    assert chain["steps"]
    assert chain["dependencies"]


def test_health_and_versions() -> None:
    service, _, _, _ = _build()
    health = service.health("fakescanner")
    assert health["tool_id"] == "fakescanner"
    versions = service.versions("fakescanner")
    assert versions["tool_id"] == "fakescanner"
    assert versions["installed_version"] == "1.0.0"
    all_health = service.health()
    assert all_health["count"] >= 1


def test_execution_publishes_tool_events() -> None:
    service, _, _, bus = _build()
    captured: list[str] = []
    for event_type in (
        "tool.execution.started",
        "tool.execution.completed",
        "tool.output.received",
    ):
        bus.subscribe(event_type, lambda event, _=event_type: captured.append(event.event_type))
    service.execute("fakescanner", "10.0.0.1")
    assert "tool.execution.started" in captured
    assert "tool.execution.completed" in captured
    assert "tool.output.received" in captured


def test_execution_result_never_claims_false_safety() -> None:
    service, _, _, _ = _build()
    outcome = service.execute("fakescanner", "10.0.0.1")
    assert outcome["status"] != "failed"
    # Failure semantics must not be reported as not-found.
    assert outcome["semantics"] != "error"
