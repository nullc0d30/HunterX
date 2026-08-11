# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Architecture conformance tests for the Sprint 028 finding orchestration capability.

Confirms the modules land in the expected layers and respect the dependency
policy: the finding orchestration domain stays pure (domain/shared only, never
imports infrastructure, application or concrete tools), the application service
never imports infrastructure/engines/cli/api, no domain module executes tools
directly, the domain package has no cycles and the events are typed and
catalogued.
"""

from __future__ import annotations

from pathlib import Path

from hunterx.architecture.imports import internal_imports, scan_source
from hunterx.architecture.layers import resolve_layer

DOMAIN_MODULES = (
    "hunterx.domain.vulnerability_finding.enums",
    "hunterx.domain.vulnerability_finding.models",
    "hunterx.domain.vulnerability_finding.lifecycle",
    "hunterx.domain.vulnerability_finding.evidence",
    "hunterx.domain.vulnerability_finding.strategy",
    "hunterx.domain.vulnerability_finding.execution",
    "hunterx.domain.vulnerability_finding.confidence",
    "hunterx.domain.vulnerability_finding.impact",
    "hunterx.domain.vulnerability_finding.deduplication",
    "hunterx.domain.vulnerability_finding.unknown",
    "hunterx.domain.vulnerability_finding.poc",
    "hunterx.domain.vulnerability_finding.redaction",
    "hunterx.domain.vulnerability_finding.reporting",
    "hunterx.domain.vulnerability_finding.reproduction",
    "hunterx.domain.entities.tidb.finding_orchestration",
)

APPLICATION_MODULES = ("hunterx.application.vulnerability_finding",)


def _read(module: str) -> str:
    path = Path("src") / (module.replace(".", "/") + ".py")
    return path.read_text(encoding="utf-8")


def _records(module: str) -> list[object]:
    return internal_imports(scan_source(_read(module), module), "hunterx")


def test_finding_modules_resolve_to_expected_layers() -> None:
    for module in DOMAIN_MODULES:
        assert resolve_layer(module).name == "domain", module
    for module in APPLICATION_MODULES:
        assert resolve_layer(module).name == "application", module
    assert (
        resolve_layer("hunterx.infrastructure.db.sql.tidb_models.finding_orchestration_models").name
        == "infrastructure"
    )
    assert resolve_layer("hunterx.api.finding").name == "api"
    assert resolve_layer("hunterx.cli.commands").name == "cli"


def test_finding_domain_never_imports_infrastructure_or_application() -> None:
    for module in DOMAIN_MODULES:
        for record in _records(module):
            target_layer = resolve_layer(record.target).name  # type: ignore[attr-defined]
            assert target_layer in ("domain", "shared"), f"{module} -> {record.target}"


def test_finding_domain_never_imports_concrete_tools() -> None:
    for module in DOMAIN_MODULES:
        for record in _records(module):
            assert not record.target.startswith("hunterx.tools."), f"{module} -> {record.target}"  # type: ignore[attr-defined]


def test_application_service_imports_only_approved_surfaces() -> None:
    forbidden = {"infrastructure", "engines", "cli", "api"}
    for module in APPLICATION_MODULES:
        for record in _records(module):
            target_layer = resolve_layer(record.target).name  # type: ignore[attr-defined]
            assert target_layer not in forbidden, f"{record.target} is not an approved application dependency"


def test_finding_domain_has_no_cycles() -> None:
    from hunterx.architecture.cycles import find_cycles

    records_by_module = {module: _records(module) for module in DOMAIN_MODULES}
    cycles = find_cycles(records_by_module, package="hunterx.domain.vulnerability_finding")
    assert cycles == []


def test_finding_domain_never_executes_tools_directly() -> None:
    # The domain declares engines (ValidationExecutionEngine is a pure planner)
    # but must never execute external tools: no subprocess, no dynamic code,
    # and no imports from the tool layer (covered separately).
    for module in DOMAIN_MODULES:
        source = _read(module)
        assert "subprocess" not in source, module
        assert "exec(" not in source and "eval(" not in source, module
        assert not module.startswith("hunterx.tools."), module


def test_application_executes_only_via_the_sdk() -> None:
    source = _read("hunterx.application.vulnerability_finding")
    assert "eval(" not in source and "exec(" not in source
    assert "ExecutionEngine" in source


def test_source_modules_parse() -> None:
    modules = [
        *DOMAIN_MODULES,
        *APPLICATION_MODULES,
        "hunterx.infrastructure.db.sql.tidb_models.finding_orchestration_models",
        "hunterx.api.finding",
        "hunterx.domain.events.types",
        "hunterx.domain.events.catalog",
    ]
    for module in modules:
        scan_source(_read(module), module)  # raises on syntax errors


def test_events_are_typed_and_catalogued() -> None:
    types_source = _read("hunterx.domain.events.types")
    for name in (
        "FindingOrchestrationCreatedEvent",
        "FindingValidationStartedEvent",
        "FindingEvidenceConflictEvent",
        "FindingProofValidatedEvent",
        "FindingDisprovedEvent",
        "FindingReportReadyEvent",
    ):
        assert f"class {name}" in types_source, name
    catalog_source = _read("hunterx.domain.events.catalog")
    for event_type in (
        "finding.created",
        "finding.validation.started",
        "finding.evidence.conflict",
        "finding.proof.validated",
        "finding.duplicate.detected",
        "finding.disproved",
    ):
        assert f'"{event_type}"' in catalog_source, event_type
