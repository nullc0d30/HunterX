# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Architecture tests for the vulnerability proof strategy library.

Confirms the Sprint 022 modules land in the expected layers and respect the
dependency policy: the strategy domain stays pure (domain/shared only, never
imports infrastructure or concrete tools), the application service never
imports infrastructure/engines/cli/api, reporting imports only domain/shared,
strategies never execute tools directly and the domain package has no cycles.
"""

from __future__ import annotations

from pathlib import Path

from hunterx.architecture.imports import internal_imports, scan_source
from hunterx.architecture.layers import resolve_layer

DOMAIN_MODULES = (
    "hunterx.domain.vulnerability_proof.strategy",
    "hunterx.domain.vulnerability_proof.registry",
    "hunterx.domain.vulnerability_proof.selector",
    "hunterx.domain.vulnerability_proof.validator",
    "hunterx.domain.vulnerability_proof.matrix",
    "hunterx.domain.vulnerability_proof.library",
)

APPLICATION_MODULES = (
    "hunterx.application.vulnerability_proof_strategy",
)

REPORTING_MODULES = ("hunterx.reporting.strategy",)


def _read(module: str) -> str:
    path = Path("src") / (module.replace(".", "/") + ".py")
    return path.read_text(encoding="utf-8")


def test_strategy_modules_resolve_to_expected_layers() -> None:
    for module in DOMAIN_MODULES:
        assert resolve_layer(module).name == "domain", module
    for module in APPLICATION_MODULES:
        assert resolve_layer(module).name == "application", module
    for module in REPORTING_MODULES:
        assert resolve_layer(module).name == "reporting", module
    assert resolve_layer("hunterx.domain.entities.tidb.proof_strategy").name == "domain"
    assert resolve_layer("hunterx.infrastructure.db.sql.tidb_models.proof_strategy_models").name == "infrastructure"


def test_strategy_domain_never_imports_infrastructure_or_application() -> None:
    for module in DOMAIN_MODULES:
        source = _read(module)
        records = internal_imports(scan_source(source, module), "hunterx")
        for record in records:
            target_layer = resolve_layer(record.target).name
            assert target_layer in ("domain", "shared"), f"{module} -> {record.target}"


def test_strategy_domain_never_imports_concrete_tools() -> None:
    for module in DOMAIN_MODULES:
        source = _read(module)
        records = internal_imports(scan_source(source, module), "hunterx")
        for record in records:
            assert not record.target.startswith("hunterx.tools."), f"{module} -> {record.target}"


def test_application_service_imports_only_approved_surfaces() -> None:
    for module in APPLICATION_MODULES:
        source = _read(module)
        records = internal_imports(scan_source(source, module), "hunterx")
        forbidden = {"infrastructure", "engines", "cli", "api"}
        for record in records:
            target_layer = resolve_layer(record.target).name
            assert target_layer not in forbidden, f"{record.target} is not an approved application dependency"


def test_strategy_domain_has_no_cycles() -> None:
    from hunterx.architecture.cycles import find_cycles

    records_by_module: dict[str, list[object]] = {}
    for module in DOMAIN_MODULES:
        source = _read(module)
        records_by_module[module] = internal_imports(scan_source(source, module), "hunterx")
    cycles = find_cycles(records_by_module, package="hunterx.domain.vulnerability_proof")
    assert cycles == []


def test_reporting_strategy_imports_only_domain_and_shared() -> None:
    for module in REPORTING_MODULES:
        source = _read(module)
        records = internal_imports(scan_source(source, module), "hunterx")
        for record in records:
            target_layer = resolve_layer(record.target).name
            assert target_layer in ("domain", "shared"), f"{record.target}"


def test_strategies_never_execute_tools_directly() -> None:
    # Proof strategies are pure contracts: no subprocess, no engine, no SDK.
    for module in DOMAIN_MODULES:
        source = _read(module)
        assert "subprocess" not in source, module
        assert "ExecutionEngine" not in source, module
        assert "exec(" not in source, module


def test_strategy_source_modules_parse() -> None:
    modules = [
        *DOMAIN_MODULES,
        *APPLICATION_MODULES,
        *REPORTING_MODULES,
        "hunterx.domain.entities.tidb.proof_strategy",
        "hunterx.infrastructure.db.sql.tidb_models.proof_strategy_models",
    ]
    for module in modules:
        source = _read(module)
        scan_source(source, module)  # raises on syntax errors
