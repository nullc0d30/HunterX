# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Architecture tests for the vulnerability proof & PoC capability.

Confirms the Wave 15 modules land in the expected layers and respect the
dependency policy: the proof domain package stays pure (domain/shared only), the
application service never imports infrastructure/engines/cli/api, reporting
imports only domain/shared, and the domain package has no cycles.
"""

from __future__ import annotations

from pathlib import Path

from hunterx.architecture.imports import internal_imports, scan_source
from hunterx.architecture.layers import resolve_layer

DOMAIN_MODULES = (
    "hunterx.domain.vulnerability_proof.enums",
    "hunterx.domain.vulnerability_proof.models",
    "hunterx.domain.vulnerability_proof.contracts",
    "hunterx.domain.vulnerability_proof.planning",
    "hunterx.domain.vulnerability_proof.policy",
    "hunterx.domain.vulnerability_proof.generation",
    "hunterx.domain.vulnerability_proof.replay",
    "hunterx.domain.vulnerability_proof.confidence",
    "hunterx.domain.vulnerability_proof.impact",
    "hunterx.domain.vulnerability_proof.quality",
    "hunterx.domain.vulnerability_proof.state",
    "hunterx.domain.vulnerability_proof.reasoning",
    "hunterx.domain.vulnerability_proof.temporal",
    "hunterx.domain.vulnerability_proof.evidence",
)


def _read(module: str) -> str:
    path = Path("src") / (module.replace(".", "/") + ".py")
    return path.read_text(encoding="utf-8")


def test_proof_modules_resolve_to_expected_layers() -> None:
    for module in DOMAIN_MODULES:
        assert resolve_layer(module).name == "domain", module
    assert resolve_layer("hunterx.application.vulnerability_proof").name == "application"
    assert resolve_layer("hunterx.reporting.proof").name == "reporting"
    assert resolve_layer("hunterx.tools.proof_replay.adapters").name == "tools"
    assert resolve_layer("hunterx.domain.entities.tidb.proof").name == "domain"


def test_proof_domain_never_imports_infrastructure_or_application() -> None:
    for module in DOMAIN_MODULES:
        source = _read(module)
        records = internal_imports(scan_source(source, module), "hunterx")
        for record in records:
            target_layer = resolve_layer(record.target).name
            assert target_layer in ("domain", "shared"), f"{module} -> {record.target}"


def test_application_service_imports_only_approved_surfaces() -> None:
    source = _read("hunterx.application.vulnerability_proof")
    records = internal_imports(scan_source(source, "hunterx.application.vulnerability_proof"), "hunterx")
    forbidden = {"infrastructure", "engines", "cli", "api"}
    for record in records:
        target_layer = resolve_layer(record.target).name
        assert target_layer not in forbidden, f"{record.target} is not an approved application dependency"


def test_proof_domain_has_no_cycles() -> None:
    from hunterx.architecture.cycles import find_cycles

    records_by_module: dict[str, list[object]] = {}
    for module in DOMAIN_MODULES:
        source = _read(module)
        records_by_module[module] = internal_imports(scan_source(source, module), "hunterx")
    cycles = find_cycles(records_by_module, package="hunterx.domain.vulnerability_proof")
    assert cycles == []


def test_reporting_proof_imports_only_domain_and_shared() -> None:
    source = _read("hunterx.reporting.proof")
    records = internal_imports(scan_source(source, "hunterx.reporting.proof"), "hunterx")
    for record in records:
        target_layer = resolve_layer(record.target).name
        assert target_layer in ("domain", "shared"), f"{record.target}"


def test_proof_source_modules_parse() -> None:
    modules = [
        "hunterx.domain.vulnerability_proof.enums",
        "hunterx.domain.vulnerability_proof.models",
        "hunterx.domain.vulnerability_proof.contracts",
        "hunterx.domain.vulnerability_proof.planning",
        "hunterx.domain.vulnerability_proof.policy",
        "hunterx.domain.vulnerability_proof.generation",
        "hunterx.domain.vulnerability_proof.replay",
        "hunterx.domain.vulnerability_proof.confidence",
        "hunterx.domain.vulnerability_proof.impact",
        "hunterx.domain.vulnerability_proof.quality",
        "hunterx.domain.vulnerability_proof.state",
        "hunterx.domain.vulnerability_proof.reasoning",
        "hunterx.domain.vulnerability_proof.temporal",
        "hunterx.domain.vulnerability_proof.evidence",
        "hunterx.application.vulnerability_proof",
        "hunterx.reporting.proof",
        "hunterx.tools.proof_replay.adapters",
        "hunterx.tools.proof_replay.registry",
        "hunterx.domain.entities.tidb.proof",
        "hunterx.infrastructure.db.sql.tidb_models.proof_models",
    ]
    for module in modules:
        source = _read(module)
        scan_source(source, module)  # raises on syntax errors
