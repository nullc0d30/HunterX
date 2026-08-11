# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Architecture tests for the safe vulnerability validation capability.

Confirms the Wave 13 modules land in the expected layers and respect the
dependency policy: the domain package stays pure (domain/shared only), the
application service reaches tools/reporting only through approved surfaces, and
no module depends on infrastructure.
"""

from __future__ import annotations

from hunterx.architecture.imports import internal_imports, scan_source
from hunterx.architecture.layers import resolve_layer

DOMAIN_MODULES = (
    "hunterx.domain.vulnerability_validation.models",
    "hunterx.domain.vulnerability_validation.enums",
    "hunterx.domain.vulnerability_validation.state",
    "hunterx.domain.vulnerability_validation.rules",
    "hunterx.domain.vulnerability_validation.scope",
    "hunterx.domain.vulnerability_validation.safety",
    "hunterx.domain.vulnerability_validation.planning",
    "hunterx.domain.vulnerability_validation.tool_selection",
    "hunterx.domain.vulnerability_validation.normalization",
    "hunterx.domain.vulnerability_validation.evidence",
    "hunterx.domain.vulnerability_validation.verdict",
    "hunterx.domain.vulnerability_validation.history",
)


def test_validation_modules_resolve_to_expected_layers() -> None:
    for module in DOMAIN_MODULES:
        assert resolve_layer(module).name == "domain", module
    assert resolve_layer("hunterx.application.vulnerability_validation").name == "application"
    assert resolve_layer("hunterx.reporting.validation").name == "reporting"
    assert resolve_layer("hunterx.tools.safe_validation.adapters").name == "tools"
    assert resolve_layer("hunterx.domain.entities.tidb.validation").name == "domain"


def test_validation_domain_never_imports_infrastructure_or_application() -> None:
    for module in DOMAIN_MODULES:
        source = _read(module)
        records = internal_imports(scan_source(source, module), "hunterx")
        for record in records:
            target_layer = resolve_layer(record.target).name
            assert target_layer in ("domain", "shared"), f"{module} -> {record.target}"


def test_application_service_imports_only_approved_surfaces() -> None:
    source = _read("hunterx.application.vulnerability_validation")
    records = internal_imports(scan_source(source, "hunterx.application.vulnerability_validation"), "hunterx")
    forbidden = {"infrastructure", "engines", "cli", "api"}
    for record in records:
        target_layer = resolve_layer(record.target).name
        assert target_layer not in forbidden, f"{record.target} is not an approved application dependency"


def test_validation_domain_has_no_cycles() -> None:
    from hunterx.architecture.cycles import find_cycles

    records_by_module: dict[str, list[object]] = {}
    for module in DOMAIN_MODULES:
        source = _read(module)
        records_by_module[module] = internal_imports(scan_source(source, module), "hunterx")
    cycles = find_cycles(records_by_module, package="hunterx.domain.vulnerability_validation")
    assert cycles == []


def _read(module: str) -> str:
    from pathlib import Path

    path = Path("src") / (module.replace(".", "/") + ".py")
    return path.read_text(encoding="utf-8")
