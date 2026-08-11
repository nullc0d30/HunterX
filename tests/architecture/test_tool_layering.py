# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool layering enforcement tests (Sprint 031).

The toolchain must stay properly separated: tool adapters never reach into
higher layers, reporting never executes tools, and every new module resolves
to the correct architectural layer.
"""

from __future__ import annotations

import pathlib

from hunterx.architecture.imports import internal_imports, scan_tree
from hunterx.architecture.layers import resolve_layer

_SRC = pathlib.Path(__file__).resolve().parents[2] / "src"

#: Higher layers a tool module must never import.
_FORBIDDEN_TARGETS = (
    "hunterx.application",
    "hunterx.api",
    "hunterx.cli",
    "hunterx.platform",
    "hunterx.reporting",
    "hunterx.engines",
)


def _all_imports() -> dict[str, list]:
    return scan_tree(_SRC)


def test_tool_modules_never_import_higher_layers() -> None:
    imports = _all_imports()
    violations: list[str] = []
    for module, records in imports.items():
        if not module.startswith("hunterx.tools"):
            continue
        for record in internal_imports(records, "hunterx"):
            for forbidden in _FORBIDDEN_TARGETS:
                if record.target == forbidden or record.target.startswith(f"{forbidden}."):
                    violations.append(f"{module} -> {record.target}")
    assert not violations, f"tool modules must not import higher layers:\n{chr(10).join(violations)}"


def test_reporting_never_imports_tool_sdk_engine() -> None:
    imports = _all_imports()
    violations: list[str] = []
    for module, records in imports.items():
        if not module.startswith("hunterx.reporting"):
            continue
        for record in records:
            if record.target.startswith("hunterx.tools.sdk.engine") or record.target.startswith(
                "hunterx.tools.executor"
            ):
                violations.append(f"{module} -> {record.target}")
    assert not violations, f"reporting code must not execute tools:\n{chr(10).join(violations)}"


def test_tool_modules_resolve_to_tools_layer() -> None:
    for module in (
        "hunterx.tools.sdk.engine",
        "hunterx.tools.intelligence.api",
        "hunterx.tools.mastery.knowledge_fixtures",
        "hunterx.tools.content.ffuf",
    ):
        assert resolve_layer(module).name == "tools", module


def test_toolchain_service_resolves_to_application_layer() -> None:
    assert resolve_layer("hunterx.application.toolchain").name == "application"


def test_tools_api_router_resolves_to_api_layer() -> None:
    assert resolve_layer("hunterx.api.tools").name == "api"


def test_adapter_modules_never_import_domain_repositories_directly() -> None:
    imports = _all_imports()
    violations: list[str] = []
    for module, records in imports.items():
        if not module.startswith("hunterx.tools"):
            continue
        for record in records:
            if record.target.startswith("hunterx.domain.ports.repositories"):
                violations.append(f"{module} -> {record.target}")
    assert not violations, f"adapters must use domain ports, not concrete repositories:\n{chr(10).join(violations)}"
