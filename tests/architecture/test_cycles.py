# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for circular dependency detection."""

from __future__ import annotations

from hunterx.architecture.cycles import find_cycles
from hunterx.architecture.imports import scan_source


def _records(source: str, module: str) -> dict[str, list]:
    return {module: scan_source(source, module)}


def test_no_cycles_for_acyclic_graph() -> None:
    graph = {
        "hunterx.a": scan_source("from hunterx.b import X\nfrom hunterx.c import Y\n", "hunterx.a"),
        "hunterx.b": scan_source("from hunterx.c import Z\n", "hunterx.b"),
        "hunterx.c": scan_source("import os\n", "hunterx.c"),
    }
    assert find_cycles(graph) == []


def test_direct_cycle_detected() -> None:
    graph = {
        "hunterx.a": scan_source("from hunterx.b import X\n", "hunterx.a"),
        "hunterx.b": scan_source("from hunterx.a import Y\n", "hunterx.b"),
    }
    cycles = find_cycles(graph)
    assert len(cycles) == 1
    assert set(cycles[0].modules) == {"hunterx.a", "hunterx.b"}


def test_indirect_cycle_detected() -> None:
    graph = {
        "hunterx.a": scan_source("from hunterx.b import X\n", "hunterx.a"),
        "hunterx.b": scan_source("from hunterx.c import Y\n", "hunterx.b"),
        "hunterx.c": scan_source("from hunterx.a import Z\n", "hunterx.c"),
    }
    cycles = find_cycles(graph)
    assert len(cycles) == 1
    assert set(cycles[0].modules) == {"hunterx.a", "hunterx.b", "hunterx.c"}


def test_type_checking_imports_do_not_form_cycles() -> None:
    graph = {
        "hunterx.a": scan_source("from hunterx.b import X\n", "hunterx.a"),
        "hunterx.b": scan_source(
            "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from hunterx.a import Y\n",
            "hunterx.b",
        ),
    }
    assert find_cycles(graph) == []


def test_self_import_ignored() -> None:
    graph = {"hunterx.a": scan_source("from hunterx.a import X\n", "hunterx.a")}
    assert find_cycles(graph) == []
