# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for static import extraction."""

from __future__ import annotations

from hunterx.architecture.imports import internal_imports, scan_source


def test_absolute_imports() -> None:
    records = scan_source(
        "import hunterx.domain.entities\nfrom hunterx.shared.ids import generate_id\n",
        "hunterx.application.missions",
    )
    targets = {record.target for record in records}
    assert "hunterx.domain.entities" in targets
    assert "hunterx.shared.ids" in targets


def test_relative_import_resolution() -> None:
    records = scan_source("from .base import Base\n", "hunterx.domain.entities.mission")
    assert records[0].target == "hunterx.domain.entities.base"
    records = scan_source("from ..ports.repositories import MissionRepository\n", "hunterx.domain.entities.mission")
    assert records[0].target == "hunterx.domain.ports.repositories"


def test_type_checking_import_detected() -> None:
    records = scan_source(
        "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from hunterx.domain.ports import StorePort\n",
        "hunterx.domain.entities.mission",
    )
    type_checking = [record for record in records if record.target == "hunterx.domain.ports"]
    assert type_checking
    assert type_checking[0].is_type_checking


def test_lazy_import_detected() -> None:
    records = scan_source(
        "def load():\n    from hunterx.infrastructure.cache import MemoryCache\n    return MemoryCache()\n",
        "hunterx.application.missions",
    )
    assert records
    assert records[0].target == "hunterx.infrastructure.cache"
    assert records[0].is_lazy


def test_line_numbers() -> None:
    records = scan_source(
        "import os\n\nfrom hunterx.shared.ids import generate_id\n",
        "hunterx.x",
    )
    assert [record.line for record in records] == [1, 3]


def test_internal_imports_filter() -> None:
    records = scan_source(
        "import os\nfrom hunterx.shared.ids import generate_id\n",
        "hunterx.x",
    )
    internal = internal_imports(records, "hunterx")
    assert len(internal) == 1
    assert internal[0].target == "hunterx.shared.ids"


def test_future_import_ignored() -> None:
    records = scan_source("from __future__ import annotations\nimport os\n", "hunterx.x")
    assert all(record.target != "__future__" for record in records)
