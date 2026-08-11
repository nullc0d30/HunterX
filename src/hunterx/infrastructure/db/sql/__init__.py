# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""SQL persistence layer.

Provides a thin SQLAlchemy 2.x foundation: an engine/session factory, a
declarative base, and repository implementations of the domain repository
ports. Importing SQLAlchemy happens lazily inside functions so the rest of the
foundation works even when the optional ``db`` extra is not installed.
"""

from __future__ import annotations

from hunterx.infrastructure.db.sql.factory import (
    SessionFactory,
    create_engine_from_settings,
    get_base,
)
from hunterx.infrastructure.db.sql.repositories import (
    SqlAssetRepository,
    SqlFindingRepository,
    SqlMissionRepository,
    SqlReportRepository,
    SqlScanRepository,
    SqlTargetRepository,
)

__all__ = [
    "SessionFactory",
    "create_engine_from_settings",
    "get_base",
    "SqlMissionRepository",
    "SqlFindingRepository",
    "SqlTargetRepository",
    "SqlScanRepository",
    "SqlAssetRepository",
    "SqlReportRepository",
]
