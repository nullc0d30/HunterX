# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Report entity.

A report is the final deliverable of a mission: a structured view over
findings, evidence, targets and metrics. Reports are rendered into multiple
formats by the reporting layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from hunterx.domain.entities._tidb_fields import TidbEnvelopeMixin
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


class ReportKind(Enum):
    """Canonical report kinds."""

    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    COMPLIANCE = "compliance"
    SARIF = "sarif"
    CUSTOM = "custom"


class ReportStatus(Enum):
    """Lifecycle states of a report."""

    DRAFT = "draft"
    READY = "ready"
    RENDERED = "rendered"
    FAILED = "failed"


@dataclass(slots=True)
class Report(TidbEnvelopeMixin):
    """A structured, multi-format deliverable.

    Attributes:
        mission_id: owning mission.
        kind: report kind.
        title: display title.
        summary: executive summary text.
        status: current state.
        finding_ids: identifiers of the findings covered.
        report_id: stable identity.
        updated_at / first_seen / last_seen / version / revision /
        schema_version / deleted_at: TIDB envelope.

    """

    mission_id: str
    kind: ReportKind
    title: str
    summary: str = ""
    status: ReportStatus = ReportStatus.DRAFT
    finding_ids: list[str] = field(default_factory=list)
    report_id: str = field(default_factory=generate_id)
    created_at: str = field(default_factory=utcnow_iso)
    updated_at: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    version: int = 1
    revision: int = 1
    schema_version: int = 1
    deleted_at: str | None = None
