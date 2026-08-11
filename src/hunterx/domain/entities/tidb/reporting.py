# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Reporting-layer Target Intelligence Database entities.

Report building blocks and exports. The canonical ``Report`` aggregate lives
in ``hunterx.domain.entities``; these entities add structure, attachments
and export/consumption records around it.
"""

from __future__ import annotations

from dataclasses import dataclass

from hunterx.domain.entities.tidb._base import TidbEntity


@dataclass(slots=True)
class ReportSection(TidbEntity):
    """A section of a report.

    Attributes:
        report_id: owning report.
        section_key: stable machine name (e.g. ``executive-summary``).
        title: section title.
        order: display order.
        body: section body (markdown/text).
        kind: section kind (markdown, findings, charts, metrics, ...).

    """

    report_id: str
    section_key: str = ""
    title: str = ""
    order: int = 0
    body: str = ""
    kind: str = "markdown"


@dataclass(slots=True)
class ReportAttachment(TidbEntity):
    """A file attached to a report.

    Attributes:
        report_id: owning report.
        object_key: object-store key.
        file_path: local/relative path.
        size: size in bytes.
        sha256: content hash.
        mime_type: content MIME type.
        caption: display caption.

    """

    report_id: str
    object_key: str | None = None
    file_path: str | None = None
    size: int | None = None
    sha256: str | None = None
    mime_type: str | None = None
    caption: str = ""


@dataclass(slots=True)
class ReportExport(TidbEntity):
    """A report export run and its deliverable.

    Attributes:
        report_id: owning report.
        format: pdf|docx|html|json|markdown|... .
        status: pending|rendering|ready|failed.
        object_key: object-store key of the produced artifact.
        size: artifact size in bytes.
        rendered_by: renderer identifier.
        error: error message on failure.
        exported_at: UTC ISO-8601 timestamp.

    """

    report_id: str
    format: str = "pdf"
    status: str = "pending"
    object_key: str | None = None
    size: int | None = None
    rendered_by: str | None = None
    error: str = ""
    exported_at: str | None = None


@dataclass(slots=True)
class ReportConsumption(TidbEntity):
    """A record of a report being read/downloaded.

    Attributes:
        report_id: owning report.
        format: format consumed.
        consumer: consumer identifier.
        consumer_type: human|automation|api.
        consumed_at: UTC ISO-8601 timestamp.

    """

    report_id: str
    format: str = "pdf"
    consumer: str | None = None
    consumer_type: str = "human"
    consumed_at: str | None = None
