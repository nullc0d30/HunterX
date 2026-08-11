# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Report exporter adapter.

The reporting-layer adapter that renders a
:class:`~hunterx.domain.reporting.models.ReportDocument` into a concrete
output format. The application layer depends only on the
:class:`~hunterx.domain.ports.reporting.ReportExporterPort` contract; this
adapter is wired in the composition root.
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.ports.reporting import ReportExporterPort
from hunterx.reporting import report_renderers


class ReportExporter(ReportExporterPort):
    """Report exporter delegating to the format renderers."""

    def export(self, document: Any, *, fmt: str) -> str:
        """Render ``document`` into ``fmt``."""
        return report_renderers.render(document, fmt=fmt)


__all__ = ["ReportExporter"]
