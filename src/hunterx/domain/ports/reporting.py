# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Reporting ports.

The report exporter port decouples the application layer from the concrete
report renderers so dependency direction stays inward: the application service
depends on this domain contract and the reporting layer provides the adapter.
"""

from __future__ import annotations

import abc
from typing import Any


class ReportExporterPort(abc.ABC):
    """Contract every report exporter adapter implements.

    Adapters live in the reporting layer and render a report document into a
    concrete output format without the application layer knowing the details.
    """

    @abc.abstractmethod
    def export(self, document: Any, *, fmt: str) -> str:
        """Render ``document`` into ``fmt`` and return the output text."""


__all__ = ["ReportExporterPort"]
