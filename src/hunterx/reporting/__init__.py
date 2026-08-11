# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Reporting infrastructure.

View models describe report content; renderers convert those views into
specific output formats. Templates ship inside :mod:`hunterx.reporting.templates`.
"""

from __future__ import annotations

from hunterx.reporting.proof import (
    ProofEntryView,
    ProofReportBuilder,
    ProofReportView,
)
from hunterx.reporting.renderers import JsonRenderer, MarkdownRenderer, Renderer
from hunterx.reporting.validation import (
    ValidationEntryView,
    ValidationReportBuilder,
    ValidationReportView,
)
from hunterx.reporting.views import FindingView, MissionView, ReportView

__all__ = [
    "Renderer",
    "JsonRenderer",
    "MarkdownRenderer",
    "ReportView",
    "FindingView",
    "MissionView",
    "ProofEntryView",
    "ProofReportBuilder",
    "ProofReportView",
    "ValidationEntryView",
    "ValidationReportBuilder",
    "ValidationReportView",
]
