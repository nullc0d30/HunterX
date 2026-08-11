# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool category base classes.

Specialized base classes for each tool family. They exist so plugins can pick
a well-defined contract (e.g. scanners must declare ``capabilities``
containing ``scan``) while still inheriting the full tool runtime.
"""

from __future__ import annotations

import abc

from hunterx.tools.adapter import BaseTool


class ScannerTool(BaseTool, abc.ABC):
    """Base class for vulnerability scanners."""


class CrawlerTool(BaseTool, abc.ABC):
    """Base class for web/content crawlers."""


class EnumeratorTool(BaseTool, abc.ABC):
    """Base class for resource enumerators."""


class AnalyzerTool(BaseTool, abc.ABC):
    """Base class for passive analyzers."""


class ReporterTool(BaseTool, abc.ABC):
    """Base class for evidence-collecting reporters."""
