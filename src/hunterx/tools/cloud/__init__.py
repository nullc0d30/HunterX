# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Cloud & SaaS intelligence tool integration.

The Tool Integration SDK adapter (``cloud-analysis``) runs the in-process
:class:`CloudAnalyzer` over a static-material bundle and serialises the typed
observations under the ``cloud`` payload key. The TIP registration mirrors the
adapter descriptor so intelligence and execution share one contract.
"""

from __future__ import annotations

from hunterx.tools.cloud.analyzer import CloudAnalyzerAdapter
from hunterx.tools.cloud.base import CloudToolAdapter
from hunterx.tools.cloud.registry import CLOUD_TOOL_IDS, cloud_adapters, register_cloud_adapters
from hunterx.tools.cloud.tip import CloudToolSpec, cloud_tool_specs, register_cloud_tools

__all__ = [
    "CLOUD_TOOL_IDS",
    "CloudAnalyzerAdapter",
    "CloudToolAdapter",
    "CloudToolSpec",
    "cloud_adapters",
    "cloud_tool_specs",
    "register_cloud_adapters",
    "register_cloud_tools",
]
