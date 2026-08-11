# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Public plugin SDK.

The stable surface plugin authors compile against. The SDK is deliberately
small and stable: context access, result types, event emission and manifest
metadata.
"""

from __future__ import annotations

from hunterx.plugins.sdk.context import PluginContext, PluginResult, PluginSession
from hunterx.plugins.sdk.events import emit
from hunterx.plugins.sdk.results import EvidenceResult, FindingResult, PluginResultTypes

__all__ = [
    "PluginContext",
    "PluginResult",
    "PluginSession",
    "emit",
    "FindingResult",
    "EvidenceResult",
    "PluginResultTypes",
]
