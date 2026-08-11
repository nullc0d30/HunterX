# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""SAST tool adapters."""

from hunterx.tools.sast.registry import (
    SAST_TOOL_IDS,
    SastAdapterFactory,
    register_sast_adapters,
    sast_adapters,
)
from hunterx.tools.sast.semgrep import SemgrepAdapter
from hunterx.tools.vuln.scanbase import VulnerabilityScanAdapter

__all__ = [
    "SAST_TOOL_IDS",
    "SastAdapterFactory",
    "SemgrepAdapter",
    "VulnerabilityScanAdapter",
    "register_sast_adapters",
    "sast_adapters",
]
