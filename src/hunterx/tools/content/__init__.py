# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Content discovery tool integrations.

SDK adapters and Tool Intelligence registrations for the content discovery
tools HunterX integrates (ffuf). Every adapter runs through the Tool
Integration SDK pipeline and emits canonical content-discovery records.
"""

from __future__ import annotations

from hunterx.tools.content.bruteforcers import (
    DirsearchAdapter,
    FeroxbusterAdapter,
    GobusterAdapter,
)
from hunterx.tools.content.registry import (
    CONTENT_TOOL_IDS,
    ContentAdapterFactory,
    content_adapters,
    register_content_adapters,
)
from hunterx.tools.content.tip import content_tool_ids, register_content_tools

__all__ = [
    "CONTENT_TOOL_IDS",
    "ContentAdapterFactory",
    "DirsearchAdapter",
    "FeroxbusterAdapter",
    "GobusterAdapter",
    "content_adapters",
    "content_tool_ids",
    "register_content_adapters",
    "register_content_tools",
]
