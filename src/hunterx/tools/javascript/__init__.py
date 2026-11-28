# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""JavaScript intelligence tool adapters.

SDK tool adapters for the JavaScript Intelligence & Client-Side Attack-Surface Discovery capability.
"""

from hunterx.tools.javascript.analyzer import JavaScriptAnalyzerAdapter
from hunterx.tools.javascript.base import JavaScriptToolAdapter
from hunterx.tools.javascript.external import (
    LinkFinderAdapter,
    SecretFinderAdapter,
    XnLinkFinderAdapter,
)
from hunterx.tools.javascript.registry import (
    JS_TOOL_IDS,
    JavaScriptAdapterFactory,
    javascript_adapters,
    register_javascript_adapters,
)
from hunterx.tools.javascript.tip import (
    JavaScriptToolSpec,
    javascript_tool_specs,
    register_javascript_tools,
)
from hunterx.tools.sdk.adapter import ToolAdapter

__all__ = [
    "JS_TOOL_IDS",
    "JavaScriptAdapterFactory",
    "JavaScriptAnalyzerAdapter",
    "JavaScriptToolAdapter",
    "JavaScriptToolSpec",
    "LinkFinderAdapter",
    "SecretFinderAdapter",
    "ToolAdapter",
    "XnLinkFinderAdapter",
    "javascript_adapters",
    "javascript_tool_specs",
    "register_javascript_adapters",
    "register_javascript_tools",
]
