# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Plugin system.

Manages plugin discovery, loading, lifecycle and permissions. The public
plugin authoring surface lives in :mod:`hunterx.plugins.sdk`.
"""

from __future__ import annotations

from hunterx.plugins.dependencies import resolve_load_order
from hunterx.plugins.loader import PluginLoader
from hunterx.plugins.manager import PluginManager
from hunterx.plugins.manifest import PermissionFlag, PluginKind, PluginManifest
from hunterx.plugins.registry import PluginRegistry

__all__ = [
    "PluginManager",
    "PluginRegistry",
    "PluginLoader",
    "PluginManifest",
    "PluginKind",
    "PermissionFlag",
    "resolve_load_order",
]
