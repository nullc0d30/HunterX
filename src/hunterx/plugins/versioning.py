# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Plugin versioning.

Checks a plugin manifest against the platform version and against the plugin
entry point's declared requirements. Uses a minimal, dependency-free version
comparison so the plugin manager works everywhere.
"""

from __future__ import annotations

import re

from hunterx.domain.exceptions import PluginLoadError
from hunterx.plugins.manifest import PluginManifest

_PART_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def _parse(version: str) -> tuple[int, int, int]:
    match = _PART_RE.search(version)
    if match is None:
        return (0, 0, 0)
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def check_platform_compatibility(manifest: PluginManifest, platform_version: str = "7.0.0") -> None:
    """Raise :class:`PluginLoadError` when ``requires_platform`` is unsatisfied.

    Supports ``>=`` and ``==`` constraints with ``major.minor.patch``
    versions; anything else is treated as an unverified (passing) constraint.
    """
    constraint = (manifest.requires_platform or "").strip()
    if not constraint:
        return
    current = _parse(platform_version)
    if constraint.startswith(">="):
        required = _parse(constraint[2:].strip())
        if current < required:
            raise PluginLoadError(
                f"Plugin '{manifest.name}' requires platform {constraint} but running {platform_version}."
            )
    elif constraint.startswith("=="):
        required = _parse(constraint[2:].strip())
        if current != required:
            raise PluginLoadError(
                f"Plugin '{manifest.name}' requires platform {constraint} but running {platform_version}."
            )
