# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Plugin dependency resolution.

Computes a load order that satisfies plugin-to-plugin dependencies, and
detects missing dependencies and cycles.
"""

from __future__ import annotations

from hunterx.domain.exceptions import PluginLoadError


def resolve_load_order(plugins: dict[str, set[str]]) -> list[str]:
    """Return plugin names in dependency-satisfying order.

    ``plugins`` maps a plugin name to the set of plugin names it depends on.
    Raises :class:`PluginLoadError` for missing dependencies or dependency
    cycles.
    """
    resolved: list[str] = []
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(name: str) -> None:
        if name in visited:
            return
        if name in visiting:
            raise PluginLoadError(f"Dependency cycle detected involving '{name}'.")
        visiting.add(name)
        for dependency in plugins.get(name, ()):
            if dependency not in plugins:
                raise PluginLoadError(f"Plugin '{name}' depends on missing plugin '{dependency}'.")
            visit(dependency)
        visiting.remove(name)
        visited.add(name)
        resolved.append(name)

    for name in plugins:
        visit(name)
    return resolved
