# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Plugin descriptor.

A plugin is a self-contained capability package (tool, agent, engine,
normalizer, renderer). The descriptor is the manifest-level contract shared by
the plugin manager, the registries and the plugin SDK.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class PluginDescriptor:
    """Static description of an installed plugin.

    Attributes:
        name: unique plugin name.
        version: semantic version string.
        description: one-line description.
        kind: plugin kind (``tool``, ``agent``, ``engine``, ...).
        entrypoint: importable entry point (e.g. ``"pkg.mod:Plugin"``).
        dependencies: plugin names this plugin requires.
        permissions: permission flags requested (network, fs, exec, ...).

    """

    name: str
    version: str = "0.1.0"
    description: str = ""
    kind: str = "tool"
    entrypoint: str = ""
    dependencies: tuple[str, ...] = ()
    permissions: tuple[str, ...] = ()
    metadata: dict[str, object] = field(default_factory=dict)

    def __str__(self) -> str:
        return f"{self.name}@{self.version} ({self.kind})"
