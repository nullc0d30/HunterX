# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Plugin manifest model."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class PluginKind(Enum):
    """Canonical plugin kinds."""

    TOOL = "tool"
    AGENT = "agent"
    ENGINE = "engine"
    NORMALIZER = "normalizer"
    RENDERER = "renderer"
    EXTENSION = "extension"


class PermissionFlag(Enum):
    """Permission flags a plugin may request at runtime."""

    NONE = "none"
    NETWORK = "network"
    FILESYSTEM = "filesystem"
    PROCESS = "process"
    SECRETS = "secrets"


@dataclass(frozen=True, slots=True)
class PluginManifest:
    """Declared metadata of a plugin package.

    Attributes:
        name: unique plugin name (package identifier).
        version: semantic version.
        description: one-line description.
        kind: plugin kind.
        entrypoint: import path to the plugin's main class.
        dependencies: other plugin names required.
        permissions: runtime permission flags requested.
        requires_platform: minimum platform version constraint.

    """

    name: str
    version: str = "0.1.0"
    description: str = ""
    kind: PluginKind = PluginKind.TOOL
    entrypoint: str = ""
    dependencies: tuple[str, ...] = ()
    permissions: tuple[PermissionFlag, ...] = (PermissionFlag.NONE,)
    requires_platform: str = ">=7.0.0"
    metadata: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("plugin name must not be empty.")
        if not self.entrypoint:
            raise ValueError("plugin entrypoint must not be empty.")
