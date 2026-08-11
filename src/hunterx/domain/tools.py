# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool descriptor.

A tool is an adapter that produces normalized observations (findings,
evidence, assets) by interrogating a target. The descriptor is the static
contract that the tool registry and the tool executor rely on.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class ToolDescriptor:
    """Static description of an installed tool adapter.

    Attributes:
        name: unique tool name.
        version: semantic version string.
        description: one-line description.
        entrypoint: importable adapter class.
        targets: target kinds this tool can operate on.
        capabilities: capability flags (recon, scan, detect, ...).
        parameters: JSON-schema style parameter specification.
        permissions: permission flags requested at runtime.

    """

    name: str
    version: str = "0.1.0"
    description: str = ""
    entrypoint: str = ""
    targets: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()
    parameters: dict[str, object] = field(default_factory=dict)
    permissions: tuple[str, ...] = ()

    def __str__(self) -> str:
        return f"{self.name}@{self.version}"
