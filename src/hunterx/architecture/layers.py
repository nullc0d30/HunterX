# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Layer definitions and module-to-layer resolution.

A *layer* is the architectural unit enforced by the framework. Every module
under ``src/hunterx`` belongs to exactly one layer (or to the special ``root``
layer for the side-effect-free ``hunterx`` package itself).
"""

from __future__ import annotations

from dataclasses import dataclass

#: The special pseudo-layer representing the ``hunterx`` package itself.
ROOT_LAYER = "root"

#: The pseudo-layer for the legacy flat ``hunterx/`` v6 package and other
#: non-v7 roots that must never be imported by shipping code.
LEGACY_LAYER = "legacy"


@dataclass(frozen=True, slots=True)
class Layer:
    """A named architectural layer.

    Attributes:
        name: unique layer identifier (e.g. ``"domain"``).
        packages: package prefixes that belong to this layer.
        description: human-readable responsibilities.
        owner: owning team or council.
        rank: ordering hint; lower values are more foundational.

    """

    name: str
    packages: tuple[str, ...] = ()
    description: str = ""
    owner: str = ""
    rank: int = 0


#: Built-in layer catalogue. The YAML policy may override descriptions and
#: owners; the packages mapping is normative for module resolution.
DEFAULT_LAYERS: tuple[Layer, ...] = (
    Layer(
        name="shared",
        packages=("hunterx.shared",),
        description="Cross-cutting helpers importable by every layer.",
        owner="Architecture Council",
        rank=1,
    ),
    Layer(
        name="domain",
        packages=("hunterx.domain",),
        description="Pure domain: entities, value objects, ports, services, events, exceptions.",
        owner="Architecture Council",
        rank=2,
    ),
    Layer(
        name="config",
        packages=("hunterx.config",),
        description="Configuration loading and typed settings.",
        owner="Platform Team",
        rank=3,
    ),
    Layer(
        name="security",
        packages=("hunterx.security",),
        description="Cross-cutting security services: policies, permissions, secret resolution.",
        owner="Security Team",
        rank=4,
    ),
    Layer(
        name="infrastructure",
        packages=("hunterx.infrastructure",),
        description="Adapters implementing domain ports (db, cache, queue, ai, sandbox, secrets).",
        owner="Platform Team",
        rank=5,
    ),
    Layer(
        name="application",
        packages=("hunterx.application",),
        description="Use-case services and DTOs.",
        owner="Application Team",
        rank=6,
    ),
    Layer(
        name="knowledge",
        packages=("hunterx.knowledge",),
        description="Knowledge base runtime and knowledge graph client.",
        owner="Intelligence Team",
        rank=7,
    ),
    Layer(
        name="reporting",
        packages=("hunterx.reporting",),
        description="Report views, renderers and evidence packaging.",
        owner="Reporting Team",
        rank=8,
    ),
    Layer(
        name="scheduler",
        packages=("hunterx.scheduler",),
        description="Mission scheduling and job definitions.",
        owner="Platform Team",
        rank=9,
    ),
    Layer(
        name="engines",
        packages=("hunterx.engines",),
        description="Engine facades: mission, workflow, planner, reasoning, correlation, report.",
        owner="Engine Team",
        rank=10,
    ),
    Layer(
        name="tools",
        packages=("hunterx.tools",),
        description="Tool runtime, Tool Integration Factory, Tool Intelligence and SDK.",
        owner="Tooling Team",
        rank=11,
    ),
    Layer(
        name="plugins",
        packages=("hunterx.plugins",),
        description="Plugin host, registry, loader and public plugin SDK.",
        owner="Plugin Team",
        rank=12,
    ),
    Layer(
        name="agents",
        packages=("hunterx.agents",),
        description="Multi-agent platform.",
        owner="AI Team",
        rank=13,
    ),
    Layer(
        name="api",
        packages=("hunterx.api",),
        description="REST API framework (routing structure, middleware, schemas).",
        owner="API Team",
        rank=14,
    ),
    Layer(
        name="cli",
        packages=("hunterx.cli",),
        description="CLI framework and command registry.",
        owner="CLI Team",
        rank=15,
    ),
    Layer(
        name="platform",
        packages=("hunterx.platform",),
        description="Composition root: assembles and wires every subsystem.",
        owner="Architecture Council",
        rank=16,
    ),
    Layer(
        name="architecture",
        packages=("hunterx.architecture",),
        description="The architecture enforcement framework itself (leaf layer).",
        owner="Architecture Council",
        rank=0,
    ),
    Layer(
        name="facade",
        packages=(
            "hunterx.cache",
            "hunterx.queue",
            "hunterx.events",
            "hunterx.logging",
            "hunterx.telemetry",
            "hunterx.observability",
            "hunterx.models",
            "hunterx.exceptions",
            "hunterx.utils",
            "hunterx.managers",
        ),
        description="Convenience facade re-export modules at the package root.",
        owner="Architecture Council",
        rank=0,
    ),
    Layer(
        name=ROOT_LAYER,
        packages=(),
        description="The ``hunterx`` package itself (side-effect-free).",
        owner="Architecture Council",
        rank=0,
    ),
    Layer(
        name=LEGACY_LAYER,
        packages=(),
        description="Legacy v6 flat package roots that must not be imported by v7 code.",
        owner="Architecture Council",
        rank=0,
    ),
)


def _build_index() -> dict[str, Layer]:
    """Return a mapping of every package prefix to its owning layer."""
    index: dict[str, Layer] = {}
    for layer in DEFAULT_LAYERS:
        for package in layer.packages:
            index[package] = layer
    return index


_INDEX = _build_index()


def resolve_layer(module: str) -> Layer:
    """Resolve the owning layer of a ``hunterx.*`` module.

    The longest matching package prefix wins. The bare ``hunterx`` package
    resolves to the :data:`ROOT_LAYER`; anything else resolves to the
    :data:`LEGACY_LAYER`.

    Args:
        module: dotted module name (e.g. ``"hunterx.domain.entities.target"``).

    Returns:
        The owning :class:`Layer`.

    """
    if module == "hunterx":
        return Layer(name=ROOT_LAYER, packages=("hunterx",))
    prefix = module
    while prefix:
        layer = _INDEX.get(prefix)
        if layer is not None:
            return layer
        if prefix == "hunterx" or "." not in prefix:
            break
        prefix = prefix.rsplit(".", 1)[0]
    return Layer(name=LEGACY_LAYER, packages=())
