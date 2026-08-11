# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Generator engine foundations.

Defines the :class:`PackContext` handed to every generator and the
:class:`PackGenerator` contract all generators implement. Generators produce
:class:`GeneratedFile` artifacts for a :class:`ToolPackSpec`; the engine
assembles them into a pack.
"""

from __future__ import annotations

import abc
from collections.abc import Mapping
from dataclasses import dataclass

from hunterx.domain.tool_factory import GeneratedFile, PackArtifactKind, ToolPackSpec
from hunterx.tools.factory.render import TemplateRenderer


@dataclass(frozen=True, slots=True)
class PackContext:
    """Everything a generator needs to emit pack files."""

    spec: ToolPackSpec
    templates: Mapping[str, str]
    renderer: TemplateRenderer
    context: Mapping[str, object]


class PackGenerator(abc.ABC):
    """Base contract for every Tool Integration Factory generator."""

    name: str
    description: str = ""

    @abc.abstractmethod
    def generate(self, ctx: PackContext) -> list[GeneratedFile]:
        """Emit the :class:`GeneratedFile` artifacts for ``ctx.spec``."""

    def render(self, ctx: PackContext, path: str, fallback: str) -> str:
        """Render ``path``'s template (store or ``fallback``) against the context."""
        template = ctx.templates.get(path, fallback)
        return ctx.renderer.render(template, ctx.context)

    def file(self, path: str, content: str, kind: PackArtifactKind) -> GeneratedFile:
        """Build a single generated file."""
        return GeneratedFile(path=path, content=content, kind=kind)

    def files(
        self,
        ctx: PackContext,
        contents: Mapping[str, tuple[str, PackArtifactKind]],
    ) -> list[GeneratedFile]:
        """Build many files from a ``path -> (content, kind)`` mapping."""
        return [
            self.file(path, content, kind)
            for path, (content, kind) in contents.items()
        ]
