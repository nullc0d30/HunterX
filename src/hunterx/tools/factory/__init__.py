# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool Integration Factory.

Generates standardized Tool Integration Packs for future security tools using
one unified development standard. The factory composes generators, integration
templates, a validator, compatibility checks and versioning; every generated
pack follows the exact same layout and engineering standards.
"""

from __future__ import annotations

from hunterx.tools.factory.api import ToolIntegrationFactory
from hunterx.tools.factory.compatibility import CompatibilityValidator
from hunterx.tools.factory.engine import ToolPackGeneratorEngine
from hunterx.tools.factory.generators import default_generators
from hunterx.tools.factory.layout import (
    GENERATOR_VERSION,
    HUNTERX_VERSION,
    PACK_LAYOUT,
    PACK_STRUCTURE_VERSION,
    QUALITY_GATES,
    SDK_VERSION,
    quality_gate_files,
    required_files,
)
from hunterx.tools.factory.render import TemplateRenderer, render_context
from hunterx.tools.factory.templates import (
    BUILTIN_TEMPLATE,
    PackTemplateStore,
)
from hunterx.tools.factory.validator import ToolPackValidator
from hunterx.tools.factory.versioning import VersionResolver

__all__ = [
    "ToolIntegrationFactory",
    "ToolPackGeneratorEngine",
    "CompatibilityValidator",
    "ToolPackValidator",
    "VersionResolver",
    "PackTemplateStore",
    "TemplateRenderer",
    "render_context",
    "default_generators",
    "BUILTIN_TEMPLATE",
    "GENERATOR_VERSION",
    "HUNTERX_VERSION",
    "SDK_VERSION",
    "PACK_STRUCTURE_VERSION",
    "PACK_LAYOUT",
    "QUALITY_GATES",
    "required_files",
    "quality_gate_files",
]
