# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Template rendering for the Tool Integration Factory.

The renderer expands ``${placeholder}`` references in integration templates
using a spec-derived context. Rendering is strict: an unknown placeholder
raises :class:`TemplateRenderError` so generated packs never ship with a hole.
"""

from __future__ import annotations

import string
from collections.abc import Mapping

from hunterx.domain.exceptions import TemplateRenderError
from hunterx.domain.tool_factory import ToolPackSpec
from hunterx.tools.factory.layout import GENERATOR_VERSION, HUNTERX_VERSION, SDK_VERSION

#: Copyright header stamped into every generated source file.
COPYRIGHT_LINE = "Copyright (c) 2026 Ahmed Awad (NullC0d3)"

#: Supported literal placeholder delimiters.
_DELIMITER = "${"


class TemplateRenderer:
    """Render ``${name}`` templates against a variable context."""

    def render(self, template: str, context: Mapping[str, object]) -> str:
        """Expand placeholders in ``template`` using ``context``.

        Missing variables raise :class:`TemplateRenderError`.
        """
        if _DELIMITER not in template:
            return template
        values = {key: str(value) for key, value in context.items()}
        try:
            return string.Template(template).substitute(values)
        except KeyError as exc:
            raise TemplateRenderError(
                f"template references undefined variable '{exc.args[0]}'."
            ) from exc
        except ValueError as exc:
            raise TemplateRenderError(f"invalid template placeholder: {exc}") from exc


def render_context(spec: ToolPackSpec) -> dict[str, object]:
    """Build the render context for ``spec`` (spec fields + shared constants)."""
    display_name = spec.display_name or " ".join(part.capitalize() for part in spec.tool_name.split("-"))
    return {
        "pack_id": spec.pack_id,
        "vendor": spec.vendor,
        "tool_name": spec.tool_name,
        "display_name": display_name,
        "description": spec.description,
        "version": spec.version,
        "author": spec.author,
        "license": spec.license,
        "entrypoint": spec.entrypoint,
        "adapter_class_name": spec.adapter_class_name,
        "parser_class_name": _pascal(spec.pack_id) + "Parser",
        "normalizer_class_name": _pascal(spec.pack_id) + "Normalizer",
        "capabilities_joined": ", ".join(spec.capabilities),
        "capabilities_list": ", ".join(f'"{capability}"' for capability in spec.capabilities),
        "targets_list": ", ".join(f'"{target}"' for target in spec.targets),
        "permissions_list": ", ".join(f'"{permission}"' for permission in spec.permissions),
        "mission_profiles_list": ", ".join(f'"{profile}"' for profile in spec.mission_profiles),
        "output_format": spec.output_format,
        "parser_strategy": spec.parser_strategy,
        "cli_binary": spec.cli_binary or spec.tool_name,
        "install_command": spec.install_command,
        "package_manager": spec.package_manager,
        "health_command": spec.health_command,
        "execution_type": spec.execution_type.value,
        "deprecated": "yes" if spec.deprecated else "no",
        "deprecation_reason": spec.deprecation_reason,
        "generator_version": GENERATOR_VERSION,
        "hunterx_version": HUNTERX_VERSION,
        "sdk_version": SDK_VERSION,
        "copyright": COPYRIGHT_LINE,
        "structure_version": "1.0",
    }


def _pascal(value: str) -> str:
    return "".join(part.capitalize() for part in value.replace("_", "-").split("-"))
