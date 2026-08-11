# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool validation.

Validates tool parameters and runtime context before execution. Reuses the
JSON-schema style ``parameters`` field of a tool descriptor to validate
incoming parameter dictionaries.
"""

from __future__ import annotations

from typing import Any

import jsonschema

from hunterx.domain.exceptions import InvalidFindingError, ToolExecutionError
from hunterx.domain.tools import ToolDescriptor


class ToolValidator:
    """Validate parameters against a tool's declared schema."""

    def validate(self, descriptor: ToolDescriptor, parameters: dict[str, Any]) -> None:
        """Raise :class:`InvalidFindingError` on schema violations."""
        schema = descriptor.parameters
        if not schema:
            return
        try:
            jsonschema.validate(instance=parameters, schema=schema)
        except jsonschema.ValidationError as exc:
            raise InvalidFindingError(
                f"Invalid parameters for '{descriptor.name}': {exc.message}"
            ) from exc

    @staticmethod
    def check_target_kind(descriptor: ToolDescriptor, target_kind: str) -> None:
        """Raise :class:`ToolExecutionError` when the target kind is unsupported."""
        if descriptor.targets and target_kind not in descriptor.targets:
            raise ToolExecutionError(
                f"Tool '{descriptor.name}' does not support target kind '{target_kind}'."
            )
