# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool discovery.

Discovers installed tool adapters from an importable set of modules/classes
and registers them with an executor. Tools declare their descriptors; the
discovery layer just finds and instantiates them.
"""

from __future__ import annotations

import importlib

from hunterx.domain.exceptions import ToolExecutionError
from hunterx.tools.adapter import BaseTool


class ToolDiscovery:
    """Discover and instantiate tool adapters.

    Accepts either an explicit list of ``(name, instance)`` pairs or an
    iterable of ``(module_path, class_name)`` entry points.
    """

    def instantiate(self, entrypoint: str) -> BaseTool:
        """Import ``module.path:ClassName`` and return an instance.

        Raises:
            ToolExecutionError: if the entry point is invalid or the loaded
                class is not a :class:`BaseTool`.

        """
        if ":" not in entrypoint:
            raise ToolExecutionError(f"Tool entrypoint '{entrypoint}' must be 'module:Class'.")
        module_path, class_name = entrypoint.split(":", 1)
        try:
            module = importlib.import_module(module_path)
            tool_class = getattr(module, class_name)
        except (ImportError, AttributeError) as exc:
            raise ToolExecutionError(f"Could not load tool entrypoint '{entrypoint}': {exc}") from exc
        try:
            instance = tool_class()
        except TypeError as exc:
            raise ToolExecutionError(f"Tool class '{class_name}' could not be instantiated: {exc}") from exc
        if not isinstance(instance, BaseTool):
            raise ToolExecutionError(f"'{entrypoint}' does not produce a BaseTool instance.")
        return instance
