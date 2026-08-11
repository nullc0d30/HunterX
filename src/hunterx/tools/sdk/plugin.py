# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Execution plugin manager.

Hot-loads and unloads execution plugin modules that provide tool adapters and
configuration hooks. Plugins are loaded by entrypoint (``module.path:Object``)
or by module path, mirroring the platform plugin loader contract while staying
SDK-local.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.exceptions import ToolInstallationError


@dataclass(slots=True)
class LoadedPlugin:
    """A successfully loaded execution plugin.

    Attributes:
        name: plugin name.
        version: plugin version string.
        module: the imported module.
        tools: tool ids contributed by the plugin.

    """

    name: str
    version: str
    module: Any
    tools: list[str] = field(default_factory=list)


PluginHook = Callable[[], list[str]]


class ExecutionPluginManager:
    """Load/unload SDK execution plugins by module or entrypoint.

    A plugin module may expose ``__hunterx_plugin__`` (mapping with ``name``,
    ``version``) and ``register_tools()`` returning tool ids.
    """

    def __init__(self) -> None:
        self._loaded: dict[str, LoadedPlugin] = {}

    def load(self, entrypoint: str) -> LoadedPlugin:
        """Load a plugin from ``module.path:Object`` or ``module.path``.

        Raises:
            ToolInstallationError: when the module cannot be imported or does
                not declare a plugin.

        """
        module_path = entrypoint.split(":")[0].strip()
        try:
            module = importlib.import_module(module_path)
        except ImportError as error:
            raise ToolInstallationError(module_path, reason=f"plugin import failed: {error}") from error
        manifest = getattr(module, "__hunterx_plugin__", None)
        if not isinstance(manifest, dict):
            raise ToolInstallationError(
                module_path,
                reason="module does not declare __hunterx_plugin__",
            )
        name = str(manifest.get("name", module_path))
        version = str(manifest.get("version", "0.0.0"))
        tools: list[str] = []
        register = getattr(module, "register_tools", None)
        if callable(register):
            registered = register()
            if isinstance(registered, list):
                tools = [str(tool_id) for tool_id in registered]
        plugin = LoadedPlugin(name=name, version=version, module=module, tools=tools)
        self._loaded[name] = plugin
        return plugin

    def unload(self, name: str) -> None:
        """Unload a previously loaded plugin by name (idempotent)."""
        self._loaded.pop(name, None)

    def is_loaded(self, name: str) -> bool:
        """Return ``True`` when ``name`` is loaded."""
        return name in self._loaded

    def plugin(self, name: str) -> LoadedPlugin | None:
        """Return a loaded plugin, or ``None``."""
        return self._loaded.get(name)

    def loaded(self) -> list[LoadedPlugin]:
        """Return all loaded plugins."""
        return list(self._loaded.values())
