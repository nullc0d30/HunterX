# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Plugin loader.

Imports a plugin's entrypoint class from its declared import path and
instantiates it. Loading is separated from lifecycle management so the loader
stays small and reusable.
"""

from __future__ import annotations

import importlib
from typing import Any

from hunterx.domain.exceptions import PluginLoadError
from hunterx.plugins.manifest import PluginManifest


class PluginLoader:
    """Import and instantiate a plugin from its manifest."""

    def load(self, manifest: PluginManifest) -> Any:
        """Load the plugin class and return an instance.

        Raises:
            PluginLoadError: if the entrypoint cannot be imported or the
                loaded object is not instantiable.

        """
        if ":" not in manifest.entrypoint:
            raise PluginLoadError(
                f"Plugin '{manifest.name}' entrypoint must be 'module.path:ClassName'."
            )
        module_path, class_name = manifest.entrypoint.split(":", 1)
        try:
            module = importlib.import_module(module_path)
        except ImportError as exc:
            raise PluginLoadError(f"Plugin '{manifest.name}' failed to import '{module_path}': {exc}") from exc
        try:
            plugin_class = getattr(module, class_name)
        except AttributeError as exc:
            raise PluginLoadError(
                f"Plugin '{manifest.name}' has no class '{class_name}' in '{module_path}'."
            ) from exc
        try:
            return plugin_class()
        except TypeError as exc:
            raise PluginLoadError(f"Plugin '{manifest.name}' class could not be instantiated: {exc}") from exc
