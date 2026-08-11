# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Plugin manager.

Coordinates the full plugin lifecycle: dependency resolution → load → version
check → permission grant → activate. The manager implements
:class:`~hunterx.domain.ports.services.PluginRegistryPort` and delegates
actual registration to the registry.
"""

from __future__ import annotations

from hunterx.domain.exceptions import PluginLoadError
from hunterx.domain.plugins import PluginDescriptor
from hunterx.domain.ports.services import PluginRegistryPort
from hunterx.plugins.dependencies import resolve_load_order
from hunterx.plugins.lifecycle import LifecycleHooks
from hunterx.plugins.loader import PluginLoader
from hunterx.plugins.manifest import PluginManifest
from hunterx.plugins.permissions import PluginPermissions
from hunterx.plugins.registry import PluginRegistry
from hunterx.plugins.sandbox import SandboxPolicy
from hunterx.plugins.versioning import check_platform_compatibility


class PluginManager:
    """Full plugin lifecycle manager.

    Usage::

        manager = PluginManager(registry=PluginRegistry())
        manager.register_manifest(manifest)          # via dependency order
        manager.activate("my.plugin")                # load + activate
    """

    def __init__(
        self,
        registry: PluginRegistryPort | None = None,
        *,
        loader: PluginLoader | None = None,
        platform_version: str = "7.0.0",
    ) -> None:
        self._registry = registry or PluginRegistry()
        self._loader = loader or PluginLoader()
        self._platform_version = platform_version
        self._manifests: dict[str, PluginManifest] = {}
        self._instances: dict[str, object] = {}
        self._permissions: dict[str, PluginPermissions] = {}

    # -- registry delegation ----------------------------------------------

    def register(self, descriptor: PluginDescriptor) -> None:
        """Register a plugin descriptor, replacing any same-name entry."""
        self._registry.register(descriptor)

    def unregister(self, name: str) -> None:
        """Remove the plugin descriptor named ``name``."""
        self._registry.unregister(name)

    def get(self, name: str) -> PluginDescriptor | None:
        """Return the plugin descriptor by name, or ``None`` if absent."""
        return self._registry.get(name)

    def list(self) -> list[PluginDescriptor]:
        """Return all registered plugin descriptors."""
        return self._registry.list()

    # -- manifest + lifecycle ---------------------------------------------

    def register_manifest(self, manifest: PluginManifest) -> None:
        """Record a manifest and validate platform compatibility."""
        check_platform_compatibility(manifest, self._platform_version)
        self._manifests[manifest.name] = manifest

    def resolve_load_order(self) -> list[str]:
        """Return plugin names ordered so dependencies load first."""
        dependencies = {name: set(manifest.dependencies) for name, manifest in self._manifests.items()}
        return resolve_load_order(dependencies)

    def activate(self, name: str, *, context: object = None) -> object:
        """Load and activate a plugin, returning its instance."""
        manifest = self._manifests.get(name)
        if manifest is None:
            raise PluginLoadError(f"Plugin '{name}' has no registered manifest.")
        if name in self._instances:
            return self._instances[name]

        instance = self._loader.load(manifest)
        self._permissions[name] = PluginPermissions.from_manifest(manifest.permissions)
        self._instances[name] = instance

        if isinstance(instance, LifecycleHooks):
            instance.on_load(context)
            instance.on_activate(context)

        descriptor = PluginDescriptor(
            name=manifest.name,
            version=manifest.version,
            description=manifest.description,
            kind=manifest.kind.value,
            entrypoint=manifest.entrypoint,
            dependencies=manifest.dependencies,
            permissions=tuple(flag.value for flag in manifest.permissions),
        )
        self._registry.register(descriptor)
        return instance

    def deactivate(self, name: str, *, context: object = None) -> None:
        """Deactivate and unload a plugin."""
        instance = self._instances.pop(name, None)
        if isinstance(instance, LifecycleHooks):
            instance.on_deactivate(context)
            instance.on_unload()
        self._permissions.pop(name, None)
        self._registry.unregister(name)

    def permissions_for(self, name: str) -> PluginPermissions:
        """Return the granted permissions of an active plugin."""
        return self._permissions.get(name, PluginPermissions())

    def active(self) -> list[str]:
        """Return the names of currently active plugins."""
        return sorted(self._instances)

    @property
    def policy(self) -> SandboxPolicy:
        """Return the shared sandbox policy for permission enforcement."""
        return SandboxPolicy()
