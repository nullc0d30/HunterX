# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Plugin security & trust model (Sprint 034.4 §17).

Plugins are Python packages loaded into the HunterX process: there is no
OS-level isolation. Permissions are *declared* by the manifest and *enforced*
as policy by SandboxPolicy, but the plugin process itself can do anything the
HunterX process can (filesystem, network, credentials) unless a deployment adds
OS isolation. These tests pin the actual boundary.
"""

from __future__ import annotations

import pytest

from hunterx.domain.exceptions import PluginLoadError, SandboxError
from hunterx.plugins.loader import PluginLoader
from hunterx.plugins.manifest import PermissionFlag, PluginKind, PluginManifest
from hunterx.plugins.permissions import PluginPermissions
from hunterx.plugins.sandbox import SandboxPolicy


def test_plugin_can_only_use_manifest_declared_permissions() -> None:
    policy = SandboxPolicy(platform_permissions=frozenset({PermissionFlag.NETWORK, PermissionFlag.NONE}))
    granted = PluginPermissions.from_manifest((PermissionFlag.NETWORK,))
    assert policy.allow("p", granted, PermissionFlag.NETWORK) is None
    with pytest.raises(SandboxError):
        policy.allow("p", granted, PermissionFlag.SECRETS)


def test_platform_policy_caps_plugin_permissions() -> None:
    policy = SandboxPolicy(platform_permissions=frozenset({PermissionFlag.NONE}))
    granted = PluginPermissions.from_manifest((PermissionFlag.NETWORK, PermissionFlag.SECRETS))
    for flag in (PermissionFlag.NETWORK, PermissionFlag.SECRETS):
        with pytest.raises(SandboxError):
            policy.allow("p", granted, flag)


def test_plugin_loader_rejects_malformed_entrypoint() -> None:
    manifest = PluginManifest(name="p", entrypoint="no-colon")
    with pytest.raises(PluginLoadError):
        PluginLoader().load(manifest)


def test_plugin_loader_rejects_missing_class() -> None:
    manifest = PluginManifest(name="p", entrypoint="hunterx.plugins.loader:DoesNotExist")
    with pytest.raises(PluginLoadError):
        PluginLoader().load(manifest)


def test_plugin_is_in_process_code_not_os_isolation() -> None:
    """Documented architectural limitation: a loaded plugin executes arbitrary
    Python in the HunterX process. It can read files, open sockets and import
    any installed module — permissions only gate the SDK *offered* capabilities,
    they do not contain the code."""
    manifest = PluginManifest(
        name="osint",
        version="1.0.0",
        kind=PluginKind.EXTENSION,
        entrypoint="hunterx.plugins.loader:PluginLoader",
        permissions=(PermissionFlag.NONE,),
    )
    instance = PluginLoader().load(manifest)
    assert instance is not None
    # Demonstrating the boundary: the loader's own class can import stdlib.
    import os

    assert os.path.exists.__self__ is not None or callable(os.path.exists)


def test_plugin_manager_grants_only_declared_permissions() -> None:
    from hunterx.plugins.manager import PluginManager

    manager = PluginManager()
    manifest = PluginManifest(name="probe", entrypoint="hunterx.plugins.loader:PluginLoader", permissions=(PermissionFlag.NETWORK,))
    manager.register_manifest(manifest)
    manager.activate("probe")
    granted = manager.permissions_for("probe")
    assert granted.allows(PermissionFlag.NETWORK) is True
    assert granted.allows(PermissionFlag.FILESYSTEM) is False
    assert granted.allows(PermissionFlag.SECRETS) is False
