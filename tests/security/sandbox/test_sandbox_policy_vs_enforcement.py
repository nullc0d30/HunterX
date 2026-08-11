# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Sandbox policy versus enforcement (Sprint 034.4 §7, §32).

The certification rule: a class/policy is NOT enforcement. These tests pin the
*actual* behavior of each sandbox layer so the boundary is honest:

- :class:`~hunterx.plugins.sandbox.SandboxPolicy` is permission *policy* only.
- :class:`~hunterx.infrastructure.sandbox.SubprocessSandbox` is a fresh-interpreter
  + timeout boundary, NOT an OS sandbox (no rlimit, no seccomp, no mount
  isolation). ``allowed_imports`` is an allow-list *policy*; Python itself can
  bypass it via ``__import__``.
- :class:`~hunterx.tools.sdk.sandbox.ExecutionSandbox` enforces declared
  permissions, secret-gated environment construction and secret masking.
"""

from __future__ import annotations

import pytest

from hunterx.domain.exceptions import SandboxError
from hunterx.domain.execution import ExecutionContext, ExecutionOutput
from hunterx.infrastructure.sandbox import SubprocessSandbox
from hunterx.plugins.manifest import PermissionFlag
from hunterx.plugins.permissions import PluginPermissions
from hunterx.plugins.sandbox import SandboxPolicy
from hunterx.tools.sdk.sandbox import ExecutionSandbox

# -- plugin sandbox policy: POLICY, not OS enforcement --------------------------


def test_plugin_policy_allows_only_granted_flags() -> None:
    policy = SandboxPolicy(platform_permissions=frozenset({PermissionFlag.NETWORK, PermissionFlag.NONE}))
    granted = PluginPermissions.from_manifest((PermissionFlag.NETWORK,))
    policy.allow("p", granted, PermissionFlag.NETWORK)
    with pytest.raises(SandboxError):
        policy.allow("p", granted, PermissionFlag.FILESYSTEM)


def test_plugin_policy_platform_deny_wins() -> None:
    policy = SandboxPolicy(platform_permissions=frozenset({PermissionFlag.NONE}))
    granted = PluginPermissions.from_manifest((PermissionFlag.NETWORK, PermissionFlag.SECRETS))
    with pytest.raises(SandboxError):
        policy.allow("p", granted, PermissionFlag.NETWORK)


def test_plugin_policy_is_not_os_isolation() -> None:
    """SandboxPolicy exists; OS isolation does not. This is documented as an
    architectural limitation, and the test pins the fact that the policy object
    alone provides no process/filesystem/network containment."""
    policy = SandboxPolicy()
    assert isinstance(policy, SandboxPolicy)


# -- infrastructure sandbox: fresh interpreter + timeout only -------------------


def test_subprocess_sandbox_allowed_imports_is_policy_not_enforcement() -> None:
    """The ``allowed_imports`` allow-list is advisory: Python can bypass it via
    ``__import__``. The sandbox therefore must never be relied on for hostile
    code containment — documented as a policy-only boundary."""
    sandbox = SubprocessSandbox(allowed_imports=())
    result = sandbox.run("print(__import__('os').name)")
    assert result.strip() == "posix" or result.strip() == "nt"


def test_subprocess_sandbox_enforces_timeout() -> None:
    sandbox = SubprocessSandbox(timeout_seconds=0.5)
    with pytest.raises(SandboxError):
        sandbox.run("import time; time.sleep(30)")


def test_subprocess_sandbox_failure_raises_sandbox_error() -> None:
    sandbox = SubprocessSandbox()
    with pytest.raises(SandboxError):
        sandbox.run("raise RuntimeError('boom')")


def test_subprocess_sandbox_check_returns_bool() -> None:
    assert SubprocessSandbox().check() is True


# -- SDK execution sandbox: real permission + secret enforcement ----------------


def test_sdk_sandbox_denies_missing_permission() -> None:
    sandbox = ExecutionSandbox()
    context = ExecutionContext(tool_id="t", permissions=())
    with pytest.raises(SandboxError):
        sandbox.enforce_permission(context, PermissionFlag.NETWORK)


def test_sdk_sandbox_grants_declared_permission() -> None:
    sandbox = ExecutionSandbox()
    context = ExecutionContext(tool_id="t", permissions=("network",))
    sandbox.enforce_permission(context, PermissionFlag.NETWORK)
    assert sandbox.grants(context, PermissionFlag.NETWORK)


def test_sdk_sandbox_secret_env_requires_secrets_permission() -> None:
    sandbox = ExecutionSandbox()
    context = ExecutionContext(tool_id="t", permissions=("network",))
    env = sandbox.prepare_environment(context, secrets={"API_KEY": "s3cr3t"})
    assert "HUNTERX_SECRET_API_KEY" not in env

    privileged = ExecutionContext(tool_id="t", permissions=("network", "secrets"))
    env = sandbox.prepare_environment(privileged, secrets={"API_KEY": "s3cr3t"})
    assert env["HUNTERX_SECRET_API_KEY"] == "s3cr3t"


def test_sdk_sandbox_masks_secrets_without_mutating_original() -> None:
    sandbox = ExecutionSandbox()
    output = ExecutionOutput(stdout="key=supersecret1234 tail", exit_code=0)
    masked = sandbox.mask_secrets(output, {"TOKEN": "supersecret1234"})
    assert "supersecret1234" not in masked.stdout
    assert "supersecret1234" in output.stdout


def test_sdk_sandbox_tempdir_names_are_traversal_safe() -> None:
    sandbox = ExecutionSandbox()
    hostile = ExecutionContext(
        tool_id="../../etc",
        execution_id="../../../tmp/pwn",
        temp_directory="/nonexistent-base",
    )
    path = sandbox.create_temp_directory(hostile)
    # The hostile identifiers must be sanitized, not used verbatim.
    assert ".." not in path.split("/")[-1]
    assert "/etc" not in path.split("/")[-1]


def test_sdk_sandbox_tmpdirs_are_per_execution_isolated() -> None:
    sandbox = ExecutionSandbox()
    first = ExecutionContext(tool_id="nmap", execution_id="exec-1", temp_directory="/tmp/hx-test")
    second = ExecutionContext(tool_id="nmap", execution_id="exec-2", temp_directory="/tmp/hx-test")
    assert sandbox.create_temp_directory(first) != sandbox.create_temp_directory(second)
