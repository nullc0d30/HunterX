# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the dependency policy (matrix)."""

from __future__ import annotations

import pathlib

import pytest

from hunterx.architecture.policy import default_policy, load_policy


def test_default_policy_shape() -> None:
    policy = default_policy()
    assert policy.version == "1.0.0"
    assert "domain" in policy.layers
    assert "domain" in policy.allowed
    assert len(policy.waivers) >= 1
    assert len(policy.known_cycles) >= 1


def test_domain_may_import_shared_but_not_infrastructure() -> None:
    policy = default_policy()
    assert policy.is_allowed("domain", "shared")
    assert not policy.is_allowed("domain", "infrastructure")
    assert not policy.is_allowed("domain", "engines")
    assert not policy.is_allowed("domain", "api")
    assert not policy.is_allowed("domain", "cli")


def test_application_may_import_domain_but_not_infrastructure() -> None:
    policy = default_policy()
    assert policy.is_allowed("application", "domain")
    assert policy.is_allowed("application", "shared")
    assert not policy.is_allowed("application", "infrastructure")
    assert not policy.is_allowed("application", "api")


def test_platform_may_import_everything() -> None:
    policy = default_policy()
    # The architecture (enforcement tooling), legacy (forbidden) and root
    # (namespace) layers are not runtime subsystems the composition root imports.
    runtime_layers = {name for name in policy.layers if name not in ("architecture", "legacy", "root")}
    for layer in runtime_layers:
        assert policy.is_allowed("platform", layer), layer


def test_conditional_import_for_di_container() -> None:
    policy = default_policy()
    rule = policy.is_conditional("hunterx.shared.di", "hunterx.domain.exceptions")
    assert rule is not None
    assert policy.is_conditional("hunterx.shared.di", "hunterx.infrastructure.cache") is None


def test_waiver_matching() -> None:
    policy = default_policy()
    waiver = policy.find_waiver(
        "hunterx.domain.execution",
        "hunterx.plugins.sdk.results",
        "ARCH-001",
    )
    assert waiver is not None
    assert waiver.id == "ARCH-W-001"


def test_known_cycle_matching() -> None:
    policy = default_policy()
    known = policy.find_known_cycle(
        ("hunterx.tools.sdk", "hunterx.tools.sdk.engine", "hunterx.tools.sdk.pipeline")
    )
    assert known is not None
    assert policy.find_known_cycle(("hunterx.a", "hunterx.b")) is None


@pytest.fixture
def policy_file(tmp_path: pathlib.Path) -> pathlib.Path:
    """A minimal YAML policy exercising the loader."""
    path = tmp_path / "architecture.yaml"
    path.write_text(
        """
version: "9.9.9"
package_root: "pkg"
rules:
  domain: [domain, shared]
  tools: [tools, domain, shared, plugins]
waivers:
  - id: "ARCH-W-X"
    code: "ARCH-001"
    module: "hunterx.domain.execution"
    target: "hunterx.plugins.sdk.results"
    reason: "test"
known_cycles:
  - id: "ARCH-W-Y"
    modules: ["hunterx.a", "hunterx.b"]
    reason: "test"
plugin_boundary: ["hunterx.plugins.sdk"]
""",
        encoding="utf-8",
    )
    return path


def test_yaml_policy_overrides(policy_file: pathlib.Path) -> None:
    policy = load_policy(policy_file)
    assert policy.version == "9.9.9"
    assert policy.package_root == "pkg"
    assert policy.is_allowed("domain", "shared")
    assert not policy.is_allowed("domain", "engines")
    assert policy.plugin_boundary == ("hunterx.plugins.sdk",)
    assert policy.find_waiver("hunterx.domain.execution", "hunterx.plugins.sdk.results", "ARCH-001") is not None


def test_missing_policy_file_falls_back_to_default(tmp_path: pathlib.Path) -> None:
    policy = load_policy(tmp_path / "does-not-exist.yaml")
    assert policy.version == "1.0.0"
    assert "domain" in policy.allowed


def test_load_policy_none_returns_default() -> None:
    assert load_policy(None).version == "1.0.0"
