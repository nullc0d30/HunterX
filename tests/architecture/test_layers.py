# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for layer resolution."""

from __future__ import annotations

from hunterx.architecture.layers import ROOT_LAYER, resolve_layer


def test_domain_layer_resolution() -> None:
    layer = resolve_layer("hunterx.domain.entities.target")
    assert layer.name == "domain"
    assert "hunterx.domain" in layer.packages


def test_deepest_prefix_wins() -> None:
    assert resolve_layer("hunterx.domain.exceptions").name == "domain"
    assert resolve_layer("hunterx.domain.exceptions.config").name == "domain"


def test_facade_modules_map_to_facade_layer() -> None:
    for module in ("hunterx.cache", "hunterx.managers", "hunterx.utils", "hunterx.exceptions"):
        assert resolve_layer(module).name == "facade"


def test_architecture_leaf_layer() -> None:
    assert resolve_layer("hunterx.architecture.lint").name == "architecture"


def test_root_package() -> None:
    assert resolve_layer("hunterx").name == ROOT_LAYER


def test_legacy_modules_resolve_to_legacy() -> None:
    assert resolve_layer("hunterx.cli").name == "cli"
    assert resolve_layer("core.agents.base").name == "legacy"
    assert resolve_layer("scripts.foo").name == "legacy"


def test_every_declared_package_resolves() -> None:
    from hunterx.architecture.layers import DEFAULT_LAYERS

    for layer in DEFAULT_LAYERS:
        for package in layer.packages:
            resolved = resolve_layer(package)
            assert resolved.name == layer.name, f"{package} -> {resolved.name}"
