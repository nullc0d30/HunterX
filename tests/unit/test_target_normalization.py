# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for Defect 1 — scheme-aware target normalization.

A full URL target (``http://localhost:3010``) must never be passed verbatim to
host/domain tools: they silently return empty results. Web-facing tools get the
full URL; host/network tools get the bare host.
"""

from __future__ import annotations

from hunterx.shared.target import (
    has_meaningful_content,
    normalize_target,
    target_for_adapter,
    target_type_for,
)


class TestNormalizeTarget:
    def test_full_url_splits_scheme_host_port_path(self) -> None:
        spec = normalize_target("https://example.com:8443/api/v1")

        assert spec.scheme == "https"
        assert spec.hostname == "example.com"
        assert spec.host_or_ip == "example.com"
        assert spec.port == 8443
        assert spec.url == "https://example.com:8443/api/v1"
        assert spec.path == "/api/v1"

    def test_bare_host_port_gets_implicit_scheme(self) -> None:
        spec = normalize_target("localhost:3010")

        assert spec.scheme == ""
        assert spec.host_or_ip == "localhost"
        assert spec.port == 3010
        assert spec.url == "http://localhost:3010"

    def test_bare_hostname(self) -> None:
        spec = normalize_target("juice-shop.example.com")

        assert spec.host_or_ip == "juice-shop.example.com"
        assert spec.port == 0
        assert spec.url == "http://juice-shop.example.com"

    def test_ip_target(self) -> None:
        spec = normalize_target("10.0.0.5")

        assert spec.host_or_ip == "10.0.0.5"
        assert spec.is_ip
        assert not spec.is_domain

    def test_scheme_default_port(self) -> None:
        assert normalize_target("https://example.com").port == 443
        assert normalize_target("http://example.com").port == 80

    def test_empty_target_is_safe(self) -> None:
        spec = normalize_target("")

        assert spec.host_or_ip == ""
        assert spec.url == ""


class TestTargetForAdapter:
    def test_web_tools_receive_full_url(self) -> None:
        spec = normalize_target("http://localhost:3010")

        assert target_for_adapter(spec, ("url", "host", "domain", "ip")) == "http://localhost:3010"

    def test_host_tools_receive_bare_host(self) -> None:
        spec = normalize_target("http://localhost:3010")

        assert target_for_adapter(spec, ("ip", "cidr", "host", "domain")) == "localhost"
        assert target_type_for(spec, ("ip", "cidr", "host", "domain")) == "host"

    def test_host_tools_receive_bare_host_without_path(self) -> None:
        spec = normalize_target("https://api.example.com/v2")

        assert target_for_adapter(spec, ("ip", "cidr", "host", "domain")) == "api.example.com"
        assert "://" not in target_for_adapter(spec, ("ip", "cidr", "host", "domain"))
        assert "/v2" not in target_for_adapter(spec, ("ip", "cidr", "host", "domain"))

    def test_ip_target_type(self) -> None:
        spec = normalize_target("10.0.0.5")

        assert target_type_for(spec, ("ip", "cidr", "host", "domain")) == "ip"
        assert target_type_for(spec, ("host",)) == "host"

    def test_unknown_declarations_fall_back_to_host(self) -> None:
        spec = normalize_target("http://localhost:3010")

        assert target_for_adapter(spec, ()) == "localhost"


class TestMeaningfulContent:
    def test_empty_dict_is_not_meaningful(self) -> None:
        assert not has_meaningful_content({})
        assert not has_meaningful_content({"stdout": ""})
        assert not has_meaningful_content({"records": [], "count": 0})
        assert not has_meaningful_content({"value": ""})
        assert not has_meaningful_content({})

    def test_content_with_any_value_is_meaningful(self) -> None:
        assert has_meaningful_content({"name": "express"})
        assert has_meaningful_content({"ports": [80, 443]})
        assert has_meaningful_content({"records": [] , "count": 1})
        assert has_meaningful_content({"endpoints": ["/api"]})

    def test_nested_meaningful_values(self) -> None:
        assert has_meaningful_content({"nested": {"deep": {"name": "x"}}})
        assert not has_meaningful_content({"nested": {"deep": {}}})


def test_import_is_stable() -> None:
    # The module must import without triggering the repo-root shim.
    import hunterx.shared.target  # noqa: F401

    assert hunterx.shared.target.normalize_target is normalize_target
