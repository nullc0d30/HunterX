# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the mission configuration resolver."""

from __future__ import annotations

import pytest

from hunterx.domain.exceptions import MissionPlanningError
from hunterx.domain.mission_planning import (
    MissionPhase,
    MissionPhaseKind,
    MissionProfile,
    MissionRequest,
    MissionTemplate,
    MissionType,
)
from hunterx.engines.mission_planning.config import ConfigurationResolver


def _profile() -> MissionProfile:
    return MissionProfile(
        profile_id="p",
        name="P",
        phases=(
            MissionPhase(
                phase_id="recon",
                name="Recon",
                kind=MissionPhaseKind.RECONNAISSANCE,
                variables={"depth": "medium", "threads": 4},
            ),
        ),
    )


def _request(**overrides: object) -> MissionRequest:
    base: dict[str, object] = {
        "profile_id": "p",
        "mission_type": MissionType.EXTERNAL_PENTEST,
        "name": "M",
        "targets": ("a.com",),
    }
    base.update(overrides)
    return MissionRequest(**base)  # type: ignore[arg-type]


class TestConfigurationResolver:
    def test_phase_variables_are_defaults(self) -> None:
        resolver = ConfigurationResolver(environment={})
        config = resolver.resolve(_profile(), _request(), phase=_profile().phase("recon"))
        assert config["depth"] == "medium"

    def test_precedence_template_over_phase(self) -> None:
        resolver = ConfigurationResolver(environment={})
        template = MissionTemplate(template_id="t", name="T", profile_id="p", variables={"depth": "fast"})
        config = resolver.resolve(_profile(), _request(), template, phase=_profile().phase("recon"))
        assert config["depth"] == "fast"

    def test_precedence_request_over_template(self) -> None:
        resolver = ConfigurationResolver(environment={})
        template = MissionTemplate(template_id="t", name="T", profile_id="p", variables={"depth": "fast"})
        request = _request(variables={"depth": "thorough"})
        config = resolver.resolve(_profile(), request, template)
        assert config["depth"] == "thorough"

    def test_environment_override_wins(self) -> None:
        resolver = ConfigurationResolver(environment={"MISSION_DEPTH": "env-value"})
        request = _request(variables={"depth": "request"})
        config = resolver.resolve(_profile(), request)
        assert config["depth"] == "env-value"

    def test_env_prefix_ignores_unrelated_variables(self) -> None:
        resolver = ConfigurationResolver(environment={"OTHER_DEPTH": "x"})
        config = resolver.resolve(_profile(), _request())
        assert "depth" not in config or config["depth"] == "medium"

    def test_interpolation(self) -> None:
        resolver = ConfigurationResolver(environment={})
        config = resolver.resolve(
            _profile(),
            _request(variables={"prefix": "acme", "name": "{{ prefix }}-edge"}),
        )
        assert config["name"] == "acme-edge"

    def test_interpolation_in_nested_values(self) -> None:
        resolver = ConfigurationResolver(environment={})
        request = _request(
            variables={
                "scope": {"url": "https://{{ host }}/", "labels": ["{{ env_test }}"]},
                "host": "example.com",
                "env_test": "prod",
            }
        )
        config = resolver.resolve(_profile(), request)
        assert config["scope"]["url"] == "https://example.com/"
        assert config["scope"]["labels"] == ["prod"]

    def test_env_placeholder(self) -> None:
        resolver = ConfigurationResolver(environment={"API_TOKEN": "secret-token"})
        config = resolver.resolve(_profile(), _request(variables={"token": "{{ env.API_TOKEN }}"}))
        assert config["token"] == "secret-token"

    def test_undefined_variable_raises(self) -> None:
        resolver = ConfigurationResolver(environment={})
        with pytest.raises(MissionPlanningError, match="undefined variable"):
            resolver.render("{{ missing }}", {})

    def test_undefined_env_placeholder_raises(self) -> None:
        resolver = ConfigurationResolver(environment={})
        with pytest.raises(MissionPlanningError, match="not set"):
            resolver.render("{{ env.NOPE }}", {})

    def test_has_placeholders_and_required(self) -> None:
        resolver = ConfigurationResolver(environment={})
        assert resolver.has_placeholders("{{ a }} {{ b }}")
        assert not resolver.has_placeholders("plain")
        assert resolver.required_variables("{{ a }} {{ b }}") == ["a", "b"]

    def test_deep_merge(self) -> None:
        base = {"a": 1, "nested": {"x": 1, "y": 2}}
        override = {"nested": {"y": 3, "z": 4}, "b": 5}
        merged = ConfigurationResolver.deep_merge(base, override)
        assert merged == {"a": 1, "nested": {"x": 1, "y": 3, "z": 4}, "b": 5}
