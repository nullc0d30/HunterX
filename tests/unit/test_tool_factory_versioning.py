# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for factory version resolution and compatibility validation."""

from __future__ import annotations

from hunterx.domain.exceptions import CompatibilityError
from hunterx.domain.tool_factory import SemanticVersion
from hunterx.shared.result import Failure, Success
from hunterx.tools.factory.compatibility import CompatibilityValidator
from hunterx.tools.factory.versioning import VersionResolver
from tests.unit.test_tool_factory_models import make_spec


class TestVersionResolver:
    def test_sort_ascending(self) -> None:
        versions = ["1.10.0", "1.2.0", "2.0.0", "1.2.0-rc.1"]
        assert VersionResolver.sort(versions) == ["1.2.0-rc.1", "1.2.0", "1.10.0", "2.0.0"]

    def test_sort_reverse(self) -> None:
        assert VersionResolver.sort(["1.0.0", "2.0.0"], reverse=True) == ["2.0.0", "1.0.0"]

    def test_latest(self) -> None:
        assert VersionResolver.latest(["1.0.0", "1.5.0", "1.10.0"]) == "1.10.0"

    def test_latest_empty(self) -> None:
        assert VersionResolver.latest([]) is None

    def test_satisfies(self) -> None:
        assert VersionResolver.satisfies("1.5.0", ">=1.0.0")
        assert not VersionResolver.satisfies("0.9.0", ">=1.0.0")

    def test_is_stable(self) -> None:
        assert VersionResolver.is_stable("1.0.0")
        assert not VersionResolver.is_stable("0.9.0")
        assert not VersionResolver.is_stable("1.0.0-rc.1")

    def test_deprecation_plan(self) -> None:
        plan = VersionResolver.deprecation_plan(make_spec())
        assert plan["deprecated"] is False
        deprecating = VersionResolver.deprecation_plan(
            make_spec(deprecated=True, deprecation_reason="superseded by v2")
        )
        assert deprecating["deprecated"] is True
        assert deprecating["removal"] == "next major release"

    def test_parse(self) -> None:
        parsed = VersionResolver.parse(["1.0.0", "2.0.0"])
        assert all(isinstance(version, SemanticVersion) for version in parsed)


class TestCompatibilityValidator:
    def test_build_matrix(self) -> None:
        validator = CompatibilityValidator(supported_hunterx=("7.0.0", "7.1.0"))
        matrix = validator.build_matrix(make_spec(hunterx_versions=("7.0.0",)))
        assert matrix.tool_id == "nmap"
        assert matrix.entries[0].hunterx_version == "7.0.0"
        assert matrix.status_for("1.0.0", "7.0.0") == "compatible"
        assert matrix.status_for("1.0.0", "8.0.0") == "incompatible"

    def test_is_compatible_same_major(self) -> None:
        validator = CompatibilityValidator(hunterx_version="7.2.0")
        spec = make_spec(version="1.0.0", hunterx_versions=("7.0.0",))
        assert validator.is_compatible(spec, hunterx_version="7.2.0")
        assert not validator.is_compatible(spec, hunterx_version="8.0.0")

    def test_zero_major_uses_minor(self) -> None:
        validator = CompatibilityValidator(hunterx_version="7.0.0")
        spec = make_spec(version="1.0.0", hunterx_versions=("0.2.0",))
        assert validator.is_compatible(spec, hunterx_version="0.2.9")
        assert not validator.is_compatible(spec, hunterx_version="0.3.0")

    def test_deprecated_never_compatible(self) -> None:
        validator = CompatibilityValidator(hunterx_version="7.0.0")
        spec = make_spec(deprecated=True, deprecation_reason="replaced")
        assert not validator.is_compatible(spec)

    def test_check_returns_result(self) -> None:
        validator = CompatibilityValidator(hunterx_version="7.0.0")
        result = validator.check(make_spec(version="1.0.0"), hunterx_version="7.0.0")
        assert isinstance(result, Success)
        assert result.value is True

    def test_check_malformed_version_fails(self) -> None:
        validator = CompatibilityValidator()
        result = validator.check(make_spec(version="1.0.0"), hunterx_version="oops")
        assert isinstance(result, Failure)
        assert isinstance(result.error, CompatibilityError)

    def test_status_strings(self) -> None:
        validator = CompatibilityValidator(hunterx_version="7.0.0")
        assert validator.status(make_spec(version="1.0.0"), hunterx_version="7.0.0") == "compatible"
        assert validator.status(make_spec(version="1.0.0"), hunterx_version="8.0.0") == "incompatible"
        deprecated = make_spec(deprecated=True, deprecation_reason="replaced")
        assert validator.status(deprecated) == "deprecated"
