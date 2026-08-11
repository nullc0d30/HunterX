# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Tool Integration Factory domain models."""

from __future__ import annotations

import pytest

from hunterx.domain.exceptions import (
    InvalidToolPackSpecError,
    TemplateRenderError,
)
from hunterx.domain.tool_factory import (
    GeneratedFile,
    PackArtifactKind,
    SemanticVersion,
    ToolPack,
    ToolPackManifest,
    ToolPackSpec,
    ValidationIssue,
    ValidationSeverity,
    manifest_to_yaml,
    new_pack_id,
    render_yaml,
)
from hunterx.domain.tool_intelligence import ToolExecutionType


def make_spec(**overrides: object) -> ToolPackSpec:
    base: dict[str, object] = {
        "pack_id": "nmap",
        "vendor": "acme",
        "tool_name": "nmap",
        "display_name": "Nmap",
        "description": "Network mapper",
        "capabilities": ("port-scanning", "service-fingerprint"),
        "targets": ("host", "range"),
        "permissions": ("network",),
        "mission_profiles": ("external-pentest",),
    }
    base.update(overrides)
    return ToolPackSpec(**base)  # type: ignore[arg-type]


class TestSemanticVersion:
    def test_parse_full_version(self) -> None:
        version = SemanticVersion.parse("1.2.3-rc.1+build.5")
        assert (version.major, version.minor, version.patch) == (1, 2, 3)
        assert version.prerelease == "rc.1"
        assert version.build == "build.5"

    def test_parse_rejects_malformed(self) -> None:
        for value in ("", "1.2", "1.2.3.4", "a.b.c", "1.2.-3"):
            with pytest.raises(ValueError):
                SemanticVersion.parse(value)

    def test_ordering(self) -> None:
        assert SemanticVersion.parse("1.2.3") > SemanticVersion.parse("1.2.2")
        assert SemanticVersion.parse("1.2.3-rc.1") < SemanticVersion.parse("1.2.3")
        assert SemanticVersion.parse("2.0.0") > SemanticVersion.parse("1.9.9")

    def test_satisfies_operators(self) -> None:
        version = SemanticVersion.parse("1.5.0")
        assert version.satisfies(">=1.0.0")
        assert version.satisfies("<2.0.0")
        assert version.satisfies("~=1.5.0")
        assert not version.satisfies("~=1.4.0")
        assert version.satisfies("^1.0.0")
        assert not version.satisfies("^2.0.0")
        assert version.satisfies("*")

    def test_satisfies_invalid_constraint(self) -> None:
        with pytest.raises(TemplateRenderError):
            SemanticVersion.parse("1.5.0").satisfies(">=not-a-version")

    def test_compatibility_rule(self) -> None:
        assert SemanticVersion.parse("2.1.0").is_compatible_with(SemanticVersion.parse("2.9.9"))
        assert not SemanticVersion.parse("2.1.0").is_compatible_with(SemanticVersion.parse("3.0.0"))
        assert SemanticVersion.parse("0.2.1").is_compatible_with(SemanticVersion.parse("0.2.9"))
        assert not SemanticVersion.parse("0.2.1").is_compatible_with(SemanticVersion.parse("0.3.0"))

    def test_bumps(self) -> None:
        version = SemanticVersion.parse("1.2.3")
        assert str(version.bump_major()) == "2.0.0"
        assert str(version.bump_minor()) == "1.3.0"
        assert str(version.bump_patch()) == "1.2.4"


class TestToolPackSpec:
    def test_valid_spec(self) -> None:
        spec = make_spec()
        assert spec.entrypoint.endswith(":NmapAdapter")
        assert spec.adapter_class_name == "NmapAdapter"
        assert spec.root_path() == "acme/nmap"

    def test_rejects_bad_pack_id(self) -> None:
        with pytest.raises(InvalidToolPackSpecError):
            make_spec(pack_id="Nmap Scan")

    def test_rejects_bad_vendor(self) -> None:
        with pytest.raises(InvalidToolPackSpecError):
            make_spec(vendor="ACME Corp")

    def test_rejects_empty_tool_name(self) -> None:
        with pytest.raises(InvalidToolPackSpecError):
            make_spec(tool_name="  ")

    def test_rejects_bad_version(self) -> None:
        with pytest.raises(InvalidToolPackSpecError):
            make_spec(version="latest")

    def test_rejects_unknown_permission(self) -> None:
        with pytest.raises(InvalidToolPackSpecError):
            make_spec(permissions=("database",))

    def test_rejects_bad_output_format(self) -> None:
        with pytest.raises(InvalidToolPackSpecError):
            make_spec(output_format="binary")

    def test_rejects_bad_parser_strategy(self) -> None:
        with pytest.raises(InvalidToolPackSpecError):
            make_spec(parser_strategy="regex")

    def test_deprecated_requires_reason(self) -> None:
        with pytest.raises(InvalidToolPackSpecError):
            make_spec(deprecated=True, deprecation_reason="")

    def test_bad_capability(self) -> None:
        with pytest.raises(InvalidToolPackSpecError):
            make_spec(capabilities=("port scan",))


class TestGeneratedFile:
    def test_normalizes_separators(self) -> None:
        file = GeneratedFile("adapters\\adapter.py", "x", PackArtifactKind.ADAPTER)
        assert file.path == "adapters/adapter.py"

    def test_rejects_absolute_path(self) -> None:
        with pytest.raises(InvalidToolPackSpecError):
            GeneratedFile("/etc/passwd", "x")

    def test_rejects_traversal(self) -> None:
        with pytest.raises(InvalidToolPackSpecError):
            GeneratedFile("../../secret", "x")


class TestToolPack:
    def test_duplicate_paths_rejected(self) -> None:
        manifest = ToolPackManifest(pack_id="nmap", vendor="acme", name="Nmap", version="1.0.0")
        files = (GeneratedFile("a.txt", "x"), GeneratedFile("a.txt", "y"))
        with pytest.raises(InvalidToolPackSpecError):
            ToolPack("nmap", "acme", "Nmap", "1.0.0", files, manifest)

    def test_manifest_pack_id_mismatch_rejected(self) -> None:
        manifest = ToolPackManifest(pack_id="other", vendor="acme", name="Nmap", version="1.0.0")
        files = (GeneratedFile("a.txt", "x"),)
        with pytest.raises(InvalidToolPackSpecError):
            ToolPack("nmap", "acme", "Nmap", "1.0.0", files, manifest)

    def test_file_lookup(self) -> None:
        manifest = ToolPackManifest(pack_id="nmap", vendor="acme", name="Nmap", version="1.0.0")
        files = (GeneratedFile("a.txt", "x"),)
        pack = ToolPack("nmap", "acme", "Nmap", "1.0.0", files, manifest)
        assert pack.file("a.txt") is files[0]
        assert pack.file("missing.txt") is None
        assert pack.has("a.txt")
        assert pack.count(PackArtifactKind.BOILERPLATE) == 1


class TestValidationReport:
    def test_passed_with_no_errors(self) -> None:
        issue = ValidationIssue(ValidationSeverity.WARNING, "W1", "warn")
        assert not any(i.severity is ValidationSeverity.ERROR for i in [issue])


class TestYamlRendering:
    def test_manifest_to_yaml_roundtrip_keys(self) -> None:
        manifest = ToolPackManifest(
            pack_id="nmap",
            vendor="acme",
            name="Nmap",
            version="1.0.0",
            capabilities=("port-scanning",),
            targets=("host",),
        )
        yaml_text = manifest_to_yaml(manifest)
        assert "pack_id: nmap" in yaml_text
        assert "version: 1.0.0" in yaml_text
        assert "'port-scanning'" in yaml_text

    def test_render_yaml_quotes_special_scalars(self) -> None:
        assert render_yaml({"desc": "needs: quoting"}) == "desc: 'needs: quoting'"
        assert render_yaml({"flag": True}) == "flag: true"
        assert render_yaml({"nothing": None}) == "nothing: null"

    def test_new_pack_id_is_unique(self) -> None:
        assert new_pack_id() != new_pack_id()


class TestExecutionTypeDefaults:
    def test_default_execution_type(self) -> None:
        spec = make_spec()
        assert spec.execution_type is ToolExecutionType.BINARY
