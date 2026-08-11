# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Tool Integration Pack validator."""

from __future__ import annotations

from hunterx.domain.tool_factory import GeneratedFile, ToolPack, ToolPackManifest
from hunterx.tools.factory.engine import ToolPackGeneratorEngine
from hunterx.tools.factory.validator import ToolPackValidator
from tests.unit.test_tool_factory_models import make_spec


def _valid_pack():
    engine = ToolPackGeneratorEngine()
    return engine.generate_pack(make_spec())


class TestValidPack:
    def test_passes_all_checks(self) -> None:
        report = ToolPackValidator().validate(_valid_pack())
        assert report.passed
        assert not report.errors

    def test_generated_pack_report_is_attached(self) -> None:
        pack = _valid_pack()
        assert pack.validation is not None
        assert pack.validation.passed
        assert pack.manifest.quality_gates_passed


class TestNaming:
    def test_invalid_pack_id(self) -> None:
        pack = _valid_pack()
        manifest = ToolPackManifest(
            pack_id="Bad Pack!",
            vendor=pack.vendor,
            name=pack.name,
            version=pack.version,
            entrypoint=pack.manifest.entrypoint,
        )
        modified = ToolPack(
            pack_id="Bad Pack!",
            vendor=pack.vendor,
            name=pack.name,
            version=pack.version,
            files=pack.files,
            manifest=manifest,
        )
        report = ToolPackValidator().validate(modified)
        assert any(issue.code == "NAMING_PACK_ID" for issue in report.errors)

    def test_bad_path(self) -> None:
        pack = _valid_pack()
        bad = GeneratedFile(path="runtime/Extra+File.py", content="x")
        modified = ToolPack(
            pack_id=pack.pack_id,
            vendor=pack.vendor,
            name=pack.name,
            version=pack.version,
            files=(*pack.files, bad),
            manifest=pack.manifest,
        )
        report = ToolPackValidator().validate(modified)
        assert any(issue.code == "NAMING_PATH" for issue in report.errors)

    def test_entrypoint_requires_colon(self) -> None:
        pack = _valid_pack()
        manifest = ToolPackManifest(
            pack_id=pack.pack_id,
            vendor=pack.vendor,
            name=pack.name,
            version=pack.version,
            entrypoint="nmap",
        )
        modified = ToolPack(
            pack_id=pack.pack_id,
            vendor=pack.vendor,
            name=pack.name,
            version=pack.version,
            files=pack.files,
            manifest=manifest,
        )
        report = ToolPackValidator().validate(modified)
        assert any(issue.code == "NAMING_ENTRYPOINT" for issue in report.errors)


class TestRequiredFiles:
    def test_missing_required_file(self) -> None:
        pack = _valid_pack()
        filtered = tuple(f for f in pack.files if f.path != "metadata/tool.yaml")
        modified = ToolPack(
            pack_id=pack.pack_id,
            vendor=pack.vendor,
            name=pack.name,
            version=pack.version,
            files=filtered,
            manifest=pack.manifest,
        )
        report = ToolPackValidator().validate(modified)
        assert any(issue.code == "REQUIRED_FILE" for issue in report.errors)

    def test_missing_quality_gate(self) -> None:
        pack = _valid_pack()
        filtered = tuple(f for f in pack.files if f.path != "tests/test_unit.py")
        modified = ToolPack(
            pack_id=pack.pack_id,
            vendor=pack.vendor,
            name=pack.name,
            version=pack.version,
            files=filtered,
            manifest=pack.manifest,
        )
        report = ToolPackValidator().validate(modified)
        assert any(issue.code == "QUALITY_GATE" for issue in report.errors)


class TestContentChecks:
    def test_parser_contract(self) -> None:
        pack = _valid_pack()
        files = tuple(
            GeneratedFile(f.path, f.content.replace("def parse", "def x", 1), f.kind) if f.path == "parsing/parser.py" else f
            for f in pack.files
        )
        modified = ToolPack(
            pack_id=pack.pack_id,
            vendor=pack.vendor,
            name=pack.name,
            version=pack.version,
            files=files,
            manifest=pack.manifest,
        )
        report = ToolPackValidator().validate(modified)
        assert any(issue.code == "PARSER_CONTRACT" for issue in report.errors)

    def test_empty_docs(self) -> None:
        pack = _valid_pack()
        files = tuple(
            GeneratedFile(f.path, "", f.kind) if f.path == "docs/developer.md" else f for f in pack.files
        )
        modified = ToolPack(
            pack_id=pack.pack_id,
            vendor=pack.vendor,
            name=pack.name,
            version=pack.version,
            files=files,
            manifest=pack.manifest,
        )
        report = ToolPackValidator().validate(modified)
        assert any(issue.code == "DOCS_MISSING" for issue in report.errors)

    def test_bad_metadata_yaml(self) -> None:
        pack = _valid_pack()
        files = tuple(
            GeneratedFile(f.path, "not: [valid: yaml", f.kind) if f.path == "metadata/tool.yaml" else f
            for f in pack.files
        )
        modified = ToolPack(
            pack_id=pack.pack_id,
            vendor=pack.vendor,
            name=pack.name,
            version=pack.version,
            files=files,
            manifest=pack.manifest,
        )
        report = ToolPackValidator().validate(modified)
        assert any(issue.code == "METADATA_PARSE" for issue in report.errors)

    def test_bad_output_schema(self) -> None:
        pack = _valid_pack()
        files = tuple(
            GeneratedFile(f.path, '{"type": "array"}', f.kind) if f.path == "schemas/output.json" else f
            for f in pack.files
        )
        modified = ToolPack(
            pack_id=pack.pack_id,
            vendor=pack.vendor,
            name=pack.name,
            version=pack.version,
            files=files,
            manifest=pack.manifest,
        )
        report = ToolPackValidator().validate(modified)
        assert any(issue.code == "SCHEMA_OUTPUT" for issue in report.errors)

    def test_version_parse_failure(self) -> None:
        pack = _valid_pack()
        files = tuple(
            GeneratedFile(f.path, f.content.replace("semver: 1.0.0", "semver: nope", 1), f.kind)
            if f.path == "metadata/version.yaml"
            else f
            for f in pack.files
        )
        modified = ToolPack(
            pack_id=pack.pack_id,
            vendor=pack.vendor,
            name=pack.name,
            version=pack.version,
            files=files,
            manifest=pack.manifest,
        )
        report = ToolPackValidator().validate(modified)
        assert any(issue.code == "VERSION_INVALID" for issue in report.errors)


class TestWarnings:
    def test_empty_mission_profiles_warns(self) -> None:
        engine = ToolPackGeneratorEngine()
        pack = engine.generate_pack(make_spec(mission_profiles=()))
        report = ToolPackValidator().validate(pack)
        assert any(issue.code == "MISSION_RULES_EMPTY" for issue in report.warnings)
