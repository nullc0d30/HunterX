# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool Integration Pack validator.

Validates generated packs for naming, required files, metadata completeness,
parser/normalizer availability, documentation completeness, test
availability, mission compatibility, schema compatibility and the quality
gates. A pack with any error-level issue is rejected.
"""

from __future__ import annotations

import json
import re

import yaml

from hunterx.domain.tool_factory import PackValidationReport, SemanticVersion, ToolPack
from hunterx.tools.factory.layout import PACK_LAYOUT, QUALITY_GATES

_PACK_ID = re.compile(r"[a-z0-9][a-z0-9-]*")
_VENDOR_ID = re.compile(r"[a-z0-9][a-z0-9-]*")
_FILE_PATH = re.compile(r"^[A-Za-z0-9/._-]+$")

_METADATA_FILE = "metadata/tool.yaml"
_VERSION_FILE = "metadata/version.yaml"
_KNOWLEDGE_FILE = "knowledge/knowledge_profile.yaml"
_MISSION_RULES_FILE = "rules/mission.yaml"
_INPUT_SCHEMA_FILE = "schemas/input.json"
_OUTPUT_SCHEMA_FILE = "schemas/output.json"

_DOCS = ("docs/developer.md", "docs/integration.md", "docs/architecture.md", "docs/lifecycle.md", "docs/examples.md")
_TESTS = ("tests/test_unit.py", "tests/test_integration.py", "tests/test_performance.py")


class ToolPackValidator:
    """Validates a generated :class:`ToolPack` against the standard layout."""

    def __init__(
        self,
        *,
        layout: dict[str, tuple[object, object]] | None = None,
        quality_gates: list[str] | None = None,
    ) -> None:
        self._layout = {path: kind for path, (kind, _purpose) in (layout or PACK_LAYOUT).items()}
        self._gates = list(quality_gates if quality_gates is not None else QUALITY_GATES)

    def validate(self, pack: ToolPack) -> PackValidationReport:
        """Validate ``pack``, returning the full validation report."""
        report = PackValidationReport(pack.pack_id)
        self._check_naming(pack, report)
        self._check_required_files(pack, report)
        self._check_metadata(pack, report)
        self._check_parser_normalizer(pack, report)
        self._check_documentation(pack, report)
        self._check_tests(pack, report)
        self._check_mission_compatibility(pack, report)
        self._check_schema_compatibility(pack, report)
        self._check_quality_gates(pack, report)
        return report

    # -- checks -------------------------------------------------------------

    def _check_naming(self, pack: ToolPack, report: PackValidationReport) -> None:
        if not _PACK_ID.fullmatch(pack.pack_id):
            report.add_error("NAMING_PACK_ID", f"pack_id '{pack.pack_id}' must match [a-z0-9][a-z0-9-]*.")
        if not _VENDOR_ID.fullmatch(pack.vendor):
            report.add_error("NAMING_VENDOR", f"vendor '{pack.vendor}' must match [a-z0-9][a-z0-9-]*.")
        for path in pack.paths():
            if not _FILE_PATH.fullmatch(path):
                report.add_error("NAMING_PATH", f"file path '{path}' must match [a-z0-9/._-]+.", path=path)
        entrypoint = pack.manifest.entrypoint
        if entrypoint and ":" not in entrypoint:
            report.add_error("NAMING_ENTRYPOINT", "manifest entrypoint must use module.path:ClassName form.")

    def _check_required_files(self, pack: ToolPack, report: PackValidationReport) -> None:
        for path in self._layout:
            if not pack.has(path):
                report.add_error("REQUIRED_FILE", f"required file '{path}' is missing.", path=path)

    def _check_metadata(self, pack: ToolPack, report: PackValidationReport) -> None:
        metadata = self._load_yaml(pack, _METADATA_FILE, report, "METADATA_PARSE")
        if metadata is not None:
            for key in ("tool_id", "vendor", "version"):
                if not metadata.get(key):
                    report.add_error("METADATA_MISSING", f"metadata/tool.yaml must declare '{key}'.", path=_METADATA_FILE)
            if metadata.get("tool_id") != pack.pack_id:
                report.add_error("METADATA_MISMATCH", "metadata tool_id must match the pack_id.", path=_METADATA_FILE)
        version = self._load_yaml(pack, _VERSION_FILE, report, "VERSION_PARSE")
        if version is not None:
            semver = version.get("semver")
            try:
                SemanticVersion.parse(str(semver))
            except (TypeError, ValueError):
                report.add_error("VERSION_INVALID", f"version '{semver}' is not valid semantic versioning.", path=_VERSION_FILE)
        knowledge = self._load_yaml(pack, _KNOWLEDGE_FILE, report, "KNOWLEDGE_PARSE")
        if knowledge is not None:
            for key in ("tool_id", "capabilities", "cli_binary"):
                if not knowledge.get(key):
                    report.add_error("KNOWLEDGE_MISSING", f"knowledge profile must declare '{key}'.", path=_KNOWLEDGE_FILE)

    def _check_parser_normalizer(self, pack: ToolPack, report: PackValidationReport) -> None:
        parser = pack.file("parsing/parser.py")
        if parser is None:
            report.add_error("PARSER_MISSING", "parser file is missing.", path="parsing/parser.py")
        elif "def parse" not in parser.content:
            report.add_error("PARSER_CONTRACT", "parser must implement a 'parse' method.", path="parsing/parser.py")
        normalizer = pack.file("parsing/normalizer.py")
        if normalizer is None:
            report.add_error("NORMALIZER_MISSING", "normalizer file is missing.", path="parsing/normalizer.py")
        elif "def normalize" not in normalizer.content:
            report.add_error("NORMALIZER_CONTRACT", "normalizer must implement a 'normalize' method.", path="parsing/normalizer.py")

    def _check_documentation(self, pack: ToolPack, report: PackValidationReport) -> None:
        for path in _DOCS:
            file = pack.file(path)
            if file is None or not file.content.strip():
                report.add_error("DOCS_MISSING", f"documentation file '{path}' is missing or empty.", path=path)

    def _check_tests(self, pack: ToolPack, report: PackValidationReport) -> None:
        for path in _TESTS:
            file = pack.file(path)
            if file is None or not file.content.strip():
                report.add_error("TESTS_MISSING", f"test file '{path}' is missing or empty.", path=path)

    def _check_mission_compatibility(self, pack: ToolPack, report: PackValidationReport) -> None:
        rules = self._load_yaml(pack, _MISSION_RULES_FILE, report, "MISSION_RULES_PARSE")
        if rules is not None:
            profiles = rules.get("mission_profiles") or []
            if not isinstance(profiles, list):
                report.add_error("MISSION_RULES_INVALID", "mission rules must declare 'mission_profiles'.", path=_MISSION_RULES_FILE)
            elif not profiles and pack.manifest.capabilities:
                report.add_warning(
                    "MISSION_RULES_EMPTY",
                    "mission rules declare no mission profiles for a pack with capabilities.",
                    path=_MISSION_RULES_FILE,
                )

    def _check_schema_compatibility(self, pack: ToolPack, report: PackValidationReport) -> None:
        for path, kind in ((_INPUT_SCHEMA_FILE, "input"), (_OUTPUT_SCHEMA_FILE, "output")):
            file = pack.file(path)
            if file is None:
                report.add_error("SCHEMA_MISSING", f"{kind} schema file is missing.", path=path)
                continue
            try:
                schema = json.loads(file.content)
            except json.JSONDecodeError:
                report.add_error("SCHEMA_PARSE", f"{kind} schema is not valid JSON.", path=path)
                continue
            if schema.get("type") != "object":
                report.add_error("SCHEMA_SHAPE", f"{kind} schema must be a JSON object schema.", path=path)
            if kind == "output" and "findings" not in schema.get("properties", {}):
                report.add_error("SCHEMA_OUTPUT", "output schema must declare a 'findings' property.", path=path)

    def _check_quality_gates(self, pack: ToolPack, report: PackValidationReport) -> None:
        for path in self._gates:
            if not pack.has(path):
                report.add_error("QUALITY_GATE", f"quality gate file '{path}' is missing.", path=path)

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def _load_yaml(pack: ToolPack, path: str, report: PackValidationReport, code: str) -> dict[str, object] | None:
        file = pack.file(path)
        if file is None:
            report.add_error(code, f"required file '{path}' is missing.", path=path)
            return None
        try:
            data = yaml.safe_load(file.content)
        except yaml.YAMLError:
            report.add_error(code, f"file '{path}' is not valid YAML.", path=path)
            return None
        if not isinstance(data, dict):
            report.add_error(code, f"file '{path}' must contain a YAML mapping.", path=path)
            return None
        return data
