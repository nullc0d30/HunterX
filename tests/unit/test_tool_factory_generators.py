# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Tool Integration Factory generators."""

from __future__ import annotations

import json

import yaml

from hunterx.domain.tool_factory import PackArtifactKind, ToolPackSpec
from hunterx.tools.factory.engine import ToolPackGeneratorEngine
from hunterx.tools.factory.generators import default_generators
from tests.unit.test_tool_factory_models import make_spec


def _generate(spec: ToolPackSpec):
    engine = ToolPackGeneratorEngine()
    return engine.generate_pack(spec)


class TestDefaultGenerators:
    def test_twenty_generators_in_order(self) -> None:
        generators = default_generators()
        assert len(generators) == 20
        names = [generator.name for generator in generators]
        assert names == [
            "boilerplate",
            "metadata",
            "version-metadata",
            "knowledge",
            "installation",
            "execution-rules",
            "mission-rules",
            "workflow-rules",
            "schemas",
            "parser",
            "normalizer",
            "database-mapping",
            "adapter",
            "error-handling",
            "logging",
            "telemetry",
            "tests",
            "documentation",
            "validation",
            "packaging",
        ]

    def test_every_generator_declares_name(self) -> None:
        for generator in default_generators():
            assert generator.name


class TestGeneratedFiles:
    def test_metadata(self) -> None:
        pack = _generate(make_spec())
        data = yaml.safe_load(pack.file("metadata/tool.yaml").content)
        assert data["tool_id"] == "nmap"
        assert data["vendor"] == "acme"
        assert data["execution_type"] == "binary"

    def test_version_metadata(self) -> None:
        pack = _generate(make_spec())
        version = yaml.safe_load(pack.file("metadata/version.yaml").content)
        assert version["semver"] == "1.0.0"
        assert version["major"] == 1
        compatibility = yaml.safe_load(pack.file("metadata/compatibility.yaml").content)
        assert compatibility["tool_id"] == "nmap"
        assert compatibility["entries"][0]["status"] == "compatible"

    def test_knowledge(self) -> None:
        pack = _generate(make_spec())
        knowledge = yaml.safe_load(pack.file("knowledge/knowledge_profile.yaml").content)
        assert knowledge["capabilities"] == ["port-scanning", "service-fingerprint"]
        capabilities = yaml.safe_load(pack.file("knowledge/capabilities.yaml").content)
        assert capabilities["capabilities"][0]["capability_id"] == "port-scanning"

    def test_installation(self) -> None:
        pack = _generate(make_spec())
        installation = yaml.safe_load(pack.file("install/installation.yaml").content)
        assert installation["binary"] == "nmap"
        health = yaml.safe_load(pack.file("install/health_check.yaml").content)
        assert health["expected_exit_code"] == 0

    def test_rules(self) -> None:
        pack = _generate(make_spec())
        execution = yaml.safe_load(pack.file("rules/execution.yaml").content)
        assert execution["sandbox"] is True
        assert execution["permissions"] == ["network"]
        mission = yaml.safe_load(pack.file("rules/mission.yaml").content)
        assert mission["mission_profiles"] == ["external-pentest"]
        workflow = yaml.safe_load(pack.file("rules/workflow.yaml").content)
        assert workflow["parallelism"] == "sequential"

    def test_schemas(self) -> None:
        pack = _generate(make_spec())
        input_schema = json.loads(pack.file("schemas/input.json").content)
        assert input_schema["type"] == "object"
        assert "target" in input_schema["required"]
        output_schema = json.loads(pack.file("schemas/output.json").content)
        assert "findings" in output_schema["properties"]

    def test_parser_and_normalizer(self) -> None:
        pack = _generate(make_spec())
        parser = pack.file("parsing/parser.py").content
        assert "def parse" in parser
        assert "class NmapParser" in parser
        normalizer = pack.file("parsing/normalizer.py").content
        assert "def normalize" in normalizer
        assert "class NmapNormalizer" in normalizer

    def test_adapter(self) -> None:
        pack = _generate(make_spec())
        adapter = pack.file("adapters/adapter.py").content
        assert "class NmapAdapter(ToolAdapter)" in adapter
        assert "descriptor" in adapter
        init_content = pack.file("adapters/__init__.py").content
        assert "NmapAdapter" in init_content

    def test_mapping(self) -> None:
        pack = _generate(make_spec())
        database = yaml.safe_load(pack.file("mapping/database.yaml").content)
        assert database["tool_id"] == "nmap"
        assert database["findings"]["dedup_key"] == ["target", "title"]
        evidence = yaml.safe_load(pack.file("mapping/evidence.yaml").content)
        assert "pcap" in evidence["evidence_capture"]

    def test_runtime(self) -> None:
        pack = _generate(make_spec())
        errors = pack.file("runtime/errors.py").content
        assert "NmapAdapterError" in errors
        logging_content = pack.file("runtime/logging.py").content
        assert "get_logger" in logging_content
        telemetry = pack.file("runtime/telemetry.py").content
        assert "class Telemetry" in telemetry

    def test_tests(self) -> None:
        pack = _generate(make_spec())
        unit = pack.file("tests/test_unit.py").content
        assert "test_descriptor_is_defined" in unit
        assert "NmapParser" in unit
        assert pack.file("tests/test_integration.py").content.strip()
        assert pack.file("tests/test_performance.py").content.strip()

    def test_documentation(self) -> None:
        pack = _generate(make_spec())
        developer = pack.file("docs/developer.md").content
        assert "Developer Guide" in developer
        assert "Nmap" in developer
        integration = pack.file("docs/integration.md").content
        assert "Integration Guide" in integration
        architecture = pack.file("docs/architecture.md").content
        assert "Architecture Guide" in architecture
        lifecycle = pack.file("docs/lifecycle.md").content
        assert "Lifecycle Guide" in lifecycle
        examples = pack.file("docs/examples.md").content
        assert "Examples" in examples

    def test_validation_and_packaging(self) -> None:
        pack = _generate(make_spec())
        rules = yaml.safe_load(pack.file("validation/rules.yaml").content)
        assert rules["tool_id"] == "nmap"
        assert len(rules["quality_gates"]) == 19
        pyproject = pack.file("pyproject.toml").content
        assert "hunterx-tool-pack-acme-nmap" in pyproject
        readme = pack.file("README.md").content
        assert "# Nmap" in readme
        assert pack.file("MANIFEST.in").content.strip()

    def test_manifest_file_generated(self) -> None:
        pack = _generate(make_spec())
        manifest = yaml.safe_load(pack.file("pack.yaml").content)
        assert manifest["pack_id"] == "nmap"
        assert manifest["vendor"] == "acme"
        assert manifest["generator_version"]
        assert "pack.yaml" in manifest["files"]

    def test_deprecated_pack_flags(self) -> None:
        pack = _generate(make_spec(deprecated=True, deprecation_reason="replaced by nmap2"))
        version = yaml.safe_load(pack.file("metadata/version.yaml").content)
        assert version["deprecation"]["deprecated"] is True
        compatibility = yaml.safe_load(pack.file("metadata/compatibility.yaml").content)
        assert compatibility["entries"][0]["status"] == "deprecated"


class TestFileKinds:
    def test_every_layout_file_has_kind(self) -> None:
        pack = _generate(make_spec())
        assert pack.count(PackArtifactKind.BOILERPLATE) == 4
        assert pack.count(PackArtifactKind.DOCUMENTATION) == 4
        assert pack.count(PackArtifactKind.EXAMPLES) == 1
        assert pack.count(PackArtifactKind.MANIFEST) == 1
        assert pack.count(PackArtifactKind.METADATA) == 1
        assert pack.count(PackArtifactKind.PACKAGING) == 3
