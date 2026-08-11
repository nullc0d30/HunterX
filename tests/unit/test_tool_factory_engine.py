# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Tool Integration Factory engine, facade and service."""

from __future__ import annotations

import pytest

from hunterx.application import ToolFactoryService
from hunterx.domain.exceptions import (
    GeneratorNotFoundError,
    PackValidationError,
    ToolPackNotFoundError,
)
from hunterx.domain.tool_factory import (
    GeneratedFile,
    IntegrationTemplate,
    PackArtifactKind,
    ToolPack,
)
from hunterx.shared.result import Failure, Success
from hunterx.tools.factory.api import ToolIntegrationFactory
from hunterx.tools.factory.engine import ToolPackGeneratorEngine
from tests.framework.tool_factory import (
    InMemoryPackTemplateRepository,
    InMemoryToolPackRepository,
    make_factory,
)
from tests.unit.test_tool_factory_models import make_spec


class TestEngine:
    def test_generate_returns_success(self) -> None:
        engine = ToolPackGeneratorEngine()
        result = engine.generate(make_spec())
        assert isinstance(result, Success)
        assert result.value.pack_id == "nmap"

    def test_generate_rejects_non_spec(self) -> None:
        engine = ToolPackGeneratorEngine()
        result = engine.generate("nmap")  # type: ignore[arg-type]
        assert isinstance(result, Failure)

    def test_generate_pack_raises_for_non_spec(self) -> None:
        engine = ToolPackGeneratorEngine()
        with pytest.raises(Exception):
            engine.generate_pack("nmap")  # type: ignore[arg-type]

    def test_generator_names_ordered(self) -> None:
        engine = ToolPackGeneratorEngine()
        assert engine.generator_names()[0] == "boilerplate"
        assert "adapter" in engine.generator_names()

    def test_generator_lookup(self) -> None:
        engine = ToolPackGeneratorEngine()
        assert engine.generator("adapter").name == "adapter"
        with pytest.raises(GeneratorNotFoundError):
            engine.generator("ghost")

    def test_generate_strict_passes_for_valid(self) -> None:
        engine = ToolPackGeneratorEngine()
        result = engine.generate_strict(make_spec())
        assert isinstance(result, Success)

    def test_generate_strict_fails_for_missing_gate(self) -> None:
        engine = ToolPackGeneratorEngine()
        pack = engine.generate_pack(make_spec())
        filtered = tuple(f for f in pack.files if f.path != "adapters/adapter.py")
        modified = ToolPack(
            pack_id=pack.pack_id,
            vendor=pack.vendor,
            name=pack.name,
            version=pack.version,
            files=filtered,
            manifest=pack.manifest,
        )
        from hunterx.tools.factory.validator import ToolPackValidator

        report = ToolPackValidator().validate(modified)
        assert not report.passed
        assert any(issue.code == "QUALITY_GATE" for issue in report.errors)

    def test_engine_persists_when_repository(self) -> None:
        repository = InMemoryToolPackRepository()
        engine = ToolPackGeneratorEngine(repository=repository)
        engine.generate(make_spec())
        assert repository.get("nmap") is not None

    def test_custom_generator_supported(self) -> None:
        from hunterx.tools.factory.generators.base import PackGenerator

        class ExtraGenerator(PackGenerator):
            name = "extra"
            description = "Adds an extra marker file."

            def generate(self, ctx):
                return [
                    GeneratedFile("runtime/extra.txt", "extra", PackArtifactKind.TELEMETRY),
                ]

        engine = ToolPackGeneratorEngine(generators=[ExtraGenerator()])
        pack = engine.generate_pack(make_spec())
        assert pack.has("runtime/extra.txt")
        assert engine.generator("extra").name == "extra"


class TestFacade:
    def test_generate(self) -> None:
        factory = make_factory()
        result = factory.generate(make_spec())
        assert isinstance(result, Success)

    def test_generate_and_validate(self) -> None:
        factory = make_factory()
        result = factory.generate_and_validate(make_spec())
        assert isinstance(result, Success)
        assert result.value.manifest.quality_gates_passed

    def test_accept_valid_pack(self) -> None:
        factory = make_factory()
        pack = factory.generate_pack(make_spec())
        assert factory.accept(pack) is True

    def test_assert_acceptable_raises(self) -> None:
        factory = make_factory()
        pack = factory.generate_pack(make_spec())
        broken = ToolPack(
            pack_id=pack.pack_id,
            vendor=pack.vendor,
            name=pack.name,
            version=pack.version,
            files=tuple(f for f in pack.files if f.path != "schemas/input.json"),
            manifest=pack.manifest,
        )
        with pytest.raises(PackValidationError):
            factory.assert_acceptable(broken)

    def test_layout_and_gates(self) -> None:
        factory = make_factory()
        assert "pack.yaml" in factory.pack_layout()
        assert len(factory.required_files()) >= 40
        assert len(factory.quality_gates()) == 19

    def test_template_register_and_list(self) -> None:
        factory = make_factory()
        template = IntegrationTemplate(template_id="custom", name="Custom")
        factory.register_template(template)
        assert any(t.template_id == "custom" for t in factory.list_templates())
        assert factory.template("custom") is template

    def test_compatibility_matrix(self) -> None:
        factory = make_factory()
        matrix = factory.compatibility_matrix(make_spec(hunterx_versions=("7.0.0",)))
        assert matrix.status_for("1.0.0", "7.0.0") == "compatible"

    def test_check_compatibility(self) -> None:
        factory = make_factory()
        result = factory.check_compatibility(make_spec())
        assert isinstance(result, Success)
        assert result.value is True

    def test_persistence(self) -> None:
        repository = InMemoryToolPackRepository()
        factory = make_factory(pack_repository=repository)
        factory.generate_pack(make_spec())
        assert factory.get("nmap") is not None
        assert factory.list_packs(vendor="acme")[0].pack_id == "nmap"
        assert factory.list_packs(vendor="other") == []
        factory.delete("nmap")
        assert factory.get("nmap") is None

    def test_delete_missing_raises(self) -> None:
        repository = InMemoryToolPackRepository()
        factory = make_factory(pack_repository=repository)
        with pytest.raises(ToolPackNotFoundError):
            factory.delete("ghost")

    def test_get_returns_none_without_repository(self) -> None:
        factory = ToolIntegrationFactory()
        assert factory.get("nmap") is None
        assert factory.list_packs() == []

    def test_save_without_repository_raises(self) -> None:
        factory = ToolIntegrationFactory()
        pack = factory.generate_pack(make_spec())
        with pytest.raises(ToolPackNotFoundError):
            factory.save(pack)

    def test_template_persistence(self) -> None:
        repository = InMemoryPackTemplateRepository()
        factory = make_factory(template_repository=repository)
        template = IntegrationTemplate(template_id="custom", name="Custom")
        factory.register_template(template)
        assert repository.get("custom") is not None

    def test_register_unknown_template_fetched_from_repo(self) -> None:
        repository = InMemoryPackTemplateRepository()
        factory = make_factory(template_repository=repository)
        assert factory.template("standard").template_id == "standard"


class TestWriteToDisk:
    def test_write_to_creates_all_files(self, tmp_path) -> None:
        factory = make_factory()
        pack = factory.generate_pack(make_spec())
        written = pack.write_to(str(tmp_path))
        assert len(written) == len(pack.files)
        assert (tmp_path / "acme" / "nmap" / "pack.yaml").exists()
        assert (tmp_path / "acme" / "nmap" / "adapters" / "adapter.py").exists()


class TestService:
    def test_generate(self) -> None:
        service = ToolFactoryService()
        result = service.generate(make_spec())
        assert isinstance(result, Success)

    def test_generate_and_validate(self) -> None:
        service = ToolFactoryService()
        result = service.generate_and_validate(make_spec())
        assert isinstance(result, Success)

    def test_validate(self) -> None:
        service = ToolFactoryService()
        pack = service.factory.generate_pack(make_spec())
        assert service.validate(pack).passed

    def test_accept(self) -> None:
        service = ToolFactoryService()
        pack = service.factory.generate_pack(make_spec())
        assert service.accept(pack)

    def test_require_acceptable(self) -> None:
        service = ToolFactoryService()
        pack = service.factory.generate_pack(make_spec())
        assert service.require_acceptable(pack).pack_id == "nmap"

    def test_layout_and_gates(self) -> None:
        service = ToolFactoryService()
        assert len(service.pack_layout()) == len(service.required_files())
        assert service.quality_gates()

    def test_compatibility_matrix(self) -> None:
        service = ToolFactoryService()
        matrix = service.compatibility_matrix(make_spec())
        assert matrix.tool_id == "nmap"

    def test_list_and_get_pack(self) -> None:
        service = ToolFactoryService(pack_repository=InMemoryToolPackRepository())
        service.factory.generate_pack(make_spec())
        assert service.list_packs()[0].pack_id == "nmap"
        assert service.get_pack("nmap").pack_id == "nmap"

    def test_get_missing_raises(self) -> None:
        service = ToolFactoryService(pack_repository=InMemoryToolPackRepository())
        with pytest.raises(ToolPackNotFoundError):
            service.get_pack("ghost")

    def test_delete_pack(self) -> None:
        service = ToolFactoryService(pack_repository=InMemoryToolPackRepository())
        service.factory.generate_pack(make_spec())
        service.delete_pack("nmap")
        assert service.list_packs() == []

    def test_list_templates(self) -> None:
        service = ToolFactoryService()
        assert any(t.template_id == "standard" for t in service.list_templates())
