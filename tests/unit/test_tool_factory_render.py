# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the factory renderer, layout and template store."""

from __future__ import annotations

import pytest

from hunterx.domain.exceptions import TemplateNotFoundError, TemplateRenderError
from hunterx.domain.tool_factory import IntegrationTemplate
from hunterx.tools.factory.layout import (
    GENERATOR_VERSION,
    HUNTERX_VERSION,
    PACK_LAYOUT,
    PACK_STRUCTURE_VERSION,
    QUALITY_GATES,
    SDK_VERSION,
    quality_gate_files,
    required_files,
)
from hunterx.tools.factory.render import TemplateRenderer, render_context
from hunterx.tools.factory.templates import (
    BUILTIN_FILES,
    BUILTIN_TEMPLATE,
    PackTemplateStore,
)
from tests.unit.test_tool_factory_models import make_spec


class TestTemplateRenderer:
    def test_renders_placeholders(self) -> None:
        renderer = TemplateRenderer()
        assert renderer.render("hello ${name}", {"name": "world"}) == "hello world"

    def test_no_placeholder_passthrough(self) -> None:
        renderer = TemplateRenderer()
        assert renderer.render("plain text", {}) == "plain text"

    def test_missing_variable_raises(self) -> None:
        renderer = TemplateRenderer()
        with pytest.raises(TemplateRenderError):
            renderer.render("${missing}", {})

    def test_escaped_dollar(self) -> None:
        renderer = TemplateRenderer()
        assert renderer.render("$${literal}", {"literal": "x"}) == "${literal}"


class TestRenderContext:
    def test_contains_spec_fields(self) -> None:
        context = render_context(make_spec())
        assert context["pack_id"] == "nmap"
        assert context["vendor"] == "acme"
        assert context["generator_version"] == GENERATOR_VERSION
        assert context["hunterx_version"] == HUNTERX_VERSION
        assert context["sdk_version"] == SDK_VERSION
        assert context["structure_version"] == PACK_STRUCTURE_VERSION
        assert context["copyright"]

    def test_derived_names(self) -> None:
        context = render_context(make_spec())
        assert context["adapter_class_name"] == "NmapAdapter"
        assert context["parser_class_name"] == "NmapParser"
        assert context["normalizer_class_name"] == "NmapNormalizer"

    def test_display_name_fallback(self) -> None:
        context = render_context(make_spec(display_name="", tool_name="open-vas"))
        assert context["display_name"] == "Open Vas"

    def test_lists_joined(self) -> None:
        context = render_context(make_spec())
        assert '"port-scanning"' in context["capabilities_list"]
        assert '"host"' in context["targets_list"]


class TestLayout:
    def test_layout_has_all_directories(self) -> None:
        assert "pack.yaml" in PACK_LAYOUT
        assert "metadata/tool.yaml" in PACK_LAYOUT
        assert "adapters/adapter.py" in PACK_LAYOUT
        assert "docs/examples.md" in PACK_LAYOUT

    def test_required_files_matches_layout(self) -> None:
        assert required_files() == list(PACK_LAYOUT)

    def test_quality_gates_subset(self) -> None:
        gates = set(quality_gate_files())
        assert gates <= set(PACK_LAYOUT)
        assert len(gates) == len(QUALITY_GATES)

    def test_structure_version(self) -> None:
        assert PACK_STRUCTURE_VERSION == "1.0"


class TestPackTemplateStore:
    def test_get_builtin(self) -> None:
        store = PackTemplateStore()
        template = store.get("standard")
        assert template is BUILTIN_TEMPLATE

    def test_get_unknown_raises(self) -> None:
        store = PackTemplateStore()
        with pytest.raises(TemplateNotFoundError):
            store.get("ghost")

    def test_register_override(self) -> None:
        store = PackTemplateStore()
        override = IntegrationTemplate(
            template_id="custom",
            name="Custom",
            files={"README.md": "custom ${pack_id} readme"},
        )
        store.register(override)
        resolved = store.resolve("custom")
        assert resolved["README.md"] == "custom ${pack_id} readme"
        assert "adapters/adapter.py" in resolved

    def test_resolve_default_is_builtin(self) -> None:
        store = PackTemplateStore()
        resolved = store.resolve(None)
        assert resolved == BUILTIN_FILES

    def test_list_contains_builtin(self) -> None:
        store = PackTemplateStore()
        assert any(template.template_id == "standard" for template in store.list())


class TestBuiltinFiles:
    def test_every_file_participates(self) -> None:
        assert BUILTIN_FILES
        assert "adapters/adapter.py" in BUILTIN_FILES
        assert "pyproject.toml" in BUILTIN_FILES

    def test_templates_render_clean(self) -> None:
        renderer = TemplateRenderer()
        context = render_context(make_spec())
        for path, content in BUILTIN_FILES.items():
            rendered = renderer.render(content, context)
            assert rendered, path
