# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for documentation validation."""

from __future__ import annotations

import pathlib

from hunterx.architecture.docs import validate_documentation
from hunterx.architecture.policy import default_policy
from hunterx.architecture.violations import ViolationCodes


def _modules(tmp_path: pathlib.Path) -> dict[str, pathlib.Path]:
    return {
        "hunterx.mod": tmp_path / "mod.py",
        "hunterx.pkg": tmp_path / "pkg" / "__init__.py",
    }


def test_missing_docstring_is_error(tmp_path: pathlib.Path) -> None:
    modules = _modules(tmp_path)
    modules["hunterx.mod"].write_text("class A:\n    pass\n", encoding="utf-8")
    modules["hunterx.pkg"].parent.mkdir(parents=True, exist_ok=True)
    modules["hunterx.pkg"].write_text('"""Pkg doc."""\n', encoding="utf-8")
    violations = validate_documentation(modules, default_policy().doc_requirements)
    errors = [v for v in violations if v.code == ViolationCodes.DOCSTRING_MISSING]
    assert len(errors) == 1
    assert errors[0].module == "hunterx.mod"
    assert errors[0].severity == "error"


def test_package_sections_recommended(tmp_path: pathlib.Path) -> None:
    modules = _modules(tmp_path)
    modules["hunterx.mod"].write_text('"""A module."""\n', encoding="utf-8")
    modules["hunterx.pkg"].parent.mkdir(parents=True, exist_ok=True)
    modules["hunterx.pkg"].write_text(
        '"""Pkg.\n\nResponsibilities:\n    Does things.\n\nDependencies:\n    stdlib.\n"""\n',
        encoding="utf-8",
    )
    violations = validate_documentation(modules, default_policy().doc_requirements)
    section_warnings = [v for v in violations if v.code == ViolationCodes.DOC_SECTION_MISSING]
    # non-package modules are not checked for sections
    assert all(v.module == "hunterx.pkg" for v in section_warnings)
    missing = section_warnings[0].details["missing"] if section_warnings else []
    assert "extension points" in missing
