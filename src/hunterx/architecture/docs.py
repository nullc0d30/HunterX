# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Documentation validation.

Every public module must carry a module docstring describing its purpose. The
Bible's documentation standard additionally recommends Responsibilities,
Dependencies and Extension points sections; missing recommended sections are
reported as warnings so reports surface them without failing CI.
"""

from __future__ import annotations

import ast
import pathlib
import re
from dataclasses import dataclass

from hunterx.architecture.policy import DocRequirement
from hunterx.architecture.violations import Violation, ViolationCodes


@dataclass(slots=True)
class _ModuleDoc:
    """Parsed docstring facts for one module."""

    has_docstring: bool
    text: str


def _extract_docstring(path: pathlib.Path) -> _ModuleDoc:
    """Return whether ``path`` has a module docstring and its text."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, OSError):
        return _ModuleDoc(has_docstring=False, text="")
    body = getattr(tree, "body", [])
    if not body:
        return _ModuleDoc(has_docstring=False, text="")
    first = body[0]
    if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
        return _ModuleDoc(has_docstring=True, text=first.value.value)
    return _ModuleDoc(has_docstring=False, text="")


_SECTION_PATTERNS = {
    "responsibilities": re.compile(r"responsibilit|responsible for", re.IGNORECASE),
    "dependencies": re.compile(r"dependenc|depends on", re.IGNORECASE),
    "extension points": re.compile(r"extension|extendable|plugin|adapter", re.IGNORECASE),
}


def _find_sections(text: str, keywords: dict[str, tuple[str, ...]]) -> set[str]:
    """Return the recommended sections present in ``text``."""
    found: set[str] = set()
    lowered = text.lower()
    for section, words in keywords.items():
        for word in words:
            if word in lowered:
                found.add(section)
                break
    return found


def validate_documentation(
    modules: dict[str, pathlib.Path],
    requirements: DocRequirement,
) -> list[Violation]:
    """Validate module docstrings for every module path.

    Every module must carry a purpose docstring (error). The recommended
    Responsibilities / Dependencies / Extension points sections are checked
    for package ``__init__.py`` modules only, which are the public module
    reference docs developers read first (warnings).

    Args:
        modules: dotted module name to file path mapping.
        requirements: the doc validation rules from the policy.

    Returns:
        A list of violations (missing docstring = error, missing recommended
        sections = warning).

    """
    violations: list[Violation] = []
    for module, path in sorted(modules.items()):
        doc = _extract_docstring(path)
        if not doc.has_docstring:
            violations.append(
                Violation(
                    code=ViolationCodes.DOCSTRING_MISSING,
                    severity="error",
                    message=f"Module '{module}' has no module docstring (Purpose).",
                    remediation=(
                        "Add a module docstring describing the module's purpose before "
                        "any other statement."
                    ),
                    module=module,
                )
            )
            continue
        is_package = path.name == "__init__.py"
        if not requirements.recommended or not is_package:
            continue
        sections = _find_sections(doc.text, requirements.section_keywords)
        missing = [section for section in requirements.recommended if section not in sections]
        if missing:
            violations.append(
                Violation(
                    code=ViolationCodes.DOC_SECTION_MISSING,
                    severity="warning",
                    message=(
                        f"Package module '{module}' docstring is missing recommended "
                        f"section(s): {', '.join(missing)}."
                    ),
                    remediation=(
                        "Extend the package docstring with the missing section(s) so the "
                        "module reference documents responsibilities, dependencies and "
                        "extension points."
                    ),
                    module=module,
                    details={"missing": list(missing)},
                )
            )
    return violations
