# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Static import extraction.

Parses Python modules with :mod:`ast` and records every import statement as a
:class:`ImportRecord`. Records carry the information the linter needs:

- whether the import is guarded by ``if TYPE_CHECKING:`` (never executed at
  runtime, so it cannot create a real import cycle);
- whether it appears inside a function body (a lazy import);
- the resolved absolute target module (relative imports are resolved against
  the source package).
"""

from __future__ import annotations

import ast
import os
import pathlib
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ImportRecord:
    """A single import statement inside a module.

    Attributes:
        source: absolute dotted name of the importing module.
        target: absolute dotted name of the imported module (``None`` for
            relative ``from . import x`` with no resolved package).
        line: 1-based line number of the statement.
        kind: ``"import"`` or ``"from"``.
        is_type_checking: imported inside ``if TYPE_CHECKING:``.
        is_lazy: imported inside a function or method body.
        raw: the import name as written.

    """

    source: str
    target: str
    line: int
    kind: str
    is_type_checking: bool = False
    is_lazy: bool = False
    raw: str = ""


def module_name_for(path: pathlib.Path, root: pathlib.Path) -> str:
    """Convert a file path under ``root`` into a dotted module name.

    Args:
        path: absolute path to a ``.py`` file.
        root: absolute path to the package root (e.g. ``src``).

    Returns:
        The dotted module name. ``__init__.py`` files map to the package name.

    """
    relative = path.relative_to(root)
    parts = list(relative.parts)
    if parts[-1] == "__init__.py":
        parts = parts[:-1]
    else:
        parts[-1] = parts[-1][: -len(".py")]
    return ".".join(parts)


def _build_parent_map(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    """Return a child-to-parent mapping for an AST tree."""
    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    return parents


def _in_type_checking(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    """Return ``True`` if ``node`` sits inside an ``if TYPE_CHECKING:`` block."""
    current: ast.AST | None = node
    while current is not None:
        if (
            isinstance(current, ast.If)
            and isinstance(current.test, ast.Name)
            and current.test.id == "TYPE_CHECKING"
        ):
            return True
        current = parents.get(current)
    return False


def _in_function(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    """Return ``True`` if ``node`` sits inside a function or method body."""
    current: ast.AST | None = node
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return True
        current = parents.get(current)
    return False


def scan_file(path: pathlib.Path, source_module: str) -> list[ImportRecord]:
    """Scan a single Python file and return its import records.

    Args:
        path: absolute path to the ``.py`` file.
        source_module: absolute dotted name of the module.

    Returns:
        A list of :class:`ImportRecord` in source order.

    """
    try:
        source = path.read_text(encoding="utf-8")
    except OSError:
        return []
    return scan_source(source, source_module)


def scan_source(source: str, source_module: str) -> list[ImportRecord]:
    """Scan Python source text and return its import records.

    Args:
        source: the module source code.
        source_module: absolute dotted name of the module.

    Returns:
        A list of :class:`ImportRecord` in source order.

    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    parents = _build_parent_map(tree)
    package = source_module.rsplit(".", 1)[0] if "." in source_module else source_module

    records: list[ImportRecord] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            in_tc = _in_type_checking(node, parents)
            in_fn = _in_function(node, parents)
            for alias in node.names:
                records.append(
                    ImportRecord(
                        source=source_module,
                        target=alias.name,
                        line=getattr(node, "lineno", 0),
                        kind="import",
                        is_type_checking=in_tc,
                        is_lazy=in_fn,
                        raw=alias.name,
                    )
                )
        elif isinstance(node, ast.ImportFrom):
            in_tc = _in_type_checking(node, parents)
            in_fn = _in_function(node, parents)
            level = node.level or 0
            module = node.module or ""
            if module == "__future__":
                continue
            if level == 0:
                target = module
            else:
                # Resolve a relative import against the source package.
                base = package
                if level > 1:
                    parts = package.split(".")
                    drop = min(level - 1, len(parts) - 1)
                    base = ".".join(parts[: len(parts) - drop])
                target = f"{base}.{module}" if module else base
            records.append(
                ImportRecord(
                    source=source_module,
                    target=target,
                    line=getattr(node, "lineno", 0),
                    kind="from",
                    is_type_checking=in_tc,
                    is_lazy=in_fn,
                    raw=f"{module or '.' * level}",
                )
            )
    return records


def scan_tree(root: pathlib.Path) -> dict[str, list[ImportRecord]]:
    """Scan every ``.py`` file below ``root``.

    Args:
        root: absolute path to the package root (e.g. ``src``).

    Returns:
        A mapping of dotted module name to its import records. Modules whose
        source failed to parse are omitted.

    """
    result: dict[str, list[ImportRecord]] = {}
    for dirpath, _, filenames in os.walk(root):
        for filename in filenames:
            if not filename.endswith(".py"):
                continue
            path = pathlib.Path(dirpath) / filename
            module = module_name_for(path, root)
            records = scan_file(path, module)
            if records:
                result[module] = records
    return result


def internal_imports(records: list[ImportRecord], package: str) -> list[ImportRecord]:
    """Return only records whose target is inside ``package``.

    Args:
        records: import records for a module.
        package: dotted package prefix to match (e.g. ``"hunterx"``).

    Returns:
        Records whose target equals ``package`` or starts with ``package.``.

    """
    return [
        record
        for record in records
        if record.target == package or record.target.startswith(f"{package}.")
    ]
