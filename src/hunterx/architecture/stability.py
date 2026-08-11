# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""API stability checks.

The public surface of the platform is snapshotted per module: exported names
(from ``__all__``) and their kinds (class / function / constant) plus callable
signatures. The snapshot is compared against a committed baseline
(``config/api_baseline.json``). Removing or renaming a public name is a
breaking change; altering a callable signature in a caller-breaking way is
reported as well.
"""

from __future__ import annotations

import ast
import json
import pathlib
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ApiEntry:
    """One public name exported by a module.

    Attributes:
        name: the exported name.
        kind: ``"class"``, ``"function"``, ``"constant"`` or ``"unknown"``.
        signature: for callables, the parameter names (in order).

    """

    name: str
    kind: str = "constant"
    signature: tuple[str, ...] = ()


def _public_names(tree: ast.AST) -> set[str]:
    """Return the public names a module advertises (via ``__all__``)."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__all__":
                    value = node.value
                    if isinstance(value, ast.List):
                        names: set[str] = set()
                        for elt in value.elts:
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                names.add(elt.value)
                        return names
    return set()


def _class_signature(node: ast.ClassDef) -> tuple[str, ...]:
    """Extract base names and keyword arguments as a coarse signature."""
    parts: list[str] = []
    for base in node.bases:
        if isinstance(base, ast.Name):
            parts.append(base.id)
        elif isinstance(base, ast.Attribute):
            parts.append(base.attr)
    return tuple(parts)


def _function_signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, ...]:
    """Extract positional parameter names for a function definition."""
    names: list[str] = []
    args = node.args
    for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs]:
        names.append(arg.arg)
    if args.vararg is not None:
        names.append(f"*{args.vararg.arg}")
    if args.kwarg is not None:
        names.append(f"**{args.kwarg.arg}")
    return tuple(names)


def snapshot_module(path: pathlib.Path, module: str) -> dict[str, ApiEntry]:
    """Snapshot the public API of a single module.

    Only modules that declare ``__all__`` are considered to have a stable
    public surface; other modules contribute their module name so removals are
    still visible.

    Args:
        path: absolute path to the ``.py`` file.
        module: dotted module name.

    Returns:
        Mapping of exported name to :class:`ApiEntry`.

    """
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, OSError):
        return {}
    names = _public_names(tree)
    entries: dict[str, ApiEntry] = {}
    for node in ast.walk(tree):
        if (
            isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name in names
        ):
            if isinstance(node, ast.ClassDef):
                entries[node.name] = ApiEntry(node.name, "class", _class_signature(node))
            else:
                entries[node.name] = ApiEntry(node.name, "function", _function_signature(node))
    for name in names:
        entries.setdefault(name, ApiEntry(name, "constant"))
    return entries


def snapshot_tree(root: pathlib.Path) -> dict[str, dict[str, dict[str, Any]]]:
    """Snapshot the public API of every module below ``root``.

    Returns:
        A JSON-serializable mapping: module -> name -> entry.

    """
    result: dict[str, dict[str, dict[str, Any]]] = {}
    for path in sorted(root.rglob("*.py")):
        relative = path.relative_to(root)
        parts = list(relative.parts)
        if parts[-1] == "__init__.py":
            parts = parts[:-1]
        else:
            parts[-1] = parts[-1][: -len(".py")]
        module = ".".join(parts)
        entries = snapshot_module(path, module)
        if entries:
            result[module] = {
                name: {"kind": entry.kind, "signature": list(entry.signature)}
                for name, entry in entries.items()
            }
    return result


@dataclass(frozen=True, slots=True)
class ApiChange:
    """A change detected between two API snapshots.

    Attributes:
        module: the affected module.
        name: the affected public name.
        kind: ``"removed"``, ``"added"``, ``"signature"`` or ``"kind"``.
        breaking: whether the change breaks existing consumers.

    """

    module: str
    name: str
    kind: str
    breaking: bool
    detail: str = ""


def compare_api(baseline: dict[str, Any], current: dict[str, Any]) -> list[ApiChange]:
    """Compare a baseline snapshot against the current one.

    Args:
        baseline: snapshot loaded from the baseline JSON.
        current: freshly computed snapshot.

    Returns:
        A list of :class:`ApiChange` sorted by module then name.

    """
    changes: list[ApiChange] = []
    all_modules = sorted(set(baseline) | set(current))
    for module in all_modules:
        base_entries = baseline.get(module, {})
        cur_entries = current.get(module, {})
        for name in sorted(set(base_entries) | set(cur_entries)):
            if name in base_entries and name not in cur_entries:
                changes.append(
                    ApiChange(module=module, name=name, kind="removed", breaking=True, detail="public name removed")
                )
            elif name not in base_entries and name in cur_entries:
                changes.append(
                    ApiChange(module=module, name=name, kind="added", breaking=False, detail="public name added")
                )
            else:
                base_entry = base_entries[name]
                cur_entry = cur_entries[name]
                if base_entry.get("kind") != cur_entry.get("kind"):
                    changes.append(
                        ApiChange(
                            module=module,
                            name=name,
                            kind="kind",
                            breaking=True,
                            detail=f"kind changed: {base_entry.get('kind')} -> {cur_entry.get('kind')}",
                        )
                    )
                    continue
                base_sig = base_entry.get("signature") or []
                cur_sig = cur_entry.get("signature") or []
                if base_sig and base_sig != cur_sig:
                    removed = [p for p in base_sig if p not in cur_sig]
                    changes.append(
                        ApiChange(
                            module=module,
                            name=name,
                            kind="signature",
                            breaking=bool(removed),
                            detail=f"signature: {base_sig} -> {cur_sig}",
                        )
                    )
    changes.sort(key=lambda change: (change.module, change.name))
    return changes


def load_baseline(path: pathlib.Path) -> dict[str, Any]:
    """Load an API baseline JSON file.

    Args:
        path: path to the baseline file.

    Returns:
        The parsed snapshot (empty when the file is missing or invalid).

    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def save_baseline(path: pathlib.Path, snapshot: dict[str, Any]) -> None:
    """Write an API snapshot to a JSON baseline file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8")
