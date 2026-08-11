# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for API stability snapshotting and comparison."""

from __future__ import annotations

import pathlib

from hunterx.architecture.stability import compare_api, snapshot_module, snapshot_tree


def test_snapshot_module_exports(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "mod.py"
    path.write_text(
        "__all__ = ['PublicClass', 'public_fn', 'PUBLIC_CONST']\n\n"
        "class PublicClass:\n    pass\n\n"
        "def public_fn(a, b=1):\n    pass\n\n"
        "PUBLIC_CONST = 42\n",
        encoding="utf-8",
    )
    entries = snapshot_module(path, "hunterx.mod")
    assert entries["PublicClass"].kind == "class"
    assert entries["public_fn"].kind == "function"
    assert entries["PUBLIC_CONST"].kind == "constant"


def test_removed_public_name_is_breaking(tmp_path: pathlib.Path) -> None:
    module = tmp_path / "m.py"
    module.write_text("__all__ = ['A', 'B']\nclass A:\n    pass\nclass B:\n    pass\n", encoding="utf-8")
    baseline = snapshot_tree(tmp_path)
    module.write_text("__all__ = ['A']\nclass A:\n    pass\n", encoding="utf-8")
    current = snapshot_tree(tmp_path)
    changes = compare_api(baseline, current)
    removed = [change for change in changes if change.kind == "removed"]
    assert len(removed) == 1
    assert removed[0].name == "B"
    assert removed[0].breaking


def test_signature_removal_is_breaking(tmp_path: pathlib.Path) -> None:
    module = tmp_path / "m.py"
    module.write_text(
        "__all__ = ['fn']\ndef fn(a, b):\n    pass\n",
        encoding="utf-8",
    )
    baseline = snapshot_tree(tmp_path)
    module.write_text(
        "__all__ = ['fn']\ndef fn(a):\n    pass\n",
        encoding="utf-8",
    )
    current = snapshot_tree(tmp_path)
    changes = compare_api(baseline, current)
    assert any(change.kind == "signature" and change.breaking for change in changes)


def test_added_public_name_is_not_breaking(tmp_path: pathlib.Path) -> None:
    module = tmp_path / "m.py"
    module.write_text("__all__ = ['A']\nclass A:\n    pass\n", encoding="utf-8")
    baseline = snapshot_tree(tmp_path)
    module.write_text("__all__ = ['A', 'B']\nclass A:\n    pass\nclass B:\n    pass\n", encoding="utf-8")
    current = snapshot_tree(tmp_path)
    changes = compare_api(baseline, current)
    added = [change for change in changes if change.kind == "added"]
    assert len(added) == 1
    assert not added[0].breaking
