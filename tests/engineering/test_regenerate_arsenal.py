# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Regenerate the universal security arsenal manifest (Sprint 025).

Run:  python -m pytest -q tests/engineering/test_regenerate_arsenal.py
"""

from __future__ import annotations

import os

from hunterx.tools.mastery.api import ToolMasteryAPI


def test_regenerate_arsenal_manifest():
    mastery = ToolMasteryAPI()
    path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
        "capabilities",
        "universal-security-arsenal.json",
    )
    path = os.path.abspath(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    mastery.export_manifest(path)
    import json

    with open(path, encoding="utf-8") as handle:
        manifest = json.load(handle)
    assert manifest["manifest_version"] == "1.0.0"
    assert len(manifest["tools"]) >= 80
    assert len(manifest["playbooks"]) >= 17
    assert len(manifest["relationships"]) > 0
    assert len(manifest["datasets"]) >= 10
