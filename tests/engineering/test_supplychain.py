# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for supply-chain security (eng.supplychain)."""

from __future__ import annotations

import json
import pathlib

from eng.supplychain import (
    _ALLOWED_LICENSES,
    _canonical_license,
    _expression_allowed,
    check_licenses,
    check_lock_consistency,
    generate_sbom,
    generate_sbom_spdx,
    parse_requirements,
    write_provenance,
)
from eng.tooling import ToolResult


def test_parse_requirements() -> None:
    text = "pydantic==2.0.0\n# comment\npyyaml>=6.0\nrequests ~= 2.28\nfoo @ https://example.com\n\n"
    parsed = parse_requirements(text)
    assert parsed["pydantic"] == "2.0.0"
    assert parsed["pyyaml"] == "6.0"
    assert parsed["requests"] == "2.28"
    assert "foo" not in parsed


def test_lock_consistency(tmp_path: pathlib.Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="hunterx"\ndependencies=["pydantic>=2.0", "pyyaml>=6.0"]\n',
        encoding="utf-8",
    )
    (tmp_path / "requirements.lock").write_text("pydantic==2.0.0\npyyaml==6.0.1\n", encoding="utf-8")
    check = check_lock_consistency(tmp_path)
    assert check.ok is True


def test_lock_consistency_detects_unlocked(tmp_path: pathlib.Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="hunterx"\ndependencies=["pydantic>=2.0", "rich>=13"]\n',
        encoding="utf-8",
    )
    (tmp_path / "requirements.lock").write_text("pydantic==2.0.0\n", encoding="utf-8")
    check = check_lock_consistency(tmp_path)
    assert check.ok is False
    assert "rich" in check.detail


def test_lock_consistency_missing_lock(tmp_path: pathlib.Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\ndependencies=["x>=1"]\n', encoding="utf-8")
    check = check_lock_consistency(tmp_path)
    assert check.ok is False


def test_generate_sbom_offline(tmp_path: pathlib.Path) -> None:
    (tmp_path / "requirements.lock").write_text("pydantic==2.0.0\nrich==13.0.0\n", encoding="utf-8")
    result = generate_sbom(tmp_path)
    assert result.components == 2
    path = tmp_path / result.path
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["bomFormat"] == "CycloneDX"
    assert any(c["name"] == "pydantic" for c in data["components"])


def test_generate_sbom_without_lock(tmp_path: pathlib.Path) -> None:
    result = generate_sbom(tmp_path)
    assert result.components == 0


def test_generate_sbom_spdx(tmp_path: pathlib.Path) -> None:
    (tmp_path / "requirements.lock").write_text("pydantic==2.0.0\nrich==13.0.0\n", encoding="utf-8")
    path = generate_sbom_spdx(tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["spdxVersion"] == "SPDX-2.3"
    assert len(data["packages"]) == 2
    assert data["packages"][0]["SPDXID"].startswith("SPDXRef-Package-")


def test_check_licenses_allowlist() -> None:
    assert "MIT" in _ALLOWED_LICENSES
    assert "Apache-2.0" in _ALLOWED_LICENSES


def test_canonical_license_aliases() -> None:
    assert _canonical_license("Apache Software License") == "Apache-2.0"
    assert _canonical_license("BSD License") == "BSD-3-Clause"
    assert _canonical_license("MIT License") == "MIT"
    assert _canonical_license("Mozilla Public License 2.0 (MPL 2.0)") == "MPL-2.0"
    assert _canonical_license("ISC License (ISCL)") == "ISC"
    assert _canonical_license("Apache-2.0") == "Apache-2.0"
    assert _canonical_license("UNKNOWN") == "UNKNOWN"
    assert _canonical_license("") == ""


def test_expression_allowed() -> None:
    assert _expression_allowed("Apache-2.0", _ALLOWED_LICENSES) is True
    assert _expression_allowed("Apache-2.0 OR BSD-3-Clause", _ALLOWED_LICENSES) is True
    assert _expression_allowed("MIT AND PSF-2.0", _ALLOWED_LICENSES) is True
    assert _expression_allowed("Apache-2.0 WITH LLVM-exception", _ALLOWED_LICENSES) is True
    assert _expression_allowed("BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0", _ALLOWED_LICENSES) is True
    assert _expression_allowed("Apache-2.0 AND CNRI-Python", _ALLOWED_LICENSES) is True
    assert _expression_allowed("GPL-3.0-only", _ALLOWED_LICENSES) is False
    assert _expression_allowed("MIT AND GPL-3.0-only", _ALLOWED_LICENSES) is False
    assert _expression_allowed("", _ALLOWED_LICENSES) is True


class _CannedRunner:
    """Returns canned ToolResults for the tool names the pipeline invokes."""

    def __init__(self, outcomes: dict[str, ToolResult]) -> None:
        self.outcomes = outcomes

    def available(self, executable: str) -> bool:
        return executable in self.outcomes

    def run(
        self, args: list[str], *, cwd: str | None = None, env: dict[str, str] | None = None, timeout: int = 600
    ) -> ToolResult:
        return self.outcomes.get(args[0], ToolResult(returncode=127, stderr=f"missing {args[0]}"))


def _licenses_json(items: list[dict[str, str]]) -> ToolResult:
    return ToolResult(returncode=0, stdout=json.dumps(items))


def test_check_licenses_accepts_aliased_and_expression_licenses(tmp_path: pathlib.Path) -> None:
    runner = _CannedRunner(
        {
            "pip-licenses": _licenses_json(
                [
                    {"Name": "requests", "Version": "2.0.0", "License": "Apache Software License"},
                    {"Name": "rich", "Version": "13.0.0", "License": "MIT License"},
                    {"Name": "torch", "Version": "2.0.0", "License": "Apache-2.0 WITH LLVM-exception"},
                ]
            )
        }
    )
    check = check_licenses(tmp_path, runner=runner)
    assert check.ok is True
    assert check.disallowed == []


def test_check_licenses_rejects_disallowed_license(tmp_path: pathlib.Path) -> None:
    runner = _CannedRunner(
        {
            "pip-licenses": _licenses_json(
                [{"Name": "evil-pkg", "Version": "1.0.0", "License": "GPL-3.0-only"}]
            )
        }
    )
    check = check_licenses(tmp_path, runner=runner)
    assert check.ok is False
    assert any("evil-pkg" in entry for entry in check.disallowed)


def test_check_licenses_skips_when_tool_unavailable(tmp_path: pathlib.Path) -> None:
    check = check_licenses(tmp_path, runner=_CannedRunner({}))
    assert check.ok is True
    assert "skipped" in check.detail


def test_write_provenance(tmp_path: pathlib.Path) -> None:
    manifest = write_provenance(tmp_path, version="7.1.0", artifacts=["hunterx.whl"], commit="abc123")
    assert manifest.version == "7.1.0"
    assert manifest.commit == "abc123"
    data = json.loads((tmp_path / "artifacts" / "provenance.json").read_text(encoding="utf-8"))
    assert data["version"] == "7.1.0"
    assert data["artifacts"] == ["hunterx.whl"]
