# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Regression guard: shell scripts must use Unix LF line endings.

CRLF shebangs (``#!/usr/bin/env bash\r``) break execution on Linux/WSL with
``/usr/bin/env: 'bash\r': No such file or directory``. ``.gitattributes``
enforces ``*.sh text eol=lf``; this test fails fast if a tracked ``*.sh`` file
ever contains a carriage return, preventing the regression from re-entering.
"""

from __future__ import annotations

import pathlib
import subprocess

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]


def _tracked_shell_scripts() -> list[str]:
    """Return the tracked ``*.sh`` files (repository-relative paths)."""
    output = subprocess.run(
        ["git", "ls-files", "*.sh"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    ).stdout
    return [line.strip() for line in output.splitlines() if line.strip()]


def test_tracked_shell_scripts_use_lf_line_endings() -> None:
    scripts = _tracked_shell_scripts()
    assert scripts, "expected at least one tracked *.sh script"
    offenders: list[str] = []
    for relative in scripts:
        path = REPO_ROOT / relative
        if not path.exists():
            continue
        raw = path.read_bytes()
        if b"\r" in raw:
            offenders.append(relative)
    assert not offenders, f"CRLF line endings found in shell scripts: {offenders}"


def test_install_shebang_is_valid_unix_bash() -> None:
    install = REPO_ROOT / "install.sh"
    assert install.exists()
    first = install.read_bytes().split(b"\n", 1)[0]
    assert first == b"#!/usr/bin/env bash", f"invalid shebang: {first!r}"
    assert b"\r" not in first, "shebang must not contain a carriage return"
