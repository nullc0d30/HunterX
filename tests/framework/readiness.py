# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Shared doubles for Tool Readiness tests.

Never installs real packages: the provisioner command runner is stubbed and
fake executables are tiny script files written to a temp directory on PATH.
"""

from __future__ import annotations

import os
import pathlib
from typing import Any

from hunterx.domain.tool_intelligence import ToolExecutionType, ToolMetadata
from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.intelligence.registry import ToolIntelligenceRegistry
from hunterx.tools.readiness.discovery import ToolDiscovery
from hunterx.tools.readiness.platform import PlatformInfo


def tip_with(tool_ids: list[str]) -> ToolIntelligenceAPI:
    """Return a TIP with registered metadata for ``tool_ids`` (no knowledge)."""
    tip = ToolIntelligenceAPI()
    for index, tool_id in enumerate(tool_ids):
        tip.register_tool(
            ToolMetadata(
                tool_id=tool_id,
                display_name=tool_id.title(),
                vendor="test",
                project_url="",
                license="Apache-2.0",
                category="test",
                subcategory="",
                version=f"1.{index}.0",
                platforms=("linux", "darwin", "windows"),
                architectures=("x86_64",),
                language="",
                execution_type=ToolExecutionType.BINARY,
                package_manager="",
                container_available=False,
                binary_available=True,
                maintenance_status="active",
                project_activity="active",
                community_score=0.0,
                description=f"test tool {tool_id}",
                tags=(),
            )
        )
    return tip


def linux_platform(*, distro: str = "ubuntu", is_root: bool = False) -> PlatformInfo:
    """Return a Linux :class:`PlatformInfo` for a given distro."""
    return PlatformInfo(
        os="linux",
        distro=distro,
        package_manager="apt" if distro in ("ubuntu", "debian", "kali") else "none",
        arch="x86_64",
        supported=True,
        is_root=is_root,
    )


def fake_executable(directory: pathlib.Path, name: str, output: str, *, exit_code: int = 0) -> pathlib.Path:
    """Write a runnable fake executable named ``name`` in ``directory``.

    On Windows a ``.cmd`` wrapper is used (discoverable via ``shutil.which``
    and spawnable by the version probe). On POSIX a plain executable script is
    written.
    """
    if os.name == "nt":
        path = directory / f"{name}.cmd"
        body = f"@echo off\necho {output}\nexit /b {exit_code}\n"
        path.write_text(body, encoding="utf-8")
    else:
        path = directory / name
        body = f"#!/bin/sh\nprintf '%s\\n' \"{output}\"\nexit {exit_code}\n"
        path.write_text(body, encoding="utf-8")
        path.chmod(0o755)
    return path


def add_to_path(directory: pathlib.Path) -> None:
    """Prepend ``directory`` to ``PATH`` in-process (test isolation)."""
    os.environ["PATH"] = str(directory) + os.pathsep + os.environ.get("PATH", "")


def make_discovery(engine=None) -> ToolDiscovery:  # noqa: ANN001
    """Return a discovery probe bound to an optional engine."""
    return ToolDiscovery(engine)


def fake_engine() -> ToolIntelligenceRegistry:
    """Return a bare SDK engine double exposing the readiness surface."""
    class _FakeEngine:  # noqa: D101
        def __init__(self) -> None:
            self._intelligence = ToolIntelligenceRegistry()
            self._adapters: dict[str, object] = {}
            self._installed: dict[str, str] = {}

        def adapter_for(self, tool_id: str) -> object | None:
            return self._adapters.get(tool_id)

        @property
        def versions(self) -> _Versions:
            return _Versions(self._installed)

        def health_check(self, tool_id: str) -> bool:
            return tool_id in self._installed

    class _Versions:  # noqa: D101
        def __init__(self, store: dict[str, str]) -> None:
            self._store = store

        def installed(self, tool_id: str) -> str | None:
            return self._store.get(tool_id)

        def record(self, tool_id: str, version: str) -> None:
            self._store[tool_id] = version

    return _FakeEngine()  # type: ignore[return-value]


class StubRunner:
    """Command runner stub recording invocations and returning canned results.

    Args:
        results: mapping of ``command[0]`` → ``(returncode, stdout, stderr)``.

    """

    def __init__(self, results: dict[str, tuple[int, str, str]] | None = None) -> None:
        self._results = results or {}
        self.calls: list[list[str]] = []

    def run(self, argv: list[str]) -> tuple[int, str, str]:
        """Record the argv and return the canned result for its first element."""
        self.calls.append(list(argv))
        return self._results.get(argv[0], (0, "", ""))

    def install_succeeded(self) -> None:
        """Make every future invocation succeed."""
        self._results = {}


def commands_available(*names: str) -> Any:
    """Return a ``command_available`` stub reporting only ``names`` present."""
    available = set(names)

    def check(name: str) -> str | None:
        return name if name in available else None

    return check


def all_commands_available(name: str) -> str:
    """``command_available`` stub reporting every command as available."""
    return name


def engine_has(engine: object, tool_id: str, *, installed: bool = False) -> None:
    """Register ``tool_id`` adapter (and install state) on the fake engine."""
    engine._adapters[tool_id] = object()  # type: ignore[attr-defined]  # test double
    if installed:
        engine._installed[tool_id] = "1.0.0"  # type: ignore[attr-defined]  # test double
