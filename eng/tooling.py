# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool invocation helpers.

Every external tool (ruff, mypy, pytest, coverage, bandit, semgrep, ...) is
run through :class:`ToolRunner`. It is deliberately small and injectable so the
gate/report logic can be unit-tested with fakes and does not shell out
unpredictably in CI.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Protocol


@dataclass(slots=True)
class ToolResult:
    """Outcome of one external tool invocation.

    Attributes:
        returncode: process exit code (``0`` on success).
        stdout: captured standard output.
        stderr: captured standard error.
        executable: resolved executable name that was run.

    """

    returncode: int
    stdout: str = ""
    stderr: str = ""
    executable: str = ""

    @property
    def ok(self) -> bool:
        """Return ``True`` when the tool exited successfully."""
        return self.returncode == 0

    @property
    def combined(self) -> str:
        """Return stdout and stderr joined for report embedding."""
        parts = [self.stdout, self.stderr]
        return "\n".join(p for p in parts if p)


class ToolInvoker(Protocol):
    """Protocol for anything that can run a command (real or fake)."""

    def run(
        self,
        args: list[str],
        *,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout: int = 600,
    ) -> ToolResult:
        """Execute ``args`` and return a :class:`ToolResult`."""


@dataclass(slots=True)
class ToolRunner:
    """Run external tools via ``subprocess``.

    Attributes:
        cwd: working directory; defaults to the repository root.
        env: environment overrides merged over ``os.environ``.
        timeout: default command timeout in seconds.

    """

    cwd: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    timeout: int = 600

    def available(self, executable: str) -> bool:
        """Return ``True`` when ``executable`` is resolvable on ``PATH``."""
        return shutil.which(executable) is not None

    def run(
        self,
        args: list[str],
        *,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout: int | None = None,
    ) -> ToolResult:
        """Execute ``args`` and capture output.

        Args:
            args: command and arguments to run.
            cwd: optional working directory override.
            env: optional environment override (merged).
            timeout: optional timeout override (seconds).

        Returns:
            A :class:`ToolResult`.

        """
        merged_env = dict(os.environ)
        merged_env.update(self.env)
        if env:
            merged_env.update(env)
        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=cwd or self.cwd,
                env=merged_env,
                timeout=timeout or self.timeout,
                check=False,
            )
        except FileNotFoundError:
            return ToolResult(returncode=127, stderr=f"executable not found: {args[0]}", executable=args[0])
        except subprocess.TimeoutExpired:  # pragma: no cover - rare in CI
            return ToolResult(
                returncode=124,
                stderr=f"timed out after {(timeout or self.timeout)}s",
                executable=args[0],
            )
        except OSError as exc:  # e.g. platform policy blocking the executable
            return ToolResult(
                returncode=126,
                stderr=f"could not execute {args[0]}: {exc}",
                executable=args[0],
            )
        return ToolResult(
            returncode=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            executable=args[0],
        )
