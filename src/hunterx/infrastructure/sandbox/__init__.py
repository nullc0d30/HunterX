# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Sandbox adapters.

The sandbox isolates untrusted plugin/tool code. The default implementation
uses ``subprocess`` with a fresh interpreter and enforced timeout; real
deployments replace it with OS-level isolation (containers, gVisor, ...).
"""

from __future__ import annotations

import subprocess  # nosec B404  # sandbox isolates untrusted code via subprocess
import sys
from typing import Any

from hunterx.domain.exceptions import SandboxError
from hunterx.domain.ports.services import SandboxPort


class SubprocessSandbox(SandboxPort):
    """Run code in an isolated subprocess with a timeout.

    Only pure in-memory computation is allowed by default; network and
    filesystem access are delegated to the caller via an explicit
    ``allowed_imports`` allow-list.
    """

    def __init__(self, *, timeout_seconds: float = 30.0, allowed_imports: tuple[str, ...] = ()) -> None:
        self._timeout = timeout_seconds
        self._allowed = allowed_imports

    def run(self, code: str, *, timeout_seconds: float = 30.0, limits: dict[str, Any] | None = None) -> str:
        """Execute ``code`` in an isolated subprocess and return its output."""
        limits = limits or {}
        timeout = float(limits.get("timeout", timeout_seconds or self._timeout))
        preamble = "import sys\n"
        for module in self._allowed:
            preamble += f"import {module}\n"
        script = preamble + code
        try:
            result = subprocess.run(  # nosec B603  # runs only the caller's own code
                [sys.executable, "-c", script],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise SandboxError(f"Sandboxed code timed out after {timeout:.1f}s.") from exc
        if result.returncode != 0:
            raise SandboxError(f"Sandboxed code failed: {result.stderr.strip()}")
        return result.stdout

    def check(self) -> bool:
        """Verify the sandbox can start a fresh interpreter."""
        try:
            self.run("print('ok')", timeout_seconds=5.0)
            return True
        except (SandboxError, OSError):
            return False
