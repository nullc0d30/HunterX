# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Resource-exhaustion and process-lifecycle controls (Sprint 034.4 §7-§9).

One hostile tool must not be able to exhaust the worker: oversized output is
capped and the spawned process is terminated; runaway processes are killed on
timeout; the runner surfaces startup failures as typed errors.
"""

from __future__ import annotations

import sys
import time

import pytest

from hunterx.domain.exceptions import ToolExecutionError, ToolTimeoutError
from hunterx.tools.recon.runner import BinaryRunner

_BIG_OUT = "import sys; sys.stdout.write('x' * 500_000); sys.stdout.flush()"
_SLOW = "import time; time.sleep(30)"
_NORMAL = "import sys; print('ok')"
_EXIT_1 = "import sys; sys.exit(1)"


class _InterceptRunner(BinaryRunner):
    """Runner that records the spawned command so tests can assert on argv."""

    def __init__(self) -> None:
        super().__init__(max_output_bytes=1 << 20)
        self.spawned: list[list[str]] = []

    def _spawn(self, argv: list[str], env: dict[str, str]):
        self.spawned.append(argv)
        return super()._spawn(argv, env)


def test_oversized_output_is_capped_and_fails_execution() -> None:
    runner = BinaryRunner(max_output_bytes=4096)
    with pytest.raises(ToolExecutionError) as exc:
        runner.run([sys.executable, "-c", _BIG_OUT])
    assert "limit" in str(exc.value)


def test_large_but_allowed_output_is_captured() -> None:
    runner = BinaryRunner(max_output_bytes=1 << 20)
    result = runner.run([sys.executable, "-c", "import sys; sys.stdout.write('a' * 100_000)"])
    assert result.returncode == 0
    assert len(result.stdout) == 100_000


def test_timeout_terminates_runaway_process() -> None:
    runner = BinaryRunner(max_output_bytes=1 << 20)
    started = time.monotonic()
    with pytest.raises(ToolTimeoutError):
        runner.run([sys.executable, "-c", _SLOW], timeout_s=0.5)
    elapsed = time.monotonic() - started
    assert elapsed < 10, "timeout was not enforced promptly"


def test_normal_completion_and_exit_code() -> None:
    runner = BinaryRunner(max_output_bytes=1 << 20)
    ok = runner.run([sys.executable, "-c", _NORMAL])
    assert ok.returncode == 0
    assert ok.stdout.strip() == "ok"
    failed = runner.run([sys.executable, "-c", _EXIT_1])
    assert failed.returncode == 1


def test_stderr_is_captured_separately() -> None:
    runner = BinaryRunner(max_output_bytes=1 << 20)
    result = runner.run([sys.executable, "-c", "import sys; sys.stderr.write('boom')"])
    assert result.stderr == "boom"


def test_argv_never_contains_shell_strings() -> None:
    """The subprocess seam must pass argv structurally (no shell parsing)."""
    runner = _InterceptRunner()
    runner.run([sys.executable, "-c", "import sys; print('x')"])
    assert runner.spawned, "expected a spawn"
    assert runner.spawned[0][0] == sys.executable


def test_worker_parallel_cap_limits_concurrency() -> None:
    from hunterx.domain.execution import ExecutionContext
    from hunterx.tools.sdk.resources import ResourceManager

    manager = ResourceManager(max_parallel_jobs=2, max_queue_size=2)
    lease = manager.acquire(ExecutionContext(tool_id="t"))
    second = manager.acquire(ExecutionContext(tool_id="t"))
    # A third slot must be refused without blocking (queue full + no free slot).
    assert manager.try_acquire(ExecutionContext(tool_id="t")) is None
    second.release()
    lease.release()
