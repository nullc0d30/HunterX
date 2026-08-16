# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""External binary runner for tool adapters.

Wraps ``subprocess`` behind a small seam so adapters stay testable without any
external tool installed: unit tests inject a fake runner that returns golden
output. The runner captures stdout/stderr as text and propagates timeouts as
:class:`ToolTimeoutError` so the SDK pipeline classifies them correctly.

SECURITY MODEL (Sprint 034.4): the runner is the single guarded subprocess
seam in the Tool Integration SDK.

- ``argv`` is always passed structurally (no ``shell=True``); shell metacharacters
  in arguments are inert data.
- Captured stdout/stderr are capped at :attr:`max_output_bytes` so one hostile
  tool cannot exhaust worker memory. When the cap is exceeded the execution is
  failed (the process is terminated) rather than silently truncated.
- On timeout or output overflow the entire spawned process is terminated
  best-effort (the process tree where the platform supports it) so no tool
  process outlives its mission step.
- Startup failures (missing binary, permission) are surfaced as
  :class:`ToolExecutionError` instead of an unclassified exception.
"""

from __future__ import annotations

import contextlib
import os
import subprocess  # nosec B404  # the runner is the single guarded subprocess seam
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from io import BufferedReader

from hunterx.domain.exceptions import ToolExecutionError, ToolTimeoutError
from hunterx.shared.time import utcnow_iso

#: Default cap for combined captured stdout/stderr of one execution.
_DEFAULT_MAX_OUTPUT_BYTES = 32 * 1024 * 1024

#: Reader chunk size while draining a pipe.
_READ_CHUNK = 64 * 1024

#: Join timeout (seconds) for pipe-drain threads after the process exits.
_DRAIN_JOIN_TIMEOUT = 5.0

_NEW_PROCESS_GROUP = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) or 0


@dataclass(frozen=True, slots=True)
class CommandObservation:
    """The actual command line that was spawned, with execution context.

    Produced at the single guarded subprocess seam (:class:`BinaryRunner`) so
    observers always see the argv that really ran — never a reconstruction.
    When the execution was bound to a mission (see :func:`bind_active_execution`)
    the correlation fields are populated; ad-hoc executions leave them empty.

    Attributes:
        argv: the command line that was spawned (including the binary).
        tool_id: tool id of the executing adapter.
        mission_id: owning mission, when bound.
        execution_id: execution id of the owning context, when bound.
        capability: the mission capability driving the execution, when bound.
        action_id: the mission action id, when bound.
        target: the assessed target, when bound.
        started_at: UTC ISO-8601 spawn timestamp.

    """

    argv: tuple[str, ...]
    tool_id: str = ""
    mission_id: str = ""
    execution_id: str = ""
    capability: str = ""
    action_id: str = ""
    target: str = ""
    started_at: str = field(default_factory=utcnow_iso)


CommandObserver = Callable[[CommandObservation], None]

#: Registered command observers (live CLI, audit, ...). Module-level because
#: every tool adapter constructs its own :class:`BinaryRunner`; the registry is
#: the single hook point that sees every spawned command.
_command_observers: list[CommandObserver] = []

#: Thread-local binding of the currently executing mission step. The mission
#: runner binds before ``engine.execute`` so observers can correlate a spawned
#: command with its mission/execution context.
_active_execution = threading.local()


def register_command_observer(observer: CommandObserver) -> None:
    """Register ``observer`` to receive every spawned command (idempotent)."""
    if observer not in _command_observers:
        _command_observers.append(observer)


def unregister_command_observer(observer: CommandObserver) -> None:
    """Remove a previously registered command observer."""
    with contextlib.suppress(ValueError):
        _command_observers.remove(observer)


def bind_active_execution(
    *,
    tool_id: str = "",
    mission_id: str = "",
    execution_id: str = "",
    capability: str = "",
    action_id: str = "",
    target: str = "",
) -> None:
    """Bind the calling thread's active mission execution for observers.

    Must be paired with :func:`clear_active_execution` after the execution
    completes. Safe to call from a thread that never runs a tool: the binding
    is thread-local and simply stays unused.
    """
    _active_execution.bound = {
        "tool_id": tool_id,
        "mission_id": mission_id,
        "execution_id": execution_id,
        "capability": capability,
        "action_id": action_id,
        "target": target,
    }


def clear_active_execution() -> None:
    """Clear the calling thread's active mission execution binding."""
    _active_execution.bound = {}


def _observe_command(argv: Sequence[str], tool_id: str) -> None:
    """Notify all observers of a spawned command (best-effort, never raises).

    An observer failure must never break a tool execution: observers are
    advisory (live rendering, audit trails).
    """
    bound = dict(getattr(_active_execution, "bound", {}))
    observation = CommandObservation(
        argv=tuple(str(part) for part in argv),
        tool_id=tool_id or str(bound.get("tool_id", "")),
        mission_id=str(bound.get("mission_id", "")),
        execution_id=str(bound.get("execution_id", "")),
        capability=str(bound.get("capability", "")),
        action_id=str(bound.get("action_id", "")),
        target=str(bound.get("target", "")),
    )
    for observer in list(_command_observers):
        with contextlib.suppress(Exception):  # noqa: BLE001 - observers are advisory
            observer(observation)


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Outcome of invoking an external recon tool.

    Attributes:
        returncode: process exit code (0 = success).
        stdout: captured standard output.
        stderr: captured standard error.
        argv: the command line that was run.

    """

    returncode: int
    stdout: str
    stderr: str = ""
    argv: tuple[str, ...] = field(default_factory=tuple)


def guard_positional_target(value: str, *, label: str = "target") -> str:
    """Reject a positional target that a CLI would parse as an option.

    Tools that take the target as a bare positional argument (``nmap``,
    ``masscan``, ``assetfinder``, ``traceroute``, ``whatweb``) parse option
    flags from any argv element. A hostile value such as ``--script=...`` must
    never become a new option; it is rejected before the process is spawned.
    """
    value = value or ""
    if value.lstrip().startswith("-"):
        raise ToolExecutionError(
            f"{label} must not begin with '-' (option injection attempt): {value[:64]!r}"
        )
    return value


def guard_option_value(value: str, *, label: str = "value") -> str:
    """Reject a flag value that would be reinterpreted as a new option.

    Even when a target is passed as a flag value (``-d <domain>``), a value
    beginning with ``-`` can be re-parsed as an option by CLIs that scan the
    whole command line. Apply this guard to any user-controlled value placed on
    the command line.
    """
    value = value or ""
    if value.lstrip().startswith("-"):
        raise ToolExecutionError(
            f"{label} must not begin with '-' (option injection attempt): {value[:64]!r}"
        )
    return value


class BinaryRunner:
    """Run an external binary, capturing its output as bounded text.

    Usage::

        runner = BinaryRunner()
        result = runner.run(["subfinder", "-d", "example.com", "-silent"])
    """

    def __init__(
        self,
        *,
        timeout_s: float = 0.0,
        env: Mapping[str, str] | None = None,
        max_output_bytes: int = _DEFAULT_MAX_OUTPUT_BYTES,
    ) -> None:
        self._default_timeout = timeout_s
        self._env = dict(env) if env else None
        self._max_output_bytes = max_output_bytes

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_s: float = 0.0,
        tool_id: str = "",
    ) -> CommandResult:
        """Execute ``argv`` and return its bounded captured output.

        Args:
            argv: full command line including the binary name.
            timeout_s: per-run timeout in seconds (overrides the default).
            tool_id: tool id used in the :class:`ToolTimeoutError` raised when
                the process exceeds its deadline.

        Returns:
            The captured :class:`CommandResult`.

        Raises:
            ToolTimeoutError: when the process exceeds ``timeout_s``.
            ToolExecutionError: when the binary cannot start or when the
                captured output exceeds :attr:`max_output_bytes`.

        """
        effective = timeout_s or self._default_timeout
        env = {**os.environ, **(self._env or {})}
        argv = [str(part) for part in argv]
        _observe_command(argv, tool_id)
        process = self._spawn(argv, env)
        sink = _CaptureSink(self._max_output_bytes)
        readers = (
            threading.Thread(target=_drain, args=(process.stdout, sink.stdout_chunks, sink), daemon=True),
            threading.Thread(target=_drain, args=(process.stderr, sink.stderr_chunks, sink), daemon=True),
        )
        for reader in readers:
            reader.start()
        try:
            process.wait(timeout=effective if effective > 0 else None)
        except subprocess.TimeoutExpired:
            _terminate_process_tree(process)
            _close_pipes(process)
            for reader in readers:
                reader.join(timeout=_DRAIN_JOIN_TIMEOUT)
            raise ToolTimeoutError(tool_id or str(argv[0]), effective) from None

        for reader in readers:
            reader.join(timeout=_DRAIN_JOIN_TIMEOUT)
        _close_pipes(process)

        if sink.exceeded:
            _terminate_process_tree(process)
            raise ToolExecutionError(
                f"Tool '{tool_id or argv[0]}' output exceeded the {self._max_output_bytes}-byte limit"
            )
        return CommandResult(
            returncode=process.returncode,
            stdout=sink.stdout_text(),
            stderr=sink.stderr_text(),
            argv=tuple(argv),
        )

    # -- helpers -----------------------------------------------------------

    def _spawn(self, argv: list[str], env: dict[str, str]) -> subprocess.Popen[bytes]:
        """Start the child in its own process group where supported."""
        try:
            return subprocess.Popen(  # nosec B603  # trusted constructed argv
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                start_new_session=os.name != "nt",
                creationflags=_NEW_PROCESS_GROUP if os.name == "nt" else 0,
            )
        except OSError as exc:
            raise ToolExecutionError(
                f"Failed to start tool binary '{argv[0]}': {exc}"
            ) from exc


class _CaptureSink:
    """Bounded in-memory capture of a process's output pipes."""

    __slots__ = ("_cap", "_total", "exceeded", "stdout_chunks", "stderr_chunks")

    def __init__(self, cap: int) -> None:
        self._cap = cap
        self._total = 0
        self.exceeded = False
        self.stdout_chunks: list[bytes] = []
        self.stderr_chunks: list[bytes] = []

    def add(self, chunks: list[bytes], chunk: bytes) -> None:
        """Record ``chunk`` unless the cap has already been exceeded."""
        if not chunk:
            return
        self._total += len(chunk)
        if self._total > self._cap:
            self.exceeded = True
            return
        chunks.append(chunk)

    def stdout_text(self) -> str:
        return _decode(self.stdout_chunks)

    def stderr_text(self) -> str:
        return _decode(self.stderr_chunks)


def _drain(
    pipe: BufferedReader | None,
    chunks: list[bytes],
    sink: _CaptureSink,
) -> None:
    """Read ``pipe`` to EOF in bounded chunks, forwarding to ``sink``."""
    if pipe is None:
        return
    try:
        while True:
            chunk = pipe.read(_READ_CHUNK)
            if not chunk:
                break
            sink.add(chunks, chunk)
    except (OSError, ValueError):
        pass


def _decode(chunks: list[bytes]) -> str:
    if not chunks:
        return ""
    try:
        return b"".join(chunks).decode("utf-8", errors="replace")
    except UnicodeDecodeError:  # pragma: no cover - decode uses errors=replace
        return ""


def _close_pipes(process: subprocess.Popen[bytes]) -> None:
    """Close the child's pipe handles so drain threads can finish."""
    for pipe in (process.stdout, process.stderr):
        if pipe is not None and not pipe.closed:
            with contextlib.suppress(OSError):
                pipe.close()


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    """Best-effort termination of the spawned process and its children.

    The child is started in its own process group (POSIX session / Windows
    process group) so group termination covers grandchildren spawned by the
    tool. Where group termination is unavailable the direct child is killed;
    orphaned grandchildren are a documented residual risk for exotic tools.
    """
    try:
        if os.name == "nt":
            _terminate_windows_tree(process)
        else:
            os.killpg(os.getpgid(process.pid), 9)  # type: ignore[attr-defined]  # POSIX-only branch  # noqa: S606
    except (ProcessLookupError, OSError):
        _terminate_direct(process)


def _terminate_direct(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        with contextlib.suppress(OSError):
            process.kill()


def _terminate_windows_tree(process: subprocess.Popen[bytes]) -> None:
    """Terminate the child and its descendants via ``taskkill /T``."""
    if process.poll() is not None:
        return
    try:
        completed = subprocess.run(  # nosec B603, B607  # noqa: S603 - fixed command vector, no shell
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            capture_output=True,
            timeout=5.0,
        )
        if completed.returncode != 0:
            _terminate_direct(process)
    except (OSError, subprocess.SubprocessError):
        _terminate_direct(process)


__all__ = [
    "BinaryRunner",
    "CommandObservation",
    "CommandObserver",
    "CommandResult",
    "bind_active_execution",
    "clear_active_execution",
    "guard_option_value",
    "guard_positional_target",
    "register_command_observer",
    "unregister_command_observer",
]
