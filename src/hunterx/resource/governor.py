# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission Resource Governor.

The single authoritative resource-governance layer for a HunterX mission. It
manages the resource envelope of the ENTIRE mission process tree (HunterX
process + child tools + grandchildren + external binaries) across RAM budget,
CPU/concurrency budget, execution budget, tool concurrency, probe concurrency,
model-call concurrency, queue limits, evidence/context limits and graceful
degradation.

Design rules:

- The absolute HunterX RAM ceiling is 3 GB by default and is an upper safety
  ceiling, never a default allocation. The effective mission budget is derived
  from the runtime environment (bare-metal/VM/WSL/container via
  :mod:`hunterx.resource.detect`).
- The governor evaluates a :class:`~hunterx.resource.state.ResourceState`
  (NORMAL / CONSTRAINED / DEGRADED / CRITICAL / EMERGENCY) from the live
  process-tree RSS and host pressure, and adapts concurrency/admission.
- Every external tool execution, probe, model call and assessment scheduling
  passes through the governor for admission control.
- On EMERGENCY the governor stops new work, terminates the registered process
  tree gracefully, and the mission runner persists state and marks the mission
  degraded with a structured resource reason.
- Telemetry logs are throttled (``[RESOURCE] ...``) so stdout is never flooded.
"""

from __future__ import annotations

import contextlib
import logging
import os
import signal
import threading
import time
from dataclasses import dataclass
from typing import Any

from hunterx.resource.admission import Admission
from hunterx.resource.config import ResourceConfig, ResourceMetrics
from hunterx.resource.detect import EnvironmentInfo, describe_environment, detect_environment
from hunterx.resource.sampler import ProcessSnapshot, ProcessTreeSampler
from hunterx.resource.state import ResourceState

#: Time (seconds) to wait for a SIGTERM'ed child process before SIGKILL.
_TERM_GRACE_S = 3.0

#: Log throttling for non-state-change telemetry.
_DEFAULT_TELEMETRY_INTERVAL_S = 5.0

#: Process-tree CPU budget when ``cpu_budget_percent == 0`` (percent per core).
_AUTO_CPU_PER_CORE_PERCENT = 100.0


@dataclass(slots=True)
class MissionAccount:
    """Per-mission resource account kept by the governor."""

    mission_id: str = ""
    started_monotonic: float = 0.0
    deadline_s: float = 0.0
    replan_used: int = 0
    tool_executions: int = 0
    model_calls: int = 0
    probes: int = 0


class ResourceGovernor:
    """Centralized resource governance for the whole mission process tree."""

    def __init__(
        self,
        config: ResourceConfig | None = None,
        *,
        environment: EnvironmentInfo | None = None,
        sampler: ProcessTreeSampler | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self._config = config or ResourceConfig()
        self._environment = environment or detect_environment()
        self._sampler = sampler if sampler is not None else ProcessTreeSampler()
        self._logger = logger or logging.getLogger("hunterx.resource")
        self._lock = threading.RLock()
        self._accounts: dict[str, MissionAccount] = {}
        self._processes: dict[int, Any] = {}
        self._active_tools = 0
        self._active_model_calls = 0
        self._active_probes = 0
        self._state = ResourceState.NORMAL
        self._last_sample: ProcessSnapshot | None = None
        self._peak_rss_mb = 0.0
        self._last_log_ts = 0.0
        self._budget_mb = self._derive_budget_mb()
        self._ceiling_mb = self._derive_ceiling_mb()
        #: Background sampling watchdog (optional). Started by
        #: :meth:`start_monitoring`; keeps the resource state current even while
        #: the main thread is busy inside a single blocking operation, so a
        #: runaway can be detected between explicit evaluation points.
        self._watchdog_thread: threading.Thread | None = None
        self._watchdog_stop = threading.Event()

    # -- watchdog -----------------------------------------------------------------

    def start_monitoring(self) -> None:
        """Start the background sampling watchdog (daemon thread).

        Samples the process tree every ``watchdog_interval_s`` and updates the
        resource state. Disabled when the configured interval is ``0``. Safe to
        call multiple times (idempotent).
        """
        if self._config.watchdog_interval_s <= 0:
            return
        if self._watchdog_thread is not None and self._watchdog_thread.is_alive():
            return
        self._watchdog_stop.clear()
        self._watchdog_thread = threading.Thread(
            target=self._watchdog_loop,
            name="hunterx-resource-watchdog",
            daemon=True,
        )
        self._watchdog_thread.start()

    def stop_monitoring(self, *, join_s: float = 2.0) -> None:
        """Stop the background sampling watchdog (best-effort join)."""
        self._watchdog_stop.set()
        thread = self._watchdog_thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=join_s)
        self._watchdog_thread = None

    def emergency_raised(self) -> bool:
        """Return ``True`` when the current resource state is EMERGENCY."""
        return self.state() is ResourceState.EMERGENCY

    def _watchdog_loop(self) -> None:
        interval = max(0.05, self._config.watchdog_interval_s)
        while not self._watchdog_stop.wait(interval):
            try:
                self.evaluate()
            except Exception:  # noqa: BLE001 - the watchdog must never die
                continue

    # -- derived envelope ------------------------------------------------------

    def _derive_budget_mb(self) -> float:
        """Derive the effective mission RAM budget from the environment.

        ``budget_ratio`` (default 0.5) of the effective environment limit,
        bounded by the absolute ceiling. A 4 GB environment therefore yields a
        ~2 GB budget; an 8 GB environment reaches the absolute 3 GB ceiling; a
        16 GB environment stays at the ceiling.
        """
        cfg = self._config
        limit = self._environment.effective_memory_limit_mb
        if limit <= 0:
            return min(cfg.memory_ceiling_mb, cfg.memory_ceiling_mb)
        return min(cfg.memory_ceiling_mb, limit * cfg.budget_ratio)

    def _derive_ceiling_mb(self) -> float:
        """Derive the effective absolute ceiling, preserving host headroom.

        The ceiling is the absolute configured ceiling capped so HunterX never
        consumes more than ``host_headroom_ratio`` of the physical host RAM (a
        small host must keep usable headroom).
        """
        cfg = self._config
        host = self._environment.total_memory_mb
        budget = self._budget_mb
        headroom_cap = host * cfg.host_headroom_ratio if host > 0 else 0.0
        if headroom_cap <= 0:
            return cfg.memory_ceiling_mb
        return min(cfg.memory_ceiling_mb, max(budget, headroom_cap))

    def mission_budget_mb(self) -> float:
        """Return the effective mission RAM budget (MiB)."""
        return self._budget_mb

    def memory_ceiling_mb(self) -> float:
        """Return the effective absolute RAM ceiling (MiB)."""
        return self._ceiling_mb

    def tool_timeout_s(self) -> float:
        """Return the hard per-tool wall-clock deadline."""
        return self._config.tool_timeout_s

    def model_timeout_s(self) -> float:
        """Return the hard per-model-call wall-clock deadline."""
        return self._config.model_timeout_s

    def max_queue_depth(self) -> int:
        """Return the assessment-queue backpressure cap (0 = unbounded)."""
        return self._config.max_queue_depth

    def max_probes_per_cycle(self) -> int:
        """Return the max differential probes executed per mission cycle."""
        return self._config.max_probes_per_cycle

    def max_observation_content_bytes(self) -> int:
        """Return the per-observation content byte cap retained in memory."""
        return self._config.max_observation_content_bytes

    def max_aggregate_state_bytes(self) -> int:
        """Return the mission-aggregate byte cap retained in memory."""
        return self._config.max_aggregate_state_bytes

    def environment(self) -> EnvironmentInfo:
        """Return the detected effective environment."""
        return self._environment

    # -- mission lifecycle ------------------------------------------------------

    def start_mission(self, mission_id: str, *, deadline_s: float | None = None) -> None:
        """Register an active mission with the governor.

        ``deadline_s`` overrides the configured mission deadline for this
        mission (``0`` = unlimited for this mission). Idempotent: an already
        registered mission (e.g. pre-started by a caller with a specific
        deadline) is kept unchanged.
        """
        with self._lock:
            if mission_id in self._accounts:
                return
            effective_deadline = self._config.mission_deadline_s if deadline_s is None else deadline_s
            account = MissionAccount(
                mission_id=mission_id,
                started_monotonic=time.monotonic(),
                deadline_s=effective_deadline,
            )
            self._accounts[mission_id] = account

    def end_mission(self, mission_id: str) -> None:
        """Deregister a mission from the governor."""
        with self._lock:
            self._accounts.pop(mission_id, None)

    def mission_remaining_s(self, mission_id: str) -> float:
        """Return the mission's remaining wall-clock budget (``0`` when expired)."""
        with self._lock:
            account = self._accounts.get(mission_id)
        if account is None:
            return 0.0
        if account.deadline_s <= 0:
            return float("inf")
        return max(0.0, account.deadline_s - (time.monotonic() - account.started_monotonic))

    def mission_deadline_exceeded(self, mission_id: str) -> bool:
        """Return ``True`` when the mission's configured deadline has expired."""
        with self._lock:
            account = self._accounts.get(mission_id)
        if account is None or account.deadline_s <= 0:
            return False
        return time.monotonic() - account.started_monotonic >= account.deadline_s

    # -- resource evaluation ------------------------------------------------------

    def snapshot(self) -> ProcessSnapshot:
        """Return the latest process-tree/host resource snapshot (never raises)."""
        try:
            return self._sampler.snapshot()
        except Exception:  # noqa: BLE001 - sampling must never raise
            return ProcessSnapshot()

    def evaluate(self) -> ResourceState:
        """Evaluate the live resource state of the process tree and host.

        State transitions (see :class:`ResourceState` for behaviour):

        - EMERGENCY: process-tree RSS >= effective ceiling, or host memory
          pressure >= ``system_emergency_ratio``.
        - CRITICAL: pressure >= ``memory_hard_ratio`` (or host pressure 0.90).
        - DEGRADED: pressure >= ``memory_high_ratio`` (or host pressure 0.85).
        - CONSTRAINED: pressure >= ``memory_soft_ratio``.
        - otherwise NORMAL.

        Thresholds are configuration-driven (``ResourceConfig``).
        """
        sample = self.snapshot()
        with self._lock:
            self._last_sample = sample
            self._peak_rss_mb = max(self._peak_rss_mb, sample.rss_mb)

        budget = self._budget_mb or self._ceiling_mb or 1.0
        pressure = sample.rss_mb / budget if budget else 0.0
        system_pressure = 0.0
        if sample.host_total_mb > 0:
            system_pressure = max(0.0, min(1.0, sample.host_used_mb / sample.host_total_mb))

        cfg = self._config
        state: ResourceState = ResourceState.NORMAL
        if self._ceiling_mb and sample.rss_mb >= self._ceiling_mb or system_pressure >= cfg.system_emergency_ratio:
            state = ResourceState.EMERGENCY
        elif pressure >= cfg.memory_hard_ratio or system_pressure >= 0.90:
            state = ResourceState.CRITICAL
        elif pressure >= cfg.memory_high_ratio or system_pressure >= 0.85:
            state = ResourceState.DEGRADED
        elif pressure >= cfg.memory_soft_ratio:
            state = ResourceState.CONSTRAINED

        self._transition(state, sample, pressure, system_pressure)
        return state

    def state(self) -> ResourceState:
        """Return the last evaluated state (evaluates on first call)."""
        with self._lock:
            if self._last_sample is None:
                return self.evaluate()
            return self._state

    def _transition(
        self,
        state: ResourceState,
        sample: ProcessSnapshot,
        pressure: float,
        system_pressure: float,
    ) -> None:
        with self._lock:
            previous = self._state
            self._state = state
            changed = previous != state
            now = time.monotonic()
        if changed or now - self._last_log_ts >= self._config.telemetry_interval_s:
            self._last_log_ts = now
            self._log_telemetry(state, sample, pressure, system_pressure, changed=changed)

    def _log_telemetry(
        self,
        state: ResourceState,
        sample: ProcessSnapshot,
        pressure: float,
        system_pressure: float,
        *,
        changed: bool,
    ) -> None:
        prefix = "[RESOURCE]"
        if changed:
            self._logger.info(
                "%s state transition: current process-tree RSS %.1f MiB, "
                "mission budget %.0f MiB, ceiling %.0f MiB, pressure %.0f%%, "
                "host pressure %.0f%%, concurrency state %s",
                prefix,
                sample.rss_mb,
                self._budget_mb,
                self._ceiling_mb,
                pressure * 100.0,
                system_pressure * 100.0,
                state.value,
            )
        else:
            self._logger.info(
                "%s effective memory limit: %.0f MiB | mission memory budget: %.0f MiB | "
                "current process-tree RSS: %.1f MiB | CPU: %.1f%% | CPUs: %d | state: %s",
                prefix,
                self._environment.effective_memory_limit_mb,
                self._budget_mb,
                sample.rss_mb,
                sample.cpu_percent,
                sample.cpu_cores,
                state.value,
            )

    # -- adaptive concurrency -------------------------------------------------------

    def suggested_concurrency(self, base: int) -> int:
        """Return the bounded concurrency suggested by the current resource state.

        NORMAL → ``base``; CONSTRAINED → ~60%; DEGRADED → ~35%; CRITICAL → 1;
        EMERGENCY → 0 (no new work).
        """
        if base <= 0:
            return 0
        state = self.state()
        if state is ResourceState.EMERGENCY:
            return 0
        if state is ResourceState.CRITICAL:
            return 1
        if state is ResourceState.DEGRADED:
            return max(1, round(base * 0.35))
        if state is ResourceState.CONSTRAINED:
            return max(1, round(base * 0.6))
        return base

    def cpu_budget_percent(self) -> float:
        """Return the effective process-tree CPU budget in percent."""
        configured = self._config.cpu_budget_percent
        if configured > 0:
            return configured
        return max(1, self._environment.cpu_count) * _AUTO_CPU_PER_CORE_PERCENT

    # -- admission control ------------------------------------------------------------

    def _admission_state(self) -> ResourceState:
        """Return the live resource state for an admission decision.

        Admission re-samples the process tree (fresh ``evaluate``) rather than
        using a cached state, so a memory climb that happened inside a long
        operation is seen the moment the next operation asks for admission.
        """
        return self.evaluate()

    def admit_tool(
        self,
        *,
        memory_class: str = "low",
        cpu_class: str = "low",
        tool_id: str = "",
        timeout_s: float | None = None,
    ) -> Admission:
        """Approve/defer/deny an external tool execution.

        ``memory_class``/``cpu_class`` are ``low``/``medium``/``high``. Under
        CRITICAL/EMERGENCY expensive tools are denied; under DEGRADED high-memory
        tools are deferred. ``max_tool_concurrency`` is enforced with an active
        count (callers must release with :meth:`release_tool`).
        """
        state = self._admission_state()
        if state is ResourceState.EMERGENCY:
            return Admission.deny("emergency: memory ceiling reached; no new tool executions")
        if state is ResourceState.CRITICAL:
            if memory_class in ("high", "medium") or cpu_class in ("high", "medium"):
                return Admission.deny(f"critical: stopping expensive tool executions ({tool_id or 'tool'})")
        elif state is ResourceState.DEGRADED and memory_class == "high":
            return Admission.defer(f"degraded: deferring high-memory tool ({tool_id or 'tool'})")
        with self._lock:
            if self._active_tools >= self._config.max_tool_concurrency:
                return Admission.defer("tool concurrency cap reached", delay_s=1.0)
            self._active_tools += 1
        return Admission.allow()

    def release_tool(self, admission: Admission | None = None) -> None:
        """Release a previously approved tool slot (idempotent)."""
        if admission is not None and not admission.approved:
            return
        with self._lock:
            self._active_tools = max(0, self._active_tools - 1)

    def admit_model_call(self) -> Admission:
        """Approve/deny a model (LLM) call.

        Model calls are expensive (large context, long wall-clock): under
        CRITICAL/EMERGENCY they are denied, and ``max_model_concurrency`` is
        enforced.
        """
        state = self._admission_state()
        if state in (ResourceState.EMERGENCY, ResourceState.CRITICAL):
            return Admission.deny(f"{state.value}: stopping new model calls")
        with self._lock:
            if self._active_model_calls >= self._config.max_model_concurrency:
                return Admission.defer("model concurrency cap reached", delay_s=1.0)
            self._active_model_calls += 1
        return Admission.allow()

    def release_model_call(self, admission: Admission | None = None) -> None:
        """Release a previously approved model-call slot (idempotent)."""
        if admission is not None and not admission.approved:
            return
        with self._lock:
            self._active_model_calls = max(0, self._active_model_calls - 1)

    def admit_probe(self, *, pending: int = 0) -> Admission:
        """Approve/deny an HTTP differential probe.

        Probes are cheap individually but can flood in bulk: under CRITICAL they
        are denied and ``max_probe_concurrency`` bounds simultaneous probes.
        """
        state = self._admission_state()
        if state in (ResourceState.EMERGENCY, ResourceState.CRITICAL):
            return Admission.deny(f"{state.value}: stopping new probes")
        with self._lock:
            if self._active_probes >= self._config.max_probe_concurrency:
                return Admission.defer("probe concurrency cap reached", delay_s=0.5)
            self._active_probes += 1
        return Admission.allow()

    def release_probe(self, admission: Admission | None = None) -> None:
        """Release a previously approved probe slot (idempotent)."""
        if admission is not None and not admission.approved:
            return
        with self._lock:
            self._active_probes = max(0, self._active_probes - 1)

    def admit_assessment(self, *, pending: int = 0) -> Admission:
        """Approve/deny scheduling of a new assessment-queue task.

        Enforces both the resource state and the ``max_queue_depth`` backpressure
        cap so the assessment queue can never consume unbounded RAM when the
        consumers cannot keep up.
        """
        state = self._admission_state()
        if state in (ResourceState.EMERGENCY, ResourceState.CRITICAL):
            return Admission.deny(f"{state.value}: stopping new assessment scheduling")
        if self._config.max_queue_depth and pending >= self._config.max_queue_depth:
            return Admission.defer(f"assessment queue at capacity ({pending})", delay_s=2.0)
        return Admission.allow()

    # -- replanning / work budget -----------------------------------------------------

    def replan_budget(self, mission_id: str) -> int:
        """Return the remaining replan-scheduling budget for ``mission_id``."""
        with self._lock:
            account = self._accounts.get(mission_id)
        if account is None:
            return self._config.max_replan_cycles
        return max(0, self._config.max_replan_cycles - account.replan_used)

    def consume_replan(self, mission_id: str) -> bool:
        """Consume one replan-scheduling slot; return ``False`` when exhausted."""
        with self._lock:
            account = self._accounts.get(mission_id)
            if account is None:
                return True
            if account.replan_used >= self._config.max_replan_cycles:
                return False
            account.replan_used += 1
            return True

    def record_execution(self, mission_id: str) -> None:
        """Record a tool execution against the mission account (telemetry)."""
        with self._lock:
            account = self._accounts.get(mission_id)
            if account is not None:
                account.tool_executions += 1

    def record_model_call(self, mission_id: str) -> None:
        """Record a model call against the mission account (telemetry)."""
        with self._lock:
            account = self._accounts.get(mission_id)
            if account is not None:
                account.model_calls += 1

    def record_probe(self, mission_id: str) -> None:
        """Record a probe against the mission account (telemetry)."""
        with self._lock:
            account = self._accounts.get(mission_id)
            if account is not None:
                account.probes += 1

    # -- process-tree management ------------------------------------------------------

    def register_process(self, process: Any) -> None:
        """Register a spawned child process so emergency termination can reach it."""
        pid = getattr(process, "pid", None)
        if pid is None:
            return
        with self._lock:
            self._processes[pid] = process

    def unregister_process(self, process: Any) -> None:
        """Unregister a finished child process."""
        pid = getattr(process, "pid", None)
        if pid is None:
            return
        with self._lock:
            self._processes.pop(pid, None)

    def active_process_count(self) -> int:
        """Return the number of registered child processes."""
        with self._lock:
            return len(self._processes)

    def terminate_process_tree(self, *, grace_s: float = _TERM_GRACE_S) -> int:
        """Terminate every registered child process (graceful, then forced).

        Sends SIGTERM to the child's process group, waits up to ``grace_s`` and
        SIGKILLs whatever remains. Returns the number of processes handled. Safe
        to call from the mission runner during an EMERGENCY stop.
        """
        with self._lock:
            processes = list(self._processes.values())
            self._processes.clear()
        terminated = 0
        for process in processes:
            if self._terminate_one(process, grace_s=grace_s):
                terminated += 1
        return terminated

    def _terminate_one(self, process: Any, *, grace_s: float) -> bool:
        pid = getattr(process, "pid", None)
        if pid is None or _process_alive(process) is False:
            return False
        try:
            _signal_process_group(pid, signal.SIGTERM)
            deadline = time.monotonic() + grace_s
            while time.monotonic() < deadline:
                if _process_alive(process) is False:
                    return True
                time.sleep(0.05)
            if _process_alive(process) is False:
                return True
            _signal_process_group(pid, signal.SIGKILL)
            return True
        except Exception:  # noqa: BLE001 - best-effort termination
            with contextlib.suppress(Exception):
                process.kill()
            return True

    # -- telemetry ---------------------------------------------------------------

    def metrics(self) -> ResourceMetrics:
        """Return an operator-facing telemetry snapshot."""
        sample = self._last_sample or self.snapshot()
        budget = self._budget_mb or 1.0
        pressure = sample.rss_mb / budget if budget else 0.0
        system_pressure = 0.0
        if sample.host_total_mb > 0:
            system_pressure = max(0.0, min(1.0, sample.host_used_mb / sample.host_total_mb))
        with self._lock:
            active_tools = self._active_tools
            active_model = self._active_model_calls
            missions = len(self._accounts)
            state = self._state
            peak = self._peak_rss_mb
        return ResourceMetrics(
            state=state.value,
            rss_mb=sample.rss_mb,
            peak_rss_mb=peak,
            budget_mb=self._budget_mb,
            ceiling_mb=self._ceiling_mb,
            memory_pressure=pressure,
            system_memory_pressure=system_pressure,
            cpu_percent=sample.cpu_percent,
            cpu_cores=sample.cpu_cores,
            effective_memory_limit_mb=self._environment.effective_memory_limit_mb,
            environment=describe_environment(self._environment),
            active_tools=active_tools,
            active_model_calls=active_model,
            process_count=sample.process_count,
            mission_count=missions,
        )

    def report(self) -> dict[str, Any]:
        """Return a JSON-safe resource report for mission telemetry."""
        return self.metrics().to_dict()

    def describe_limits(self) -> dict[str, Any]:
        """Return the resolved resource envelope (for logs and mission telemetry)."""
        return {
            "environment": describe_environment(self._environment),
            "effective_memory_limit_mb": self._environment.effective_memory_limit_mb,
            "mission_budget_mb": self._budget_mb,
            "absolute_ceiling_mb": self._ceiling_mb,
            "cpu_count": self._environment.cpu_count,
            "cpu_budget_percent": self.cpu_budget_percent(),
            "tool_timeout_s": self._config.tool_timeout_s,
            "model_timeout_s": self._config.model_timeout_s,
            "mission_deadline_s": self._config.mission_deadline_s,
            "max_tool_concurrency": self._config.max_tool_concurrency,
            "max_probe_concurrency": self._config.max_probe_concurrency,
            "max_model_concurrency": self._config.max_model_concurrency,
            "max_queue_depth": self._config.max_queue_depth,
            "max_replan_cycles": self._config.max_replan_cycles,
        }


def _process_alive(process: Any) -> bool | None:
    poll = getattr(process, "poll", None)
    if callable(poll):
        try:
            return poll() is None
        except Exception:  # noqa: BLE001
            return None
    return None


def _signal_process_group(pid: int, sig: int) -> None:
    if os.name == "nt":
        raise OSError("process-group signalling is POSIX-only")
    os.killpg(os.getpgid(pid), sig)  # type: ignore[attr-defined]


__all__ = ["MissionAccount", "ResourceGovernor"]
