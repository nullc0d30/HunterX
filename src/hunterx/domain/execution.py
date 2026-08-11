# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Execution domain models.

Pure data contracts for the Tool Integration SDK execution layer. These models
describe a single tool execution: its context (mission, target, profile,
configuration, environment, permissions, timeouts, resource limits), its raw
output (stdout/stderr/files/structured formats), and its final result. No I/O,
no execution — the execution framework reads and writes these structures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from hunterx.plugins.sdk.results import EvidenceResult, FindingResult
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


class ExecutionStatus(Enum):
    """Lifecycle states of a single tool execution.

    Follows the ratified SDK pipeline: pending → scheduled → preparing →
    running → monitoring → collecting → validating → normalizing → storing →
    completed, with failure branches (failed, timed-out, cancelled, retrying).
    """

    PENDING = "pending"
    SCHEDULED = "scheduled"
    PREPARING = "preparing"
    RUNNING = "running"
    MONITORING = "monitoring"
    COLLECTING = "collecting"
    VALIDATING = "validating"
    NORMALIZING = "normalizing"
    STORING = "storing"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed-out"
    CANCELLED = "cancelled"
    RETRYING = "retrying"
    SKIPPED = "skipped"

    @property
    def is_terminal(self) -> bool:
        """Return ``True`` for states that end an execution."""
        return self in (
            ExecutionStatus.COMPLETED,
            ExecutionStatus.FAILED,
            ExecutionStatus.TIMED_OUT,
            ExecutionStatus.CANCELLED,
            ExecutionStatus.SKIPPED,
        )

    @property
    def is_success(self) -> bool:
        """Return ``True`` only for a completed execution."""
        return self is ExecutionStatus.COMPLETED


class FailureKind(Enum):
    """Classification of execution failures, driving retry/rollback policy."""

    NOT_RETRYABLE = "not-retryable"
    RETRYABLE = "retryable"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    RESOURCE_EXHAUSTED = "resource-exhausted"
    SANDBOX_VIOLATION = "sandbox-violation"
    MISSING_DEPENDENCY = "missing-dependency"
    CONFIGURATION = "configuration"
    INSTALLATION = "installation"
    OUTPUT_INVALID = "output-invalid"
    NORMALIZATION_FAILED = "normalization-failed"


class OutputFormat(Enum):
    """Canonical output formats a tool execution can produce."""

    STDOUT = "stdout"
    STDERR = "stderr"
    FILE = "file"
    JSON = "json"
    XML = "xml"
    CSV = "csv"
    TXT = "txt"
    YAML = "yaml"
    HTML = "html"
    BINARY = "binary"
    SCREENSHOT = "screenshot"
    PCAP = "pcap"


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """Retry configuration for a tool execution.

    Attributes:
        max_attempts: total execution attempts (1 = no retry).
        base_delay_s: initial backoff delay in seconds.
        max_delay_s: backoff ceiling in seconds.
        backoff_factor: multiplier applied to the delay each attempt.
        retryable_kinds: failure kinds eligible for retry.
        jitter: apply random jitter to backoff delays.

    """

    max_attempts: int = 1
    base_delay_s: float = 1.0
    max_delay_s: float = 60.0
    backoff_factor: float = 2.0
    retryable_kinds: tuple[FailureKind, ...] = (
        FailureKind.RETRYABLE,
        FailureKind.TIMEOUT,
        FailureKind.RESOURCE_EXHAUSTED,
    )
    jitter: bool = False

    def retries(self) -> int:
        """Return the number of retries permitted after the first attempt."""
        return max(0, self.max_attempts - 1)


@dataclass(frozen=True, slots=True)
class ResourceLimits:
    """Resource budget for a tool execution.

    A value of ``0`` means "unlimited" for numeric limits. The parallel job
    and queue limits are shared platform-wide rather than per execution.

    Attributes:
        max_cpu_percent: CPU utilization ceiling in percent.
        max_memory_mb: resident memory ceiling in MB.
        max_disk_mb: scratch disk ceiling in MB.
        network_allowed: whether outbound network is permitted.
        max_threads: thread ceiling for the execution.
        max_parallel_jobs: platform-wide concurrent execution cap.
        max_queue_size: platform-wide pending queue cap.
        timeout_seconds: default execution timeout.

    """

    max_cpu_percent: float = 0.0
    max_memory_mb: float = 0.0
    max_disk_mb: float = 0.0
    network_allowed: bool = True
    max_threads: int = 0
    max_parallel_jobs: int = 0
    max_queue_size: int = 0
    timeout_seconds: float = 0.0

    def capped(self) -> bool:
        """Return ``True`` when at least one numeric limit is set."""
        return any(
            (
                self.max_cpu_percent,
                self.max_memory_mb,
                self.max_disk_mb,
                self.max_threads,
                self.max_parallel_jobs,
                self.max_queue_size,
                self.timeout_seconds,
            )
        )


@dataclass(frozen=True, slots=True)
class ExecutionEnvironment:
    """Description of the environment an execution runs in."""

    os_name: str = ""
    architecture: str = ""
    python_version: str = ""
    platform_version: str = ""
    containerized: bool = False
    air_gapped: bool = False


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    """Everything an execution needs, passed to the tool and the pipeline.

    Attributes:
        execution_id: unique execution identifier (ULID).
        tool_id: the tool being executed.
        mission_id: owning mission (empty for ad-hoc runs).
        target: the target being assessed.
        target_type: canonical target kind (``host``, ``ip``, ``domain``, ``url``).
        profile: mission profile name.
        configuration: configuration/profile reference.
        tool_version: requested tool version.
        environment: environment description.
        permissions: granted permission flags.
        timeout_seconds: effective timeout (0 = unlimited).
        retry_policy: retry configuration.
        resource_limits: resource budget.
        working_directory: scratch working directory.
        output_directory: where artifacts are written.
        temp_directory: isolated temporary directory.
        correlation_id: correlation identifier for a batch/mission.
        parameters: tool parameters.
        created_at: UTC ISO-8601 creation timestamp.

    """

    execution_id: str = field(default_factory=generate_id)
    tool_id: str = ""
    mission_id: str = ""
    target: str = ""
    target_type: str = ""
    profile: str = ""
    configuration: str = ""
    tool_version: str = ""
    environment: ExecutionEnvironment = field(default_factory=ExecutionEnvironment)
    permissions: tuple[str, ...] = ()
    timeout_seconds: float = 0.0
    retry_policy: RetryPolicy = field(default_factory=RetryPolicy)
    resource_limits: ResourceLimits = field(default_factory=ResourceLimits)
    working_directory: str = ""
    output_directory: str = ""
    temp_directory: str = ""
    correlation_id: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utcnow_iso)

    @property
    def timeout_effective(self) -> float:
        """Return the effective timeout (explicit or from resource limits)."""
        if self.timeout_seconds > 0:
            return self.timeout_seconds
        return self.resource_limits.timeout_seconds


@dataclass(slots=True)
class ExecutionOutput:
    """Raw and structured output produced by a tool execution.

    Attributes:
        stdout: captured standard output text.
        stderr: captured standard error text.
        exit_code: process exit code (0 = success).
        files: paths of output files produced.
        json: parsed JSON output.
        xml: XML output text.
        csv: parsed CSV rows.
        txt: plain-text output.
        yaml: YAML output text.
        html: HTML output text.
        binary: binary payload bytes.
        screenshots: screenshot artifact paths.
        pcap_references: packet-capture artifact paths.
        formats: detected output formats present.

    """

    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    files: list[str] = field(default_factory=list)
    json: dict[str, Any] | None = None
    xml: str = ""
    csv: list[list[str]] = field(default_factory=list)
    txt: str = ""
    yaml: str = ""
    html: str = ""
    binary: bytes = b""
    screenshots: list[str] = field(default_factory=list)
    pcap_references: list[str] = field(default_factory=list)
    formats: set[OutputFormat] = field(default_factory=set)

    def add_format(self, fmt: OutputFormat) -> None:
        """Record that ``fmt`` is present in this output."""
        self.formats.add(fmt)

    @property
    def ok(self) -> bool:
        """Return ``True`` when the process exited cleanly."""
        return self.exit_code == 0

    @property
    def has_content(self) -> bool:
        """Return ``True`` when any output channel carried data."""
        return any(
            (
                self.stdout,
                self.stderr,
                self.files,
                self.json,
                self.xml,
                self.csv,
                self.txt,
                self.yaml,
                self.html,
                self.binary,
                self.screenshots,
                self.pcap_references,
            )
        )


@dataclass(slots=True)
class ExecutionResult:
    """The outcome of a single tool execution.

    Attributes:
        execution_id: the executed context's identifier.
        tool_id: the executed tool.
        status: terminal or in-progress status.
        output: collected output.
        error: error message on failure.
        failure_kind: failure classification.
        retry_count: number of retries performed.
        duration_ms: total elapsed execution time.
        started_at: UTC ISO-8601 start timestamp.
        completed_at: UTC ISO-8601 completion timestamp.
        normalized: whether output normalization succeeded.
        stored: whether results were persisted.
        events_published: whether lifecycle events were emitted.
        trace: ordered list of pipeline stage names visited.

    """

    execution_id: str = field(default_factory=generate_id)
    tool_id: str = ""
    status: ExecutionStatus = ExecutionStatus.PENDING
    output: ExecutionOutput = field(default_factory=ExecutionOutput)
    error: str = ""
    failure_kind: FailureKind | None = None
    retry_count: int = 0
    duration_ms: int = 0
    started_at: str = ""
    completed_at: str = ""
    normalized: bool = False
    stored: bool = False
    events_published: bool = False
    trace: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """Return ``True`` when the execution completed successfully."""
        return self.status is ExecutionStatus.COMPLETED

    @property
    def retryable(self) -> bool:
        """Return ``True`` when the failure kind permits another attempt."""
        from hunterx.domain.execution import FailureKind

        return self.failure_kind in (
            FailureKind.RETRYABLE,
            FailureKind.TIMEOUT,
            FailureKind.RESOURCE_EXHAUSTED,
        )

    def summarize(self) -> dict[str, Any]:
        """Return a JSON-safe summary for telemetry and events."""
        return {
            "execution_id": self.execution_id,
            "tool_id": self.tool_id,
            "status": self.status.value,
            "error": self.error,
            "failure_kind": self.failure_kind.value if self.failure_kind else "",
            "retry_count": self.retry_count,
            "duration_ms": self.duration_ms,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "normalized": self.normalized,
            "stored": self.stored,
        }


@dataclass(slots=True)
class ToolExecutionEvidence:
    """Findings and evidence extracted from a completed execution.

    Bridges the raw :class:`ExecutionOutput` and the canonical tool output
    consumed by the correlation and reporting layers.

    Attributes:
        tool_id: the executed tool.
        findings: normalized findings.
        evidence: supporting evidence.
        assets: discovered assets.
        duration_ms: execution duration.

    """

    tool_id: str = ""
    findings: list[FindingResult] = field(default_factory=list)
    evidence: list[EvidenceResult] = field(default_factory=list)
    assets: list[dict[str, Any]] = field(default_factory=list)
    duration_ms: int = 0
