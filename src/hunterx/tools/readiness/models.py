# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool Readiness — pure data contracts.

Machine-readable definitions of external security tools, per-tool readiness
verdicts, capability coverage and mission preflight results. These models are
the shared vocabulary between the discovery, provisioning, readiness and
preflight layers. No I/O happens here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ToolReadinessStatus(Enum):
    """Lifecycle states of a tool's readiness probe.

    ``UNKNOWN`` — not yet probed.
    ``DISCOVERING`` — probe in progress.
    ``AVAILABLE`` — executable found, executability verified, version detected.
    ``MISSING`` — executable not found on PATH (tool does not exist).
    ``BROKEN`` — executable exists but cannot execute / version probe failed.
    ``OUTDATED`` — installed version below the supported minimum.
    ``UNSUPPORTED`` — no supported installation method for this platform.
    ``PROVISIONING_FAILED`` — an install attempt was made but verification failed.

    """

    UNKNOWN = "unknown"
    DISCOVERING = "discovering"
    AVAILABLE = "available"
    MISSING = "missing"
    BROKEN = "broken"
    OUTDATED = "outdated"
    UNSUPPORTED = "unsupported"
    PROVISIONING_FAILED = "provisioning_failed"


class CapabilityLevel(Enum):
    """Importance of a mission capability (drives preflight gating)."""

    REQUIRED = "required"
    RECOMMENDED = "recommended"
    OPTIONAL = "optional"


class PreflightStatus(Enum):
    """Mission preflight verdict.

    ``PASS`` — every required capability has an available provider.
    ``DEGRADED`` — required capabilities are satisfied; optional/recommended
        providers are missing (mission may run with reduced coverage).
    ``BLOCKED`` — a required capability has no provider and provisioning is not
        possible or failed; the mission must not enter active execution.

    """

    PASS = "passed"
    DEGRADED = "degraded"
    BLOCKED = "blocked"


@dataclass(frozen=True, slots=True)
class InstallMethod:
    """A trusted, static installation method for one tool.

    The manifest is the only source of install commands: package names and go
    module paths are static constants. User or target input NEVER influences
    these values.

    Attributes:
        kind: installation family (``apt``, ``brew``, ``pacman``, ``dnf``,
            ``go``, ``cargo``, ``pip``, ``pipx``, ``npm``, ``script``).
        package: package name for package-manager families.
        name: module/repo path for ``go``/``cargo`` or script id for ``script``.
        platforms: platforms this method targets.
        requires_elevation: whether the method needs root/administrator rights.
        timeout_s: hard per-method timeout in seconds; ``0`` means the
            provisioner's per-kind default applies.

    """

    kind: str
    package: str = ""
    name: str = ""
    platforms: tuple[str, ...] = ("linux", "darwin", "windows")
    requires_elevation: bool = False
    timeout_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping of this method."""
        return {
            "kind": self.kind,
            "package": self.package,
            "name": self.name,
            "platforms": list(self.platforms),
            "requires_elevation": self.requires_elevation,
            "timeout_s": self.timeout_s,
        }


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    """Machine-readable definition of an integrated external tool.

    Fields not present in the static manifest are derived from the TIP
    knowledge contract (``cli_binary``, capabilities, version constraints).
    ``capabilities`` holds the planner capability ids (underscore form) that
    this tool provides.

    Attributes:
        tool_id: canonical HunterX tool id.
        name: display name.
        executable: primary binary name on PATH.
        aliases: alternative binary names to probe.
        version_command: argv used to request the version.
        version_regex: regex used to extract the version from the output.
        min_version: minimum supported version (semver) or ``""``.
        capabilities: planner capability ids provided.
        platform_support: platforms this tool supports.
        installation_methods: trusted static installation methods.
        kind: ``"binary"`` for external executables, ``"inprocess"`` for
            in-process adapters that need no external binary.
        profiles: installation profiles that include this tool.
        required: ``True`` when the tool is part of the base HunterX
            environment (the ``minimal`` profile).

    """

    tool_id: str
    name: str = ""
    executable: str = ""
    aliases: tuple[str, ...] = ()
    version_command: tuple[str, ...] = ("--version",)
    version_regex: str = ""
    min_version: str = ""
    capabilities: tuple[str, ...] = ()
    platform_support: tuple[str, ...] = ("linux", "darwin", "windows")
    installation_methods: tuple[InstallMethod, ...] = ()
    kind: str = "binary"
    profiles: tuple[str, ...] = ("full",)
    required: bool = False
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping of this definition."""
        return {
            "tool_id": self.tool_id,
            "name": self.name,
            "executable": self.executable,
            "aliases": list(self.aliases),
            "version_command": list(self.version_command),
            "version_regex": self.version_regex,
            "min_version": self.min_version,
            "capabilities": list(self.capabilities),
            "platform_support": list(self.platform_support),
            "installation_methods": [method.to_dict() for method in self.installation_methods],
            "kind": self.kind,
            "profiles": list(self.profiles),
            "required": self.required,
            "description": self.description,
        }


@dataclass(slots=True)
class ToolReadiness:
    """The readiness verdict for one tool after a discovery probe.

    Attributes:
        tool_id: the tool under probe.
        status: the classified readiness status.
        executable: the binary name resolved.
        path: absolute path of the discovered binary (``""`` when missing).
        version: normalized detected version.
        expected_version: known/recommended version from the catalog.
        detected_command: the version probe argv actually run.
        stdout / stderr: captured probe output.
        error: error message when the probe failed.
        definition: the tool definition probed.
        install_methods: install methods available on the current platform.
        platform: detected platform id.

    """

    tool_id: str
    status: ToolReadinessStatus = ToolReadinessStatus.UNKNOWN
    executable: str = ""
    path: str = ""
    version: str = ""
    expected_version: str = ""
    detected_command: tuple[str, ...] = ()
    stdout: str = ""
    stderr: str = ""
    error: str = ""
    definition: ToolDefinition | None = None
    install_methods: tuple[InstallMethod, ...] = ()
    platform: str = ""
    #: Executable shadowing/collision report. Each entry describes a same-named
    #: executable elsewhere on the PATH (or in a preferred HunterX tool
    #: directory) that competes with the resolved provider. The probe
    #: validates which one is actually the expected security-tool provider.
    collisions: tuple[dict[str, str], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping of this readiness verdict."""
        return {
            "tool_id": self.tool_id,
            "status": self.status.value,
            "executable": self.executable,
            "path": self.path,
            "version": self.version,
            "expected_version": self.expected_version,
            "detected_command": list(self.detected_command),
            "error": self.error,
            "install_methods": [method.to_dict() for method in self.install_methods],
            "platform": self.platform,
            "collisions": [dict(entry) for entry in self.collisions],
        }


@dataclass(slots=True)
class CapabilityReadiness:
    """Readiness of one mission capability.

    Attributes:
        capability: planner capability id.
        level: capability importance (required/recommended/optional).
        providers: all registered candidate provider tool ids.
        available: providers currently available (healthy).
        missing: providers not available.
        status: ``"ready"`` when at least one provider is available,
            ``"missing"`` otherwise.

    """

    capability: str
    level: CapabilityLevel = CapabilityLevel.REQUIRED
    providers: tuple[str, ...] = ()
    available: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()

    @property
    def ready(self) -> bool:
        """Return ``True`` when at least one provider is available."""
        return bool(self.available)

    @property
    def status(self) -> str:
        """Return the human capability status."""
        return "ready" if self.ready else "missing"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping of this capability readiness."""
        return {
            "capability": self.capability,
            "level": self.level.value,
            "status": self.status,
            "providers": list(self.providers),
            "available": list(self.available),
            "missing": list(self.missing),
        }


@dataclass(slots=True)
class ReadinessReport:
    """Full snapshot of the toolchain readiness for one platform.

    Attributes:
        platform: the detected platform mapping.
        tools: readiness verdicts for every definition.
        capabilities: capability coverage derived from the tool verdicts.
        summary: aggregate counters.

    """

    platform: dict[str, Any] = field(default_factory=dict)
    tools: list[ToolReadiness] = field(default_factory=list)
    capabilities: list[CapabilityReadiness] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping of the report."""
        return {
            "platform": self.platform,
            "tools": [tool.to_dict() for tool in self.tools],
            "capabilities": [capability.to_dict() for capability in self.capabilities],
            "summary": dict(self.summary),
        }


@dataclass(slots=True)
class InstallOutcome:
    """Result of one provisioning attempt.

    Attributes:
        tool_id: the tool provisioned.
        success: ``True`` when post-install verification passed.
        status: readiness status after the attempt.
        version: detected version after install.
        method: the install method used (or ``None`` when unsupported).
        command: the static command executed.
        stdout / stderr: captured install output.
        error: error message on failure.
        skipped: ``True`` when the tool was already available (idempotent skip).

    """

    tool_id: str
    success: bool = False
    status: ToolReadinessStatus = ToolReadinessStatus.MISSING
    version: str = ""
    method: InstallMethod | None = None
    command: tuple[str, ...] = ()
    stdout: str = ""
    stderr: str = ""
    error: str = ""
    skipped: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping of this outcome."""
        return {
            "tool_id": self.tool_id,
            "success": self.success,
            "status": self.status.value,
            "version": self.version,
            "method": self.method.to_dict() if self.method is not None else None,
            "command": list(self.command),
            "error": self.error,
            "skipped": self.skipped,
        }


@dataclass(frozen=True, slots=True)
class InstallProgress:
    """Live per-tool progress event emitted during provisioning.

    The installer UI consumes these events to render ``[N/M] tool ... ✓``
    lines without polluting the provisioning layer with terminal concerns.

    Attributes:
        index: 1-based position of the tool in the current install run.
        total: total number of tools in the run.
        tool_id: the tool currently being provisioned.
        phase: ``"start"`` before the external installer runs, ``"done"``
            after an outcome has been produced.
        outcome: the resulting :class:`InstallOutcome` (only on ``"done"``).

    """

    index: int
    total: int
    tool_id: str
    phase: str
    outcome: InstallOutcome | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping of this event."""
        return {
            "index": self.index,
            "total": self.total,
            "tool_id": self.tool_id,
            "phase": self.phase,
            "outcome": self.outcome.to_dict() if self.outcome is not None else None,
        }


@dataclass(slots=True)
class ToolInventory:
    """Grouped view of a readiness probe (for compact installer output).

    Splits the per-tool verdicts into the five actionable buckets so the
    installer can render ``Available`` / ``Missing`` / ``Broken`` /
    ``Outdated`` / ``Unsupported`` inventories independently of the detailed
    report.

    Attributes:
        available: tool ids whose binary is present and verifiable.
        missing: tool ids with no executable on PATH.
        broken: tool ids whose executable exists but cannot be verified.
        outdated: tool ids whose installed version is below the minimum.
        unsupported: tool ids with no compatible install method on this platform.

    """

    available: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    broken: list[str] = field(default_factory=list)
    outdated: list[str] = field(default_factory=list)
    unsupported: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping of this inventory."""
        return {
            "available": list(self.available),
            "missing": list(self.missing),
            "broken": list(self.broken),
            "outdated": list(self.outdated),
            "unsupported": list(self.unsupported),
        }

    @classmethod
    def from_report(cls, report: ReadinessReport) -> ToolInventory:
        """Build the grouped inventory from a :class:`ReadinessReport`."""
        inventory = cls()
        for verdict in report.tools:
            bucket = {
                ToolReadinessStatus.AVAILABLE: inventory.available,
                ToolReadinessStatus.MISSING: inventory.missing,
                ToolReadinessStatus.BROKEN: inventory.broken,
                ToolReadinessStatus.OUTDATED: inventory.outdated,
                ToolReadinessStatus.UNSUPPORTED: inventory.unsupported,
            }.get(verdict.status)
            if bucket is not None:
                bucket.append(verdict.tool_id)
        return inventory


@dataclass(slots=True)
class PreflightResult:
    """Mission preflight verdict.

    Attributes:
        status: the mission verdict.
        mission_id: the mission assessed.
        required_missing: required capabilities with no available provider.
        missing_tools: concrete missing tool ids for the blocked capabilities.
        optional_missing: capabilities (recommended/optional) without providers.
        provision_attempted: whether auto-provisioning was attempted.
        provisioned: tools successfully provisioned during the preflight.
        provision_failures: tools that failed to provision.
        blocked_reason: human reason when the mission is blocked.

    """

    status: PreflightStatus = PreflightStatus.PASS
    mission_id: str = ""
    required_missing: tuple[str, ...] = ()
    missing_tools: tuple[str, ...] = ()
    optional_missing: tuple[str, ...] = ()
    provision_attempted: bool = False
    provisioned: tuple[str, ...] = ()
    provision_failures: tuple[str, ...] = ()
    blocked_reason: str = ""

    @property
    def may_execute(self) -> bool:
        """Return ``True`` when the mission may enter active execution."""
        return self.status is not PreflightStatus.BLOCKED

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping of this preflight verdict."""
        return {
            "status": self.status.value,
            "mission_id": self.mission_id,
            "may_execute": self.may_execute,
            "required_missing": list(self.required_missing),
            "missing_tools": list(self.missing_tools),
            "optional_missing": list(self.optional_missing),
            "provision_attempted": self.provision_attempted,
            "provisioned": list(self.provisioned),
            "provision_failures": list(self.provision_failures),
            "blocked_reason": self.blocked_reason,
        }


__all__ = [
    "CapabilityLevel",
    "CapabilityReadiness",
    "InstallMethod",
    "InstallOutcome",
    "InstallProgress",
    "PreflightResult",
    "PreflightStatus",
    "ReadinessReport",
    "ToolDefinition",
    "ToolInventory",
    "ToolReadiness",
    "ToolReadinessStatus",
]
