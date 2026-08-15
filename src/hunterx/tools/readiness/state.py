# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Installation state persistence.

The installer is resumable: interrupted installations (Ctrl+C, reboot, power
loss) must be safely reconcilable by re-running the installer instead of
starting from zero. This module persists enough state to do that:

- the installation phase;
- the tool currently being installed;
- tools completed and failed so far (with timestamps and error reasons);
- profile and platform facts;
- an ``install_id`` so state from a previous run is never confused with the
  current one.

State is stored as JSON under a caller-supplied directory (the installer uses
``<install-dir>/state/`` for system installs and the user state directory for
``--user`` installs). Reads are tolerant of missing/corrupt files so a broken
state file never blocks installation.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hunterx.tools.readiness.models import InstallOutcome


@dataclass(slots=True)
class ToolStateRecord:
    """One tool's installation record in the persisted state.

    Attributes:
        tool_id: the tool id.
        status: ``"completed"`` or ``"failed"``.
        version: detected version when available.
        error: human error reason (failed tools).
        started_at / finished_at: ISO timestamps.
        method: the install method used (``apt``, ``go``, ...) when available.

    """

    tool_id: str = ""
    status: str = "failed"
    version: str = ""
    error: str = ""
    started_at: str = ""
    finished_at: str = ""
    method: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping of this record."""
        return {
            "tool_id": self.tool_id,
            "status": self.status,
            "version": self.version,
            "error": self.error,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "method": self.method,
        }


@dataclass(slots=True)
class InstallationState:
    """Persistent installation state for resume support.

    Attributes:
        install_id: unique id for the current installation run.
        started_at: ISO timestamp of the first run.
        updated_at: ISO timestamp of the last mutation.
        phase: current installer phase (``"os"``, ``"package"``,
            ``"database"``, ``"resources"``, ``"toolchain"``,
            ``"verification"``, ``"complete"``).
        profile: the tool profile being provisioned (``minimal``/``full``/...).
        platform: the detected platform mapping (JSON-safe).
        current_tool: the tool currently being installed (``""`` when idle).
        tools: per-tool records (completed + failed).
        interrupted: ``True`` when the previous run ended via Ctrl+C/error.
        error: message captured when the previous run was interrupted.

    """

    install_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    started_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    updated_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    phase: str = "started"
    profile: str = ""
    platform: dict[str, Any] = field(default_factory=dict)
    current_tool: str = ""
    tools: list[ToolStateRecord] = field(default_factory=list)
    interrupted: bool = False
    error: str = ""
    #: Optional persistent directory; when set, mutations are flushed to
    #: ``<save_dir>/install.json`` so an interrupted run stays recoverable.
    save_dir: str = ""

    def persist(self) -> None:
        """Flush state to ``save_dir`` when configured (best-effort)."""
        if self.save_dir:
            self.save(self.save_dir)

    # -- persistence --------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping of the state."""
        return {
            "install_id": self.install_id,
            "started_at": self.started_at,
            "updated_at": self.updated_at,
            "phase": self.phase,
            "profile": self.profile,
            "platform": dict(self.platform),
            "current_tool": self.current_tool,
            "tools": [record.to_dict() for record in self.tools],
            "interrupted": self.interrupted,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InstallationState:
        """Rebuild a state object from a JSON-safe mapping."""
        tools = [ToolStateRecord(**item) for item in data.get("tools", ()) if isinstance(item, dict)]
        return cls(
            install_id=str(data.get("install_id") or cls().install_id),
            started_at=str(data.get("started_at") or ""),
            updated_at=str(data.get("updated_at") or ""),
            phase=str(data.get("phase") or "started"),
            profile=str(data.get("profile") or ""),
            platform=dict(data.get("platform") or {}),
            current_tool=str(data.get("current_tool") or ""),
            tools=tools,
            interrupted=bool(data.get("interrupted")),
            error=str(data.get("error") or ""),
        )

    def save(self, directory: str | Path) -> Path:
        """Persist the state as JSON under ``directory`` (idempotent mkdir).

        Returns the path written.
        """
        self.updated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "install.json"
        tmp = directory / "install.json.tmp"
        tmp.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp, path)
        return path

    @classmethod
    def load(cls, directory: str | Path) -> InstallationState:
        """Load the persisted state from ``directory``.

        Missing or corrupt files produce a fresh, empty state (never raises),
        so a bad state file cannot block a re-install.
        """
        directory = Path(directory)
        path = directory / "install.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return cls()
        if not isinstance(data, dict):
            return cls()
        return cls.from_dict(data)

    # -- mutation helpers ---------------------------------------------------

    def set_phase(self, phase: str) -> None:
        """Record the current installation phase."""
        self.phase = phase

    def mark_tool_started(self, tool_id: str) -> None:
        """Record that ``tool_id`` is currently being installed."""
        self.current_tool = tool_id

    def record_tool(self, outcome: InstallOutcome) -> None:
        """Record a tool outcome in the persisted state (idempotent)."""
        self.current_tool = ""
        for existing in self.tools:
            if existing.tool_id == outcome.tool_id:
                self.tools.remove(existing)
        record = ToolStateRecord(
            tool_id=outcome.tool_id,
            status="completed" if outcome.success else "failed",
            version=outcome.version,
            error=outcome.error,
            started_at=self.updated_at,
            finished_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            method=outcome.method.kind if outcome.method is not None else "",
        )
        self.tools.append(record)

    def completed_tools(self) -> list[str]:
        """Return the tool ids recorded as completed in this state."""
        return [record.tool_id for record in self.tools if record.status == "completed"]

    def failed_tools(self) -> list[ToolStateRecord]:
        """Return the tool records recorded as failed in this state."""
        return [record for record in self.tools if record.status == "failed"]

    def mark_interrupted(self, error: str = "") -> None:
        """Record an interrupted run so a re-run can reconcile."""
        self.interrupted = True
        self.error = error
        self.current_tool = ""


__all__ = ["InstallationState", "ToolStateRecord"]
