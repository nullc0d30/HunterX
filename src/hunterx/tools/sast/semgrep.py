# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""SAST / static-analysis tool adapters.

Integrates ``semgrep`` — the lightweight static analysis engine — into the Tool
Integration SDK. The adapter invokes the binary through the shared runner seam
with JSON output and normalizes findings into canonical candidate records.

SAST findings are candidates: they describe code patterns, not proven
exploitation. Every record carries ``requires_validation = True``.
"""

from __future__ import annotations

import json
from typing import Any

from hunterx.domain.execution import ExecutionContext
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.recon.runner import CommandResult
from hunterx.tools.vuln.scanbase import VulnerabilityScanAdapter

_VERSION = "1.33.0"


class SemgrepAdapter(VulnerabilityScanAdapter):
    """SDK adapter for the ``semgrep`` static analysis engine."""

    descriptor = ToolDescriptor(
        name="semgrep",
        version=_VERSION,
        description="Lightweight static analysis for many languages (SAST).",
        entrypoint="hunterx.tools.sast.semgrep:SemgrepAdapter",
        targets=("path", "repository"),
        capabilities=("static-analysis", "sast", "code-pattern-analysis"),
        permissions=("filesystem",),
        parameters={
            "source": {"type": "string", "description": "Path or repository to scan (defaults to target)."},
            "config": {"type": "string", "description": "Ruleset (auto, p/security-audit, or file path)."},
            "severity": {"type": "string", "description": "Comma-separated severity filter."},
            "timeout": {"type": "integer", "description": "Per-rule timeout in seconds."},
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build argv."""
        source = str(context.parameters.get("source") or context.target)
        argv = ["semgrep", "scan", "--json", "--quiet", source]
        config = str(context.parameters.get("config") or "auto")
        argv += ["--config", config]
        severity = context.parameters.get("severity")
        if isinstance(severity, str) and severity:
            argv += ["--severity", severity]
        timeout = self._param_int(context, "timeout", 0)
        if timeout > 0:
            argv += ["--timeout", str(timeout)]
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[dict[str, Any]]:
        """Parse output."""
        try:
            payload = json.loads(result.stdout or "{}")
        except (json.JSONDecodeError, TypeError, ValueError):
            return []
        if not isinstance(payload, dict):
            return []
        records: list[dict[str, Any]] = []
        results = payload.get("results")
        if not isinstance(results, list):
            return []
        for item in results:
            if not isinstance(item, dict):
                continue
            check_id = str(item.get("check_id") or "unknown")
            path = str(item.get("path") or "")
            start = item.get("start")
            line = start.get("line") if isinstance(start, dict) else None
            extra = item.get("extra")
            message = extra.get("message") if isinstance(extra, dict) else None
            severity = _severity(extra) if isinstance(extra, dict) else "medium"
            records.append(
                {
                    "vulnerability_class": "sast",
                    "detail": message or f"Semgrep rule match: {check_id}",
                    "evidence": message or "",
                    "endpoint": f"{path}:{line}" if line else path,
                    "parameter": "",
                    "severity": severity,
                    "check_id": check_id,
                    "path": path,
                    "line": line,
                    "confidence": 0.7,
                    "requires_validation": True,
                    "tool_id": "semgrep",
                    "tool_version": _VERSION,
                    "correlation_id": context.correlation_id,
                    "mission_id": context.mission_id,
                    "execution_id": context.execution_id,
                    "provenance": {
                        "source": "semgrep",
                        "check_id": check_id,
                        "candidate": True,
                        "validated": False,
                    },
                }
            )
        return records


def _severity(extra: dict[str, Any]) -> str:
    value = str(extra.get("severity") or "WARNING").lower()
    if value in ("error", "critical"):
        return "high"
    if value in ("warning", "warn"):
        return "medium"
    if value in ("info", "note"):
        return "low"
    return "medium"


__all__ = ["SemgrepAdapter"]
