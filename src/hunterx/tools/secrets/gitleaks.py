# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Gitleaks tool adapter.

Integrates ``gitleaks`` — a SAST tool for detecting hardcoded secrets — into
the Tool Integration SDK for secret discovery over filesystem, repository and
artifact inputs. The adapter requests JSON report output (``--report-format
json --report-path -``) and parses the findings into canonical *redacted*
secret records.

SECURITY BOUNDARY: gitleaks JSON records contain the raw ``Secret``/``Match``
values. This adapter drops those fields at parse time and persists only
``secret_type``, ``location``, ``fingerprint``, ``masked_value``, ``source``,
``confidence`` and ``provenance``. Raw output is preserved (when requested)
only inside the sandboxed execution artifact store, never in findings or the
target database.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from hunterx.domain.execution import ExecutionContext
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.recon.runner import CommandResult
from hunterx.tools.secrets.base import SecretToolAdapter

_VERSION = "8.18.0"

#: gitleaks rule confidence heuristic: entropy-only findings are weaker.
_HIGH_ENTROPY_RULES = {"generic-api-key", "aws-access-token", "private-key", "github-pat"}


class GitleaksAdapter(SecretToolAdapter):
    """SDK adapter for the ``gitleaks`` secret scanner."""

    descriptor = ToolDescriptor(
        name="gitleaks",
        version=_VERSION,
        description="Detect hardcoded secrets in filesystems, repositories and artifacts.",
        entrypoint="hunterx.tools.secrets.gitleaks:GitleaksAdapter",
        targets=("path", "repository", "artifact"),
        capabilities=("secrets-scan", "secrets-detection"),
        permissions=("filesystem",),
        parameters={
            "source": {
                "type": "string",
                "description": "Filesystem path, repository URL or artifact path to scan.",
            },
            "report_path": {
                "type": "string",
                "description": "Path where gitleaks writes its JSON report (artifact).",
            },
            "verbose": {
                "type": "boolean",
                "description": "Emit verbose logs to stderr.",
            },
            "redact": {
                "type": "boolean",
                "description": "Ask gitleaks to redact secrets from its own output.",
            },
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build the ``gitleaks`` command line for ``context``."""
        source = str(context.parameters.get("source") or context.target)
        argv = ["gitleaks", "detect", "--source", source, "--report-format", "json"]
        report_path = context.parameters.get("report_path")
        if isinstance(report_path, str) and report_path:
            argv += ["--report-path", report_path]
        else:
            argv += ["--report-path", "-"]
        if self._param_bool(context, "redact", True):
            argv.append("--redact")
        if self._param_bool(context, "verbose", False):
            argv.append("-v")
        return argv

    def parse_output(
        self, context: ExecutionContext, result: CommandResult
    ) -> list[dict[str, Any]]:
        """Convert gitleaks JSON output into canonical redacted secret records.

        The raw ``Secret`` and ``Match`` values are never emitted. The raw
        stdout is preserved as the execution's raw artifact only.
        """
        payload = _parse_json(result.stdout)
        findings = payload if isinstance(payload, list) else _extract_findings(payload)
        records: list[dict[str, Any]] = []
        for finding in findings:
            record = self._parse_finding(finding, context)
            if record is not None:
                records.append(record)
        return records

    # -- helpers -------------------------------------------------------------

    def _parse_finding(
        self, finding: Mapping[str, Any], context: ExecutionContext
    ) -> dict[str, Any] | None:
        """Convert one gitleaks finding into a redacted canonical record."""
        if not isinstance(finding, Mapping):
            return None
        rule = str(finding.get("RuleID") or finding.get("rule_id") or "unknown").strip()
        secret = str(finding.get("Secret") or finding.get("secret") or "")
        location = str(finding.get("File") or finding.get("file") or "").strip()
        if not secret and not location:
            return None
        if location.startswith("src/"):
            location = location[4:]
        fingerprint = self._fingerprint(secret, location, rule)
        confidence = _confidence(rule, finding)
        tags = _string_list(finding.get("Tags") or finding.get("tags"))
        return {
            "secret_type": rule,
            "location": location,
            "fingerprint": fingerprint,
            "masked_value": self._masked(secret) if secret else "",
            "entropy": _optional_float(finding.get("Entropy") or finding.get("entropy")),
            "confidence": confidence,
            "source": "gitleaks",
            "line": _optional_int(finding.get("StartLine") or finding.get("start_line")),
            "commit": str(finding.get("Commit") or finding.get("commit") or "") or None,
            "author": str(finding.get("Author") or finding.get("author") or "") or None,
            "date": str(finding.get("Date") or finding.get("date") or "") or None,
            "tags": tags,
            "tool_id": "gitleaks",
            "tool_version": _VERSION,
            "correlation_id": context.correlation_id,
            "mission_id": context.mission_id,
            "execution_id": context.execution_id,
            "provenance": {
                "source": "gitleaks",
                "rule": rule,
                "redacted": True,
            },
        }


def _parse_json(text: str) -> Any:
    """Parse ``text`` as JSON defensively (returns ``None`` when malformed)."""
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None


def _extract_findings(payload: Any) -> list[Any]:
    """Return the findings list from a gitleaks payload mapping."""
    if isinstance(payload, dict):
        for key in ("findings", "results", "leaks"):
            value = payload.get(key)
            if isinstance(value, list):
                return value
    return []


def _confidence(rule: str, finding: Mapping[str, Any]) -> float:
    """Estimate a confidence score for a gitleaks finding.

    A named rule with a fingerprint is stronger than an entropy-only match.
    """
    if rule.lower() in _HIGH_ENTROPY_RULES:
        return 0.85
    if rule and rule != "unknown":
        return 0.75
    return 0.55


def _optional_float(value: Any) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _optional_int(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _string_list(value: Any) -> tuple[str, ...]:
    if isinstance(value, (list, tuple)):
        return tuple(str(item) for item in value)
    if isinstance(value, str):
        return (value,) if value else ()
    return ()
