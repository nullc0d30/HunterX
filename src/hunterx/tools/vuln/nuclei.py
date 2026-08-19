# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Nuclei tool adapter.

Integrates ProjectDiscovery ``nuclei`` — a template-based vulnerability scanner
— into the Tool Integration SDK as an active *scanner*. Nuclei is invoked
through the shared :class:`~hunterx.tools.recon.runner.BinaryRunner` seam with
JSONL output (``-jsonl -silent``) and the parsed output is projected into
canonical *candidate* records.

VALIDATION BOUNDARY: Nuclei output is an OBSERVATION / CANDIDATE. It is NOT
automatically a validated finding. Every candidate record carries
``requires_validation = True`` and a confidence contribution bounded by the
tool's confidence ceiling, so the Proof and Validation subsystems retain
authority over the final verdict. Candidates are attached as assets on the
legacy surface, never as findings.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from hunterx.domain.execution import ExecutionContext
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.recon.runner import CommandResult
from hunterx.tools.vuln.scanbase import VulnerabilityScanAdapter

_VERSION = "3.2.0"

#: Base confidence per severity for a nuclei candidate. Candidates always stay
#: below the proof ceiling because template matches require validation.
_SEVERITY_CONFIDENCE: dict[str, float] = {
    "critical": 0.8,
    "high": 0.7,
    "medium": 0.6,
    "low": 0.5,
    "info": 0.4,
    "unknown": 0.4,
}


class NucleiAdapter(VulnerabilityScanAdapter):
    """SDK adapter for the ``nuclei`` template-based vulnerability scanner."""

    descriptor = ToolDescriptor(
        name="nuclei",
        version=_VERSION,
        description="Template-based vulnerability scanner for web, DNS, network and infrastructure.",
        entrypoint="hunterx.tools.vuln.nuclei:NucleiAdapter",
        targets=("url", "host", "domain", "ip"),
        capabilities=("vulnerability-scan", "template-scan"),
        permissions=("network",),
        parameters={
            "url": {
                "type": "string",
                "description": "Target URL/host/domain to scan (defaults to the execution target).",
            },
            "templates": {
                "type": "string",
                "description": "Template file, directory or comma-separated list to run.",
            },
            "severity": {
                "type": "string",
                "description": "Comma-separated severity filter (info,low,medium,high,critical).",
            },
            "tags": {
                "type": "string",
                "description": "Comma-separated template tags to include.",
            },
            "exclude_tags": {
                "type": "string",
                "description": "Comma-separated template tags to exclude.",
            },
            "rate_limit": {
                "type": "integer",
                "description": "Maximum HTTP requests per second.",
            },
            "concurrency": {
                "type": "integer",
                "description": "Maximum templates executed in parallel.",
            },
            "timeout": {
                "type": "integer",
                "description": "Per-request timeout in seconds.",
            },
            "follow_redirects": {
                "type": "boolean",
                "description": "Follow HTTP redirects.",
            },
            "silent": {
                "type": "boolean",
                "description": "Suppress verbose logging (default on).",
            },
            "no_interactsh": {
                "type": "boolean",
                "description": "Disable interactsh OAST callbacks (default on).",
            },
            "output": {
                "type": "string",
                "description": "Path where nuclei writes its JSONL report (artifact).",
            },
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build the ``nuclei`` command line for ``context``."""
        from hunterx.tools.headers import header_args

        target = str(context.parameters.get("url") or context.target)
        argv = ["nuclei", "-u", target, "-jsonl"]
        argv.extend(header_args(context))
        templates = context.parameters.get("templates")
        if isinstance(templates, str) and templates:
            argv += ["-t", templates]
        severity = context.parameters.get("severity")
        if isinstance(severity, str) and severity:
            argv += ["-severity", severity]
        tags = context.parameters.get("tags")
        if isinstance(tags, str) and tags:
            argv += ["-tags", tags]
        exclude_tags = context.parameters.get("exclude_tags")
        if isinstance(exclude_tags, str) and exclude_tags:
            argv += ["-etags", exclude_tags]
        rate_limit = self._param_int(context, "rate_limit", 0)
        if rate_limit > 0:
            argv += ["-rl", str(rate_limit)]
        concurrency = self._param_int(context, "concurrency", 0)
        if concurrency > 0:
            argv += ["-c", str(concurrency)]
        timeout = self._param_int(context, "timeout", 0)
        if timeout > 0:
            argv += ["-timeout", str(timeout)]
        if self._param_bool(context, "follow_redirects", False):
            argv.append("-fr")
        if self._param_bool(context, "silent", True):
            argv.append("-silent")
        if self._param_bool(context, "no_interactsh", True):
            argv.append("-no-interactsh")
        output = context.parameters.get("output")
        if isinstance(output, str) and output:
            argv += ["-o", output]
        return argv

    def parse_output(
        self, context: ExecutionContext, result: CommandResult
    ) -> list[dict[str, Any]]:
        """Convert nuclei JSONL output into canonical candidate records.

        Malformed or non-dict lines are skipped; an empty candidate set is a
        valid "no match" result.
        """
        records: list[dict[str, Any]] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            record = self._parse_line(line, context)
            if record is not None:
                records.append(record)
        return records

    # -- helpers -------------------------------------------------------------

    def _parse_line(
        self, line: str, context: ExecutionContext
    ) -> dict[str, Any] | None:
        """Convert one nuclei JSONL line into a canonical candidate record."""
        try:
            payload = json.loads(line)
        except (json.JSONDecodeError, TypeError, ValueError):
            return None
        if not isinstance(payload, Mapping):
            return None
        info_value = payload.get("info")
        info: Mapping[str, Any] = info_value if isinstance(info_value, Mapping) else {}
        template_id = str(payload.get("template-id") or payload.get("template_id") or "").strip()
        if not template_id:
            return None
        name = str(info.get("name") or template_id)
        severity = str(info.get("severity") or "unknown").strip().lower()
        matched_at = str(payload.get("matched-at") or payload.get("matched_at") or "")
        target = str(payload.get("host") or payload.get("target") or context.target)
        extracted = _string_list(payload.get("extracted-results") or payload.get("extracted_results"))
        return {
            "template_id": template_id,
            "template_name": name,
            "severity": severity,
            "matched_at": matched_at,
            "matcher": str(payload.get("matcher-name") or payload.get("matcher_name") or "") or None,
            "extracted_results": list(extracted),
            "metadata": _metadata(info),
            "cve_ids": _cve_ids(info),
            "timestamp": str(payload.get("timestamp") or "") or None,
            "target": target,
            "template_type": str(payload.get("type") or "").lower() or None,
            "confidence": _confidence(severity),
            "requires_validation": True,
            "tool_id": "nuclei",
            "tool_version": _VERSION,
            "correlation_id": context.correlation_id,
            "mission_id": context.mission_id,
            "execution_id": context.execution_id,
            "provenance": {
                "source": "nuclei",
                "template": template_id,
                "candidate": True,
                "validated": False,
            },
        }


def _confidence(severity: str) -> float:
    """Return the candidate confidence bounded by the nuclei ceiling."""
    return _SEVERITY_CONFIDENCE.get(severity, _SEVERITY_CONFIDENCE["unknown"])


def _metadata(info: Mapping[str, Any]) -> dict[str, Any]:
    """Project a bounded subset of nuclei template ``info`` into a mapping."""
    keys = ("name", "severity", "author", "description", "reference", "tags")
    return {key: info.get(key) for key in keys if info.get(key) is not None}


def _cve_ids(info: Mapping[str, Any]) -> list[str]:
    """Return CVE identifiers declared in the template classification."""
    classification = info.get("classification")
    if isinstance(classification, Mapping):
        raw = classification.get("cve-id") or classification.get("cve_id")
        return list(_string_list(raw))
    return []


def _string_list(value: Any) -> list[str]:
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    if isinstance(value, str):
        return [value] if value else []
    return []
