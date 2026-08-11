# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Web injection vulnerability scanner adapters.

Integrates the injection-testing toolset (dalfox, xssstrike, sqlmap, ghauri,
commix, tplmap, sstimap, xxeinjector) and the OOB interaction client
(interactsh) into the Tool Integration SDK. Each adapter invokes its external
binary through the shared runner seam and emits canonical *candidate* records
under the pipeline ``candidates`` payload.

VALIDATION BOUNDARY: every injection scanner output is a CANDIDATE. It carries
``requires_validation = True`` and a confidence contribution bounded below the
proof ceiling. Candidates never become findings automatically — the Proof and
Validation subsystems retain authority over the final verdict.
"""

from __future__ import annotations

import json
import re
from typing import Any

from hunterx.domain.execution import ExecutionContext
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.recon.runner import CommandResult
from hunterx.tools.vuln.scanbase import VulnerabilityScanAdapter

#: Base confidence per injection class for a candidate.
_CANDIDATE_CONFIDENCE: dict[str, float] = {
    "xss": 0.6,
    "sql-injection": 0.65,
    "command-injection": 0.6,
    "ssti": 0.6,
    "xxe": 0.55,
    "oob": 0.5,
}


def _candidate(
    context: ExecutionContext,
    *,
    vulnerability_class: str,
    detail: str,
    evidence: str = "",
    endpoint: str = "",
    parameter: str = "",
    severity: str = "medium",
    source: str = "",
) -> dict[str, Any]:
    """Build a canonical injection candidate record."""
    return {
        "vulnerability_class": vulnerability_class,
        "detail": detail,
        "evidence": evidence[:2048],
        "endpoint": endpoint or str(context.target),
        "parameter": parameter,
        "severity": severity,
        "confidence": _CANDIDATE_CONFIDENCE.get(vulnerability_class, 0.5),
        "requires_validation": True,
        "tool_id": source or context.tool_id,
        "tool_version": "",
        "correlation_id": context.correlation_id,
        "mission_id": context.mission_id,
        "execution_id": context.execution_id,
        "provenance": {
            "source": source or context.tool_id,
            "candidate": True,
            "validated": False,
        },
    }


class DalfoxAdapter(VulnerabilityScanAdapter):
    """SDK adapter for ``dalfox`` — fast XSS parameter scanner."""

    descriptor = ToolDescriptor(
        name="dalfox",
        version="2.9.3",
        description="Fast, comprehensive XSS scanning and parameter analysis tool.",
        entrypoint="hunterx.tools.vuln.injection:DalfoxAdapter",
        targets=("url",),
        capabilities=("xss-detection", "xss-discovery"),
        permissions=("network",),
        parameters={
            "url": {"type": "string", "description": "Target URL (defaults to execution target)."},
            "custom_payload": {"type": "string", "description": "Custom payload to inject."},
            "worker": {"type": "integer", "description": "Concurrent workers."},
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build argv."""
        target = str(context.parameters.get("url") or context.target)
        argv = ["dalfox", "url", target, "--format", "json", "--silence"]
        worker = self._param_int(context, "worker", 0)
        if worker > 0:
            argv += ["--worker", str(worker)]
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[dict[str, Any]]:
        """Parse output."""
        try:
            payload = json.loads(result.stdout or "{}")
        except (json.JSONDecodeError, TypeError, ValueError):
            payload = None
        records: list[dict[str, Any]] = []
        if isinstance(payload, dict):
            results = payload.get("results")
            if isinstance(results, list):
                for item in results:
                    if not isinstance(item, dict):
                        continue
                    detail = str(item.get("data") or item.get("type") or "XSS candidate")
                    records.append(
                        _candidate(
                            context,
                            vulnerability_class="xss",
                            detail=detail,
                            evidence=str(item.get("evidence") or ""),
                            endpoint=str(item.get("url") or ""),
                            parameter=str(item.get("param") or ""),
                            severity=str(item.get("severity") or "medium"),
                            source="dalfox",
                        )
                    )
        return records


class XSStrikeAdapter(VulnerabilityScanAdapter):
    """SDK adapter for ``XSStrike`` — advanced XSS detection suite."""

    descriptor = ToolDescriptor(
        name="xssstrike",
        version="3.1.5",
        description="Advanced XSS detection suite with fuzzing and DOM analysis.",
        entrypoint="hunterx.tools.vuln.injection:XSStrikeAdapter",
        targets=("url",),
        capabilities=("xss-detection", "xss-discovery"),
        permissions=("network",),
        parameters={
            "crawl": {"type": "boolean", "description": "Crawl the target for parameters first."},
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build argv."""
        argv = ["xsstrike", "-u", context.target, "--skip"]
        if self._param_bool(context, "crawl", False):
            argv.append("--crawl")
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[dict[str, Any]]:
        """Parse output."""
        records: list[dict[str, Any]] = []
        text = result.stdout
        if re.search(r"(XSS|vulnerable|Payload)", text, re.IGNORECASE):
            lines = [line.strip() for line in text.splitlines() if line.strip()]
            detail = "XSS candidate detected"
            for line in lines:
                if re.search(r"XSS|vulnerable", line, re.IGNORECASE):
                    detail = line[:256]
                    break
            records.append(
                _candidate(
                    context,
                    vulnerability_class="xss",
                    detail=detail,
                    evidence=text[:2048],
                    severity="medium",
                    source="xssstrike",
                )
            )
        return records


class SQLmapAdapter(VulnerabilityScanAdapter):
    """SDK adapter for ``sqlmap`` — automated SQL injection tool."""

    descriptor = ToolDescriptor(
        name="sqlmap",
        version="1.8.6",
        description="Automatic SQL injection and database takeover tool.",
        entrypoint="hunterx.tools.vuln.injection:SQLmapAdapter",
        targets=("url",),
        capabilities=("sqli-detection", "sql-injection-detection"),
        permissions=("network",),
        parameters={
            "url": {"type": "string", "description": "Target URL (defaults to execution target)."},
            "data": {"type": "string", "description": "POST body for the request."},
            "level": {"type": "integer", "description": "Test level (1-5)."},
            "risk": {"type": "integer", "description": "Test risk (1-3)."},
            "technique": {"type": "string", "description": "Injection techniques to use (BEUSTQ)."},
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build argv."""
        target = str(context.parameters.get("url") or context.target)
        argv = ["sqlmap", "-u", target, "--batch"]
        data = context.parameters.get("data")
        if isinstance(data, str) and data:
            argv += ["--data", data]
        level = self._param_int(context, "level", 0)
        if level > 0:
            argv += ["--level", str(level)]
        risk = self._param_int(context, "risk", 0)
        if risk > 0:
            argv += ["--risk", str(risk)]
        technique = context.parameters.get("technique")
        if isinstance(technique, str) and technique:
            argv += ["--technique", technique]
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[dict[str, Any]]:
        """Parse output."""
        return _parse_injection_text(context, result.stdout, "sql-injection", "sqlmap")


class GhauriAdapter(VulnerabilityScanAdapter):
    """SDK adapter for ``ghauri`` — cross-platform SQLi testing tool."""

    descriptor = ToolDescriptor(
        name="ghauri",
        version="1.2.0",
        description="Cross-platform, powerful SQL injection testing tool.",
        entrypoint="hunterx.tools.vuln.injection:GhauriAdapter",
        targets=("url",),
        capabilities=("sqli-detection", "sql-injection-detection"),
        permissions=("network",),
        parameters={
            "url": {"type": "string", "description": "Target URL (defaults to execution target)."},
            "data": {"type": "string", "description": "POST body for the request."},
            "level": {"type": "integer", "description": "Test level (1-3)."},
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build argv."""
        target = str(context.parameters.get("url") or context.target)
        argv = ["ghauri", "-u", target, "--batch"]
        data = context.parameters.get("data")
        if isinstance(data, str) and data:
            argv += ["--data", data]
        level = self._param_int(context, "level", 0)
        if level > 0:
            argv += ["--level", str(level)]
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[dict[str, Any]]:
        """Parse output."""
        return _parse_injection_text(context, result.stdout, "sql-injection", "ghauri")


class CommixAdapter(VulnerabilityScanAdapter):
    """SDK adapter for ``commix`` — automated command injection tool."""

    descriptor = ToolDescriptor(
        name="commix",
        version="3.9.0",
        description="Automated command injection exploitation tool.",
        entrypoint="hunterx.tools.vuln.injection:CommixAdapter",
        targets=("url",),
        capabilities=("command-injection", "command-injection-detection"),
        permissions=("network",),
        parameters={
            "data": {"type": "string", "description": "POST body for the request."},
            "cookie": {"type": "string", "description": "Cookie header to send."},
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build argv."""
        argv = ["commix", "--url", context.target, "--batch"]
        data = context.parameters.get("data")
        if isinstance(data, str) and data:
            argv += ["--data", data]
        cookie = context.parameters.get("cookie")
        if isinstance(cookie, str) and cookie:
            argv += ["--cookie", cookie]
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[dict[str, Any]]:
        """Parse output."""
        return _parse_injection_text(context, result.stdout, "command-injection", "commix")


class TplmapAdapter(VulnerabilityScanAdapter):
    """SDK adapter for ``tplmap`` — server-side template injection tool."""

    descriptor = ToolDescriptor(
        name="tplmap",
        version="1.1.0",
        description="Server-side template injection and code execution detection.",
        entrypoint="hunterx.tools.vuln.injection:TplmapAdapter",
        targets=("url",),
        capabilities=("ssti-detection", "template-injection"),
        permissions=("network",),
        parameters={
            "data": {"type": "string", "description": "POST body for the request."},
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build argv."""
        argv = ["tplmap", "-u", context.target]
        data = context.parameters.get("data")
        if isinstance(data, str) and data:
            argv += ["--data", data]
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[dict[str, Any]]:
        """Parse output."""
        return _parse_injection_text(context, result.stdout, "ssti", "tplmap")


class SSTImapAdapter(VulnerabilityScanAdapter):
    """SDK adapter for ``sstimap`` — SSTI detection and exploitation framework."""

    descriptor = ToolDescriptor(
        name="sstimap",
        version="1.1.1",
        description="Automatic server-side template injection detection framework.",
        entrypoint="hunterx.tools.vuln.injection:SSTImapAdapter",
        targets=("url",),
        capabilities=("ssti-detection", "template-injection"),
        permissions=("network",),
        parameters={
            "data": {"type": "string", "description": "POST body for the request."},
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build argv."""
        argv = ["sstimap", "-u", context.target]
        data = context.parameters.get("data")
        if isinstance(data, str) and data:
            argv += ["--data", data]
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[dict[str, Any]]:
        """Parse output."""
        return _parse_injection_text(context, result.stdout, "ssti", "sstimap")


class XXEinjectorAdapter(VulnerabilityScanAdapter):
    """SDK adapter for ``XXEinjector`` — XXE injection toolkit."""

    descriptor = ToolDescriptor(
        name="xxeinjector",
        version="1.0.0",
        description="Toolkit for XXE (XML External Entity) injection testing.",
        entrypoint="hunterx.tools.vuln.injection:XXEinjectorAdapter",
        targets=("url",),
        capabilities=("xxe-detection",),
        permissions=("network",),
        parameters={
            "file": {"type": "string", "description": "Path to a file containing the payload requests."},
            "path": {"type": "string", "description": "Local path to write extracted files."},
            "logging": {"type": "boolean", "description": "Enable request logging."},
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build argv."""
        file_path = context.parameters.get("file")
        if not isinstance(file_path, str) or not file_path:
            raise ValueError("xxeinjector requires a 'file' parameter with XXE payload requests")
        argv = ["xxeinjector", "--url", context.target, "--file", file_path]
        path = context.parameters.get("path")
        if isinstance(path, str) and path:
            argv += ["--path", path]
        if self._param_bool(context, "logging", False):
            argv.append("--logging")
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[dict[str, Any]]:
        """Parse output."""
        records: list[dict[str, Any]] = []
        text = result.stdout
        if re.search(r"(XXE|Possible|vulnerable|File found)", text, re.IGNORECASE):
            records.append(
                _candidate(
                    context,
                    vulnerability_class="xxe",
                    detail="XXE candidate detected",
                    evidence=text[:2048],
                    severity="medium",
                    source="xxeinjector",
                )
            )
        return records


class InteractshAdapter(VulnerabilityScanAdapter):
    """SDK adapter for ``interactsh`` — OAST (out-of-band) callback client.

    The client generates a unique interaction domain and listens for out-of-band
    callbacks. The adapter captures the interaction domain as an observation.
    Execution is time-bounded by the operator (short timeout) and OAST callbacks
    are evidence data, never proof by themselves.
    """

    descriptor = ToolDescriptor(
        name="interactsh",
        version="1.2.0",
        description="Out-of-band interaction client for OAST callback evidence.",
        entrypoint="hunterx.tools.vuln.injection:InteractshAdapter",
        targets=("url", "host", "domain"),
        capabilities=("oob-testing", "oob-callback"),
        permissions=("network",),
        parameters={
            "output": {"type": "string", "description": "File where interactions are logged."},
            "no_poll": {"type": "boolean", "description": "Disable polling for callbacks."},
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build argv."""
        argv = ["interactsh-client"]
        output = context.parameters.get("output")
        if isinstance(output, str) and output:
            argv += ["-o", output]
        if self._param_bool(context, "no_poll", False):
            argv.append("-n")
        argv.append("-v")
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[dict[str, Any]]:
        """Parse output."""
        domain = _extract_interaction_domain(result.stdout)
        if not domain:
            return []
        return [
            {
                "vulnerability_class": "oob",
                "detail": f"OAST interaction domain acquired: {domain}",
                "evidence": domain,
                "endpoint": domain,
                "parameter": "",
                "severity": "info",
                "confidence": _CANDIDATE_CONFIDENCE["oob"],
                "requires_validation": True,
                "tool_id": "interactsh",
                "correlation_id": context.correlation_id,
                "mission_id": context.mission_id,
                "execution_id": context.execution_id,
                "provenance": {
                    "source": "interactsh",
                    "candidate": True,
                    "validated": False,
                    "oob": True,
                },
            }
        ]


def _parse_injection_text(
    context: ExecutionContext,
    text: str,
    vulnerability_class: str,
    source: str,
) -> list[dict[str, Any]]:
    """Parse human-readable injection scanner output into a candidate."""
    records: list[dict[str, Any]] = []
    lowered = text.lower()
    hit_phrases = ("vulnerable", "injection point", "identified", "sql injection", "command injection",
                   "template injection", "xss", "payload", "code execution", "blind")
    if not any(phrase in lowered for phrase in hit_phrases):
        return records
    detail = "Injection candidate detected"
    parameter = ""
    for line in text.splitlines():
        stripped = line.strip()
        match = re.search(r"Parameter:\s*([^\s(]+)", stripped, re.IGNORECASE)
        if match:
            parameter = match.group(1)
        if re.search(r"Type:\s*", stripped, re.IGNORECASE):
            detail = stripped[:256]
        if re.search(r"identified the following|is vulnerable|injection point", stripped, re.IGNORECASE):
            detail = stripped[:256]
    records.append(
        _candidate(
            context,
            vulnerability_class=vulnerability_class,
            detail=detail,
            evidence=text[:2048],
            parameter=parameter,
            severity="medium",
            source=source,
        )
    )
    return records


_INTERACTION_RE = re.compile(r"(?:^|[\s\*\/:\(])([a-z0-9]{6,}\.(?:oast\.(?:me|pro|live|site|fun)|interact\.sh|callback\.interactsh\.com))", re.IGNORECASE)


def _extract_interaction_domain(text: str) -> str:
    for match in _INTERACTION_RE.finditer(text):
        return match.group(1)
    return ""


__all__ = [
    "DalfoxAdapter",
    "XSStrikeAdapter",
    "SQLmapAdapter",
    "GhauriAdapter",
    "CommixAdapter",
    "TplmapAdapter",
    "SSTImapAdapter",
    "XXEinjectorAdapter",
    "InteractshAdapter",
]
