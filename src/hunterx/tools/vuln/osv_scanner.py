# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""OSV-scanner adapter — dependency vulnerability scanning.

Runs the installed ``osv-scanner scan --format json`` against a lockfile or
local path and parses the OSV JSON into dependency-vulnerability candidates.
Against a remote URL target with no local manifest, the scan is bounded to the
mission's temp directory and honestly produces no candidates (there is no
dependency evidence) rather than fabricating one.
"""

from __future__ import annotations

import json
import os
from typing import Any

from hunterx.tools.recon.runner import BinaryRunner, CommandResult
from hunterx.tools.sdk.adapter import ToolDescriptor
from hunterx.tools.sdk.context import ExecutionContext
from hunterx.tools.vuln.scanbase import VulnerabilityScanAdapter

_VERSION = "1.9.2"


def _is_url(value: str) -> bool:
    """Return ``True`` when ``value`` looks like a URL (scheme:// or a bare host/port)."""
    if value.startswith(("http://", "https://")):
        return True
    return "/" not in value and ("." in value or ":" in value)


class OsvScannerAdapter(VulnerabilityScanAdapter):
    """SDK adapter running the external ``osv-scanner`` dependency scanner."""

    descriptor = ToolDescriptor(
        name="osv-scanner",
        version=_VERSION,
        description="Google OSV scanner producing dependency-vulnerability candidates.",
        entrypoint="hunterx.tools.vuln.osv_scanner:OsvScannerAdapter",
        targets=("filesystem", "host"),
        capabilities=("dependency-check", "vulnerability-knowledge"),
        permissions=("filesystem",),
    )

    def __init__(self, runner: BinaryRunner | None = None) -> None:
        super().__init__(runner)

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build ``osv-scanner scan --format json <path>``.

        The path is the explicit ``manifest``/``path`` parameter, the target
        when it is a real local path, or the mission temp directory (a bounded,
        honest-empty scan) otherwise. A URL target (host or full URL) has no
        local lockfile to scan, so the scan is bounded to the temp directory.
        """
        path = str(context.parameters.get("manifest") or context.parameters.get("path") or "")
        if not path:
            target = str(context.target or "")
            if not _is_url(target) and os.path.exists(target):
                path = target
        if not path:
            path = str(getattr(context, "temp_directory", None) or "/tmp")
        return ["osv-scanner", "scan", "--format", "json", path]

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[dict[str, Any]]:
        """Parse the OSV JSON into dependency-vulnerability candidates."""
        if not result.stdout:
            return []
        try:
            payload = json.loads(result.stdout)
        except (ValueError, TypeError):
            return []
        records: list[dict[str, Any]] = []
        for source in payload.get("results", []):
            for package in source.get("packages", []):
                pkg = package.get("package") or {}
                name = str(pkg.get("name") or "")
                version = str(pkg.get("version") or "")
                if not name:
                    continue
                for vulnerability in package.get("vulnerabilities", []):
                    vulnerability_id = str(vulnerability.get("id") or "")
                    aliases = [str(alias) for alias in vulnerability.get("aliases", [])]
                    cve = next((alias for alias in aliases if alias.startswith("CVE-")), "")
                    records.append(
                        {
                            "vulnerability_class": "dependency-vulnerability",
                            "dependency": name,
                            "version": version,
                            "ecosystem": str(pkg.get("ecosystem") or ""),
                            "vulnerability_id": vulnerability_id,
                            "cve": cve,
                            "summary": str(vulnerability.get("summary") or "")[:500],
                            "source": str(source.get("source") or source.get("path") or ""),
                            "severity": "medium",
                            "confidence": 0.7,
                            "requires_validation": True,
                            "provenance": {"source": "osv-scanner", "candidate": True, "validated": False},
                        }
                    )
        return records


__all__ = ["OsvScannerAdapter"]
