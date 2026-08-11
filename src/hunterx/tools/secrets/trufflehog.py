# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""TruffleHog tool adapter.

Integrates ``trufflehog`` — a secret scanner for repositories, filesystems and
S3 buckets — into the Tool Integration SDK. The adapter requests JSONL output
(``--json``) and parses each finding into canonical *redacted* secret records.

SECURITY BOUNDARY: trufflehog JSON records contain the raw ``Secret`` value.
This adapter drops it at parse time and persists only ``secret_type``,
``location``, ``fingerprint``, ``masked_value``, ``source``, ``confidence`` and
``provenance``.
"""

from __future__ import annotations

import json
from typing import Any

from hunterx.domain.execution import ExecutionContext
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.recon.runner import CommandResult
from hunterx.tools.secrets.base import SecretToolAdapter

_VERSION = "3.80.0"


class TrufflehogAdapter(SecretToolAdapter):
    """SDK adapter for the ``trufflehog`` secret scanner."""

    descriptor = ToolDescriptor(
        name="trufflehog",
        version=_VERSION,
        description="Detect and verify credentials across repositories, filesystems and clouds.",
        entrypoint="hunterx.tools.secrets.trufflehog:TrufflehogAdapter",
        targets=("path", "repository", "url"),
        capabilities=("secrets-scan", "secret-discovery", "credential-discovery"),
        permissions=("filesystem", "network"),
        parameters={
            "source": {
                "type": "string",
                "description": "Filesystem path, repository URL or S3 URI to scan.",
            },
            "kind": {
                "type": "string",
                "enum": ["filesystem", "git", "s3", "github"],
                "description": "Scan target kind.",
            },
            "verified_only": {
                "type": "boolean",
                "description": "Only report verified credentials.",
            },
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build argv."""
        kind = str(context.parameters.get("kind") or "filesystem").lower()
        source = str(context.parameters.get("source") or context.target)
        argv = ["trufflehog", kind, source, "--json", "--no-update"]
        if self._param_bool(context, "verified_only", False):
            argv.append("--only-verified")
        return argv

    def parse_output(
        self, context: ExecutionContext, result: CommandResult
    ) -> list[dict[str, Any]]:
        """Convert trufflehog JSONL output into canonical redacted records."""
        records: list[dict[str, Any]] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            record = self._parse_line(line, context)
            if record is not None:
                records.append(record)
        return records

    # -- helpers -------------------------------------------------------------

    def _parse_line(
        self, line: str, context: ExecutionContext
    ) -> dict[str, Any] | None:
        """Convert one trufflehog JSONL finding into a redacted record."""
        try:
            payload = json.loads(line)
        except (json.JSONDecodeError, TypeError, ValueError):
            return None
        if not isinstance(payload, dict):
            return None
        secret = str(payload.get("Secret") or payload.get("Raw") or "")
        detector = str(payload.get("DetectorName") or payload.get("decoder_type") or "unknown")
        verified = bool(payload.get("Verified"))
        location = _location(payload)
        if not secret and not location:
            return None
        fingerprint = self._fingerprint(secret, location, detector)
        return {
            "secret_type": detector,
            "location": location,
            "fingerprint": fingerprint,
            "masked_value": self._masked(secret) if secret else "",
            "verified": verified,
            "confidence": 0.9 if verified else 0.6,
            "source": "trufflehog",
            "tool_id": "trufflehog",
            "tool_version": _VERSION,
            "correlation_id": context.correlation_id,
            "mission_id": context.mission_id,
            "execution_id": context.execution_id,
            "provenance": {
                "source": "trufflehog",
                "detector": detector,
                "verified": verified,
                "redacted": True,
            },
        }


def _location(payload: dict[str, Any]) -> str:
    metadata = payload.get("SourceMetadata")
    if not isinstance(metadata, dict):
        return str(payload.get("File") or "")
    for value in metadata.values():
        if isinstance(value, dict):
            file_path = value.get("file") or value.get("path") or value.get("url") or ""
            if file_path:
                return str(file_path)
    return str(payload.get("File") or "")


__all__ = ["TrufflehogAdapter"]
