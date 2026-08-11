# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""ProjectDiscovery httpx tool adapter.

Integrates ProjectDiscovery's ``httpx`` — a fast, multi-purpose HTTP(S) toolkit
with technology detection — into the Tool Integration SDK. The adapter builds
the CLI command from the execution context, parses the JSONL output
(``-json -tech-detect``) into canonical technology observations and publishes
them on the execution output.

CLI contract (verified against ProjectDiscovery docs):
    ``httpx -u <target> -json -tech-detect -cdn -title -server -location
    -tls-grab -silent`` emits one JSON object per target to stdout. Each object
    carries ``url``, ``host``, ``port``, ``scheme``, ``status_code``,
    ``webserver``, ``tech`` (array), ``cdn_name``, ``title``, ``location`` and
    ``tls`` (certificate fields).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from hunterx.domain.execution import ExecutionContext
from hunterx.domain.technology.models import TechnologyObservation, infer_asset_type
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.recon.runner import CommandResult
from hunterx.tools.tech.base import TechToolAdapter

_VERSION = "1.3.9"


class HttpxAdapter(TechToolAdapter):
    """SDK adapter for the ``httpx`` technology detection toolkit."""

    descriptor = ToolDescriptor(
        name="httpx",
        version=_VERSION,
        description="ProjectDiscovery httpx HTTP(S) probing with technology detection.",
        entrypoint="hunterx.tools.tech.httpx:HttpxAdapter",
        targets=("url", "host", "domain", "ip"),
        capabilities=("technology-fingerprinting", "http-metadata"),
        permissions=("network",),
        parameters={
            "cdn": {
                "type": "boolean",
                "description": "Detect CDN providers (adds cdn_name).",
            },
            "tls_grab": {
                "type": "boolean",
                "description": "Collect TLS certificate metadata.",
            },
            "threads": {
                "type": "integer",
                "description": "Concurrent scan threads.",
            },
            "rate_limit": {
                "type": "integer",
                "description": "Maximum HTTP requests per second.",
            },
            "timeout": {
                "type": "integer",
                "description": "Per-request timeout in seconds.",
            },
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build the ``httpx`` command line for ``context``."""
        argv = [
            "httpx",
            "-u",
            context.target,
            "-json",
            "-tech-detect",
            "-silent",
            "-no-fallback",
        ]
        if self._param_bool(context, "cdn", True):
            argv.append("-cdn")
        if self._param_bool(context, "tls_grab", True):
            argv += ["-tls-grab", "-title", "-server", "-location", "-status-code"]
        threads = self._param_int(context, "threads", 0)
        if threads > 0:
            argv += ["-threads", str(threads)]
        rate = self._param_int(context, "rate_limit", 0)
        if rate > 0:
            argv += ["-rate-limit", str(rate)]
        timeout = self._param_int(context, "timeout", 0)
        if timeout > 0:
            argv += ["-timeout", str(timeout)]
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[TechnologyObservation]:
        """Parse httpx JSONL output into canonical technology observations."""
        observations: list[TechnologyObservation] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue
            observations.extend(_parse_target(context, payload, self))
        return observations

    def _param_bool(self, context: ExecutionContext, name: str, default: bool) -> bool:
        value = context.parameters.get(name, default)
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("1", "true", "yes")

    def _param_int(self, context: ExecutionContext, name: str, default: int) -> int:
        value = context.parameters.get(name, default)
        try:
            return int(value)
        except (TypeError, ValueError):
            return default


def _parse_target(context: ExecutionContext, payload: Mapping[str, Any], adapter: TechToolAdapter) -> list[TechnologyObservation]:
    """Convert one httpx target record into observations."""
    observations: list[TechnologyObservation] = []
    evidence = _evidence_from_payload(payload)

    tech_names = payload.get("tech")
    if isinstance(tech_names, list):
        for name in tech_names:
            raw = str(name).strip()
            if not raw:
                continue
            observations.append(
                adapter._observation(
                    context,
                    raw,
                    source="httpx",
                    evidence=evidence,
                )
            )

    webserver = str(payload.get("webserver") or "").strip()
    if webserver:
        observations.append(
            adapter._observation(
                context,
                webserver,
                source="httpx",
                evidence=evidence,
            )
        )

    cdn_name = str(payload.get("cdn_name") or "").strip()
    if cdn_name and cdn_name.lower() != "unknown":
        observations.append(
            adapter._observation(
                context,
                cdn_name,
                category="cdn",
                source="httpx",
                evidence=evidence,
            )
        )
    return observations


def _target_asset(context: ExecutionContext, payload: Mapping[str, Any]) -> tuple[str, str]:
    """Return the canonical ``(asset, asset_type)`` for a target record.

    The asset is always the execution target so observations from every tool
    correlate onto the same asset; the payload URL is preserved as evidence.
    """
    value = context.target
    return value, infer_asset_type(value)


def _evidence_from_payload(payload: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    """Build evidence fragments from an httpx record."""
    evidence: list[dict[str, Any]] = []
    if payload.get("webserver"):
        evidence.append(
            {
                "evidence_type": "response-header",
                "value": f"server: {payload['webserver']}",
                "source": "httpx",
                "strength": "strong",
                "detail": f"server: {payload['webserver']}",
            }
        )
    status = payload.get("status_code")
    if isinstance(status, int):
        evidence.append(
            {
                "evidence_type": "http-status",
                "value": str(status),
                "source": "httpx",
                "strength": "moderate",
                "detail": f"status: {status}",
            }
        )
    tls = payload.get("tls")
    if isinstance(tls, Mapping):
        issuer = str(tls.get("issuer_cn") or "").strip()
        if issuer:
            evidence.append(
                {
                    "evidence_type": "tls-certificate",
                    "value": issuer,
                    "source": "httpx",
                    "strength": "moderate",
                    "detail": f"issuer: {issuer}",
                }
            )
    return tuple(evidence)
