# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""WhatWeb tool adapter.

Integrates ``whatweb`` — a deep web technology fingerprinting scanner — into
the Tool Integration SDK. The adapter builds the CLI command, parses the JSON
log (``--log-json=-``) into canonical technology observations and publishes
them on the execution output.

CLI contract (verified against WhatWeb docs):
    ``whatweb --no-errors --log-json=- --quiet <target>`` emits one JSON object
    per target to stdout. Each object carries ``target``, ``http_status`` and
    a ``plugins`` mapping whose keys are technology names and whose values are
    dicts/lists of dicts with ``certainty`` (0-100), ``version``, ``string``
    and ``module`` fields.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

from hunterx.domain.execution import ExecutionContext
from hunterx.domain.technology.models import TechnologyObservation
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.recon.runner import CommandResult, guard_positional_target
from hunterx.tools.tech.base import TechToolAdapter

_VERSION = "0.5.5"


class WhatWebAdapter(TechToolAdapter):
    """SDK adapter for the ``whatweb`` technology fingerprinting scanner."""

    descriptor = ToolDescriptor(
        name="whatweb",
        version=_VERSION,
        description="WhatWeb deep web technology fingerprinting.",
        entrypoint="hunterx.tools.tech.whatweb:WhatWebAdapter",
        targets=("url", "host", "domain"),
        capabilities=("technology-fingerprinting",),
        permissions=("network",),
        parameters={
            "aggression": {
                "type": "integer",
                "description": "Aggression level (1 passive .. 4 aggressive).",
            },
            "follow_redirects": {
                "type": "boolean",
                "description": "Follow HTTP redirects.",
            },
            "user_agent": {
                "type": "string",
                "description": "Custom user agent string.",
            },
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build the ``whatweb`` command line for ``context``."""
        argv = [
            "whatweb",
            "--no-errors",
            "--log-json=-",
            "--quiet",
        ]
        aggression = self._param_int(context, "aggression", 0)
        if aggression > 0:
            argv += ["--aggression", str(min(4, aggression))]
        if self._param_bool(context, "follow_redirects", True):
            argv.append("--follow-redirect=never")
        user_agent = context.parameters.get("user_agent")
        if isinstance(user_agent, str) and user_agent:
            argv += ["--user-agent", user_agent]
        argv.append(guard_positional_target(context.target, label="whatweb target"))
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[TechnologyObservation]:
        """Parse WhatWeb JSON output into canonical technology observations."""
        observations: list[TechnologyObservation] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
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
    """Convert one WhatWeb target record into observations."""
    observations: list[TechnologyObservation] = []
    status = payload.get("http_status")
    plugins = payload.get("plugins")
    if not isinstance(plugins, Mapping):
        return observations
    for name, raw in plugins.items():
        raw_name = str(name).strip()
        if not raw_name:
            continue
        entries = _plugin_entries(raw)
        certainty = max((_entry_certainty(entry) for entry in entries), default=0)
        version = next((_entry_version(entry) for entry in entries if _entry_version(entry)), "")
        evidence = _plugin_evidence(raw_name, entries, status)
        observations.append(
            adapter._observation(
                context,
                raw_name,
                version=version,
                version_strong=bool(version),
                source="whatweb",
                evidence=evidence,
                confidence=max(0.1, min(1.0, certainty / 100.0)),
            )
        )
    return observations


def _plugin_entries(raw: object) -> list[Mapping[str, Any]]:
    """Normalize a WhatWeb plugin value into a list of entry dicts."""
    if isinstance(raw, Mapping):
        return [raw]
    if isinstance(raw, list):
        return [entry for entry in raw if isinstance(entry, Mapping)]
    return []


def _entry_certainty(entry: Mapping[str, Any]) -> int:
    try:
        return int(entry.get("certainty") or 0)
    except (TypeError, ValueError):
        return 0


def _entry_version(entry: Mapping[str, Any]) -> str:
    return str(entry.get("version") or "").strip()


def _plugin_evidence(
    name: str, entries: Sequence[Mapping[str, Any]], status: object
) -> tuple[dict[str, Any], ...]:
    """Build evidence fragments for a WhatWeb plugin."""
    evidence: list[dict[str, Any]] = []
    for entry in entries:
        certainty = _entry_certainty(entry)
        strength = "strong" if certainty >= 90 else ("moderate" if certainty >= 60 else "weak")
        evidence.append(
            {
                "evidence_type": "known-signature",
                "value": f"{name} certainty={certainty}",
                "source": "whatweb",
                "strength": strength,
                "detail": str(entry.get("string") or "") or f"certainty={certainty}",
            }
        )
    if isinstance(status, int):
        evidence.append(
            {
                "evidence_type": "http-status",
                "value": str(status),
                "source": "whatweb",
                "strength": "moderate",
                "detail": f"status: {status}",
            }
        )
    return tuple(evidence)
