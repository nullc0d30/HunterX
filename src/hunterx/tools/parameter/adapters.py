# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Parameter discovery adapters.

Integrates ``arjun`` (get/post parameter discovery), ``paramspider`` (passive
parameter harvesting from archived URLs) and ``kiterunner`` (route/endpoint
bruteforcing) into the Tool Integration SDK. External binaries run through the
shared runner seam and emit canonical parameter records.
"""

from __future__ import annotations

import json
import re
from typing import Any

from hunterx.domain.execution import ExecutionContext
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.parameter.base import ParameterToolAdapter
from hunterx.tools.recon.runner import CommandResult

_ARJUN_VERSION = "2.2.6"
_PARAMSPIDER_VERSION = "1.0.0"
_KITERUNNER_VERSION = "1.0.0"

#: Matches ``name=value`` pairs inside discovered URLs.
_PARAM_RE = re.compile(r"[?&]([A-Za-z0-9_\-\.\[\]]+)=([^&#]*)")
#: Matches ``name: [values]`` inside arjun JSON.
_ARJUN_KEY_RE = re.compile(r'^"([^"]+)"\s*:\s*(\[.*\])$')


class ArjunAdapter(ParameterToolAdapter):
    """SDK adapter for ``arjun`` HTTP parameter discovery."""

    descriptor = ToolDescriptor(
        name="arjun",
        version=_ARJUN_VERSION,
        description="HTTP parameter discovery for GET and POST requests.",
        entrypoint="hunterx.tools.parameter.adapters:ArjunAdapter",
        targets=("url", "host"),
        capabilities=("parameter-discovery", "get-parameter-discovery", "post-parameter-discovery"),
        permissions=("network",),
        parameters={
            "method": {"type": "string", "enum": ["GET", "POST"], "description": "HTTP method to probe."},
            "wordlist": {"type": "string", "description": "Path to the parameter wordlist."},
            "threads": {"type": "integer", "description": "Concurrent workers."},
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build argv."""
        argv = ["arjun", "-u", context.target, "-oJ", "-q"]
        method = str(context.parameters.get("method") or "GET").upper()
        if method == "POST":
            argv.append("-m")
            argv.append("POST")
        wordlist = context.parameters.get("wordlist")
        if isinstance(wordlist, str) and wordlist:
            argv += ["-w", wordlist]
        threads = self._param_int(context, "threads", 0)
        if threads > 0:
            argv += ["-t", str(threads)]
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[dict[str, Any]]:
        """Parse output."""
        records: list[dict[str, Any]] = []
        text = result.stdout
        if not text.strip():
            return records
        try:
            payload = json.loads(text)
        except (json.JSONDecodeError, TypeError, ValueError):
            payload = None
        if isinstance(payload, dict):
            for name, values in payload.items():
                if not isinstance(name, str):
                    continue
                records.append(_parameter_record(name, values, context, method=str(context.parameters.get("method") or "GET")))
            return records
        # Arjun also prints a per-line ``name: [values]`` summary.
        for line in text.splitlines():
            match = _ARJUN_KEY_RE.match(line.strip())
            if match:
                records.append(_parameter_record(match.group(1), match.group(2), context, method="GET"))
        return records


class ParamspiderAdapter(ParameterToolAdapter):
    """SDK adapter for ``paramspider`` passive parameter harvesting."""

    descriptor = ToolDescriptor(
        name="paramspider",
        version=_PARAMSPIDER_VERSION,
        description="Passive parameter discovery from archived URLs.",
        entrypoint="hunterx.tools.parameter.adapters:ParamspiderAdapter",
        targets=("domain",),
        capabilities=("parameter-discovery", "historical-parameter-discovery"),
        permissions=("network",),
        parameters={
            "level": {"type": "string", "enum": ["low", "medium", "high"], "description": "Crawl depth for archived URLs."},
            "exclude": {"type": "array", "items": {"type": "string"}, "description": "Extensions to exclude."},
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build argv."""
        argv = ["paramspider", "-d", context.target, "-q"]
        level = str(context.parameters.get("level") or "medium")
        if level in ("low", "medium", "high"):
            argv += ["--level", level]
        exclude = context.parameters.get("exclude")
        if isinstance(exclude, (list, tuple)) and exclude:
            argv += ["-e", ",".join(str(item).lstrip(".") for item in exclude)]
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[dict[str, Any]]:
        """Parse output."""
        records: list[dict[str, Any]] = []
        seen: set[str] = set()
        for line in result.stdout.splitlines():
            url = line.strip()
            if not url.startswith("http://") and not url.startswith("https://"):
                continue
            for name in _extract_params(url):
                key = f"{url}::{name}"
                if key in seen:
                    continue
                seen.add(key)
                records.append(
                    _parameter_record(
                        name,
                        [],
                        context,
                        endpoint=url,
                        method="GET",
                        source="paramspider",
                    )
                )
        return records


class KiterunnerAdapter(ParameterToolAdapter):
    """SDK adapter for ``kiterunner`` route/endpoint bruteforcing."""

    descriptor = ToolDescriptor(
        name="kiterunner",
        version=_KITERUNNER_VERSION,
        description="Route and endpoint discovery using wordlists of common API paths.",
        entrypoint="hunterx.tools.parameter.adapters:KiterunnerAdapter",
        targets=("url", "host"),
        capabilities=("endpoint-discovery", "api-discovery"),
        permissions=("network",),
        parameters={
            "wordlist": {"type": "string", "description": "Path to the route wordlist (kr-wordlist)."},
            "threads": {"type": "integer", "description": "Concurrent workers."},
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build argv."""
        wordlist = context.parameters.get("wordlist")
        if not isinstance(wordlist, str) or not wordlist:
            raise ValueError("kiterunner requires a 'wordlist' parameter")
        argv = ["kr", "scan", context.target, "-w", wordlist, "-j", "-q"]
        threads = self._param_int(context, "threads", 0)
        if threads > 0:
            argv += ["-t", str(threads)]
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[dict[str, Any]]:
        """Parse output."""
        records: list[dict[str, Any]] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                payload = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                continue
            if not isinstance(payload, dict):
                continue
            url = str(payload.get("url") or "").strip()
            if not url:
                continue
            status = payload.get("statusCode")
            records.append(
                {
                    "endpoint": url,
                    "method": str(payload.get("method") or "GET"),
                    "status": int(status) if isinstance(status, int) else None,
                    "length": _optional_int(payload.get("totalLength")),
                    "parameters": [],
                    "tool_id": "kiterunner",
                    "source": "kiterunner",
                    "correlation_id": context.correlation_id,
                    "mission_id": context.mission_id,
                    "execution_id": context.execution_id,
                }
            )
        return records


def _parameter_record(
    name: str,
    values: Any,
    context: ExecutionContext,
    *,
    endpoint: str = "",
    method: str = "GET",
    source: str = "arjun",
) -> dict[str, Any]:
    value_list: list[str] = []
    if isinstance(values, list):
        value_list = [str(item) for item in values]
    elif isinstance(values, str):
        value_list = [values]
    return {
        "name": name,
        "values": value_list,
        "endpoint": endpoint or str(context.target),
        "method": method,
        "tool_id": source,
        "source": source,
        "correlation_id": context.correlation_id,
        "mission_id": context.mission_id,
        "execution_id": context.execution_id,
    }


def _extract_params(url: str) -> list[str]:
    names: list[str] = []
    for match in _PARAM_RE.finditer(url):
        name = match.group(1)
        if name not in names:
            names.append(name)
    return names


def _optional_int(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


__all__ = ["ArjunAdapter", "ParamspiderAdapter", "KiterunnerAdapter"]
