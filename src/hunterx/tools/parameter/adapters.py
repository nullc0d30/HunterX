# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Parameter discovery adapters.

Integrates ``arjun`` (get/post parameter discovery), ``paramspider`` (passive
parameter harvesting from archived URLs) and ``kiterunner`` (route/endpoint
bruteforcing) into the Tool Integration SDK. External binaries run through the
shared runner seam and emit canonical parameter records.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import tempfile
from typing import Any

from hunterx.domain.execution import ExecutionContext
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.parameter.base import ParameterToolAdapter
from hunterx.tools.recon.runner import BinaryRunner, CommandResult

_ARJUN_VERSION = "2.2.6"
_PARAMSPIDER_VERSION = "1.0.0"
_KITERUNNER_VERSION = "1.0.0"


def _arjun_uid() -> str:
    """Return a short unique suffix for an arjun temp report file."""
    import uuid

    return uuid.uuid4().hex[:8]

#: Matches ``name=value`` pairs inside discovered URLs.
_PARAM_RE = re.compile(r"[?&]([A-Za-z0-9_\-\.\[\]]+)=([^&#]*)")
#: Matches ``name: [values]`` inside arjun JSON.
_ARJUN_KEY_RE = re.compile(r'^"([^"]+)"\s*:\s*(\[.*\])$')


class ArjunAdapter(ParameterToolAdapter):
    """SDK adapter for ``arjun`` HTTP parameter discovery."""

    #: Arjun's CLI contract is verified by running its actual invocation (the
    #: health check catches a broken command even when the binary is installed).
    INVOCATION_VERIFIABLE = True

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

    def __init__(self, runner: BinaryRunner | None = None) -> None:
        super().__init__(runner=runner)
        self._json_path: str = ""

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build argv.

        ``-oJ`` is arjun's documented JSON-output flag and REQUIRES a file
        argument (``arjun -h``: ``-o, -oJ JSON_FILE``); without it arjun exits
        with an argparse usage error. Arjun writes its JSON parameter report to
        that file (``-q`` silences the progress), and the adapter reads it back
        in :meth:`parse_output`.
        """
        if not self._json_path:
            self._json_path = os.path.join(
                tempfile.gettempdir(),
                f"hunterx-arjun-{context.correlation_id or context.execution_id or _arjun_uid()}.json",
            )
        argv = ["arjun", "-u", context.target, "-oJ", self._json_path, "-q"]
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
        payload = self._read_json_report()
        if isinstance(payload, dict):
            records = self._records_from_dict(payload, context, from_file=True)
            if records:
                return records
        # stdout fallback: arjun JSON dict or per-line ``name: [values]``.
        text = result.stdout
        if not text.strip():
            return records
        try:
            payload = json.loads(text)
        except (json.JSONDecodeError, TypeError, ValueError):
            payload = None
        if isinstance(payload, dict):
            records = self._records_from_dict(payload, context, from_file=False)
            if records:
                return records
        for line in text.splitlines():
            match = _ARJUN_KEY_RE.match(line.strip())
            if match:
                records.append(_parameter_record(match.group(1), match.group(2), context, method="GET"))
        return records

    @staticmethod
    def _records_from_dict(
        payload: dict[str, Any], context: ExecutionContext, *, from_file: bool
    ) -> list[dict[str, Any]]:
        """Extract parameter records from either arjun report shape.

        * JSON report file (``-oJ``): ``{url: {headers, method, params: [..]}}``.
        * stdout JSON: ``{parameter_name: [values, ...]}``.
        """
        records: list[dict[str, Any]] = []
        for key, value in payload.items():
            if isinstance(value, dict) and from_file:
                for name in value.get("params") or ():
                    if not isinstance(name, str) or not name:
                        continue
                    records.append(
                        _parameter_record(
                            name,
                            [],
                            context,
                            endpoint=str(key or context.target),
                            method=str(value.get("method") or context.parameters.get("method") or "GET"),
                        )
                    )
            elif isinstance(value, list) and isinstance(key, str):
                records.append(_parameter_record(key, value, context, method="GET"))
        return records

    def cleanup(self, context: ExecutionContext) -> None:
        """Remove the temporary arjun JSON report file."""
        if self._json_path:
            with contextlib.suppress(OSError):
                os.remove(self._json_path)
            self._json_path = ""

    def _read_json_report(self) -> dict[str, Any] | None:
        """Return the parsed arjun JSON report, or ``None`` when absent."""
        if not self._json_path or not os.path.exists(self._json_path):
            return None
        try:
            with open(self._json_path, encoding="utf-8") as handle:
                return json.load(handle)
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            return None


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
