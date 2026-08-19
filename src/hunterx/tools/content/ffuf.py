# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Ffuf tool adapter.

Integrates ``ffuf`` — a fast web fuzzer — into the Tool Integration SDK for
content discovery, URL fuzzing and parameter fuzzing. The adapter builds a
structured command line from the execution context (URL, wordlist, matcher,
rate/concurrency controls), requests JSON output (``-o - -of json``) and parses
the ``results`` array into canonical content-discovery records.

Scope and wordlist safety are enforced upstream by the arsenal layer: the
wordlist is validated data (a regular file on disk), never executable content,
and the target URL must stay inside the authorized scope.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from hunterx.domain.execution import ExecutionContext
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.content.base import ContentToolAdapter
from hunterx.tools.recon.runner import CommandResult

_VERSION = "2.1.0"

#: Default matcher flags: report 200-299, 300-399, 401, 403, 405, 429 responses.
_DEFAULT_MATCHER = "200-299,300-399,401,403,405,429"

#: Default false-positive size/length exclusions supplied by the caller.
_DEFAULT_FILTER_SIZE = "0"


class FfufAdapter(ContentToolAdapter):
    """SDK adapter for the ``ffuf`` web fuzzer."""

    descriptor = ToolDescriptor(
        name="ffuf",
        version=_VERSION,
        description="Fast web fuzzer for content, directory and parameter discovery.",
        entrypoint="hunterx.tools.content.ffuf:FfufAdapter",
        targets=("url",),
        capabilities=("directory-discovery", "web-fuzzing", "parameter-discovery"),
        permissions=("network",),
        parameters={
            "url": {
                "type": "string",
                "description": "Target URL template with the FUZZ keyword (or target + wordlist).",
            },
            "wordlist": {
                "type": "string",
                "description": "Path to a wordlist data file (validated upstream).",
            },
            "matcher": {
                "type": "string",
                "description": "HTTP status-code matcher (e.g. 200,301,403).",
            },
            "filter_size": {
                "type": "string",
                "description": "Comma separated response-size filters (false-positive control).",
            },
            "threads": {"type": "integer", "description": "Concurrent fuzzing threads."},
            "rate_limit": {"type": "integer", "description": "Maximum requests per second."},
            "delay": {"type": "number", "description": "Delay between requests in seconds."},
            "timeout": {"type": "integer", "description": "Per-request timeout in seconds."},
            "method": {"type": "string", "description": "HTTP method to use (GET/POST/...)."},
            "mode": {
                "type": "string",
                "enum": ["directory", "parameter", "combined"],
                "description": "Fuzzing mode (directory/parameter/combined).",
            },
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build the ``ffuf`` command line for ``context``.

        The command line is assembled from typed parameters only. ``url`` and
        ``wordlist`` are required: a missing wordlist would emit an invalid
        ``-w ''`` invocation that ffuf rejects with a usage error, so the
        adapter fails closed like its sibling content adapters.
        """
        url = str(context.target)
        wordlist = context.parameters.get("wordlist")
        if not isinstance(wordlist, str) or not wordlist.strip():
            raise ValueError("ffuf requires a 'wordlist' parameter")
        argv = ["ffuf", "-u", url, "-w", wordlist, "-o", "-", "-of", "json", "-s"]
        matcher = str(context.parameters.get("matcher") or _DEFAULT_MATCHER)
        argv += ["-mc", matcher]
        filter_size = str(context.parameters.get("filter_size") or _DEFAULT_FILTER_SIZE)
        if filter_size:
            argv += ["-fs", filter_size]
        threads = self._param_int(context, "threads", 0)
        if threads > 0:
            argv += ["-t", str(threads)]
        rate_limit = self._param_int(context, "rate_limit", 0)
        if rate_limit > 0:
            argv += ["-rate", str(rate_limit)]
        delay = self._param_float(context, "delay", 0.0)
        if delay > 0:
            argv += ["-p", f"{delay:g}"]
        timeout = self._param_int(context, "timeout", 0)
        if timeout > 0:
            argv += ["-timeout", str(timeout)]
        method = str(context.parameters.get("method") or "GET").upper()
        if method not in ("GET",):
            argv += ["-X", method]
        return argv

    def parse_output(
        self, context: ExecutionContext, result: CommandResult
    ) -> list[dict[str, Any]]:
        """Convert ffuf JSON output into canonical content records."""
        payload = _parse_json(result.stdout)
        if payload is None:
            return []
        config = payload.get("config")
        if not isinstance(config, dict):
            config = {}
        tool_configuration = {
            "wordlist": config.get("wordlist") or context.parameters.get("wordlist", ""),
            "matcher": config.get("matcher") or context.parameters.get("matcher", ""),
            "threads": config.get("threads") or 0,
            "rate": config.get("rate") or 0,
            "method": config.get("method") or "GET",
        }
        results = payload.get("results")
        if not isinstance(results, list):
            return []
        records: list[dict[str, Any]] = []
        for item in results:
            record = self._parse_result(item, context, tool_configuration)
            if record is not None:
                records.append(record)
        return records

    # -- helpers -------------------------------------------------------------

    def _parse_result(
        self,
        item: Mapping[str, Any],
        context: ExecutionContext,
        tool_configuration: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Convert one ffuf result mapping into a canonical record."""
        if not isinstance(item, Mapping):
            return None
        url = str(item.get("url") or "").strip()
        if not url:
            return None
        status = item.get("status")
        return {
            "url": url,
            "method": str(item.get("method") or tool_configuration.get("method", "GET")),
            "status": int(status) if isinstance(status, int) else None,
            "size": _optional_int(item.get("length")),
            "words": _optional_int(item.get("words")),
            "lines": _optional_int(item.get("lines")),
            "content_type": str(item.get("content-type") or "") or None,
            "redirect": str(item.get("redirectlocation") or "") or None,
            "input": _input_mapping(item.get("input")),
            "match_condition": str(item.get("status") or "") if status else "",
            "duration_ms": _optional_int(item.get("duration")),
            "tool_configuration": tool_configuration,
            "tool_id": "ffuf",
            "target_key": _target_host(url, context),
            "source": "ffuf",
            "correlation_id": context.correlation_id,
            "mission_id": context.mission_id,
            "execution_id": context.execution_id,
        }

    def _param_float(self, context: ExecutionContext, name: str, default: float) -> float:
        value = self._param(context, name, default)
        try:
            return float(value)
        except (TypeError, ValueError):
            return default


def _parse_json(text: str) -> dict[str, Any] | None:
    """Parse ``text`` as JSON defensively (returns ``None`` when malformed)."""
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def _optional_int(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _input_mapping(value: Any) -> dict[str, str]:
    """Normalize ffuf ``input`` mapping to a JSON-safe dict of strings."""
    if not isinstance(value, Mapping):
        return {}
    return {str(key): str(item) for key, item in value.items()}


def _target_host(url: str, context: ExecutionContext) -> str:
    """Return the canonical owning host key for a discovered URL."""
    from urllib.parse import urlparse

    try:
        host = urlparse(url).netloc
        return host or context.target.strip()
    except ValueError:
        return context.target.strip()
