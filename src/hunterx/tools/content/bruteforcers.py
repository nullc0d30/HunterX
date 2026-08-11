# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Directory / content bruteforce adapters.

Integrates ``gobuster``, ``feroxbuster`` and ``dirsearch`` — the wordlist-driven
content discovery tools — into the Tool Integration SDK. Each adapter invokes
its external binary through the shared
:class:`~hunterx.tools.recon.runner.BinaryRunner` seam and normalizes JSON /
JSONL output into canonical content-discovery records.

Wordlists are treated strictly as data (validated files on disk), never as
executable content; targets must stay inside the authorized scope.
"""

from __future__ import annotations

import json
from typing import Any

from hunterx.domain.execution import ExecutionContext
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.content.base import ContentToolAdapter
from hunterx.tools.recon.runner import CommandResult

_GOBUSTER_VERSION = "3.6.0"
_FEROXBUSTER_VERSION = "2.10.4"
_DIRSEARCH_VERSION = "0.4.3"


class GobusterAdapter(ContentToolAdapter):
    """SDK adapter for the ``gobuster`` content bruteforcer."""

    descriptor = ToolDescriptor(
        name="gobuster",
        version=_GOBUSTER_VERSION,
        description="Wordlist-driven directory/file bruteforcing (dir mode).",
        entrypoint="hunterx.tools.content.bruteforcers:GobusterAdapter",
        targets=("url", "host"),
        capabilities=("directory-discovery", "file-enumeration"),
        permissions=("network",),
        parameters={
            "wordlist": {"type": "string", "description": "Path to the wordlist data file."},
            "threads": {"type": "integer", "description": "Concurrent worker threads."},
            "status_codes": {"type": "string", "description": "Comma-separated status codes to report."},
            "extensions": {"type": "array", "items": {"type": "string"}, "description": "File extensions to append."},
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build argv."""
        wordlist = context.parameters.get("wordlist")
        if not isinstance(wordlist, str) or not wordlist:
            raise ValueError("gobuster requires a 'wordlist' parameter")
        argv = ["gobuster", "dir", "-u", context.target, "-w", wordlist, "-q", "-j"]
        threads = self._param_int(context, "threads", 0)
        if threads > 0:
            argv += ["-t", str(threads)]
        status_codes = context.parameters.get("status_codes")
        if isinstance(status_codes, str) and status_codes:
            argv += ["-s", status_codes]
        extensions = context.parameters.get("extensions")
        if isinstance(extensions, (list, tuple)) and extensions:
            argv += ["-x", ",".join(str(item).lstrip(".") for item in extensions)]
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[dict[str, Any]]:
        """Parse output."""
        records: list[dict[str, Any]] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            record = _gobuster_record(line, context)
            if record is not None:
                records.append(record)
        return records


class FeroxbusterAdapter(ContentToolAdapter):
    """SDK adapter for the ``feroxbuster`` content bruteforcer."""

    descriptor = ToolDescriptor(
        name="feroxbuster",
        version=_FEROXBUSTER_VERSION,
        description="Fast, simple content discovery tool written in Rust.",
        entrypoint="hunterx.tools.content.bruteforcers:FeroxbusterAdapter",
        targets=("url", "host"),
        capabilities=("directory-discovery", "file-enumeration"),
        permissions=("network",),
        parameters={
            "wordlist": {"type": "string", "description": "Path to the wordlist data file."},
            "threads": {"type": "integer", "description": "Concurrent worker threads."},
            "depth": {"type": "integer", "description": "Maximum crawl depth."},
            "status_codes": {"type": "string", "description": "Comma-separated status codes to report."},
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build argv."""
        wordlist = context.parameters.get("wordlist")
        if not isinstance(wordlist, str) or not wordlist:
            raise ValueError("feroxbuster requires a 'wordlist' parameter")
        argv = ["feroxbuster", "-u", context.target, "-w", wordlist, "-q", "--json"]
        threads = self._param_int(context, "threads", 0)
        if threads > 0:
            argv += ["-t", str(threads)]
        depth = self._param_int(context, "depth", 0)
        if depth > 0:
            argv += ["-d", str(depth)]
        status_codes = context.parameters.get("status_codes")
        if isinstance(status_codes, str) and status_codes:
            argv += ["-s", status_codes]
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[dict[str, Any]]:
        """Parse output."""
        records: list[dict[str, Any]] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            record = _ferox_record(line, context)
            if record is not None:
                records.append(record)
        return records


class DirsearchAdapter(ContentToolAdapter):
    """SDK adapter for the ``dirsearch`` content bruteforcer."""

    descriptor = ToolDescriptor(
        name="dirsearch",
        version=_DIRSEARCH_VERSION,
        description="Advanced web path scanner with a mature status/size matcher model.",
        entrypoint="hunterx.tools.content.bruteforcers:DirsearchAdapter",
        targets=("url", "host"),
        capabilities=("directory-discovery", "file-enumeration"),
        permissions=("network",),
        parameters={
            "wordlist": {"type": "string", "description": "Path to the wordlist data file."},
            "threads": {"type": "integer", "description": "Concurrent worker threads."},
            "extensions": {"type": "array", "items": {"type": "string"}, "description": "File extensions to scan."},
            "exclude_status": {"type": "string", "description": "Comma-separated status codes to exclude."},
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build argv."""
        wordlist = context.parameters.get("wordlist")
        if not isinstance(wordlist, str) or not wordlist:
            raise ValueError("dirsearch requires a 'wordlist' parameter")
        argv = ["dirsearch", "-u", context.target, "-w", wordlist, "-q", "--format=json"]
        threads = self._param_int(context, "threads", 0)
        if threads > 0:
            argv += ["-t", str(threads)]
        extensions = context.parameters.get("extensions")
        if isinstance(extensions, (list, tuple)) and extensions:
            argv += ["-e", ",".join(str(item).lstrip(".") for item in extensions)]
        exclude = context.parameters.get("exclude_status")
        if isinstance(exclude, str) and exclude:
            argv += ["-x", exclude]
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[dict[str, Any]]:
        """Parse output."""
        payload = _parse_json(result.stdout)
        if payload is None:
            return []
        results = payload.get("results")
        if not isinstance(results, list):
            return []
        records: list[dict[str, Any]] = []
        for item in results:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url") or "").strip()
            if not url:
                continue
            status = item.get("status")
            records.append(
                {
                    "url": url,
                    "method": str(item.get("method") or "GET"),
                    "status": int(status) if isinstance(status, int) else None,
                    "size": _optional_int(item.get("content-length")),
                    "content_type": str(item.get("content-type") or "") or None,
                    "redirect": str(item.get("redirectlocation") or "") or None,
                    "tool_id": "dirsearch",
                    "source": "dirsearch",
                    "tool_configuration": {"wordlist": context.parameters.get("wordlist", "")},
                    "correlation_id": context.correlation_id,
                    "mission_id": context.mission_id,
                    "execution_id": context.execution_id,
                }
            )
        return records


def _gobuster_record(line: str, context: ExecutionContext) -> dict[str, Any] | None:
    try:
        payload = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(payload, dict):
        return None
    path = str(payload.get("path") or "").strip()
    if not path:
        return None
    status = payload.get("status")
    return {
        "url": path,
        "method": "GET",
        "status": int(status) if isinstance(status, int) else None,
        "size": _optional_int(payload.get("length")),
        "redirect": str(payload.get("redirectlocation") or "") or None,
        "tool_id": "gobuster",
        "source": "gobuster",
        "tool_configuration": {"wordlist": context.parameters.get("wordlist", "")},
        "correlation_id": context.correlation_id,
        "mission_id": context.mission_id,
        "execution_id": context.execution_id,
    }


def _ferox_record(line: str, context: ExecutionContext) -> dict[str, Any] | None:
    try:
        payload = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(payload, dict):
        return None
    url = str(payload.get("url") or "").strip()
    if not url:
        return None
    status = payload.get("status")
    return {
        "url": url,
        "method": str(payload.get("method") or "GET"),
        "status": int(status) if isinstance(status, int) else None,
        "size": _optional_int(payload.get("content_length") or payload.get("size")),
        "words": _optional_int(payload.get("words")),
        "content_type": str(payload.get("content_type") or "") or None,
        "tool_id": "feroxbuster",
        "source": "feroxbuster",
        "tool_configuration": {"wordlist": context.parameters.get("wordlist", "")},
        "correlation_id": context.correlation_id,
        "mission_id": context.mission_id,
        "execution_id": context.execution_id,
    }


def _parse_json(text: str) -> dict[str, Any] | None:
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


__all__ = ["GobusterAdapter", "FeroxbusterAdapter", "DirsearchAdapter"]
