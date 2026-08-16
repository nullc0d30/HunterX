# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Katana binary web crawler adapter.

Invokes the external ``katana`` crawler through the shared
:class:`~hunterx.tools.recon.runner.BinaryRunner` seam with a JSON-lines
output format and parses each record into canonical URL observations. Katana is
one of two integrated crawling tools alongside the in-process crawler; it is
the external-binary path for large surface discovery.

The adapter stays binary-free in unit tests: tests inject a fake runner and
assert on the JSON payload.
"""

from __future__ import annotations

import json
from typing import Any

from hunterx.domain.execution import ExecutionContext, ExecutionOutput
from hunterx.domain.tools import ToolDescriptor
from hunterx.domain.web.models import URLObservation, _http_method
from hunterx.domain.web.urls import URLNormalizer
from hunterx.tools.adapter import ToolOutput
from hunterx.tools.recon.runner import BinaryRunner, CommandResult
from hunterx.tools.sdk.output import OutputCollector
from hunterx.tools.web.base import WebToolAdapter

_VERSION = "1.0.0"

#: File extensions excluded from katana crawling by default (asset noise).
_DEFAULT_EXCLUDED_EXTENSIONS = (
    "css,png,jpg,jpeg,gif,svg,woff,woff2,ttf,eot,ico,pdf,zip,gz,tar,mp4,mp3,mov"
)


class KatanaAdapter(WebToolAdapter):
    """SDK adapter running the external ``katana`` crawler."""

    descriptor = ToolDescriptor(
        name="katana",
        version=_VERSION,
        description="External Katana web crawler producing canonical crawl observations.",
        entrypoint="hunterx.tools.web.katana:KatanaAdapter",
        targets=("url", "host", "domain"),
        capabilities=("web-crawling", "web-discovery"),
        permissions=("network",),
        parameters={
            "depth": {"type": "integer", "description": "Crawl depth passed to katana."},
            "scope": {"type": "string", "description": "Scope value passed to katana (-cs)."},
            "excluded_extensions": {
                "type": "array",
                "description": "File extensions excluded from the crawl.",
            },
            "timeout": {"type": "number", "description": "Execution timeout in seconds."},
        },
    )

    def __init__(self, runner: BinaryRunner | None = None) -> None:
        self._runner = runner or BinaryRunner()
        self._normalizer = URLNormalizer()

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build the katana command line for ``context``."""
        argv = ["katana", "-u", context.target]
        depth = self._param_int(context, "depth", 3)
        argv.extend(["-d", str(depth)])
        argv.append("-jc")
        argv.extend(["-silent"])
        scope = context.parameters.get("scope")
        if isinstance(scope, str) and scope:
            argv.extend(["-cs", scope])
        extensions = context.parameters.get("excluded_extensions")
        if isinstance(extensions, (list, tuple)) and extensions:
            argv.extend(["-ef", ",".join(str(item).lstrip(".") for item in extensions)])
        else:
            argv.extend(["-ef", _DEFAULT_EXCLUDED_EXTENSIONS])
        return argv

    def run(self, context: ExecutionContext, collector: OutputCollector) -> None:
        """Invoke katana, parse JSON-lines output and emit URL observations."""
        argv = self.build_argv(context)
        timeout = context.timeout_effective or 0.0
        result = self._runner.run(argv, timeout_s=timeout, tool_id=context.tool_id)
        collector.set_exit_code(result.returncode)
        if result.stdout:
            collector.attach_stdout(result.stdout)
        if result.stderr:
            collector.attach_stderr(result.stderr)
        observations = self.parse_output(context, result)
        self.emit(collector, urls=observations)

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[URLObservation]:
        """Convert katana JSON-lines output into canonical URL observations."""
        observations: list[URLObservation] = []
        for line in (result.stdout or "").splitlines():
            record = self._parse_line(line)
            if record is None:
                continue
            url = record.get("url", "")
            if not url:
                continue
            try:
                parsed = self._normalizer.parse(url)
            except ValueError:
                continue
            method = _http_method(str(record.get("method") or "GET"))
            status = record.get("status_code")
            observation = URLObservation(
                url=parsed.url,
                method=method,
                origin=parsed.origin,
                path=parsed.path,
                query=parsed.query,
                status_code=int(status) if isinstance(status, int) else None,
                content_type=record.get("content_type"),
                source="katana",
                tool_id="katana",
                target_key=parsed.host,
                correlation_id=context.correlation_id,
                mission_id=context.mission_id,
                execution_id=context.execution_id,
            )
            observations.append(observation)
        return _dedupe(observations)

    def validate_output(self, context: ExecutionContext, output: ExecutionOutput) -> tuple[bool, list[str]]:
        """Validate collected output; empty observation sets are valid results."""
        errors: list[str] = []
        if output.exit_code != 0:
            errors.append(f"exit code {output.exit_code}")
        if not output.has_content:
            errors.append("no output produced")
        return (not errors, errors)

    def normalize(self, context: ExecutionContext, output: ExecutionOutput) -> ToolOutput:
        """Project crawl observations into the legacy asset surface."""
        tool_output = ToolOutput()
        if output.stdout:
            tool_output.raw = output.stdout
        payload = output.json
        if isinstance(payload, dict) and isinstance(payload.get("crawl"), dict):
            urls = payload["crawl"].get("urls") or []
            tool_output.assets = [entry for entry in urls if isinstance(entry, dict)]
        if output.stderr:
            tool_output.error = output.stderr
        return tool_output

    # -- helpers --------------------------------------------------------------

    def _parse_line(self, line: str) -> dict[str, Any] | None:
        """Parse one katana output line (JSON-lines record or plain URL).

        Current katana emits one plain URL per line by default (the ``-json``
        flag was removed in newer releases); both forms are accepted so the
        crawler's observations are never discarded.
        """
        stripped = line.strip()
        if not stripped:
            return None
        try:
            record = json.loads(stripped)
        except (json.JSONDecodeError, TypeError):
            # Plain URL line (no JSON) — the most common current-katana output.
            if " " in stripped or "\t" in stripped:
                return None
            return {"url": stripped}
        if not isinstance(record, dict):
            return None
        request = record.get("request")
        if not isinstance(request, dict):
            return None
        url = request.get("endpoint") or request.get("url")
        if not isinstance(url, str) or not url:
            return None
        response = record.get("response")
        parsed: dict[str, Any] = {
            "url": url,
            "method": request.get("method"),
            "status_code": None,
            "content_type": None,
        }
        if isinstance(response, dict):
            status = response.get("status_code")
            if isinstance(status, int):
                parsed["status_code"] = status
            headers = response.get("headers")
            if isinstance(headers, dict):
                content_type = headers.get("Content-Type") or headers.get("content-type")
                if isinstance(content_type, str):
                    parsed["content_type"] = content_type.split(";", 1)[0].strip()
        return parsed

    def _param_int(self, context: ExecutionContext, name: str, default: int) -> int:
        try:
            return int(context.parameters.get(name, default))
        except (TypeError, ValueError):
            return default


def _dedupe(observations: list[URLObservation]) -> list[URLObservation]:
    """Deduplicate observations by canonical key while preserving order."""
    seen: set[str] = set()
    unique: list[URLObservation] = []
    for observation in observations:
        key = observation.key()
        if key in seen:
            continue
        seen.add(key)
        unique.append(observation)
    return unique
