# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Output collection.

Collects raw output from a tool execution into an :class:`ExecutionOutput`,
detecting the formats present (stdout, stderr, files, JSON, XML, CSV, TXT,
YAML, HTML, binary, screenshots, PCAP references). Tools and adapters write
into a collector; the pipeline freezes it into the result.
"""

from __future__ import annotations

import json
import re
from typing import Any

from hunterx.domain.execution import ExecutionOutput, OutputFormat
from hunterx.shared.time import monotonic_ms

_JSON_RE = re.compile(r"^\s*[\[{]")


class OutputCollector:
    """Incremental collector for a single execution's output.

    Usage::

        collector = OutputCollector()
        collector.attach_stdout(line)
        collector.set_json(payload)
        collector.attach_file("/tmp/out.json")
        output = collector.build()
    """

    def __init__(self) -> None:
        self._output = ExecutionOutput()
        self._started_ms = monotonic_ms()

    # -- text channels ------------------------------------------------------

    def attach_stdout(self, text: str) -> None:
        """Append text to the captured standard output."""
        if text:
            self._output.stdout = (self._output.stdout + text) if self._output.stdout else text
            self._output.add_format(OutputFormat.STDOUT)

    def attach_stderr(self, text: str) -> None:
        """Append text to the captured standard error."""
        if text:
            self._output.stderr = (self._output.stderr + text) if self._output.stderr else text
            self._output.add_format(OutputFormat.STDERR)

    def set_exit_code(self, exit_code: int) -> None:
        """Record the process exit code."""
        self._output.exit_code = int(exit_code)

    def set_json(self, payload: dict[str, Any]) -> None:
        """Store a parsed JSON payload."""
        self._output.json = payload
        self._output.add_format(OutputFormat.JSON)

    def parse_json_from_text(self, text: str) -> bool:
        """Best-effort parse of ``text`` as JSON; returns ``True`` on success."""
        try:
            payload = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return False
        if isinstance(payload, dict):
            self.set_json(payload)
            return True
        return False

    def set_xml(self, text: str) -> None:
        """Store XML output text."""
        self._output.xml = text
        self._output.add_format(OutputFormat.XML)

    def set_csv(self, rows: list[list[str]]) -> None:
        """Store parsed CSV rows."""
        self._output.csv = [list(row) for row in rows]
        self._output.add_format(OutputFormat.CSV)

    def set_txt(self, text: str) -> None:
        """Store plain-text output."""
        self._output.txt = text
        self._output.add_format(OutputFormat.TXT)

    def set_yaml(self, text: str) -> None:
        """Store YAML output text."""
        self._output.yaml = text
        self._output.add_format(OutputFormat.YAML)

    def set_html(self, text: str) -> None:
        """Store HTML output text."""
        self._output.html = text
        self._output.add_format(OutputFormat.HTML)

    def set_binary(self, payload: bytes) -> None:
        """Store a binary payload."""
        self._output.binary = payload
        self._output.add_format(OutputFormat.BINARY)

    # -- artifacts ----------------------------------------------------------

    def attach_file(self, path: str, *, screenshot: bool = False, pcap: bool = False) -> None:
        """Attach an output or artifact file produced by the tool."""
        self._output.files.append(path)
        self._output.add_format(OutputFormat.FILE)
        if screenshot:
            self._output.screenshots.append(path)
            self._output.add_format(OutputFormat.SCREENSHOT)
        if pcap:
            self._output.pcap_references.append(path)
            self._output.add_format(OutputFormat.PCAP)

    def attach_screenshot(self, path: str) -> None:
        """Attach a screenshot artifact to the output."""
        self.attach_file(path, screenshot=True)

    def attach_pcap(self, path: str) -> None:
        """Attach a packet-capture artifact to the output."""
        self.attach_file(path, pcap=True)

    # -- assembly -----------------------------------------------------------

    def build(self) -> ExecutionOutput:
        """Return the frozen output snapshot with formats finalized."""
        output = self._output
        # Auto-detect JSON when a raw stdout begins like JSON and no JSON set.
        if output.json is None and _JSON_RE.match(output.stdout):
            self.parse_json_from_text(output.stdout)
        output.formats = set(output.formats)
        return output

    @property
    def duration_ms(self) -> int:
        """Return the elapsed collection time in milliseconds."""
        return monotonic_ms() - self._started_ms
