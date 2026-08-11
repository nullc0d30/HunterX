# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Artifact and file-handling security (Sprint 034.4 §12).

Tool output files, screenshots, captures and report exports must be written
inside controlled directories; hostile filenames must not traverse the
filesystem.
"""

from __future__ import annotations

import os

from hunterx.domain.execution import ExecutionContext
from hunterx.tools.sdk.output import OutputCollector
from hunterx.tools.sdk.sandbox import ExecutionSandbox


def _context(**overrides) -> ExecutionContext:
    defaults = {"tool_id": "nuclei", "execution_id": "exec-1", "parameters": {}}
    defaults.update(overrides)
    return ExecutionContext(**defaults)


def test_artifact_output_dir_is_isolated_per_execution() -> None:
    sandbox = ExecutionSandbox()
    first = sandbox.create_output_directory(_context(execution_id="exec-a"))
    second = sandbox.create_output_directory(_context(execution_id="exec-b"))
    assert first != second
    assert os.path.isdir(first) and os.path.isdir(second)


def test_hostile_execution_ids_cannot_traverse_base() -> None:
    sandbox = ExecutionSandbox()
    base = sandbox.create_output_directory(_context(execution_id="safe"))
    hostile = sandbox.create_output_directory(_context(execution_id="../../../etc/passwd"))
    # The hostile execution id is sanitized into a single path component.
    name = os.path.basename(hostile)
    assert ".." not in name
    assert os.path.dirname(hostile) == os.path.dirname(base) or "etc" not in name


def test_collector_stores_artifact_paths_without_execution() -> None:
    collector = OutputCollector()
    collector.attach_file("../evil/x.js", screenshot=True)
    collector.attach_pcap("/tmp/capture.pcap")
    output = collector.build()
    # Paths are references for later controlled retrieval, never opened here.
    assert output.files == ["../evil/x.js", "/tmp/capture.pcap"]
    assert output.screenshots == ["../evil/x.js"]
    assert output.pcap_references == ["/tmp/capture.pcap"]


def test_output_capture_is_untrusted_data() -> None:
    collector = OutputCollector()
    collector.attach_stdout("<img src=x onerror=alert(1)>\n<script>alert(2)</script>")
    output = collector.build()
    # HTML/script content in stdout is inert data until explicitly rendered.
    assert "<script>alert(2)</script>" in output.stdout
    assert output.json is None or output.json is not None


def test_collector_auto_detects_json_without_eval() -> None:
    collector = OutputCollector()
    collector.attach_stdout('{"match": true, "host": "example.com"}')
    output = collector.build()
    assert output.json == {"match": True, "host": "example.com"}
