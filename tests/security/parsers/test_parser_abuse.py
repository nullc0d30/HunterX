# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Parser security (Sprint 034.4 §10, §11).

External tool output is hostile input. Parsers must treat it as data: no code
execution, no deserialization of unsafe objects, bounded failure behavior.
"""

from __future__ import annotations

import pytest

from hunterx.domain.exceptions import ToolExecutionError
from hunterx.tools.parser import ParserEngine

_PARSER_HOSTILE = [
    "",
    "not json at all",
    "\x1b[31mRED\x1b[0m",
    '{"a": "b"}\n{"c": "d"}',  # NDJSON to a single-dict parser
    "{'__import__': 'os'}",
    "$(rm -rf /); echo pwned",
    "<script>alert(1)</script>",
]


@pytest.mark.parametrize("payload", _PARSER_HOSTILE)
def test_default_parser_never_executes_content(payload: str) -> None:
    """Hostile text is never executed; it either parses to data or fails."""
    engine = ParserEngine()
    if payload.lstrip().startswith(("{", "[")):
        try:
            records = engine.parse("tool", payload)
        except ToolExecutionError:
            records = []
        assert isinstance(records, list)
    else:
        with pytest.raises(ToolExecutionError):
            engine.parse("tool", payload)


def test_default_parser_handles_oversized_input_without_execution() -> None:
    """A very large hostile blob is rejected as data, never executed."""
    engine = ParserEngine()
    with pytest.raises(ToolExecutionError):
        engine.parse("tool", "x" * 500_000)


def test_default_parser_accepts_json_data_only() -> None:
    engine = ParserEngine()
    records = engine.parse("tool", [{"id": 1}, {"id": 2}])
    assert records == [{"id": 1}, {"id": 2}]
    records = engine.parse("tool", {"id": 1})
    assert records == [{"id": 1}]


def test_default_parser_rejects_scalars_and_wrong_types() -> None:
    engine = ParserEngine()
    for payload in (42, 3.14, True, None, object()):
        with pytest.raises(ToolExecutionError):
            engine.parse("tool", payload)
    # Lists are projected to their dict items; non-dict entries are dropped
    # (data, never executed).
    assert engine.parse("tool", ["not-a-dict", {"a": 1}]) == [{"a": 1}]


def test_parser_registry_failure_is_wrapped() -> None:
    def hostile_parser(tool: str, raw) -> list[dict]:
        raise ValueError("boom from untrusted content")

    engine = ParserEngine()
    engine.register("tool", hostile_parser)
    with pytest.raises(ToolExecutionError):
        engine.parse("tool", "x")


def test_parsers_do_not_deserialize_unsafe_objects() -> None:
    """JSON parsing is used throughout; pickle/yaml.load are never used by
    tool parsers. The source tree must not contain unsafe deserialization
    calls in the tools layer."""
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[3] / "src" / "hunterx" / "tools"
    offenders: list[str] = []
    for path in root.rglob("*.py"):
        if "__pycache__" in str(path):
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.lstrip()
            if stripped.startswith(("pickle.load", "yaml.load(", "marshal.loads")):
                offenders.append(f"{path.name}:{lineno}")
    assert not offenders


def test_output_collector_treats_hostile_stdout_as_bytes() -> None:
    from hunterx.tools.sdk.output import OutputCollector

    collector = OutputCollector()
    collector.attach_stdout("\x1b[2J\x1b[Hwhoami; rm -rf /\n{'a':1}")
    output = collector.build()
    # The collector detects JSON but never interprets the text as code.
    assert "\x1b[2J" in output.stdout


def test_nuclei_parser_skips_malformed_lines() -> None:
    from hunterx.domain.execution import ExecutionContext
    from hunterx.tools.recon.runner import CommandResult
    from hunterx.tools.vuln.nuclei import NucleiAdapter

    adapter = NucleiAdapter()
    context = ExecutionContext(tool_id="nuclei", target="example.com")
    result = CommandResult(returncode=0, stdout="not json\n{}\n\x1b[31mgarbage\x1b[0m\n")
    records = adapter.parse_output(context, result)
    assert records == []
