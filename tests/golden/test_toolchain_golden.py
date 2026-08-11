# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Golden output tests for the full toolchain (Sprint 031).

Each tool category has representative fixtures covering successful, empty,
malformed and error output. Parsers must turn successful output into canonical
records, treat empty output as an empty result (never an error), skip
malformed input defensively and never treat tool errors as "target is safe".
"""

from __future__ import annotations

import pathlib

from hunterx.domain.execution import ExecutionContext
from hunterx.tools.content.ffuf import FfufAdapter
from hunterx.tools.dns.dnsx import DnsxAdapter
from hunterx.tools.recon.runner import CommandResult
from hunterx.tools.recon.subfinder import SubfinderAdapter
from hunterx.tools.vuln.nuclei import NucleiAdapter
from hunterx.tools.web.katana import KatanaAdapter

_GOLDEN = pathlib.Path(__file__).parent


def _read(relative: str) -> str:
    return (_GOLDEN / relative).read_text(encoding="utf-8")


def _context(tool_id: str, target: str) -> ExecutionContext:
    return ExecutionContext(tool_id=tool_id, target=target)


def _result(returncode: int, stdout: str, stderr: str = "") -> CommandResult:
    return CommandResult(returncode=returncode, stdout=stdout, stderr=stderr)


# -- content discovery (ffuf) -------------------------------------------------


def test_ffuf_success_parses_records() -> None:
    adapter = FfufAdapter()
    records = adapter.parse_output(_context("ffuf", "https://example.com"), _result(0, _read("content/ffuf_success.json")))
    assert len(records) == 2
    assert records[0]["url"] == "https://example.com/admin"
    assert records[0]["status"] == 200
    assert records[1]["redirect"] == "https://example.com/backup/"


def test_ffuf_empty_is_valid_empty_result() -> None:
    adapter = FfufAdapter()
    records = adapter.parse_output(_context("ffuf", "https://example.com"), _result(0, _read("content/ffuf_empty.json")))
    assert records == []


def test_ffuf_malformed_is_skipped() -> None:
    adapter = FfufAdapter()
    records = adapter.parse_output(_context("ffuf", "https://example.com"), _result(0, _read("content/ffuf_malformed.json")))
    assert records == []


# -- crawling (katana) ----------------------------------------------------------


def test_katana_success_parses_urls() -> None:
    adapter = KatanaAdapter()
    records = adapter.parse_output(_context("katana", "https://example.com"), _result(0, _read("web/katana_success.jsonl")))
    urls = {record.url for record in records}
    assert "https://example.com/admin" in urls


def test_katana_empty_is_valid() -> None:
    adapter = KatanaAdapter()
    assert adapter.parse_output(_context("katana", "https://example.com"), _result(0, _read("web/katana_empty.jsonl"))) == []


def test_katana_malformed_lines_are_skipped() -> None:
    adapter = KatanaAdapter()
    assert adapter.parse_output(_context("katana", "https://example.com"), _result(0, _read("web/katana_malformed.jsonl"))) == []


# -- recon (subfinder) -----------------------------------------------------------


def test_subfinder_error_output_never_becomes_findings() -> None:
    adapter = SubfinderAdapter()
    records = adapter.parse_output(_context("subfinder", "example.com"), _result(1, _read("recon/subfinder_error.txt")))
    assert records == []


def test_subfinder_empty_is_empty_result() -> None:
    adapter = SubfinderAdapter()
    assert adapter.parse_output(_context("subfinder", "example.com"), _result(0, _read("recon/subfinder_empty.jsonl"))) == []


# -- dns (dnsx) -------------------------------------------------------------------


def test_dnsx_empty_is_empty_result() -> None:
    adapter = DnsxAdapter()
    assert adapter.parse_output(_context("dnsx", "example.com"), _result(0, _read("dns/dnsx_empty.jsonl"))) == []


def test_dnsx_malformed_skipped() -> None:
    adapter = DnsxAdapter()
    records = adapter.parse_output(_context("dnsx", "example.com"), _result(0, _read("dns/dnsx_malformed.jsonl")))
    # Valid lines are parsed; malformed and empty-host lines are skipped.
    assert any(record.name == "example.com" and record.record_type.value == "A" for record in records)
    assert not any(record.name == "" for record in records)


# -- vulnerability scanning (nuclei) -------------------------------------------------


def test_nuclei_empty_means_no_matches_not_absence() -> None:
    adapter = NucleiAdapter()
    # Empty output is NOT "target is safe"; it is simply no matches.
    records = adapter.parse_output(_context("nuclei", "https://example.com"), _result(0, _read("vulnerability/nuclei_empty.jsonl")))
    assert records == []


def test_nuclei_error_output_never_becomes_candidates() -> None:
    adapter = NucleiAdapter()
    records = adapter.parse_output(_context("nuclei", "https://example.com"), _result(1, _read("vulnerability/nuclei_error.txt")))
    assert records == []


# -- golden fixtures are versioned fixtures -------------------------------------------


def test_golden_fixture_files_exist_for_each_variant() -> None:
    expected = {
        "content/ffuf_success.json",
        "content/ffuf_empty.json",
        "content/ffuf_malformed.json",
        "web/katana_success.jsonl",
        "web/katana_empty.jsonl",
        "web/katana_malformed.jsonl",
        "recon/subfinder_empty.jsonl",
        "recon/subfinder_error.txt",
        "dns/dnsx_empty.jsonl",
        "vulnerability/nuclei_empty.jsonl",
        "vulnerability/nuclei_error.txt",
    }
    for relative in expected:
        assert (_GOLDEN / relative).exists(), f"missing golden fixture {relative}"
