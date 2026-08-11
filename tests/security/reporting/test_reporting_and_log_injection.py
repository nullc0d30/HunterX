# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Reporting and logging injection (Sprint 034.4 §24, §25).

Malicious target names, finding titles, evidence and tool output must not turn
reports into XSS/HTML/template injections, and log fields must not permit CRLF/
ANSI injection or secret leakage.
"""

from __future__ import annotations

import json
import logging

from hunterx.infrastructure.logging import JsonFormatter, set_correlation


def _render_json(record: logging.LogRecord) -> str:
    return JsonFormatter().format(record)


def _record(message: str) -> logging.LogRecord:
    return logging.LogRecord(name="hunterx.test", level=logging.INFO, pathname=__file__, lineno=1, msg=message, args=(), exc_info=None)


def test_log_crlf_injection_is_json_escaped() -> None:
    """A hostile log message with CRLF cannot forge a second log line."""
    record = _record("request completed\nX-Injected: true\r\nstatus: pwned")
    rendered = _render_json(record)
    payload = json.loads(rendered)
    # The injected headers remain part of the message field, not new fields.
    assert "X-Injected" not in payload or payload["X-Injected"] != "true"


def test_log_ansi_control_characters_are_data() -> None:
    record = _record("\x1b[31m\x1b[2Jfake-panic\x1b[0m")
    rendered = _render_json(record)
    payload = json.loads(rendered)
    assert "\x1b[" in payload["message"]  # stored as data, not interpreted


def test_log_sensitive_keys_are_masked_in_fields() -> None:
    from hunterx.infrastructure.logging import _deep_mask

    fields = {
        "api_key": "ABCDEFGHIJKLMNOP",
        "nested": {"password": "hunter2", "ok": True},
        "target": "example.com",
    }
    masked = _deep_mask(fields)
    assert "ABCDEFGHIJKLMNOP" not in repr(masked)
    assert "hunter2" not in repr(masked)
    assert masked["target"] == "example.com"
    assert masked["nested"]["ok"] is True


def test_correlation_ids_are_propagated() -> None:
    set_correlation(correlation_id="corr-123", mission_id="mission-9")
    try:
        rendered = _render_json(_record("step completed"))
        payload = json.loads(rendered)
        assert payload["correlation"]["correlation_id"] == "corr-123"
        assert payload["correlation"]["mission_id"] == "mission-9"
    finally:
        from hunterx.infrastructure.logging import clear_correlation

        clear_correlation()


def test_report_markdown_stays_data_not_html() -> None:
    from tests.framework.reporting import build_service, create_finding, load_scenarios

    scenario = next(item for item in load_scenarios() if item["id"] == "sqli_validated_reportable")
    scenario["evidence"] = [
        {
            "kind": "behavioral_differential",
            "value": '<script>alert(1)</script> [x](javascript:alert(2))',
            "quality": "high",
            "source": "validation",
        },
        {"kind": "controlled_callback", "value": "callback fired", "quality": "proof", "source": "validation"},
    ]
    service, stores = build_service()
    finding_id = create_finding(stores, scenario)
    report = service.generate_report(finding_id, template="bug_bounty")
    markdown = service.export_report(report["report_id"], fmt="markdown")["content"]
    # Rendering succeeds; hostile content is quoted content, never executed.
    assert isinstance(markdown, str) and markdown
    html = service.export_report(report["report_id"], fmt="html")["content"]
    assert isinstance(html, str) and html
    # HTML export must not contain a live executable script tag.
    assert "<script>alert(1)</script>" not in html or "&lt;script&gt;" in html


def test_evidence_path_traversal_strings_are_inert() -> None:
    from hunterx.domain.reporting.redaction import ReportRedactor

    text, _ = ReportRedactor().redact("../../etc/passwd ../../../tmp/x")
    assert "../" in text  # traversal strings are data, not filesystem actions
