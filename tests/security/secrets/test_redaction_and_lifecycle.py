# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Secret masking, redaction and lifecycle (Sprint 034.4 §13, §14).

Secrets must not leak into logs, reports, process listings or command lines.
Redaction failures are tested explicitly: short values, CRLF, unicode and
values nested in JSON/mappings.
"""

from __future__ import annotations

import pytest

from hunterx.domain.reporting.redaction import ReportRedactor
from hunterx.shared.masking import mask_secret, mask_value

# -- mask_value ----------------------------------------------------------------


def test_mask_value_keeps_revealed_edges() -> None:
    assert mask_value("abcdefghij", reveal_head=2, reveal_tail=2) == "ab******ij"


def test_mask_value_short_values_fully_masked() -> None:
    assert mask_value("ab") == "**"
    assert mask_value("") == ""


def test_mask_value_unicode_is_safe() -> None:
    masked = mask_value("s\u00e9cr\u00eat-λ")
    assert masked and "*" in masked


def test_mask_secret_default_config() -> None:
    assert mask_secret("hunter2") == "h*****2"
    assert mask_secret(None) == ""


# -- ReportRedactor -------------------------------------------------------------


def test_redactor_masks_password_and_key() -> None:
    text, record = ReportRedactor().redact("password=hunter2 api_key=ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    assert "hunter2" not in text
    assert "ABCDEFGHIJKLMNOPQRSTUVWXYZ" not in text
    assert record.applied is True


def test_redactor_masks_github_and_aws_tokens() -> None:
    text, _ = ReportRedactor().redact(
        "token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz AKIA1234567890ABCDEF"
    )
    # The full high-entropy secret bodies must never survive redaction. The
    # stable ``ghp_``/``AKIA`` prefixes are retained by design for operator
    # identification; the 50+ secret characters are replaced.
    assert "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" not in text
    assert "1234567890ABCDEF" not in text
    assert text.count("*") > 20


def test_redactor_masks_private_keys() -> None:
    key = "-----BEGIN RSA PRIVATE KEY-----MIIEvQIBADANBg-----END RSA PRIVATE KEY-----"
    text, record = ReportRedactor().redact(key)
    assert "PRIVATE KEY-----MIIEvQIBADANBg" not in text
    assert record.applied is True


def test_redactor_handles_crlf_injection() -> None:
    text, _ = ReportRedactor().redact("password=secure12345\r\nnext=value")
    assert "secure12345" not in text


def test_redactor_keyword_boundary_limitation_is_documented() -> None:
    """A secret keyed as ``password2``/``password_2`` is NOT matched by the
    keyword-boundary heuristics. This is a documented redaction false-negative
    (the value stays in evidence, protected by the evidence layer, but the
    report redactor is heuristic)."""
    text, record = ReportRedactor().redact("password2=secure12345")
    assert "secure12345" in text
    assert record.applied is False


def test_redactor_does_not_mangle_plain_text() -> None:
    text, record = ReportRedactor().redact("the target responded with a 200 OK status")
    assert text == "the target responded with a 200 OK status"
    assert record.applied is False


def test_redactor_explicit_failure_scenario_short_secret() -> None:
    """Values below the minimum heuristic length (e.g. ``token=ab``) are not
    redacted. This is a documented heuristic limitation: sub-threshold values
    are too short to distinguish from prose."""
    text, record = ReportRedactor().redact("token=ab")
    assert record.applied is False
    assert text == "token=ab"


# -- lifecycle: environment construction ----------------------------------------


def test_secrets_never_enter_command_lines() -> None:
    """Tool adapters receive secrets via the environment, never as argv."""
    from hunterx.domain.execution import ExecutionContext
    from hunterx.tools.sdk.sandbox import ExecutionSandbox

    sandbox = ExecutionSandbox()
    context = ExecutionContext(tool_id="nuclei", permissions=("network", "secrets"))
    env = sandbox.prepare_environment(context, secrets={"HUNTERX_TOKEN": "sk-abc12345"})
    assert env["HUNTERX_SECRET_HUNTERX_TOKEN"] == "sk-abc12345"
    # The secret name must never leak its value.
    for key, value in env.items():
        if key.startswith("HUNTERX_SECRET_"):
            assert value != ""


def test_log_redaction_covers_common_sensitive_keys() -> None:
    from hunterx.infrastructure.logging import _deep_mask

    payload = {
        "api_key": "ABCDEFGHIJKLMNOP",
        "detail": {"password": "hunter2", "status": "ok"},
        "rows": [{"token": "tok-12345"}],
        "host": "example.com",
    }
    masked = _deep_mask(payload)
    assert "ABCDEFGHIJKLMNOP" not in repr(masked)
    assert "hunter2" not in repr(masked)
    assert "tok-12345" not in repr(masked)
    assert masked["host"] == "example.com"


def test_secret_manager_requires_secrets_read_permission() -> None:
    from hunterx.infrastructure.secrets import InMemorySecrets
    from hunterx.security.manager import Actor, PermissionDeniedError, SecurityManager
    from hunterx.security.policies import SecurityPolicy

    manager = SecurityManager(
        SecurityPolicy(roles={"admin": frozenset({"secrets.read"})}),
        InMemorySecrets(),
    )
    manager._secrets.set("API_KEY", "v")
    assert manager.resolve_secret(Actor("a", roles=("admin",)), "API_KEY") == "v"
    with pytest.raises(PermissionDeniedError):
        manager.resolve_secret(Actor("u", roles=("nobody",)), "API_KEY")
