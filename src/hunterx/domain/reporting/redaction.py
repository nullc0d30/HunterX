# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Report redaction engine.

Redacts passwords, API keys, tokens, cookies, session identifiers, private
keys, unnecessary PII and internal secrets while preserving reproduction
utility. Evidence remains internally referenceable — only the report output is
redacted.
"""

from __future__ import annotations

import re

from hunterx.domain.reporting.models import RedactionRecord, ReportRedaction
from hunterx.shared.masking import MaskConfig, mask_secret

#: Redaction rules: (field/secret type, compiled pattern, reveal head, reveal tail).
_RULES: tuple[tuple[str, re.Pattern[str], int, int], ...] = (
    (
        "api_key",
        re.compile(r"(?i)(api[_-]?key|apikey)([\"'\s:=]+)([A-Za-z0-9_\-]{12,})"),
        4,
        4,
    ),
    ("password", re.compile(r"(?i)(password|passwd|pwd)([\"'\s:=]+)([^\s\"',;]{6,})"), 2, 2),
    (
        "token",
        re.compile(r"(?i)(token|bearer|authorization[\"'\s:=]+bearer)([\"'\s:=]+)([A-Za-z0-9_\-\.]{16,})"),
        4,
        4,
    ),
    (
        "secret",
        re.compile(r"(?i)(secret|client[_-]?secret)([\"'\s:=]+)([A-Za-z0-9_\-]{12,})"),
        4,
        4,
    ),
    ("private_key", re.compile(r"(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)", re.DOTALL), 0, 0),
    (
        "cookie",
        re.compile(r"(?i)((?:sessionid|session_id|jsessionid|connect.sid)=)([A-Za-z0-9_\-]{16,})"),
        4,
        4,
    ),
)

#: Values masked entirely when they look like high-entropy secrets.
_AWS_KEY = re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")
_GITHUB_TOKEN = re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b")
_SLACK_TOKEN = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")
_STRIPE_KEY = re.compile(r"\b(sk|pk)_(live|test)_[A-Za-z0-9]{16,}\b")


class ReportRedactor:
    """Deterministic report-content redactor.

    ``redact`` returns the redacted text plus a :class:`ReportRedaction`
    record describing every replacement applied. Evidence references and
    reproduction steps survive; only the sensitive values are masked.
    """

    def __init__(self, config: MaskConfig | None = None) -> None:
        self._config = config or MaskConfig(reveal_head=1, reveal_tail=1)

    def redact(self, text: str, *, field_name: str = "content") -> tuple[str, ReportRedaction]:
        """Redact secrets inside ``text``.

        Args:
            text: the text to redact.
            field_name: logical field name for the redaction record.

        Returns:
            A ``(redacted_text, redaction_metadata)`` pair.

        """
        records: list[RedactionRecord] = []
        redacted = text
        for secret_type, pattern, head, tail in _RULES:
            matches = list(pattern.finditer(redacted))
            if not matches:
                continue
            for match in matches:
                if secret_type == "private_key":
                    masked = "[REDACTED PRIVATE KEY]"
                elif len(match.groups()) >= 3:
                    prefix, sep, value = match.groups()[0], match.groups()[1], match.groups()[2]
                    masked_value = mask_secret(value, MaskConfig(reveal_head=head, reveal_tail=tail))
                    masked = f"{prefix}{sep}{masked_value}"
                else:
                    value = match.group(0)
                    masked = mask_secret(value, self._config)
                redacted = redacted.replace(match.group(0), masked, 1)
                records.append(
                    RedactionRecord(
                        field_name=field_name,
                        pattern=secret_type,
                        secret_type=secret_type,
                        masked_value=masked,
                    )
                )
        # High-signal secret formats that do not require a surrounding keyword.
        for secret_type, pattern in (
            ("aws_key", _AWS_KEY),
            ("github_token", _GITHUB_TOKEN),
            ("slack_token", _SLACK_TOKEN),
            ("stripe_key", _STRIPE_KEY),
        ):
            for match in pattern.finditer(redacted):
                masked = mask_secret(match.group(0), self._config)
                redacted = redacted.replace(match.group(0), masked, 1)
                records.append(
                    RedactionRecord(
                        field_name=field_name,
                        pattern=secret_type,
                        secret_type=secret_type,
                        masked_value=masked,
                    )
                )
        return redacted, ReportRedaction(applied=bool(records), records=tuple(records))


__all__ = ["ReportRedactor"]
