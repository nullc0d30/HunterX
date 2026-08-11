# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Technology normalization.

Deterministic normalization of the free-form names, assets and evidence that
fingerprinting tools report. ``Apache``, ``apache`` and ``Apache httpd`` are
normalized to a canonical lowercase token; the original observation is always
preserved on the record alongside the normalized form. No fuzzy matching here —
normalization is a pure function of string rules.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: Runs of whitespace inside a name (collapsed to a single space).
_WHITESPACE = re.compile(r"\s+")

#: Non-alphanumeric characters stripped from a normalized token.
_NON_TOKEN = re.compile(r"[^a-z0-9.+/_-]")


@dataclass(frozen=True, slots=True)
class NormalizedName:
    """The normalized form of a raw technology name.

    Attributes:
        raw: the original name exactly as observed.
        normalized: the canonical lowercase token (aliases compare against it).
        token: the compact token (non-alphanumeric chars stripped) used for
            alias matching.
        had_version: whether the raw name carried an inline version suffix
            (e.g. ``nginx/1.24.0``).

    """

    raw: str
    normalized: str = ""
    token: str = ""
    had_version: bool = False


class TechnologyNormalizer:
    """Normalize technology names and assets for canonical resolution."""

    def normalize_name(self, raw: str) -> NormalizedName:
        """Return the normalized form of a technology name."""
        cleaned = _clean(raw)
        had_version = bool(re.search(r"[/\s]v?\d+(?:\.\d+){1,3}", cleaned))
        return NormalizedName(
            raw=str(raw).strip(),
            normalized=cleaned,
            token=_NON_TOKEN.sub("", cleaned),
            had_version=had_version,
        )

    def normalize_asset(self, value: str) -> str:
        """Return the canonical asset identifier for a hostname/domain/IP/URL."""
        candidate = str(value).strip().lower()
        if candidate.startswith(("http://", "https://")):
            try:
                from urllib.parse import urlparse

                candidate = urlparse(candidate).hostname or candidate
            except ValueError:  # pragma: no cover - defensive
                pass
        return candidate.rstrip(".").strip()

    def alias_key(self, raw: str) -> str:
        """Return the compact token used to match raw names against aliases."""
        return self.normalize_name(raw).token


def _clean(value: str) -> str:
    """Lowercase, trim and collapse whitespace in a name."""
    cleaned = _WHITESPACE.sub(" ", str(value).strip()).lower()
    return cleaned.strip()
