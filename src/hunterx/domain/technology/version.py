# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Technology version intelligence.

Separates a *confirmed* version from a *probable* one, a *range* or an
*unknown* version — a weak fingerprint is never promoted to a confirmed
version. Version parsing is deterministic and evidence-backed: every version
record carries the confidence state and the evidence that supports it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from hunterx.domain.technology.models import VersionConfidence, VersionSpec

#: A semver-ish version token (``1.24``, ``6.0.3``, ``2023.12``).
_VERSION_TOKEN = re.compile(r"\d+(?:\.\d+){1,3}(?:[-+][0-9a-z.-]+)?")

#: Version separator patterns between a product name and its version.
_EMBEDDED_VERSION = re.compile(r"[/\s:=:](v?\d+(?:\.\d+){1,3}(?:[-+][0-9a-z.-]+)?)$", re.IGNORECASE)

#: Range separator patterns (``1.0-2.0``, ``>=1.0``, ``<2.0``).
_RANGE = re.compile(r"^\s*(>=|<=|>|<|=)?\s*(v?\d+(?:\.\d+){0,3})(?:\s*[-~]\s*(v?\d+(?:\.\d+){0,3}))?\s*$")


@dataclass(frozen=True, slots=True)
class VersionExtraction:
    """A version extracted from a raw fingerprint string.

    Attributes:
        version: the extracted version value (``""`` when none).
        confidence: the classification of the extraction.
        lower: inclusive lower bound (``""`` when unknown).
        upper: inclusive upper bound (``""`` when unknown).
        source: the string the version came from.

    """

    version: str = ""
    confidence: VersionConfidence = VersionConfidence.UNKNOWN
    lower: str = ""
    upper: str = ""
    source: str = ""

    def to_spec(self) -> VersionSpec:
        """Return the :class:`VersionSpec` form of this extraction."""
        return VersionSpec(
            value=self.version,
            confidence=self.confidence,
            lower=self.lower,
            upper=self.upper,
            evidence=(self.source,) if self.source else (),
        )


class VersionResolver:
    """Extract and classify versions from fingerprint strings.

    Usage::

        resolver = VersionResolver()
        extraction = resolver.extract("nginx/1.24.0")
        spec = extraction.to_spec()
    """

    def extract(self, raw: str) -> VersionExtraction:
        """Extract a version from ``raw`` with a deterministic classification.

        A version embedded in a product string (``nginx/1.24.0``,
        ``Apache 2.4.57``) is treated as *probable* unless the caller
        strengthens it with direct evidence; a bare version token is *probable*
        too. Range expressions are classified as ``range``; anything else is
        ``unknown``.
        """
        source = str(raw).strip()
        match = _EMBEDDED_VERSION.search(source)
        if match is not None:
            value = match.group(1)
            return VersionExtraction(
                version=_normalize_version(value),
                confidence=VersionConfidence.PROBABLE,
                source=source,
            )
        token = _VERSION_TOKEN.search(source)
        if token is not None:
            return VersionExtraction(
                version=_normalize_version(token.group(0)),
                confidence=VersionConfidence.PROBABLE,
                source=source,
            )
        range_match = _RANGE.search(source)
        if range_match is not None and range_match.group(2):
            op = range_match.group(1) or ""
            lower = range_match.group(2)
            upper = range_match.group(3)
            value = _render_range(op, lower, upper)
            return VersionExtraction(
                version=value,
                confidence=VersionConfidence.RANGE,
                lower=_normalize_version(lower) if op not in ("<", "<=") else "",
                upper=_normalize_version(upper) if op in ("<=", "=", "") and not lower else _normalize_version(upper),
                source=source,
            )
        return VersionExtraction(source=source)

    def classify(self, value: str, *, strong: bool = False) -> VersionConfidence:
        """Classify an already-extracted version value.

        Direct evidence of a version (a version capture group from a strong
        indicator) yields ``confirmed`` when ``strong``; otherwise a bare value
        is ``probable``.
        """
        if not value:
            return VersionConfidence.UNKNOWN
        if strong:
            return VersionConfidence.CONFIRMED
        return VersionConfidence.PROBABLE

    def is_plausible(self, value: str) -> bool:
        """Return whether ``value`` looks like a version token."""
        return bool(_VERSION_TOKEN.search(value))


def _normalize_version(value: str) -> str:
    """Strip a leading ``v`` and collapse whitespace in a version token."""
    cleaned = str(value).strip()
    if cleaned[:1].lower() == "v" and cleaned[1:2].isdigit():
        cleaned = cleaned[1:]
    return cleaned


def _render_range(op: str, lower: str, upper: str) -> str:
    """Render a range as a human version value."""
    lower_norm = _normalize_version(lower)
    upper_norm = _normalize_version(upper) if upper else ""
    if op in (">", ">=") and not upper:
        return f">{lower_norm}"
    if op in ("<", "<=") and not upper:
        return f"<{lower_norm}"
    if upper_norm:
        return f"{lower_norm}..{upper_norm}"
    return lower_norm
