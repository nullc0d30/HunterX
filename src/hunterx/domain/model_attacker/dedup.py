# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Stable hypothesis fingerprinting for duplicate prevention.

Duplicates are recognised on the *actionable* fields: capability, surface,
vector, strategy, authentication context, workflow context and parent. A
changed vector or a changed authentication context is a potentially new
hypothesis (legitimate escalation) — only the exact same actionable tuple is a
duplicate.
"""

from __future__ import annotations

import hashlib
from typing import Any


def hypothesis_fingerprint(
    *,
    capability: str,
    surface: str,
    attack_vector: str,
    attack_strategy: str,
    authentication_context: str,
    workflow_context: str = "",
    parent_hypothesis: str = "",
) -> str:
    """Return the stable dedup fingerprint for an actionable hypothesis."""
    material = "|".join(
        [
            str(capability or "").strip().lower(),
            str(surface or "").strip().lower(),
            str(attack_vector or "").strip().lower(),
            str(attack_strategy or "").strip().lower(),
            str(authentication_context or "").strip().lower(),
            str(workflow_context or "").strip().lower(),
            str(parent_hypothesis or "").strip(),
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]


def seen(fingerprint: str, known: dict[str, Any]) -> bool:
    """Return ``True`` when the fingerprint is already tracked."""
    return fingerprint in known


__all__ = ["hypothesis_fingerprint", "seen"]
