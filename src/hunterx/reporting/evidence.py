# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Evidence aggregation for reports."""

from __future__ import annotations

from hunterx.domain.ports.stores import EvidenceStore


def collect_evidence(evidence_store: EvidenceStore, evidence_ids: list[str]) -> list[tuple[str, str]]:
    """Load evidence artifact contents by identifier.

    Returns ``(evidence_id, decoded_content)`` pairs. Missing artifacts are
    skipped so a single missing record cannot break a report render.
    """
    collected: list[tuple[str, str]] = []
    for evidence_id in evidence_ids:
        key = f"evidence/{evidence_id}"
        if evidence_store.exists(key):
            content = evidence_store.get(key).decode("utf-8", errors="replace")
            collected.append((evidence_id, content))
    return collected
