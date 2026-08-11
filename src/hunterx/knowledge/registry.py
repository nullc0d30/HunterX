# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Knowledge record model and registry."""

from __future__ import annotations

from dataclasses import dataclass, field
from threading import RLock
from typing import Any


@dataclass(frozen=True, slots=True)
class KnowledgeRecord:
    """A structured knowledge entry.

    Attributes:
        record_id: stable identifier (e.g. CWE-79, TTP-T1059).
        title: short title.
        category: knowledge category (``cwe``, ``cve``, ``ttp``, ``remediation``).
        description: human-readable description.
        references: external reference URLs.
        tags: search tags.
        properties: extra structured attributes.

    """

    record_id: str
    title: str
    category: str = "general"
    description: str = ""
    references: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    properties: dict[str, Any] = field(default_factory=dict)


class KnowledgeRegistry:
    """Thread-safe catalog of knowledge records.

    Records are indexed by identifier and category; ``query`` performs a
    simple tag/title keyword search for retrieval.
    """

    def __init__(self) -> None:
        self._records: dict[str, KnowledgeRecord] = {}
        self._lock = RLock()

    def upsert(self, record: KnowledgeRecord) -> None:
        """Insert or replace a knowledge record."""
        with self._lock:
            self._records[record.record_id] = record

    def get(self, record_id: str) -> KnowledgeRecord | None:
        """Return a record by identifier or ``None``."""
        with self._lock:
            return self._records.get(record_id)

    def by_category(self, category: str) -> list[KnowledgeRecord]:
        """Return records in a category."""
        with self._lock:
            return [record for record in self._records.values() if record.category == category]

    def query(self, term: str, *, limit: int = 50) -> list[KnowledgeRecord]:
        """Return records whose title/tags match ``term`` (case-insensitive)."""
        needle = term.lower()
        with self._lock:
            matches = [
                record
                for record in self._records.values()
                if needle in record.title.lower() or needle in record.record_id.lower()
                or any(needle in tag.lower() for tag in record.tags)
            ]
        return matches[:limit]

    def all(self) -> list[KnowledgeRecord]:
        """Return every registered record."""
        with self._lock:
            return list(self._records.values())
