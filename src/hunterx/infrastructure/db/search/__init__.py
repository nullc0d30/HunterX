# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Search adapters.

Provides a minimal in-memory full-text search index over normalized records.
Production deployments can back this with a dedicated search service while
keeping the same public surface.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

_WORD_RE = re.compile(r"[a-z0-9_]+")


class InMemorySearchIndex:
    """A simple inverted-index search over string documents.

    Indexed documents are dictionaries; ``index_text`` fields are tokenized
    and mapped back to their document identifiers. Results are ranked by the
    number of matched terms.
    """

    def __init__(self) -> None:
        self._documents: dict[str, dict[str, Any]] = {}
        self._inverted: dict[str, set[str]] = defaultdict(set)

    @staticmethod
    def _tokens(text: str) -> set[str]:
        return set(_WORD_RE.findall(text.lower()))

    def index(self, document_id: str, *, fields: dict[str, Any], index_fields: list[str]) -> None:
        """Store ``fields`` and index ``index_fields`` for retrieval."""
        self._documents[document_id] = dict(fields)
        for field in index_fields:
            raw = fields.get(field)
            if isinstance(raw, str):
                for token in self._tokens(raw):
                    self._inverted[token].add(document_id)

    def search(self, query: str, *, limit: int = 50) -> list[dict[str, Any]]:
        """Return documents matching any query term, ranked by term overlap."""
        tokens = self._tokens(query)
        if not tokens:
            return []
        scores: dict[str, int] = defaultdict(int)
        for token in tokens:
            for document_id in self._inverted.get(token, ()):
                scores[document_id] += 1
        ranked = sorted(scores, key=lambda doc_id: (-scores[doc_id], doc_id))
        return [self._documents[doc_id] for doc_id in ranked[:limit]]

    def delete(self, document_id: str) -> None:
        """Remove a document and all of its index entries."""
        self._documents.pop(document_id, None)
        for bucket in self._inverted.values():
            bucket.discard(document_id)
