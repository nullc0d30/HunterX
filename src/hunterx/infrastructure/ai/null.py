# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Null AI adapter.

The safe fallback used whenever no AI provider is configured. It keeps
HunterX fully runnable without any API key and fails loudly only when AI
functionality is actually invoked.

Responsibilities:
- Provide a runnable ``AIPort`` when no provider/key is configured.
- Fail loudly on ``complete`` instead of inventing content.

Dependencies:
- ``hunterx.domain`` (ports and exceptions).
"""

from __future__ import annotations

import hashlib

from hunterx.domain.exceptions import OperationError
from hunterx.domain.ports.services import AIPort


class NullAIClient(AIPort):
    """No-op AI client used when no provider is configured.

    ``complete`` refuses to run so accidental AI calls fail loudly instead of
    silently returning empty text. ``embed`` returns a deterministic
    feature vector for text so downstream code remains testable.
    """

    def __init__(self, *, default_model: str = "none") -> None:
        self._default_model = default_model

    def complete(self, prompt: str, *, model: str | None = None, temperature: float = 0.0) -> str:
        """Raise because no AI provider is configured."""
        raise OperationError(
            "No AI provider is configured. Set HUNTERX_AI_PROVIDER and the matching "
            "HUNTERX_AI_*_KEY (see .env.example) to enable AI features."
        )

    def embed(self, text: str) -> list[float]:
        """Return a deterministic feature vector derived from ``text``."""
        digest = hashlib.sha256(text.encode("utf-8")).digest()
        return [byte / 255.0 for byte in digest]
