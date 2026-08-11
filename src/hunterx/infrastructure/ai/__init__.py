# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""AI adapters.

The foundation ships a null/default AI client that clearly reports when no AI
provider is configured. Concrete providers (OpenAI, Anthropic, local models)
implement :class:`~hunterx.domain.ports.services.AIPort` in future sprints.
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
            "No AI provider is configured. Install a provider adapter to use AI features."
        )

    def embed(self, text: str) -> list[float]:
        """Return a deterministic feature vector derived from ``text``."""
        digest = hashlib.sha256(text.encode("utf-8")).digest()
        return [byte / 255.0 for byte in digest]
