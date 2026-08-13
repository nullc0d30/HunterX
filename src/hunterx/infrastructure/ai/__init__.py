# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""AI adapters.

Concrete providers implement :class:`~hunterx.domain.ports.services.AIPort`:

- :class:`NullAIClient` — safe fallback when no provider is configured.
- :class:`OpenRouterClient` — the first real provider (OpenRouter).

The :func:`build_ai_client` factory maps :class:`AISettings` to the right
adapter; the composition root injects the result through the platform.

Responsibilities:
- Provide every concrete ``AIPort`` implementation.
- Select the adapter from typed settings without global mutable state.

Dependencies:
- ``hunterx.domain`` (ports and exceptions), ``hunterx.config`` (settings),
  ``hunterx.shared`` (masking), and optionally ``httpx`` (the ``ai`` extra).

Extension points:
- Register new providers in :mod:`hunterx.infrastructure.ai.factory`.
"""

from __future__ import annotations

from hunterx.infrastructure.ai.factory import build_ai_client
from hunterx.infrastructure.ai.null import NullAIClient
from hunterx.infrastructure.ai.openrouter import OpenRouterClient

__all__ = [
    "NullAIClient",
    "OpenRouterClient",
    "build_ai_client",
]
