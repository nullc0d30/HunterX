# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Agent messaging."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


@dataclass(frozen=True, slots=True)
class AgentMessage:
    """A message exchanged between agents or between an agent and a caller.

    Attributes:
        sender: agent name that produced the message.
        recipient: target agent name (``"*"`` for broadcast).
        kind: message kind (``finding``, ``request``, ``result``, ``event``).
        payload: JSON-serializable content.

    """

    sender: str
    recipient: str = "*"
    kind: str = "event"
    payload: dict[str, Any] = field(default_factory=dict)
    message_id: str = field(default_factory=generate_id)
    created_at: str = field(default_factory=utcnow_iso)
