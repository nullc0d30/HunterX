# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Agent event adapters.

Converts agent messages into canonical domain events so the rest of the
platform (event bus, telemetry, plugins) can observe agent activity uniformly.
"""

from __future__ import annotations

from hunterx.agents.messaging import AgentMessage
from hunterx.domain.events import DomainEvent


def message_to_event(message: AgentMessage) -> DomainEvent:
    """Wrap an agent message as a domain event."""
    return DomainEvent(
        event_type=f"agent.{message.kind}",
        payload={
            "message_id": message.message_id,
            "sender": message.sender,
            "recipient": message.recipient,
            "data": message.payload,
        },
        source=message.sender,
        occurred_at=message.created_at,
    )
