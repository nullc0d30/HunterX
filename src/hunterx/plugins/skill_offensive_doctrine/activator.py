"""Doctrine activation triggers and confirmation message."""

from __future__ import annotations

TRIGGERS = ["HUNT MODE", "DOCTRINE ON"]

def activate(message: str) -> bool:
    """Return True if message activates offensive doctrine."""
    msg = message.strip().upper()
    return any(t in msg for t in TRIGGERS)

def confirmation_message() -> str:
    """Return the message shown when the doctrine is activated."""
    return "HUNTERX DOCTRINE LOADED - offensive security mode ready. Define target and scope to begin."
