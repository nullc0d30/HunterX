from __future__ import annotations
from typing import List

TRIGGERS = ["HUNT MODE", "DOCTRINE ON"]

def activate(message: str) -> bool:
    """Return True if message activates offensive doctrine."""
    msg = message.strip().upper()
    return any(t in msg for t in TRIGGERS)

def confirmation_message() -> str:
    return "HUNTERX DOCTRINE LOADED — offensive security mode ready. Define target and scope to begin."
