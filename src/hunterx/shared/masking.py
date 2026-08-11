# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Secret masking utilities.

Used to guarantee that secrets and credentials never appear verbatim in logs,
reports, or rendered output. The default mask keeps the first and last
character visible and fills the middle with asterisks so operators can still
tell which secret was referenced.
"""

from __future__ import annotations

from dataclasses import dataclass

_MASK_CHAR = "*"
_MIN_VISIBLE = 2


@dataclass(frozen=True, slots=True)
class MaskConfig:
    """Configuration controlling how a secret is masked.

    Attributes:
        reveal_head: number of leading characters to keep visible.
        reveal_tail: number of trailing characters to keep visible.

    """

    reveal_head: int = 1
    reveal_tail: int = 1


def mask_value(value: str | None, *, reveal_head: int = 1, reveal_tail: int = 1) -> str:
    """Mask ``value`` keeping ``reveal_head`` and ``reveal_tail`` characters.

    An empty string is returned as-is. A string shorter than the sum of the
    two reveal counts is fully masked. ``reveal_head``/``reveal_tail`` values
    of ``0`` reveal nothing on that side (guarded against ``value[-0:]`` which
    would return the whole string).
    """
    if not value:
        return ""
    head = max(0, int(reveal_head))
    tail = max(0, int(reveal_tail))
    visible = head + tail
    if len(value) <= visible:
        return _MASK_CHAR * len(value)
    shown_head = value[:head]
    shown_tail = value[-tail:] if tail else ""
    return f"{shown_head}{_MASK_CHAR * (len(value) - visible)}{shown_tail}"


def mask_secret(value: str | None, config: MaskConfig | None = None) -> str:
    """Mask ``value`` using ``config`` (see :func:`mask_value`)."""
    config = config or MaskConfig()
    return mask_value(value, reveal_head=config.reveal_head, reveal_tail=config.reveal_tail)


def mask_secrets_in_mapping(
    mapping: dict[str, str], config: MaskConfig | None = None
) -> dict[str, str]:
    """Return a copy of ``mapping`` with all values masked."""
    config = config or MaskConfig()
    return {key: mask_secret(value, config) for key, value in mapping.items()}
