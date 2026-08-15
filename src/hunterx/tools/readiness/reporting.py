# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Human-facing installer output helpers.

Pure formatting functions (no I/O, no terminal escapes) so the installer UX is
unit-testable and deterministic in both TTY and non-TTY environments:

- multi-column inventory blocks (available / missing / broken / ...);
- ``[N/M] tool ... ✓`` progress lines;
- provisioning summaries;
- final readiness banners.

All functions return plain strings; callers decide where to print them. Width
awareness is passed in (or auto-detected by the caller) so the layout adapts
to the terminal without the formatter touching the environment.
"""

from __future__ import annotations

import sys
from collections.abc import Iterable, Sequence
from typing import Any

from hunterx.tools.readiness.models import InstallOutcome, ToolInventory, ToolReadinessStatus

#: Unicode marks used in the human inventory/progress output. Kept as module
#: constants so tests can assert against them and non-ASCII terminals degrade
#: gracefully (the marks degrade to ASCII in ``ascii_marks``).
_MARK_AVAILABLE = "\u2713"  # ✓
_MARK_MISSING = "\u25cb"  # ○
_MARK_BROKEN = "\u2717"  # ✗
_MARK_OUTDATED = "\u26a0"  # ⚠
_MARK_UNSUPPORTED = "\u26a0"  # ⚠
_MARK_SKIPPED = "\u2713"  # ✓
_MARK_FAILED = "\u2717"  # ✗

_ASCII_MARKS = {
    "available": "OK",
    "missing": "..",
    "broken": "XX",
    "outdated": "!",
    "unsupported": "!",
    "failed": "XX",
}

_STATUS_MARKS: dict[ToolReadinessStatus, str] = {
    ToolReadinessStatus.AVAILABLE: _MARK_AVAILABLE,
    ToolReadinessStatus.MISSING: _MARK_MISSING,
    ToolReadinessStatus.BROKEN: _MARK_BROKEN,
    ToolReadinessStatus.OUTDATED: _MARK_OUTDATED,
    ToolReadinessStatus.UNSUPPORTED: _MARK_UNSUPPORTED,
}


def ascii_mode(enabled: bool = True) -> None:
    """Toggle ASCII fallback for non-Unicode terminals (global knob)."""
    global _ASCII_FALLBACK
    _ASCII_FALLBACK = enabled


_ASCII_FALLBACK = False


def _status_mark(status: ToolReadinessStatus) -> str:
    """Return the mark for a readiness status (Unicode or ASCII fallback)."""
    if _ASCII_FALLBACK:
        return {
            ToolReadinessStatus.AVAILABLE: _ASCII_MARKS["available"],
            ToolReadinessStatus.MISSING: _ASCII_MARKS["missing"],
            ToolReadinessStatus.BROKEN: _ASCII_MARKS["broken"],
            ToolReadinessStatus.OUTDATED: _ASCII_MARKS["outdated"],
            ToolReadinessStatus.UNSUPPORTED: _ASCII_MARKS["unsupported"],
        }.get(status, _ASCII_MARKS["missing"])
    return _STATUS_MARKS.get(status, _MARK_MISSING)


def columnize(items: Sequence[str], width: int, *, pad: int = 2, min_cols: int = 1) -> list[str]:
    """Render ``items`` in a dynamic multi-column grid and return the rows.

    Columns are computed from ``width`` and the longest item so the layout
    adapts to the terminal. A sensible fallback (single column) is used for
    narrow terminals or when an item alone exceeds the available width.
    """
    if not items:
        return []
    effective = max(width, 1)
    longest = max(len(item) for item in items)
    col_width = longest + pad
    cols = max(min_cols, effective // col_width)
    rows: list[str] = []
    for start in range(0, len(items), cols):
        chunk = items[start : start + cols]
        rows.append("".join(item.ljust(col_width) for item in chunk).rstrip())
    return rows


def inventory_marks(tool_id: str, status: ToolReadinessStatus, *, max_name: int = 0) -> str:
    """Return the marked, padded entry for one tool (``✓ amass  ``)."""
    mark = _status_mark(status)
    name = tool_id if max_name <= 0 else tool_id.ljust(max_name)
    return f"{mark} {name}"


def render_inventory(inventory: ToolInventory, width: int = 80) -> str:
    """Render the compact multi-column tool inventory.

    Example::

        Available
        ────────────────────────────────────────────────────────────
        ✓ amass        ✓ nmap         ✓ masscan
        ✓ whatweb      ✓ gobuster     ✓ nikto
        ────────────────────────────────────────────────────────────

        Missing
        ────────────────────────────────────────────────────────────
        ○ subfinder    ○ assetfinder  ○ findomain
        ────────────────────────────────────────────────────────────

    Only non-empty buckets are rendered. The separator width is derived from
    the widest cell so the block stays compact on narrow terminals.
    """
    sections: list[str] = []
    buckets: list[tuple[str, list[str], ToolReadinessStatus]] = [
        ("Available", inventory.available, ToolReadinessStatus.AVAILABLE),
        ("Missing", inventory.missing, ToolReadinessStatus.MISSING),
        ("Broken", inventory.broken, ToolReadinessStatus.BROKEN),
        ("Outdated", inventory.outdated, ToolReadinessStatus.OUTDATED),
        ("Unsupported", inventory.unsupported, ToolReadinessStatus.UNSUPPORTED),
    ]
    for label, tool_ids, status in buckets:
        if not tool_ids:
            continue
        entries = [inventory_marks(tool_id, status) for tool_id in tool_ids]
        sep_width = max(20, len(max(entries, key=len)))
        section = [label, "─" * sep_width, *columnize(entries, width), "─" * sep_width]
        sections.append("\n".join(section))
    return "\n\n".join(sections)


def render_progress_line(index: int, total: int, tool_id: str, outcome: InstallOutcome | None = None) -> str:
    r"""Render one live progress line.

    ``outcome is None`` means "about to start" — the line carries the tool
    name followed by dots so the user immediately sees the operation begin;
    the completed line (with ``✓`` / ``✗``) replaces it via ``\\r`` by the
    caller on a TTY, or is appended as a plain text follow-up on non-TTY.

    Example (TTY)::

        [ 1/68] subfinder ............... ✓
    """
    marker = f"[{index:>{len(str(total))}}/{total}]"
    dots = "." * max(0, 27 - len(tool_id))
    if outcome is None:
        return f"{marker} {tool_id} {dots}"
    if outcome.success and outcome.skipped:
        mark = _MARK_SKIPPED
    elif outcome.success:
        mark = _MARK_AVAILABLE
    else:
        mark = _MARK_FAILED
    return f"{marker} {tool_id} {dots} {mark}"


def terminal_width(*, default: int = 80) -> int:
    """Return the usable terminal width without touching the environment.

    Uses :func:`shutil.get_terminal_size` and falls back to ``default`` when
    the width cannot be determined (non-TTY / pipes).
    """
    import shutil

    try:
        size = shutil.get_terminal_size((default, 24))
    except (OSError, ValueError):  # pragma: no cover - best-effort probe
        return default
    return max(20, size.columns)


class ProgressWriter:
    r"""Live installer progress writer (TTY-aware, deterministic non-TTY).

    On a TTY, the in-progress line is rewritten in place with ``\\r`` so the
    user sees ``[ 1/68] subfinder ............... ✓`` without a pile of
    duplicate lines. On a non-TTY (CI, pipes, SSH without a pty) it prints
    plain, deterministic one-line-per-tool output with no cursor control: the
    start line first, then the completed line.

    Args:
        write: output callable (``sys.stdout.write``); defaults to printing.
        is_terminal: override for the TTY probe (tests).

    """

    def __init__(self, write: Any | None = None, *, is_terminal: bool | None = None) -> None:
        self._write = write or print
        self._tty = sys.stdout.isatty() if is_terminal is None else is_terminal
        self._pending: list[str] = []

    def start(self, index: int, total: int, tool_id: str) -> None:
        """Emit the "about to start" line for ``tool_id``."""
        line = render_progress_line(index, total, tool_id)
        if self._tty:
            self._write(f"\r{line}", end="", flush=True)
            self._pending.append(tool_id)
        else:
            self._write(line, flush=True)

    def finish(self, index: int, total: int, tool_id: str, outcome: InstallOutcome) -> None:
        """Emit the completed line with its mark."""
        line = render_progress_line(index, total, tool_id, outcome)
        if self._tty:
            if self._pending and self._pending[-1] == tool_id:
                self._write(f"\r{line}", end="", flush=True)
                self._pending.pop()
            else:
                self._write(f"{line}", flush=True)
            self._write("", flush=True)
        else:
            self._write(line, flush=True)


def render_summary(outcomes: Iterable[InstallOutcome], *, already_available: int = 0) -> str:
    """Render the toolchain provisioning summary.

    ``outcomes`` includes every attempted tool; ``already_available`` counts
    tools that were skipped as already present (reported separately).
    """
    outcomes = list(outcomes)
    installed = sum(1 for outcome in outcomes if outcome.success and not outcome.skipped)
    failed = [outcome for outcome in outcomes if not outcome.success]
    lines = ["Toolchain provisioning summary", ""]
    lines.append(f"{_MARK_AVAILABLE} Installed: {installed}")
    if already_available or installed == 0:
        lines.append(f"{_MARK_AVAILABLE} Already available: {already_available}")
    if failed:
        lines.append(f"{_MARK_FAILED} Failed: {len(failed)}")
        lines.append("")
        lines.append("Failed tools:")
        for outcome in failed:
            lines.append(f"  - {outcome.tool_id}: {outcome.error or 'unknown reason'}")
    return "\n".join(lines)


def render_banner(title: str, items: Sequence[tuple[str, str]], *, width: int = 60) -> str:
    """Render the final installation banner (key/value READY rows).

    Example::

        ============================================================
         HunterX v7.0.0 — Installation Complete
        ============================================================

        ✓ HunterX Core ............... READY
        ✓ Runtime ................... READY
        ✓ Database .................. READY

        HunterX is ready to use.
        ============================================================
    """
    rule = "=" * width
    lines = [rule, f" {title}", rule, ""]
    key_width = max(len(key) for key, _ in items) if items else 1
    for key, value in items:
        mark = _MARK_AVAILABLE if value.upper() == "READY" else _MARK_BROKEN
        lines.append(f"{mark} {key.ljust(key_width)} {value.upper()}")
    return "\n".join(lines)


def render_quick_start(commands: Sequence[tuple[str, str]]) -> str:
    """Render the quick-start command block.

    ``commands`` are ``(label, command)`` pairs; every command must be a
    genuinely supported HunterX CLI invocation (callers verify this).
    """
    if not commands:
        return ""
    lines = ["Quick Start", "─" * 40, ""]
    key_width = max(len(label) for label, _ in commands)
    for label, command in commands:
        lines.append(f"{label.ljust(key_width)}:")
        lines.append(f"  {command}")
        lines.append("")
    return "\n".join(lines).rstrip()


__all__ = [
    "ProgressWriter",
    "ascii_mode",
    "columnize",
    "inventory_marks",
    "render_banner",
    "render_inventory",
    "render_progress_line",
    "render_quick_start",
    "render_summary",
    "terminal_width",
]
