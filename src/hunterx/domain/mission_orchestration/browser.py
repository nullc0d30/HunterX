# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Browser automation capability detection.

Browser automation is a *capability*, not an assumption. This module detects
whether a real browser automation stack (Playwright package + a Chromium
executable + a headless launch) is available in the current environment, so a
mission can report ``browser_testing`` truthfully:

* ``available``    — Playwright importable and a headless browser launch works.
* ``unavailable``  — Playwright/Chromium is missing or cannot launch headlessly.
* ``not_assessed`` — detection itself could not run (best-effort default).

Detection is environment-only (no secrets, no network, no mission state). The
mission may continue with non-browser HTTP capabilities regardless of the
result; the outcome is recorded as a coverage cell so absence of browser
testing is never converted into negative security evidence.
"""

from __future__ import annotations

import os
import shutil
from typing import Any

_BROWSER_EXECUTABLES: tuple[str, ...] = (
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
    "chrome",
    "msedge",
    "brave",
    "firefox",
)


def detect_browser_capability() -> dict[str, Any]:
    """Return a truthful browser-capability report for this environment.

    Checks, in order: the Playwright package, a Chromium executable on PATH (or
    a Playwright-managed browser), and a real headless launch. A ``429``/WAF
    style defensive response is not relevant here — detection only answers
    "can a headless browser run?".

    Returns:
        A JSON-safe mapping: ``{"status", "playwright", "executable",
        "headless_launch", "reason"}``.

    """
    report: dict[str, Any] = {"status": "not_assessed", "reason": "detection did not run"}

    try:
        import importlib.util

        playwright_spec = importlib.util.find_spec("playwright")
        playwright_available = playwright_spec is not None
        report["playwright"] = bool(playwright_available)

        executable = _find_browser_executable()
        report["executable"] = executable or ""

        if not playwright_available:
            report["status"] = "unavailable"
            report["reason"] = "Playwright package is not installed"
            return report

        launch_ok, launch_error = _try_headless_launch(playwright_available, executable)
        report["headless_launch"] = launch_ok
        if launch_ok:
            report["status"] = "available"
            report["reason"] = "headless browser launch succeeded"
        else:
            report["status"] = "unavailable"
            report["reason"] = launch_error or "headless browser launch failed"
        return report
    except Exception as exc:  # noqa: BLE001 - detection must never crash a mission
        report["status"] = "not_assessed"
        report["reason"] = f"browser detection raised: {exc}"
        return report


def _find_browser_executable() -> str:
    """Return the first browser executable found on PATH (or empty)."""
    for name in _BROWSER_EXECUTABLES:
        path = shutil.which(name)
        if path:
            return path
    # Playwright-managed Chromium cache (linux/macOS + Windows).
    for candidate in (
        os.path.expanduser("~/.cache/ms-playwright"),
        os.environ.get("PLAYWRIGHT_BROWSERS_PATH", ""),
    ):
        if not candidate or not os.path.isdir(candidate):
            continue
        for entry in os.listdir(candidate):
            if "chrom" in entry.lower():
                return os.path.join(candidate, entry)
    return ""


def _try_headless_launch(playwright_available: bool, executable: str) -> tuple[bool, str]:
    """Return ``(launch_ok, error)`` for a real headless browser launch.

    The launch is performed with a hard timeout so a broken browser stack can
    never stall a mission. When Playwright is unavailable, the launch is simply
    reported as not attempted (not a failure).
    """
    if not playwright_available:
        return False, "playwright not available for headless launch"
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            launch_kwargs: dict[str, Any] = {"headless": True}
            if executable:
                launch_kwargs["executable_path"] = executable
            p.chromium.launch(**launch_kwargs)
        return True, ""
    except Exception as exc:  # noqa: BLE001 - a broken browser is an unavailable capability
        return False, f"headless launch failed: {exc}"


__all__ = ["detect_browser_capability"]
