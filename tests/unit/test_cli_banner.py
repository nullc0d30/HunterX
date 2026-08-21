# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Focused regression tests for the HunterX CLI startup banner.

The banner is presentation-only branding emitted through the CLI startup/help
path. It must render the exact required lines verbatim and interpolate the
canonical package version (never a second hardcoded version source).
"""

from __future__ import annotations

import hunterx
from hunterx.cli.app import CliApplication


class TestCliBanner:
    def test_banner_contains_required_branding_lines(self) -> None:
        banner = CliApplication().banner()
        for line in (
            "AI-POWERED SECURITY ORCHESTRATION & INTELLIGENCE PLATFORM",
            f"HunterX v{hunterx.__version__}",
            "Observe → Hypothesize → Probe → Verify",
            "Developed & Engineered by",
            "Ahmed Awad (AKA NullC0d3)",
            "[INFO] HunterX Environment Bootstrapper",
            "[INFO] System Mode · Profile: Full",
        ):
            assert line in banner, f"missing required banner line: {line!r}"

    def test_banner_logo_is_literal_and_deterministic(self) -> None:
        app = CliApplication()
        banner = app.banner()
        assert banner.startswith("██╗  ██╗██╗   ██╗")
        assert "████████╗███████╗██████╗" in banner
        assert banner == app.banner()

    def test_banner_interpolates_canonical_version(self) -> None:
        banner = CliApplication().banner()
        assert f"HunterX v{hunterx.__version__}" in banner

    def test_help_text_emits_the_banner(self) -> None:
        app = CliApplication()
        text = app.help_text()
        assert text.startswith("██╗  ██╗██╗   ██╗")
        assert "Observe → Hypothesize → Probe → Verify" in text
        assert "Usage: hunterx <command> [args...]" in text
        assert "HunterX is an authorized cybersecurity testing and research platform." in text
