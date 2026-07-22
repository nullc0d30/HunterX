# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# All Rights Reserved.
#
# HunterX — AI-Assisted Vulnerability Hunter
from core.plugin_loader import plugin


@plugin("detector")
class CustomHeaderDetector:
    """Example plugin: detects custom security headers."""

    def analyze(self, finding: dict) -> list:
        findings = []
        payload = finding.get("payload", "").lower()
        if "admin" in payload or "config" in payload:
            findings.append("Low - Payload targets admin/config endpoint")
        return findings
