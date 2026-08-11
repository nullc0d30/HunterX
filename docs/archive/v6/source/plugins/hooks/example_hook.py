# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
from core.plugin_loader import plugin
from core.utils import logger


@plugin("hook", hook_type="after_scan")
class LogSummaryHook:
    """Example hook: logs a summary after scan completes."""

    def run(self, **kwargs):
        results = kwargs.get("results", [])
        url = kwargs.get("url", "unknown")
        critical = sum(1 for r in results if r.get("diff_score", 0) > 80)
        logger.info(f"[Plugin Hook] Scan of {url} complete: {len(results)} findings, {critical} critical")
