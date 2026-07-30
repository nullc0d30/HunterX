# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
import time
from typing import Optional


class TimeBasedDetector:
    """Detects blind vulnerabilities via response timing analysis."""

    TIMING_PAYLOADS = {
        "SQLI_TIME": [
            ("' OR SLEEP(5)--", 5.0),
            ("'; WAITFOR DELAY '00:00:05'--", 5.0),
            ("1 AND SLEEP(5)", 5.0),
            ("1; SELECT pg_sleep(5)", 5.0),
        ],
        "SSTI_TIME": [
            ("{{sleep(5)}}", 5.0),
            ("${sleep(5)}", 5.0),
            ("{% import time %}{{time.sleep(5)}}", 5.0),
        ],
        "RCE_TIME": [
            ("; sleep 5", 5.0),
            ("| sleep 5", 5.0),
            ("`sleep 5`", 5.0),
        ],
    }

    def __init__(self, baseline_time: float = 0.5):
        self.baseline_time = baseline_time
        self.threshold_multiplier = 3.0

    def test(self, url: str, payload: str, expected_delay: float, session) -> Optional[dict]:
        """Send payload and check if response time indicates injection."""
        start = time.time()
        try:
            resp = session.get(url)
        except Exception:
            return None
        elapsed = time.time() - start

        if elapsed >= expected_delay * 0.8:
            return {
                "type": "time_based",
                "payload": payload,
                "expected_delay": expected_delay,
                "actual_delay": round(elapsed, 2),
                "confidence": min(1.0, elapsed / expected_delay),
                "status_code": resp.status_code if resp else 0,
            }
        return None

    def scan(self, category: str, url: str, session) -> list:
        """Run all timing payloads for a given category."""
        results = []
        payloads = self.TIMING_PAYLOADS.get(category, [])
        for payload, delay in payloads:
            result = self.test(url, payload, delay, session)
            if result:
                results.append(result)
        return results
