import json
import random
from typing import List, Dict, Optional

try:
    from websocket import create_connection, WebSocket
    HAS_WS = True
except ImportError:
    HAS_WS = False


class WebSocketTester:
    """Tests WebSocket endpoints for injection vulnerabilities."""

    TEST_MESSAGES = [
        {"type": "ping", "payload": "<script>alert(1)</script>"},
        {"type": "message", "payload": "' OR 1=1 --"},
        {"type": "subscribe", "payload": "../../../etc/passwd"},
        {"type": "query", "payload": "{__schema{types{name}}}"},
    ]

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def test_endpoint(self, ws_url: str) -> List[Dict]:
        """Run injection tests against a WebSocket endpoint."""
        results = []
        if not HAS_WS:
            return results

        for msg in self.TEST_MESSAGES:
            try:
                ws = create_connection(ws_url, timeout=self.timeout)
                ws.send(json.dumps({"type": msg["type"], "data": msg["payload"]}))
                response = ws.recv()
                ws.close()

                if response:
                    results.append({
                        "endpoint": ws_url,
                        "test_type": msg["type"],
                        "payload": msg["payload"],
                        "response_length": len(response),
                        "response_preview": response[:200],
                    })
            except Exception as e:
                results.append({
                    "endpoint": ws_url,
                    "test_type": msg["type"],
                    "payload": msg["payload"],
                    "error": str(e),
                })

        return results

    def detect_endpoints(self, html: str) -> List[str]:
        """Extract WebSocket endpoints from HTML."""
        import re
        ws_patterns = [
            r"wss?://[a-zA-Z0-9._/-]+",
            r"new\s+WebSocket\([\"']([^\"']+)[\"']\)",
            r"websocket[\"']\s*:\s*[\"']([^\"']+)[\"']",
        ]
        endpoints = set()
        for pattern in ws_patterns:
            for match in re.findall(pattern, html):
                if match.startswith("ws") or "://" in match:
                    endpoints.add(match)
                else:
                    endpoints.add(f"wss://{match}")
        return list(endpoints)
