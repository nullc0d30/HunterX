# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Generic safe fixture: a minimal loopback web server with no vulnerable surface.

Used by the zero-finding release gate: a real CLI mission against this target
must terminate honestly with 0 validated and 0 report-ready findings, must not
invent a vulnerability, and must not loop forever. Nothing here is
HunterX-specific or DVWA-specific.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


class _SafeHandler(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:  # noqa: ANN002
        return

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path in ("/", "/index.html"):
            self._respond(200, "<html><body><h1>Welcome</h1><p>Static content only.</p></body></html>")
            return
        self._respond(404, "not found")

    def _respond(self, status: int, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class SafeApp:
    """Context-managed loopback static server used for the zero-finding gate."""

    def __init__(self, *, host: str = "127.0.0.1", port: int = 0) -> None:
        self._host = host
        self._server = ThreadingHTTPServer((host, port), _SafeHandler)
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        return f"http://{self._host}:{self._server.server_port}"

    def start(self) -> SafeApp:
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)

    def __enter__(self) -> SafeApp:
        return self.start()

    def __exit__(self, *exc) -> None:  # noqa: ANN002
        self.stop()
