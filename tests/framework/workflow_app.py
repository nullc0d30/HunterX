# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Deterministic stateful workflow fixture for the final multi-target acceptance.

Serves a small multi-step workflow (``start -> advance -> finalize``) with
server-side state transitions and token validation. The app is deliberately
*not* vulnerable — its purpose is to prove the engine discovers, maps and
executes real assessment tasks on workflow surfaces with honest outcomes and
genuine exhaustion (a target is never exhausted because no finding exists).
"""

from __future__ import annotations

import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

_WORKFLOW_STATES = ("pending", "approved", "rejected")


class _WorkflowHandler(BaseHTTPRequestHandler):
    def log_message(self, *_: Any) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        path = urllib.parse.urlsplit(self.path).path
        if path in ("/", "/index.html"):
            links = ("/workflow/start", "/workflow/advance", "/workflow/finalize")
            body = "\n".join(f'<a href="{link}">{link}</a>' for link in links)
            self._respond(200, "text/html", f"<html><body><h1>workflow</h1>{body}</body></html>")
            return
        if path == "/workflow/start":
            self._respond(200, "application/json", json.dumps({"workflow": "checkout", "state": "pending", "next": "advance"}))
            return
        if path == "/workflow/advance":
            token = _query_param(self.path, "token")
            if not token:
                self._respond(400, "application/json", json.dumps({"error": "token required"}))
                return
            self._respond(200, "application/json", json.dumps({"workflow": "checkout", "state": "approved", "next": "finalize"}))
            return
        if path == "/workflow/finalize":
            token = _query_param(self.path, "token")
            if not token:
                self._respond(400, "application/json", json.dumps({"error": "token required"}))
                return
            self._respond(200, "application/json", json.dumps({"workflow": "checkout", "state": "complete", "next": ""}))
            return
        self._respond(404, "text/plain", "not found")

    def do_POST(self) -> None:  # noqa: N802
        path = urllib.parse.urlsplit(self.path).path
        if path in ("/workflow/start", "/workflow/advance", "/workflow/finalize"):
            body = _read_body(self)
            if path == "/workflow/start":
                self._respond(201, "application/json", json.dumps({"workflow": "checkout", "state": "pending", "token": "flow-1"}))
                return
            if not (body or {}).get("token"):
                self._respond(400, "application/json", json.dumps({"error": "token required"}))
                return
            state = "approved" if path == "/workflow/advance" else "complete"
            self._respond(200, "application/json", json.dumps({"workflow": "checkout", "state": state}))
            return
        self._respond(404, "text/plain", "not found")

    def _respond(self, status: int, content_type: str, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def _query_param(url: str, name: str) -> str:
    params = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
    return (params.get(name) or [""])[0]


def _read_body(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length") or 0)
    raw = handler.rfile.read(length) if length else b""
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


class WorkflowApp:
    """A threaded loopback server exposing a deterministic stateful workflow.

    Attributes:
        base_url: the ``http://127.0.0.1:<port>/`` base URL.
        workflow_states: the state names the fixture transitions through.

    """

    def __init__(self) -> None:
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.base_url = ""
        self.workflow_states = _WORKFLOW_STATES

    def __enter__(self) -> WorkflowApp:
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _WorkflowHandler)
        port = int(self._server.server_address[1])
        self.base_url = f"http://127.0.0.1:{port}/"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_: Any) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)


__all__ = ["WorkflowApp"]
