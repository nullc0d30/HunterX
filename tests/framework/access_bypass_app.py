# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Generic HTTP access/status-bypass fixture.

A small threaded loopback server modelling the Phase 14.3 access-control
bypass capability:

* **/protected** — 403 on the canonical path; a controlled path-normalization
  mutation (``/protected/``, ``/protected/.``) serves substantive protected
  content. Safe control ``/safe/protected`` stays 403 on every mutation.
* **/hidden** — 404 baseline; the same mutations serve protected content.
  Safe control ``/safe/hidden`` stays 404.
* **/statusbypass** — 403 -> 200 ``ok`` (status-only; never a vulnerability).
* **/lengthonly** — 403 -> 200 with a generic denied body (never a
  vulnerability).
* **/error** — 502 -> 503 (proxy status change; never a vulnerability).

A crawlable index links every endpoint so a real mission discovers the
surface without fakes. Nothing here is DVWA-specific.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


class _AccessBypassHandler(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:  # noqa: ANN002
        return

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path in ("/", "/index.html"):
            links = (
                "/protected",
                "/safe/protected",
                "/hidden",
                "/safe/hidden",
                "/statusbypass",
                "/lengthonly",
                "/error",
            )
            body = "\n".join(f'<a href="{link}">{link}</a>' for link in links)
            self._respond(200, f"<html><body><h1>index</h1>{body}</body></html>")
            return
        if path in ("/protected", "/protected/", "/protected/.", "/protected/./"):
            if path != "/protected":
                self._respond(200, _PROTECTED_CONTENT)
            else:
                self._respond(403, "forbidden")
            return
        if path in ("/safe/protected", "/safe/protected/", "/safe/protected/."):
            self._respond(403, "forbidden")
            return
        if path in ("/hidden", "/hidden/", "/hidden/.", "/hidden/./"):
            if path != "/hidden":
                self._respond(200, _HIDDEN_CONTENT)
            else:
                self._respond(404, "not found")
            return
        if path in ("/safe/hidden", "/safe/hidden/", "/safe/hidden/."):
            self._respond(404, "not found")
            return
        if path in ("/statusbypass", "/statusbypass/"):
            if path == "/statusbypass/":
                self._respond(200, "ok")
            else:
                self._respond(403, "forbidden")
            return
        if path in ("/lengthonly", "/lengthonly/"):
            if path == "/lengthonly/":
                self._respond(200, "forbidden but this is a longer generic message body")
            else:
                self._respond(403, "forbidden")
            return
        if path in ("/error", "/error/", "/error/."):
            if path == "/error":
                self._respond(502, "bad gateway")
            else:
                self._respond(503, "bad gateway variant")
            return
        self._respond(404, "not found")

    def _respond(self, status: int, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


#: Substantive protected content exposed by the bypass (marker kept so the
#: proof-marker verification path and the generic meaningful-access path both
#: operate on the same fixture).
_PROTECTED_CONTENT = (
    "PROTECTED hxbypass_protected role=admin data=classified account=alice session=authorized "
    "resource=/admin/accounts billing=premium tier=enterprise last_login=2026-01-01 "
    "access_grants=[admin,audit,ops] endpoint_whitelist=[/admin,/internal,/ops]"
)
_HIDDEN_CONTENT = (
    "HIDDEN hxbypass_hidden flag=supersecret backup_key=rotated-42 doc=internal-design "
    "spec_version=2.1 owner=platform-team review=approved encrypted_at_rest=true "
    "rotation_due=2027-03-01 classification=restricted access_scope=root-tenant"
)


class AccessBypassApp:
    """Context-managed loopback HTTP access-bypass fixture server."""

    def __init__(self, *, host: str = "127.0.0.1", port: int = 0) -> None:
        self._host = host
        self._server = ThreadingHTTPServer((host, port), _AccessBypassHandler)
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        return f"http://{self._host}:{self._server.server_port}"

    def start(self) -> AccessBypassApp:
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)

    def __enter__(self) -> AccessBypassApp:
        return self.start()

    def __exit__(self, *exc) -> None:  # noqa: ANN002
        self.stop()
