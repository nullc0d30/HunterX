# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Intentionally vulnerable local test application.

A threaded HTTP server on a random loopback port exposing deterministic
vulnerable endpoints (SQLi, NoSQLi, XSS reflection, SSTI eval, LFI, RCE) and
matching SAFE control endpoints that never produce a class signal. Used only by
the acceptance tests; never exposed beyond loopback.

The vulnerability engine's differential core distinguishes the vulnerable
endpoints from the safe controls — the whole point of the no-false-positive gate.
"""

from __future__ import annotations

import http.client
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


class _VulnerableHandler(BaseHTTPRequestHandler):
    """Handle a fixed set of vulnerable and safe endpoints."""

    def log_message(self, *args) -> None:  # noqa: ANN002
        return

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        params = {key: values[0] for key, values in parse_qs(parsed.query).items()}
        value = params.get("q") or params.get("name") or params.get("file") or params.get("cmd") or params.get("id") or params.get("url") or ""
        path = parsed.path
        self._dispatch(path, value, headers=self.headers)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        parsed = urlsplit(self.path)
        self._dispatch(parsed.path, body, headers=self.headers)

    def _dispatch(self, path: str, value: str, headers=None) -> None:  # noqa: ANN001
        if path == "/vuln/search":
            self._sql(value, vulnerable=True)
        elif path == "/safe/search":
            self._sql(value, vulnerable=False)
        elif path == "/vuln/echo":
            self._xss(value, vulnerable=True)
        elif path == "/safe/echo":
            self._xss(value, vulnerable=False)
        elif path == "/vuln/greet":
            self._ssti(value, vulnerable=True)
        elif path == "/safe/greet":
            self._ssti(value, vulnerable=False)
        elif path == "/vuln/read":
            self._lfi(value, vulnerable=True)
        elif path == "/safe/read":
            self._lfi(value, vulnerable=False)
        elif path == "/vuln/run":
            self._rce(value, vulnerable=True)
        elif path == "/safe/run":
            self._rce(value, vulnerable=False)
        elif path == "/vuln/nosql":
            self._nosql(value, vulnerable=True)
        elif path == "/safe/nosql":
            self._nosql(value, vulnerable=False)
        elif path == "/vuln/redirect":
            self._redirect(value, vulnerable=True)
        elif path == "/safe/redirect":
            self._redirect(value, vulnerable=False)
        elif path == "/vuln/cors":
            self._cors(value, vulnerable=True)
        elif path == "/safe/cors":
            self._cors(value, vulnerable=False)
        elif path == "/vuln/secrets":
            self._secrets()
        elif path == "/safe/secrets":
            self._respond(200, '{"config": {"debug": false}}')
        elif path == "/vuln/headers":
            self._headers(vulnerable=True)
        elif path == "/safe/headers":
            self._headers(vulnerable=False)
        elif path == "/vuln/version":
            self._respond(200, '{"component": "jquery", "version": "1.4.2"}')
        elif path == "/safe/version":
            self._respond(200, '{"component": "jquery", "version": "3.7.1"}')
        elif path == "/vuln/deps":
            self._respond(200, '{"dependencies": [{"name": "lodash", "version": "4.17.11"}]}')
        elif path == "/safe/deps":
            self._respond(200, '{"dependencies": [{"name": "lodash", "version": "4.17.21"}]}')
        elif path == "/vuln/parse":
            self._xxe(value, vulnerable=True)
        elif path == "/safe/parse":
            self._xxe(value, vulnerable=False)
        elif path == "/vuln/resource":
            self._idor(value, headers=headers, vulnerable=True)
        elif path == "/safe/resource":
            self._idor(value, headers=headers, vulnerable=False)
        elif path == "/vuln/account":
            self._auth(value, headers=headers, vulnerable=True)
        elif path == "/safe/account":
            self._auth(value, headers=headers, vulnerable=False)
        elif path == "/vuln/admin":
            self._authz(headers=headers, vulnerable=True)
        elif path == "/safe/admin":
            self._authz(headers=headers, vulnerable=False)
        elif path == "/vuln/api/export":
            self._api(vulnerable=True)
        elif path == "/safe/api/export":
            self._api(vulnerable=False)
        elif path == "/vuln/graphql":
            self._graphql(value, vulnerable=True)
        elif path == "/safe/graphql":
            self._graphql(value, vulnerable=False)
        elif path == "/vuln/fetch":
            self._ssrf(value, vulnerable=True)
        elif path == "/safe/fetch":
            self._ssrf(value, vulnerable=False)
        elif path == "/vuln/cloud/meta":
            self._cloud(vulnerable=True)
        elif path == "/safe/cloud/meta":
            self._cloud(vulnerable=False)
        elif path.startswith("/callback-"):
            self._respond(200, f"ssrf-callback:{path[10:]}")
        else:
            self._respond(404, "not found")

    # -- endpoint implementations -------------------------------------------

    def _sql(self, value: str, *, vulnerable: bool) -> None:
        if not vulnerable:
            self._respond(200, "ok")
            return
        lowered = value.lower()
        if "'" in value and any(sig in lowered for sig in ("sqlstate", "syntax", "sql")):
            self._respond(500, "SQLSTATE[42000]: syntax error near the input")
            return
        if "and '1'='1" in lowered:
            self._respond(200, "found: record exists")
            return
        if "and '1'='2" in lowered or "or 1=1" in lowered:
            self._respond(404, "not found")
            return
        if "'" in value or ";" in value or "--" in value:
            self._respond(500, "SQLSTATE[42000]: syntax error near the input")
            return
        self._respond(200, "found")

    def _nosql(self, value: str, *, vulnerable: bool) -> None:
        if not vulnerable:
            self._respond(200, "ok")
            return
        if "'" in value or '"' in value or "$" in value:
            self._respond(500, "MongoError: unexpected token in query")
            return
        if "=='1" in value:
            self._respond(200, "found: user")
            return
        if "=='2" in value:
            self._respond(404, "not found")
            return
        self._respond(200, "found")

    def _xss(self, value: str, *, vulnerable: bool) -> None:
        if vulnerable:
            self._respond(200, f"<div>result: {value}</div>")
        else:
            self._respond(200, "<div>result: ok</div>")

    def _ssti(self, value: str, *, vulnerable: bool) -> None:
        if vulnerable and "{{" in value:
            if value == "{{7*7}}":
                self._respond(200, "hello 49")
                return
            if value == "{{7*'7'}}":
                self._respond(200, "hello 7777777")
                return
        self._respond(200, "hello")

    def _lfi(self, value: str, *, vulnerable: bool) -> None:
        if vulnerable and ".." in value:
            if "etc/passwd" in value:
                self._respond(200, "root:x:0:0:root:/root:/bin/bash\n")
                return
            if "win.ini" in value.lower():
                self._respond(200, "[extensions]\n")
                return
        self._respond(200, "file not readable")

    def _rce(self, value: str, *, vulnerable: bool) -> None:
        if vulnerable and value.startswith((";", "|", "$(", "`")):
            try:
                result = subprocess.run(["id"], capture_output=True, text=True, timeout=3)  # nosec B404  # controlled fixture
                self._respond(200, result.stdout or "uid=0(root)")
                return
            except Exception:  # noqa: BLE001
                self._respond(200, "uid=0(root)")
                return
        self._respond(200, "ok")

    def _redirect(self, value: str, *, vulnerable: bool) -> None:
        target_url = value or "/"
        if vulnerable or target_url.startswith("/") and not target_url.startswith("//"):
            self._respond_redirect(302, target_url)
        else:
            self._respond(200, "redirect not followed")

    def _cors(self, value: str, *, vulnerable: bool) -> None:
        if vulnerable:
            self._respond_headers(200, "ok", {"Access-Control-Allow-Origin": value or "*"})
        else:
            self._respond(200, "ok")

    def _secrets(self) -> None:
        self._respond(200, '{"api_key": "sk_live_abc123", "password": "hunter2", "config": {"debug": true}}')

    def _headers(self, *, vulnerable: bool) -> None:
        if vulnerable:
            self._respond_headers(200, "ok", {"Server": "nginx/1.4.2"})
        else:
            self._respond_headers(200, "ok", {"Server": "nginx/1.24.0", "X-Frame-Options": "DENY", "Content-Security-Policy": "default-src 'self'"})

    def _xxe(self, value: str, *, vulnerable: bool) -> None:
        lowered = value.lower()
        if vulnerable and ("<!doctype" in lowered or "<!entity" in lowered or "system" in lowered):
            self._respond(500, "XMLParseError: entity expansion failed or external entity blocked")
            return
        self._respond(200, "xml ok")

    # -- Phase 2 infrastructure capabilities --------------------------------

    @staticmethod
    def _header(headers, name: str) -> str:
        if headers is None:
            return ""
        return headers.get(name) or headers.get(name.lower()) or ""

    def _idor(self, value: str, *, headers, vulnerable: bool) -> None:  # noqa: ANN001
        user = self._header(headers, "X-User") or "anonymous"
        owners = {"1": "alice", "2": "bob"}
        resource_id = value or "1"
        owner = owners.get(resource_id, "alice")
        if vulnerable:
            # IDOR: no ownership check; any authenticated caller reads any object.
            if user and user != "anonymous":
                self._respond(200, f'{{"resource": {resource_id}, "owner": "{owner}", "secret": "data-{resource_id}"}}')
                return
            self._respond(403, "forbidden")
            return
        if user == owner:
            self._respond(200, f'{{"resource": {resource_id}, "owner": "{owner}"}}')
            return
        self._respond(403, "forbidden: not your resource")

    def _auth(self, value: str, *, headers, vulnerable: bool) -> None:  # noqa: ANN001
        token = self._header(headers, "Authorization")
        valid_token = "Bearer valid-token"
        if vulnerable:
            if token and token != "none" and token != valid_token:
                self._respond(200, '{"account": {"username": "alice", "email": "alice@example.com"}}')
                return
            if token == valid_token:
                self._respond(200, '{"account": {"username": "alice", "email": "alice@example.com"}}')
                return
            self._respond(401, "unauthorized")
            return
        if token == valid_token:
            self._respond(200, '{"account": {"username": "alice"}}')
            return
        self._respond(401, "unauthorized")

    def _authz(self, *, headers, vulnerable: bool) -> None:  # noqa: ANN001
        role = self._header(headers, "X-Role") or "user"
        if vulnerable:
            if role == "admin":
                self._respond(200, '{"admin": {"privilege": "full", "users": ["alice", "bob"]}}')
                return
            self._respond(403, "forbidden: user role")
            return
        self._respond(403, "forbidden: role not trusted from client")

    def _api(self, *, vulnerable: bool) -> None:
        if vulnerable:
            self._respond(200, '{"export": [{"id": 1, "ssn": "123-45-6789", "email": "alice@example.com"}]}')
            return
        self._respond(401, "unauthorized")

    def _graphql(self, value: str, *, vulnerable: bool) -> None:
        if vulnerable and "__schema" in value:
            self._respond(200, '{"data": {"__schema": {"types": [{"name": "Query"}, {"name": "User"}]}}}')
            return
        if vulnerable:
            self._respond(200, '{"data": {"user": {"name": "alice"}}}')
            return
        self._respond(400, '{"errors": [{"message": "introspection is disabled"}]}')

    def _ssrf(self, value: str, *, vulnerable: bool) -> None:
        url = value or "/"
        if not vulnerable:
            self._respond(200, "fetch blocked by policy")
            return
        # The vulnerable endpoint performs a REAL server-side request to the
        # client-controlled URL (loopback callback), proving the server
        # initiates the outbound fetch — never a simulated response.
        parsed = urlsplit(url)
        if parsed.scheme not in ("http", "https") or parsed.hostname not in ("127.0.0.1", "localhost"):
            self._respond(200, "fetch policy: loopback only")
            return
        try:
            connection = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=3)
            connection.request("GET", parsed.path or "/")
            response = connection.getresponse()
            body = response.read(2000).decode("utf-8", "replace")
            self._respond(200, body)
        except Exception:  # noqa: BLE001
            self._respond(502, "fetch failed")

    def _cloud(self, *, vulnerable: bool) -> None:
        if vulnerable:
            self._respond(200, '{"access_key": "AKIAEXAMPLE123456", "secret_key": "secret", "region": "us-east-1"}')
            return
        self._respond(200, "{}")

    # -- helpers ------------------------------------------------------------

    def _respond(self, status: int, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _respond_headers(self, status: int, body: str, extra: dict[str, str]) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for name, value in extra.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def _respond_redirect(self, status: int, location: str) -> None:
        self.send_response(status)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()


class VulnerableApp:
    """Context-managed loopback vulnerable fixture server."""

    def __init__(self, *, host: str = "127.0.0.1", port: int = 0) -> None:
        self._host = host
        self._server = ThreadingHTTPServer((host, port), _VulnerableHandler)
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        return f"http://{self._host}:{self._server.server_port}"

    def start(self) -> VulnerableApp:
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def __enter__(self) -> VulnerableApp:
        return self.start()

    def __exit__(self, *exc) -> None:  # noqa: ANN002
        self.stop()
