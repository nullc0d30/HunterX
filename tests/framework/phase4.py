# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Phase 4 validation harness.

Drives HunterX's universal deep-discovery pipeline (Phase 4) end to end
against a generic target and produces the full Phase 4 evidence:

    * the complete stage plan (ASSET → DNS → SUBDOMAIN → HOST → PORT →
      SERVICE → TECHNOLOGY → HTTP → API → GRAPHQL → JAVASCRIPT → WORKFLOW →
      AUTH),
    * per-provider honest states (available/unavailable/failed/partial/
      not-applicable/completed) with exact gaps — never a fabricated result,
    * canonical deduplicated assets with provenance (provider, tool, source,
      evidence, confidence),
    * the attack-surface graph growth, capability mapping and assessment-queue
      scheduling fed from discovery observations,
    * continuous-discovery feedback (hosts/URLs/scripts discovered early feed
      later stages),
    * a real black-box run through the in-process adapters (crawler, JS
      analyzer, tech signatures, TCP connect probes, DNS, API intelligence,
      auth analysis) against a generic loopback fixture.

The harness never hardcodes a target: the fixture is a generic SPA/API app on
``127.0.0.1``, the plan is built from the tool registries, and every provider
payload is converted through the canonical pipeline.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from hunterx.application.discovery import UniversalDiscoveryService, build_stage_plan
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso
from hunterx.tools.api.adapters import (
    ApiHintsAdapter,
    GraphQLDiscoveryAdapter,
    OpenAPIDiscoveryAdapter,
    SoapDiscoveryAdapter,
    SwaggerDiscoveryAdapter,
    WebSocketDiscoveryAdapter,
)
from hunterx.tools.auth.analyzer import AuthAnalyzerAdapter
from hunterx.tools.dns.dnspython import DnspythonAdapter
from hunterx.tools.javascript.analyzer import JavaScriptAnalyzerAdapter
from hunterx.tools.livehost.tcp_connect import TcpConnectAdapter
from hunterx.tools.sdk.engine import ExecutionEngine
from hunterx.tools.tech.signature import SignatureAdapter
from hunterx.tools.web.crawler import CrawlerAdapter

#: In-process adapters registered on the harness engine (binary-free paths).
IN_PROCESS_ADAPTERS: dict[str, type] = {
    "crawler": CrawlerAdapter,
    "javascript": JavaScriptAnalyzerAdapter,
    "signature": SignatureAdapter,
    "tcp-connect": TcpConnectAdapter,
    "dnspython": DnspythonAdapter,
    "api-openapi": OpenAPIDiscoveryAdapter,
    "api-swagger": SwaggerDiscoveryAdapter,
    "api-graphql": GraphQLDiscoveryAdapter,
    "api-websocket": WebSocketDiscoveryAdapter,
    "api-soap": SoapDiscoveryAdapter,
    "api-hints": ApiHintsAdapter,
    "auth-analysis": AuthAnalyzerAdapter,
}

#: Binary-only tools in the stage plan but never installed on the harness
#: engine — the honest ``UNAVAILABLE`` set proving state honesty over
#: fabrication. Derived from the plan so it can never drift from the pipeline.
BINARY_ONLY_TOOL_IDS = tuple(
    sorted(set(build_stage_plan().tool_ids()) - set(IN_PROCESS_ADAPTERS))
)

_INDEX_HTML = """<!doctype html>
<html lang="en">
<head><title>Generic App</title><script src="/app.js"></script></head>
<body>
  <h1>Generic Application</h1>
  <a href="/api-docs/openapi.json">API docs</a>
  <a href="/login">Login</a>
  <script>fetch("/api/rest/products").then(r => r.json());</script>
</body>
</html>
"""

_APP_JS = """\
(function () {
  var API = "/api/rest";
  var products = API + "/products";
  var search = API + "/products/search?q=";
  var basket = "/api/rest/basket/" + 1;
  var graphql = "/graphql";
  var socket = "/ws/stream";
  var login = "/rest/user/login";
  fetch(products);
  fetch(search + "smartphone");
  console.log(graphql, socket, login, basket);
  if (window.location.pathname.startsWith("/product/")) {
    document.title = "Product " + window.location.pathname.split("/")[2];
  }
})();
"""

_OPENAPI_DOC = {
    "openapi": "3.0.3",
    "info": {"title": "Generic API", "version": "1.0.0"},
    "paths": {
        "/api/rest/products": {
            "get": {
                "operationId": "listProducts",
                "parameters": [
                    {"name": "q", "in": "query", "required": False, "schema": {"type": "string"}},
                    {"name": "page", "in": "query", "required": False, "schema": {"type": "integer"}},
                ],
                "responses": {"200": {"description": "ok"}},
            }
        },
        "/api/rest/products/search": {
            "get": {
                "operationId": "searchProducts",
                "parameters": [
                    {"name": "q", "in": "query", "required": True, "schema": {"type": "string"}}
                ],
                "responses": {"200": {"description": "ok"}},
            }
        },
        "/rest/user/login": {
            "post": {
                "operationId": "login",
                "requestBody": {
                    "content": {"application/json": {"schema": {"type": "object"}}}
                },
                "responses": {"200": {"description": "ok"}},
            }
        },
    },
    "components": {
        "securitySchemes": {
            "bearer": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
        }
    },
    "security": [{"bearer": []}],
}

_LOGIN_HTML = """<!doctype html>
<html><head><title>Login</title></head>
<body><form method="post" action="/rest/user/login">
<input name="username" type="text"/><input name="password" type="password"/>
</form></body></html>
"""


class _FixtureHandler(BaseHTTPRequestHandler):
    """Serve the generic fixture content; loopback only."""

    def log_message(self, *_: Any) -> None:
        """Silence the request log."""

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "generic-fixture/1.0")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._send(200, _INDEX_HTML.encode(), "text/html")
        elif path == "/app.js":
            self._send(200, _APP_JS.encode(), "application/javascript")
        elif path in ("/openapi.json", "/api-docs/openapi.json"):
            self._send(200, json.dumps(_OPENAPI_DOC).encode(), "application/json")
        elif path == "/login":
            self._send(200, _LOGIN_HTML.encode(), "text/html")
        elif path == "/api/rest/products":
            self._send(200, json.dumps([{"id": 1, "name": "widget"}]).encode(), "application/json")
        elif path == "/api/rest/products/search":
            self._send(200, json.dumps([{"id": 2, "name": "gadget"}]).encode(), "application/json")
        elif path == "/graphql":
            self._send(200, json.dumps({"data": {"__typename": "Query"}}).encode(), "application/json")
        elif path.startswith("/product/"):
            self._send(200, b"<h1>Product</h1>", "text/html")
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/rest/user/login":
            self._send(200, json.dumps({"authentication": {"token": "masked"}}).encode(), "application/json")
        elif path == "/graphql":
            self._send(200, json.dumps({"data": {}}).encode(), "application/json")
        else:
            self._send(404, b"not found", "text/plain")


class GenericDiscoveryFixture:
    """A generic loopback SPA/API fixture (never target-specific).

    Serves a small SPA with a JavaScript bundle, an OpenAPI document, an API
    endpoint family, a login surface and a GraphQL endpoint on ``127.0.0.1``
    with an ephemeral port — the same shape any external web application has.
    """

    def __init__(self) -> None:
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.target_url = ""

    def __enter__(self) -> "GenericDiscoveryFixture":
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
        port = int(self._server.server_address[1])
        self.target_url = f"http://127.0.0.1:{port}/"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_: Any) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)

    @property
    def target(self) -> str:
        """Return the canonical target key."""
        return self.target_url


class Phase4Harness:
    """Run the universal discovery pipeline against one target.

    Args:
        target: authorized target key (loopback for real provider runs).
        mission_id: owning mission id (``""`` generates one).
        mode: execution posture (``passive``/``active``/``hybrid``).
        session_state: optional session state label.
        timeout_seconds: per-provider execution timeout.
        adapters: tool id → adapter class mapping (``None`` uses the
            in-process adapter set above).

    """

    def __init__(
        self,
        *,
        target: str,
        mission_id: str = "",
        mode: str = "hybrid",
        session_state: str = "",
        timeout_seconds: float = 20.0,
        adapters: dict[str, type] | None = None,
    ) -> None:
        self.target = target
        self.mission_id = mission_id or f"phase4-{generate_id()[:8]}"
        self.mode = mode
        self.session_state = session_state
        self.engine = ExecutionEngine()
        self._adapters = dict(adapters or IN_PROCESS_ADAPTERS)
        self._register_adapters()
        self.service = UniversalDiscoveryService(
            engine=self.engine,
            mission_id=self.mission_id,
            target_key=target,
        )
        self.run_result: Any = None
        self._timeout_seconds = timeout_seconds

    def _register_adapters(self) -> None:
        """Register every adapter and its install/health hooks."""
        for tool_id, adapter_type in self._adapters.items():
            self.engine.register_adapter(tool_id, adapter_type())
            self.engine.install_hook(tool_id, lambda *_: "1.0")
            self.engine.install(tool_id)

    def run(self) -> dict[str, Any]:
        """Execute the full discovery pipeline and return the run dictionary."""
        self.run_result = self.service.run(
            target=self.target,
            mode=self.mode,
            session_state=self.session_state,
            timeout_seconds=self._timeout_seconds,
        )
        return self.run_result.to_dict()

    # -- reporting -----------------------------------------------------------

    def stage_states(self) -> dict[str, str]:
        """Return ``{stage: state}`` for the last run."""
        assert self.run_result is not None, "run() must be called first"
        return {stage.stage.value: stage.state.value for stage in self.run_result.stages}

    def provider_states(self) -> dict[str, str]:
        """Return ``{provider_id: state}`` for the last run."""
        assert self.run_result is not None, "run() must be called first"
        return self.run_result.provider_states()

    def assets_by_kind(self) -> dict[str, int]:
        """Return asset-kind counts for the last run."""
        assert self.run_result is not None, "run() must be called first"
        counts: dict[str, int] = {}
        for asset in self.run_result.assets:
            counts[asset.kind] = counts.get(asset.kind, 0) + 1
        return counts

    def report(self) -> dict[str, Any]:
        """Assemble the complete Phase 4 evidence report."""
        assert self.run_result is not None, "run() must be called first"
        return {
            "mission_id": self.mission_id,
            "target": self.target,
            "mode": self.mode,
            "generated_at": utcnow_iso(),
            "stage_plan": [stage.stage.value for stage in self.service.plan.stages],
            "in_process_adapters": sorted(self._adapters),
            "binary_only_tools_reported_unavailable": sorted(BINARY_ONLY_TOOL_IDS),
            "run": self.run_result.to_dict(),
            "surface": self.service.surface.snapshot(),
        }


__all__ = ["BINARY_ONLY_TOOL_IDS", "GenericDiscoveryFixture", "Phase4Harness"]