# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Phase 12 tests — authenticated attack-surface discovery.

Covers the authenticated-session layer added for Phase 12:

- the in-memory ``AuthenticatedSession`` model and its masking guarantees,
- the generic form-login session service (fixture-driven, never hardcoded),
- the HTTP page fetcher's POST/header/cookie capture support,
- session cookie/header propagation into tool argv (katana/httpx/arjun/nuclei),
- session attachment to differential probes (mission + finding service),
- the mission-runner auth wiring (establish before discovery, honest
  negatives, secret hygiene in contexts/events),
- a no-DVWA-hardcoding guard over the codebase.
"""

from __future__ import annotations

import dataclasses
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode

import pytest

from hunterx.application.session import SessionService
from hunterx.domain.auth.session import AuthenticatedSession
from hunterx.tools.headers import header_args
from hunterx.tools.web.httpclient import FetchedPage, HttpPageFetcher

SRC = Path(__file__).resolve().parents[2] / "src"

_LOGIN_HTML = """
<form action="/login.php" method="POST">
  <input type="hidden" name="user_token" value="csrf-secret-token">
  <input type="text" name="username">
  <input type="password" name="password">
  <input type="submit" value="Login">
</form>
"""


class _FakeFetcher:
    """Scripted fetch seam: serves the login page and handles the POST."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.accept_credentials = True
        self.fail_login = False

    def __call__(self, url: str, timeout_s: float = 10.0, **kwargs: Any) -> FetchedPage:
        self.calls.append({"url": url, **kwargs})
        if url.endswith("/login.php") and not kwargs.get("data"):
            return FetchedPage(
                url=url,
                status_code=200,
                headers={"content-type": "text/html"},
                content=_LOGIN_HTML,
            )
        if kwargs.get("data"):
            payload = parse_qs(kwargs["data"].decode("utf-8"))
            if self.fail_login:
                return FetchedPage(url=url, status_code=200, headers={}, content=_LOGIN_HTML)
            expected = {
                "username": ["admin"],
                "password": ["secret"],
                "user_token": ["csrf-secret-token"],
            }
            if not self.accept_credentials or payload != expected:
                # Honest failure: the server bounces back to the login page.
                return FetchedPage(url=url, status_code=200, headers={}, content=_LOGIN_HTML)
            return FetchedPage(
                url=url,
                status_code=302,
                headers={"location": "/index.php", "set-cookie": "PHPSESSID=abc123; Path=/"},
                cookies={"PHPSESSID": "abc123"},
                content="",
            )
        return FetchedPage(url=url, status_code=200, headers={}, content="<html><body>home</body></html>")


# ---------------------------------------------------------------------------
# AuthenticatedSession model + masking
# ---------------------------------------------------------------------------


class TestAuthenticatedSession:
    def test_established_requires_origin_and_cookies(self) -> None:
        session = AuthenticatedSession(
            origin="http://127.0.0.1:4280",
            cookies=(("PHPSESSID", "abc123"),),
            username="admin",
        )
        assert session.established is True
        assert session.scope_label() == "authenticated"
        assert session.cookie_header() == "PHPSESSID=abc123"

    def test_error_session_is_not_established(self) -> None:
        session = AuthenticatedSession(error="no login form discovered")
        assert session.established is False
        assert session.scope_label() == "anonymous"

    def test_to_dict_never_exposes_raw_secrets(self) -> None:
        session = AuthenticatedSession(
            origin="http://127.0.0.1:4280",
            login_url="http://127.0.0.1:4280/login.php",
            cookies=(("PHPSESSID", "abc123"), ("security", "low")),
            headers=(("Authorization", "Bearer tok123"),),
            csrf_field="user_token",
            csrf_token="csrf-secret-token",
            username="admin",
        )
        payload = session.to_dict()
        rendered = str(payload)
        assert "abc123" not in rendered
        assert "tok123" not in rendered
        assert "csrf-secret-token" not in rendered
        assert "admin" not in rendered
        assert payload["cookies"][0]["name"] == "PHPSESSID"
        assert payload["username"].startswith("a")

    def test_cookie_header_preserves_values_for_requests(self) -> None:
        session = AuthenticatedSession(
            origin="http://127.0.0.1:4280",
            cookies=(("PHPSESSID", "abc123"), ("security", "low")),
        )
        assert session.cookie_header() == "PHPSESSID=abc123; security=low"


# ---------------------------------------------------------------------------
# Session service — generic form login
# ---------------------------------------------------------------------------


class TestSessionService:
    def test_establish_performs_form_login_and_captures_cookies(self) -> None:
        fetcher = _FakeFetcher()
        service = SessionService(fetcher=fetcher)
        session = service.establish(
            login_url="http://127.0.0.1:4280/login.php",
            username="admin",
            password="secret",
        )
        assert session.established is True
        assert session.origin == "http://127.0.0.1:4280"
        assert session.cookies == (("PHPSESSID", "abc123"),)
        assert session.csrf_field == "user_token"
        assert session.csrf_token == "csrf-secret-token"
        # The POST carried credentials + CSRF + Login submit.
        post_call = next(call for call in fetcher.calls if call.get("data"))
        body = parse_qs(post_call["data"].decode("utf-8"))
        assert body["username"] == ["admin"]
        assert body["password"] == ["secret"]
        assert body["user_token"] == ["csrf-secret-token"]
        assert post_call["method"] == "POST"

    def test_wrong_credentials_yield_honest_failure(self) -> None:
        fetcher = _FakeFetcher()
        fetcher.accept_credentials = False
        service = SessionService(fetcher=fetcher)
        session = service.establish(
            login_url="http://127.0.0.1:4280/login.php",
            username="admin",
            password="wrong",
        )
        assert session.established is False
        assert "authentication failed" in session.error

    def test_failed_login_redirect_to_login_page_is_rejected(self) -> None:
        """A login POST that 302-redirects to the login page while issuing a
        fresh session id is a FAILED authentication — a new PHPSESSID on a
        redirect-to-login must never be judged an established session."""

        def fetch(url: str, timeout_s: float = 10.0, **kwargs: Any) -> FetchedPage:
            if url.endswith("/login.php") and not kwargs.get("data"):
                return FetchedPage(url=url, status_code=200, headers={}, content=_LOGIN_HTML)
            if kwargs.get("data"):
                # Failed login: redirect back to the login page with a new id.
                return FetchedPage(
                    url=url,
                    status_code=302,
                    headers={"location": "/login.php", "set-cookie": "PHPSESSID=fresh123; Path=/"},
                    cookies={"PHPSESSID": "fresh123"},
                    content="",
                    redirect_url="/login.php",
                )
            return FetchedPage(url=url, status_code=200, headers={}, content="home")

        service = SessionService(fetcher=fetch)
        session = service.establish(
            login_url="http://127.0.0.1:4280/login.php",
            username="admin",
            password="wrong",
        )
        assert session.established is False
        assert "authentication failed" in session.error

    def test_successful_login_redirect_is_followed_to_established(self) -> None:
        """A successful login POST redirect is followed and the final page is
        not a login form, so the session is established."""

        def fetch(url: str, timeout_s: float = 10.0, **kwargs: Any) -> FetchedPage:
            if url.endswith("/login.php") and not kwargs.get("data"):
                return FetchedPage(url=url, status_code=200, headers={}, content=_LOGIN_HTML)
            if kwargs.get("data"):
                return FetchedPage(
                    url=url,
                    status_code=302,
                    headers={"location": "/index.php", "set-cookie": "PHPSESSID=ok123; Path=/"},
                    cookies={"PHPSESSID": "ok123"},
                    content="",
                    redirect_url="/index.php",
                )
            if url.endswith("/index.php"):
                return FetchedPage(url=url, status_code=200, headers={}, content="<html><body>dashboard</body></html>")
            return FetchedPage(url=url, status_code=200, headers={}, content="home")

        service = SessionService(fetcher=fetch)
        session = service.establish(
            login_url="http://127.0.0.1:4280/login.php",
            username="admin",
            password="secret",
        )
        assert session.established is True
        assert ("PHPSESSID", "ok123") in session.cookies

    def test_loopback_login_page_without_form_is_explicit_negative(self) -> None:
        def fetch(url: str, timeout_s: float = 10.0, **kwargs: Any) -> FetchedPage:
            return FetchedPage(url=url, status_code=200, headers={}, content="<html><body>hi</body></html>")

        service = SessionService(fetcher=fetch)
        session = service.establish(
            login_url="http://127.0.0.1:4280/login.php",
            username="admin",
            password="secret",
        )
        assert session.established is False
        assert "no login form" in session.error

    def test_unreachable_login_page_returns_error_session(self) -> None:
        def fetch(url: str, timeout_s: float = 10.0, **kwargs: Any) -> FetchedPage:
            return FetchedPage(url=url, error="connection refused")

        service = SessionService(fetcher=fetch)
        session = service.establish(
            login_url="http://127.0.0.1:4280/login.php",
            username="admin",
            password="secret",
        )
        assert session.established is False
        assert "unreachable" in session.error

    def test_invalid_login_url_is_rejected(self) -> None:
        service = SessionService(fetcher=_FakeFetcher())
        session = service.establish(login_url="not-a-url", username="admin", password="secret")
        assert session.established is False
        assert "invalid login URL" in session.error

    def test_fetcher_exceptions_never_escape(self) -> None:
        def fetch(url: str, timeout_s: float = 10.0, **kwargs: Any) -> FetchedPage:
            raise OSError("boom")

        service = SessionService(fetcher=fetch)
        session = service.establish(
            login_url="http://127.0.0.1:4280/login.php",
            username="admin",
            password="secret",
        )
        assert session.established is False
        assert session.error


# ---------------------------------------------------------------------------
# HttpPageFetcher — POST / headers / Set-Cookie capture
# ---------------------------------------------------------------------------


class TestHttpPageFetcherExtensions:
    def test_post_captures_set_cookie_and_passes_headers(self) -> None:
        import http.server
        import threading

        received: dict[str, Any] = {}

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                received["method"] = self.command
                received["cookie"] = self.headers.get("Cookie")
                received["origin"] = self.headers.get("Origin")
                self.send_response(302)
                self.send_header("Location", "/index.php")
                self.send_header("Set-Cookie", "PHPSESSID=abc123; Path=/")
                self.send_header("Set-Cookie", "security=low; HttpOnly")
                self.end_headers()

            def log_message(self, *args: Any) -> None:
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            fetcher = HttpPageFetcher()
            page = fetcher.fetch(
                f"http://127.0.0.1:{port}/login.php",
                method="POST",
                data=b"username=admin&password=secret",
                headers={"Origin": f"http://127.0.0.1:{port}"},
                cookies={"PHPSESSID": "sess0"},
            )
        finally:
            server.shutdown()
            thread.join(timeout=5)
        assert received["method"] == "POST"
        assert received["cookie"] == "PHPSESSID=sess0"
        assert received["origin"] == f"http://127.0.0.1:{port}"
        # Both Set-Cookie headers are captured (session cookie + security flag).
        assert page.cookies["PHPSESSID"] == "abc123"
        assert page.cookies["security"] == "low"
        assert page.is_redirect is True
        assert page.redirect_url == "/index.php"


# ---------------------------------------------------------------------------
# header_args — session propagation into tool argv
# ---------------------------------------------------------------------------


class _Ctx:
    def __init__(self, parameters: dict[str, Any]) -> None:
        self.parameters = parameters


class TestHeaderArgs:
    def test_no_session_contributes_nothing(self) -> None:
        assert header_args(_Ctx({})) == []
        assert header_args(_Ctx({"auth": {"username": "admin"}})) == []

    def test_cookies_and_headers_become_flag_pairs(self) -> None:
        args = header_args(
            _Ctx(
                {
                    "cookies": {"PHPSESSID": "abc123", "security": "low"},
                    "headers": {"X-Custom": "yes"},
                }
            )
        )
        assert args == [
            "-H",
            "Cookie: PHPSESSID=abc123; security=low",
            "-H",
            "X-Custom: yes",
        ]


# ---------------------------------------------------------------------------
# Probe header attachment (mission runner + finding service helpers)
# ---------------------------------------------------------------------------


class TestProbeHeaderAttachment:
    def test_probe_headers_merge_into_spec(self) -> None:
        from hunterx.application.vulnerability_finding import _with_probe_headers
        from hunterx.domain.vulnerability_capability.models import ProbeSpec

        probe = ProbeSpec(
            vulnerability_class="sql-injection",
            endpoint="http://127.0.0.1:4280/vulnerabilities/sqli/",
            parameter="id",
            headers=(("Origin", "http://127.0.0.1:4280"),),
        )
        merged = _with_probe_headers(probe, (("Cookie", "PHPSESSID=abc123"),))
        assert merged is not probe
        assert ("Cookie", "PHPSESSID=abc123") in merged.headers
        assert ("Origin", "http://127.0.0.1:4280") in merged.headers

    def test_session_cookie_replaces_existing_cookie(self) -> None:
        from hunterx.application.vulnerability_finding import _with_probe_headers
        from hunterx.domain.vulnerability_capability.models import ProbeSpec

        probe = ProbeSpec(
            vulnerability_class="sql-injection",
            headers=(("Cookie", "old=1"),),
        )
        merged = _with_probe_headers(probe, (("Cookie", "PHPSESSID=abc123"),))
        assert ("Cookie", "PHPSESSID=abc123") in merged.headers
        assert ("Cookie", "old=1") not in merged.headers


# ---------------------------------------------------------------------------
# Mission-runner auth wiring (establish-before-discovery, hygiene, negatives)
# ---------------------------------------------------------------------------


class TestMissionAuthWiring:
    def test_incomplete_auth_config_is_skipped_without_error(self) -> None:
        from hunterx.application.mission_execution import MissionExecutionService

        service = MissionExecutionService.__new__(MissionExecutionService)
        service._session = None
        service._auth_attempted = False
        service._auth_outcome = None
        service._publish = lambda _name, _payload: None  # type: ignore[method-assign]
        events: list[dict[str, Any]] = []
        service._publish = lambda name, payload: events.append({"name": name, **payload})  # type: ignore[method-assign]
        service._orchestration = _StubOrchestration()

        service._establish_auth_session("m1", {"auth": {"login_url": "http://127.0.0.1:4280/login.php"}})
        assert service._auth_outcome == {"status": "skipped", "reason": "incomplete auth configuration"}
        assert events[-1]["name"] == "auth.session.skipped"

    def test_non_loopback_login_target_is_refused(self) -> None:
        from hunterx.application.mission_execution import MissionExecutionService

        service = MissionExecutionService.__new__(MissionExecutionService)
        service._session = None
        service._auth_attempted = False
        service._auth_outcome = None
        events: list[dict[str, Any]] = []
        service._publish = lambda name, payload: events.append({"name": name, **payload})  # type: ignore[method-assign]
        service._orchestration = _StubOrchestration()

        service._establish_auth_session(
            "m1",
            {
                "auth": {
                    "login_url": "https://example.com/login",
                    "username": "admin",
                    "password": "secret",
                }
            },
        )
        assert service._auth_outcome["status"] == "refused"
        assert events[-1]["name"] == "auth.session.refused"

    def test_successful_establishment_publishes_masked_event(self) -> None:
        from hunterx.application.mission_execution import MissionExecutionService

        service = MissionExecutionService.__new__(MissionExecutionService)
        service._session = None
        service._auth_attempted = False
        service._auth_outcome = None
        events: list[dict[str, Any]] = []
        service._publish = lambda name, payload: events.append({"name": name, **payload})  # type: ignore[method-assign]
        service._orchestration = _StubOrchestration()
        service._establish_auth_session = None  # type: ignore[assignment]  # replaced below

        from hunterx.application.session import SessionService

        original = SessionService.establish

        def fake_establish(self_: Any, **kwargs: Any) -> AuthenticatedSession:
            return AuthenticatedSession(
                origin="http://127.0.0.1:4280",
                login_url=kwargs["login_url"],
                cookies=(("PHPSESSID", "abc123"),),
                username=kwargs["username"],
            )

        SessionService.establish = fake_establish  # type: ignore[method-assign]
        try:
            MissionExecutionService._establish_auth_session(service, "m1", {"auth": {"login_url": "http://127.0.0.1:4280/login.php", "username": "admin", "password": "secret"}})
        finally:
            SessionService.establish = original  # type: ignore[method-assign]
        assert service._session is not None and service._session.established
        event = events[-1]
        assert event["name"] == "auth.session.established"
        assert "abc123" not in str(event)
        assert "secret" not in str(event)
        assert event["scope"] == "authenticated"

    def test_failed_establishment_records_honest_negative(self) -> None:
        from hunterx.application.mission_execution import MissionExecutionService

        service = MissionExecutionService.__new__(MissionExecutionService)
        service._session = None
        service._auth_attempted = False
        service._auth_outcome = None
        events: list[dict[str, Any]] = []
        service._publish = lambda name, payload: events.append({"name": name, **payload})  # type: ignore[method-assign]
        service._orchestration = _StubOrchestration()

        from hunterx.application.session import SessionService

        original = SessionService.establish

        def fake_fail(self_: Any, **kwargs: Any) -> AuthenticatedSession:
            return AuthenticatedSession(error="authentication failed")

        SessionService.establish = fake_fail  # type: ignore[method-assign]
        try:
            MissionExecutionService._establish_auth_session(service, "m1", {"auth": {"login_url": "http://127.0.0.1:4280/login.php", "username": "admin", "password": "wrong"}})
        finally:
            SessionService.establish = original  # type: ignore[method-assign]
        assert service._session is None
        assert service._auth_outcome["status"] == "failed"
        assert events[-1]["name"] == "auth.session.failed"

    def test_context_builder_strips_auth_and_injects_session_surface(self) -> None:
        from hunterx.application.mission_execution import MissionExecutionService
        from hunterx.domain.auth.session import AuthenticatedSession

        service = MissionExecutionService.__new__(MissionExecutionService)
        service._session = AuthenticatedSession(
            origin="http://127.0.0.1:4280",
            cookies=(("PHPSESSID", "abc123"),),
        )
        service._declared_targets = lambda _tool: ()  # type: ignore[method-assign]
        service._permissions_for = lambda _tool: ("network",)  # type: ignore[method-assign]
        context = MissionExecutionService._build_context(
            service, "m1", "katana", "http://127.0.0.1:4280", {"auth": {"username": "admin", "password": "secret"}, "depth": 3}
        )
        assert "auth" not in context.parameters
        assert context.parameters["cookies"] == {"PHPSESSID": "abc123"}
        assert "secret" not in str(context.parameters)


class _StubOrchestration:
    def ingest_result(self, *args: Any, **kwargs: Any) -> None:
        return None

    def get(self, *args: Any, **kwargs: Any) -> Any:
        raise AssertionError("unexpected get()")


# ---------------------------------------------------------------------------
# No DVWA hardcoding guard
# ---------------------------------------------------------------------------


class TestNoHardcoding:
    def test_source_has_no_dvwa_specific_paths_or_names(self) -> None:
        """No DVWA-specific path, parameter or product name in the source.

        The authenticated-discovery mechanism must be generic: nothing in the
        codebase may hardcode DVWA URLs (``/vulnerabilities/sqli/`` etc.) or
        the product name.
        """
        offenders: list[str] = []
        for path in SRC.rglob("*.py"):
            for line_number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
                lowered = line.lower()
                if "vulnerabilities/sqli" in lowered or "vulnerabilities/xss" in lowered:
                    offenders.append(f"{path}:{line_number}")
                if "dvwa" in lowered:
                    offenders.append(f"{path}:{line_number}")
        assert offenders == [], f"DVWA-specific artifacts found in source: {offenders}"

    def test_env_credentials_are_the_only_input_mechanism(self) -> None:
        """The CLI reads credentials exclusively from HUNTERX_AUTH_* env vars."""
        text = (SRC / "hunterx" / "cli" / "commands.py").read_text(encoding="utf-8")
        assert "HUNTERX_AUTH_LOGIN_URL" in text
        assert "HUNTERX_AUTH_USERNAME" in text
        assert "HUNTERX_AUTH_PASSWORD" in text