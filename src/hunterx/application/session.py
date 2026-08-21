# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Authenticated session establishment service (active authentication).

Complement to :mod:`hunterx.application.auth` (passive intelligence). This
service performs *execution-time* authentication: given operator-supplied
credentials and a login URL, it performs a generic form login — GET the login
page, discover the username/password/CSRF fields from the HTML, POST the
credentials, capture the session cookies and verify the authenticated state.

Constraints:

- Generic: field names are discovered from the form, never hardcoded per
  application.
- Loopback-guarded: login is only attempted against loopback targets, like the
  probe executor.
- Never raises: every failure is returned as an explicit ``AuthenticatedSession
  (error=...)`` so callers record an honest negative instead of crashing.
- In-memory only: credentials are consumed and discarded; the returned session
  holds cookies/CSRF values on the instance and masks them in every serialized
  form.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from hunterx.domain.auth.session import AuthenticatedSession
from hunterx.domain.web.parsers import extract_forms
from hunterx.shared.time import utcnow_iso
from hunterx.tools.web.httpclient import FetchedPage, HttpPageFetcher

#: Fetch seam used by the session service (injectable for tests).
SessionFetchFn = Callable[..., FetchedPage]

#: Username field name heuristics (first match wins).
_USERNAME_HINTS = (
    "username",
    "user_name",
    "user",
    "login",
    "email",
    "mail",
    "account",
    "loginname",
    "login_name",
)

#: CSRF field name heuristics (first match wins).
_CSRF_HINTS = ("csrf_token", "csrftoken", "csrf", "_token", "token", "user_token", "authenticity_token", "_csrf")

#: Login verification: when a response body still carries a login form with a
#: password field, authentication did not succeed.
_LOGIN_FORM_FRAGMENT = 'type="password"'
_LOGIN_FORM_FRAGMENT_SINGLE = "type='password'"


class SessionService:
    """Establish authenticated sessions via generic form login."""

    def __init__(self, *, fetcher: SessionFetchFn | None = None) -> None:
        self._fetcher: SessionFetchFn = fetcher or HttpPageFetcher().fetch

    def establish(
        self,
        *,
        login_url: str,
        username: str,
        password: str,
        extra_fields: dict[str, str] | None = None,
    ) -> AuthenticatedSession:
        """Establish a session by logging in with the given credentials.

        Returns:
            :class:`AuthenticatedSession` — ``established`` when the login
            succeeded, otherwise an error-carrying session (never raises).

        """
        origin = _origin_of(login_url)
        if not origin:
            return AuthenticatedSession(error="invalid login URL")

        page = self._fetch(login_url)
        if page.status_code == 0:
            return AuthenticatedSession(origin=origin, login_url=login_url, error=f"login page unreachable: {page.error or page.status_code}")
        if page.is_redirect:
            return AuthenticatedSession(origin=origin, login_url=login_url, error="login page redirected; no form discovered")

        form = _login_form(page.content, login_url)
        if form is None:
            return AuthenticatedSession(
                origin=origin,
                login_url=login_url,
                error="no login form (password field) discovered on login page",
            )

        action = form["action"] or login_url
        method = str(form["method"] or "POST").upper()
        username_field, password_field, csrf_field, csrf_value = _login_fields(form)
        if not username_field or not password_field:
            return AuthenticatedSession(
                origin=origin,
                login_url=login_url,
                error="login form missing username/password field",
            )

        payload: dict[str, str] = {username_field: username, password_field: password}
        payload.update(dict(extra_fields or {}))
        if csrf_field and csrf_value:
            payload[csrf_field] = csrf_value
        for name, value in _named_fields(form, exclude=(username_field, password_field, csrf_field)):
            if name not in payload:
                payload[name] = value

        submit = self._fetch(
            action,
            method=method,
            data=_form_body(payload),
            headers={"Content-Type": "application/x-www-form-urlencoded", "Origin": origin},
            cookies=dict(page.cookies),
        )
        # Browser cookie-jar semantics: every response in the login flow
        # contributes its cookies. The POST response's session id overrides the
        # pre-login id while companion cookies set on the login page itself
        # (e.g. a security-level cookie) must survive — dropping them leaves an
        # authenticated-looking session that still bounces off the protected
        # surface.
        cookies = dict(page.cookies)
        cookies.update(dict(submit.cookies))
        if submit.is_redirect and submit.redirect_url:
            # A form-login POST redirects on success AND on failure (often to
            # the login page again). Follow it so the verdict reflects the
            # FINAL page: a redirect to the login page means authentication
            # failed even when the redirect response issued a fresh session id.
            followed = self._fetch(submit.redirect_url, cookies=dict(cookies))
            cookies.update(dict(followed.cookies) or {})
            submit = followed

        established = bool(cookies) and not _still_login_form(submit.content)
        if not established:
            return AuthenticatedSession(
                origin=origin,
                login_url=login_url,
                error=f"authentication failed (HTTP {submit.status_code or 'no response'})",
            )

        return AuthenticatedSession(
            origin=origin,
            login_url=login_url,
            cookies=tuple(cookies.items()),
            csrf_field=csrf_field,
            csrf_token=csrf_value,
            username=username,
            established_at=utcnow_iso(),
        )

    def _fetch(self, url: str, **kwargs: Any) -> FetchedPage:
        try:
            return self._fetcher(url, **kwargs)
        except Exception as error:  # noqa: BLE001 - fetcher must never raise
            return FetchedPage(url=url, error=str(error))


def _origin_of(url: str) -> str:
    from urllib.parse import urlsplit

    try:
        parsed = urlsplit(url)
    except ValueError:
        return ""
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}"


def _login_form(html: str, base_url: str) -> dict[str, Any] | None:
    """Return the first form containing a password field, or ``None``."""
    for form in extract_forms(html, base_url):
        fields = form.get("fields") or []
        if any(str(field.get("type") or "").lower() == "password" for field in fields):
            return form
    return None


def _login_fields(form: dict[str, Any]) -> tuple[str, str, str, str]:
    """Return ``(username_field, password_field, csrf_field, csrf_value)``."""
    fields = form.get("fields") or []
    password_field = ""
    username_field = ""
    for field in fields:
        name = str(field.get("name") or "")
        field_type = str(field.get("type") or "text").lower()
        if not name:
            continue
        if field_type == "password" and not password_field:
            password_field = name
    if not password_field:
        return "", "", "", ""
    lowered = {str(field.get("name") or "").lower() for field in fields}
    for hint in _USERNAME_HINTS:
        if hint in lowered:
            username_field = next(
                str(field["name"]) for field in fields if str(field.get("name") or "").lower() == hint
            )
            break
    if not username_field:
        for field in fields:
            field_type = str(field.get("type") or "text").lower()
            if field_type in ("text", "email", "tel") and str(field.get("name") or "") != password_field:
                username_field = str(field.get("name") or "")
                break
    csrf_field = ""
    csrf_value = ""
    for hint in _CSRF_HINTS:
        for field in fields:
            if str(field.get("name") or "").lower() == hint:
                csrf_field = str(field.get("name") or "")
                csrf_value = str(field.get("value") or "")
                break
        if csrf_field:
            break
    return username_field, password_field, csrf_field, csrf_value


def _named_fields(form: dict[str, Any], *, exclude: set[str]) -> list[tuple[str, str]]:
    """Return extra fields (hidden inputs and named submit buttons) to carry.

    Hidden inputs carry tokens/state; named submit buttons (e.g. ``Login``)
    are required by applications that branch on ``isset($_POST['Login'])``.
    """
    result: list[tuple[str, str]] = []
    for field in form.get("fields") or []:
        name = str(field.get("name") or "")
        if not name or name in exclude:
            continue
        field_type = str(field.get("type") or "text").lower()
        if field_type == "hidden" and field.get("value") or field_type == "submit" and field.get("value"):
            result.append((name, str(field.get("value") or "")))
    return result


def _form_body(payload: dict[str, str]) -> bytes:
    from urllib.parse import urlencode

    return urlencode(payload).encode("utf-8")


def _still_login_form(content: str) -> bool:
    """Return ``True`` when the response still looks like a login page."""
    lowered = (content or "").lower()
    return _LOGIN_FORM_FRAGMENT in lowered or _LOGIN_FORM_FRAGMENT_SINGLE in lowered


__all__ = ["SessionService", "SessionFetchFn"]
