# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Authenticated session model for active (execution-time) authentication.

This is the *execution* counterpart of the passive authentication intelligence
models in :mod:`hunterx.domain.auth.models`. It represents a real, established
HTTP session (cookies, headers, CSRF token) that the mission uses to reach an
application's authenticated attack surface.

Security boundary: the session object is strictly in-memory and short-lived.
Raw cookie values and CSRF tokens live only on the instance; every serialized
form (:meth:`AuthenticatedSession.to_dict`, :meth:`cookie_header`) is masked or
value-free. Sessions are never persisted to the mission store, and credentials
never enter this model at all (they are consumed by the session service and
discarded).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunterx.shared.masking import mask_value
from hunterx.shared.time import utcnow_iso


@dataclass(frozen=True, slots=True)
class AuthenticatedSession:
    """An established authenticated HTTP session for one origin.

    Attributes:
        origin: canonical ``scheme://host[:port]`` the session belongs to.
        login_url: URL the session was established through.
        cookies: ``(name, value)`` session cookies (in-memory only).
        headers: extra ``(name, value)`` request headers (e.g. an
            authorization header) carried with every request.
        csrf_field: name of the CSRF form field, when the login form had one.
        csrf_token: current CSRF token value (in-memory only).
        username: authenticated identity (kept for provenance, masked in
            serialized output).
        established_at: UTC ISO-8601 establishment timestamp.
        expires_at: UTC ISO-8601 expiry timestamp (``""`` = session cookie).
        error: establishment failure reason (only when the session is not
            established).

    """

    origin: str = ""
    login_url: str = ""
    cookies: tuple[tuple[str, str], ...] = ()
    headers: tuple[tuple[str, str], ...] = ()
    csrf_field: str = ""
    csrf_token: str = ""
    username: str = ""
    established_at: str = field(default_factory=utcnow_iso)
    expires_at: str = ""
    error: str = ""

    @property
    def established(self) -> bool:
        """Return ``True`` when the session carries an authenticated identity."""
        return bool(self.origin) and not self.error and bool(self.cookies or self.headers)

    def cookie_header(self) -> str:
        """Return the ``Cookie`` header value for this session (values included).

        This is the one value-bearing surface of the session and is only ever
        attached to outbound tool/probe requests, never to observations, events,
        reports or logs.
        """
        return "; ".join(f"{name}={value}" for name, value in self.cookies)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe, fully masked mapping.

        Cookie names and header names are retained; cookie values, header
        values, the CSRF token and the username are masked.
        """
        return {
            "origin": self.origin,
            "login_url": self.login_url,
            "cookies": [
                {"name": name, "value": mask_value(value, reveal_head=1, reveal_tail=0)}
                for name, value in self.cookies
            ],
            "headers": [
                {"name": name, "value": mask_value(value, reveal_head=2, reveal_tail=0)}
                for name, value in self.headers
            ],
            "csrf_field": self.csrf_field,
            "csrf_token": mask_value(self.csrf_token, reveal_head=0, reveal_tail=0)
            if self.csrf_token
            else "",
            "username": mask_value(self.username, reveal_head=1, reveal_tail=0),
            "established_at": self.established_at,
            "expires_at": self.expires_at,
            "error": self.error,
            "established": self.established,
        }

    def scope_label(self) -> str:
        """Return a short human label for the session's access scope."""
        return "authenticated" if self.established else "anonymous"


def mask_session(session: AuthenticatedSession | None) -> dict[str, Any] | None:
    """Return a masked mapping for a session (``None`` when no session)."""
    return session.to_dict() if session is not None else None


__all__ = ["AuthenticatedSession", "mask_session"]