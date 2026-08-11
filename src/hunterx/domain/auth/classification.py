# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Authentication surface classification.

Deterministic classification of observed authentication material into canonical
surface kinds, endpoint kinds and public-vs-authenticated access states. The
classifier never infers state without evidence: every classification is a pure
function of the observed indicators and is explainable through them.
"""

from __future__ import annotations

import re

from hunterx.domain.auth.models import (
    AuthAccessState,
    AuthEndpointKind,
    AuthEndpointObservation,
    AuthSurfaceKind,
    AuthSurfaceObservation,
)

#: Surface-kind signal table: token -> canonical surface kind.
_SURFACE_SIGNALS: list[tuple[str, AuthSurfaceKind]] = [
    ("reset-password", AuthSurfaceKind.PASSWORD_RESET),
    ("forgot-password", AuthSurfaceKind.PASSWORD_RESET),
    ("forgotpassword", AuthSurfaceKind.PASSWORD_RESET),
    ("password/reset", AuthSurfaceKind.PASSWORD_RESET),
    ("change-password", AuthSurfaceKind.PASSWORD_CHANGE),
    ("password/change", AuthSurfaceKind.PASSWORD_CHANGE),
    ("password-recovery", AuthSurfaceKind.PASSWORD_RECOVERY),
    ("verify-email", AuthSurfaceKind.EMAIL_VERIFICATION),
    ("email/verify", AuthSurfaceKind.EMAIL_VERIFICATION),
    ("enroll-mfa", AuthSurfaceKind.MFA_ENROLLMENT),
    ("mfa/recovery", AuthSurfaceKind.MFA_RECOVERY),
    ("account/recovery", AuthSurfaceKind.ACCOUNT_RECOVERY),
    ("account/verify", AuthSurfaceKind.ACCOUNT_VERIFICATION),
    ("session/refresh", AuthSurfaceKind.SESSION_REFRESH),
    ("token/refresh", AuthSurfaceKind.TOKEN_REFRESH),
    ("oauth/callback", AuthSurfaceKind.AUTHORIZATION_CALLBACK),
    ("auth-callback", AuthSurfaceKind.AUTH_CALLBACK),
    ("sso", AuthSurfaceKind.SSO_ENTRYPOINT),
    ("identity-provider", AuthSurfaceKind.IDENTITY_PROVIDER),
    ("signup", AuthSurfaceKind.REGISTRATION),
    ("register", AuthSurfaceKind.REGISTRATION),
    ("logout", AuthSurfaceKind.LOGOUT),
    ("signout", AuthSurfaceKind.LOGOUT),
    ("login", AuthSurfaceKind.LOGIN),
    ("signin", AuthSurfaceKind.LOGIN),
    ("logon", AuthSurfaceKind.LOGIN),
]


class AuthClassifier:
    """Classify surfaces, endpoints and access states deterministically."""

    def classify_surface(self, observation: AuthSurfaceObservation) -> AuthSurfaceObservation:
        """Refine a surface observation's kind from its URL/indicators."""
        if observation.surface_kind is not AuthSurfaceKind.UNKNOWN:
            return observation
        url = (observation.url or "").lower()
        for token, kind in _SURFACE_SIGNALS:
            if token in url:
                from dataclasses import replace

                return replace(observation, surface_kind=kind)
        indicators = " ".join(observation.indicators).lower()
        if "password input" in indicators:
            return observation
        return observation

    def classify_endpoint(self, observation: AuthEndpointObservation) -> AuthEndpointObservation:
        """Return the endpoint observation with a canonical kind applied."""
        if observation.kind is not AuthEndpointKind.UNKNOWN:
            return observation
        from dataclasses import replace

        lowered = (observation.url or "").lower()
        if re.search(r"/login|/signin|/logon", lowered):
            return replace(observation, kind=AuthEndpointKind.LOGIN)
        if re.search(r"/logout|/signout", lowered):
            return replace(observation, kind=AuthEndpointKind.LOGOUT)
        if re.search(r"/signup|/register", lowered):
            return replace(observation, kind=AuthEndpointKind.REGISTRATION)
        return observation

    def classify_access(
        self,
        *,
        url: str = "",
        status_code: int = 0,
        has_password_field: bool = False,
        login_redirect: str = "",
        www_authenticate: bool = False,
    ) -> AuthAccessState:
        """Classify a resource as public vs authentication-required."""
        if status_code in (401, 403) or www_authenticate:
            return AuthAccessState.AUTH_REQUIRED
        if login_redirect and re.search(r"/login|/signin|/auth", login_redirect.lower()):
            return AuthAccessState.AUTH_REQUIRED
        if has_password_field or _login_path(url):
            return AuthAccessState.PUBLIC
        return AuthAccessState.UNKNOWN


def _login_path(url: str) -> bool:
    lowered = url.lower()
    return bool(re.search(r"/login(?:/|$|\?)|/signin(?:/|$|\?)|/auth(?:/|$|\?)", lowered))
