# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""In-process authentication intelligence analyzer adapter.

Runs the domain :class:`~hunterx.domain.auth.analyzer.AuthAnalyzer` over an
already-acquired :class:`AuthInput` bundle and returns the canonical
observations. No network I/O, no authentication attempts, no token validation;
sensitive values are masked inside the analyzer before they ever reach a
record.
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.auth.analyzer import AuthAnalyzer
from hunterx.domain.auth.models import AuthInput
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.auth.base import AuthToolAdapter


class AuthAnalyzerAdapter(AuthToolAdapter):
    """Run the domain authentication analyzer over one input bundle."""

    descriptor = ToolDescriptor(
        name="auth-analysis",
        version="1.0.0",
        description=(
            "In-process authentication, session & identity intelligence: "
            "surfaces, endpoints, flows, identity providers, OAuth/OIDC/SAML, "
            "JWT, cookies, token storage, CSRF, CORS, MFA, WebAuthn, "
            "roles/scopes/permissions and tenancy from static material. "
            "Intelligence only; never authenticates."
        ),
        entrypoint="hunterx.tools.auth.analyzer:AuthAnalyzerAdapter",
        targets=("host", "domain", "url", "http-snapshot", "script"),
        capabilities=("authentication-intelligence", "identity-intelligence", "session-intelligence"),
        permissions=("none",),
        parameters={
            "auth_input": {"type": "object", "description": "Static input bundle (HTTP snapshot, scripts, schemes)."},
            "url": {"type": "string", "description": "Absolute URL of the analysed resource."},
            "status_code": {"type": "integer", "description": "Observed HTTP status."},
            "headers": {"type": "object", "description": "Observed response headers."},
            "html": {"type": "string", "description": "HTML body text (bounded)."},
            "cookies": {"type": "array", "description": "Parsed cookie attribute tables."},
            "scripts": {"type": "array", "description": "Script assets as (url, content) pairs."},
            "api_schemes": {"type": "array", "description": "API security-scheme records."},
            "documents": {"type": "array", "description": "Parsed OIDC/SAML documents."},
            "observed_urls": {"type": "array", "description": "Other observed URLs on the target."},
            "tidb_hints": {"type": "array", "description": "Pre-existing TIDB intelligence records."},
        },
    )

    def analyze(self, bundle: AuthInput) -> list[Any]:
        """Analyze ``bundle`` and return every canonical observation."""
        analysis = AuthAnalyzer().analyze(bundle)
        return analysis.all_observations()
