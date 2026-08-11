# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""In-process authorization intelligence analyzer adapter.

Runs the domain :class:`~hunterx.domain.authorization.analyzer.AuthorizationAnalyzer`
over an already-acquired :class:`AuthorizationInput` bundle and returns the
canonical observations. No network I/O, no authorization testing, no identifier
substitution; sensitive values are masked inside the analyzer before they ever
reach a record.
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.authorization.analyzer import AuthorizationAnalyzer
from hunterx.domain.authorization.models import AuthorizationInput
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.authorization.base import AuthorizationToolAdapter


class AuthorizationAnalyzerAdapter(AuthorizationToolAdapter):
    """Run the domain authorization analyzer over one input bundle."""

    descriptor = ToolDescriptor(
        name="authorization-analysis",
        version="1.0.0",
        description=(
            "In-process authorization & access-control intelligence: subjects, "
            "roles, groups, permissions, scopes, claims, policies, resources, "
            "actions, ownership, tenancy, admin surfaces, function/object/field-"
            "level access control, frontend/backend enforcement, API/GraphQL/"
            "WebSocket/service authorization and decision indicators from "
            "static material. Intelligence only; never tests authorization."
        ),
        entrypoint="hunterx.tools.authorization.analyzer:AuthorizationAnalyzerAdapter",
        targets=("host", "domain", "url", "http-snapshot", "script"),
        capabilities=(
            "authorization-intelligence",
            "access-control-intelligence",
            "permission-intelligence",
        ),
        permissions=("none",),
        parameters={
            "authorization_input": {"type": "object", "description": "Static input bundle (HTTP snapshot, scripts, operations)."},
            "url": {"type": "string", "description": "Absolute URL of the analysed resource."},
            "status_code": {"type": "integer", "description": "Observed HTTP status."},
            "headers": {"type": "object", "description": "Observed response headers."},
            "html": {"type": "string", "description": "HTML body text (bounded)."},
            "scripts": {"type": "array", "description": "Script assets as (url, content) pairs."},
            "api_schemes": {"type": "array", "description": "API security-scheme records."},
            "api_operations": {"type": "array", "description": "API operation records with authorization requirements."},
            "graphql": {"type": "array", "description": "Parsed GraphQL authorization metadata."},
            "websockets": {"type": "array", "description": "Observed WebSocket endpoint records."},
            "documents": {"type": "array", "description": "Parsed policy/document records."},
            "observed_urls": {"type": "array", "description": "Other observed URLs on the target."},
            "tidb_hints": {"type": "array", "description": "Pre-existing TIDB intelligence records."},
        },
    )

    def analyze(self, bundle: AuthorizationInput) -> list[Any]:
        """Analyze ``bundle`` and return every canonical observation."""
        analysis = AuthorizationAnalyzer().analyze(bundle)
        return analysis.all_observations()
