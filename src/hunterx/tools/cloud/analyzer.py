# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Cloud analysis tool adapter.

Registers the ``cloud-analysis`` tool: an in-process adapter that runs the
:class:`~hunterx.domain.cloud.analyzer.CloudAnalyzer` over a static-material
bundle. It never contacts cloud resources, never authenticates and never
retrieves secrets.
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.cloud import CloudAnalyzer, CloudInput
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.cloud.base import CloudToolAdapter


class CloudAnalyzerAdapter(CloudToolAdapter):
    """The ``cloud-analysis`` adapter exposing the in-process analyzer."""

    descriptor = ToolDescriptor(
        name="cloud-analysis",
        version="1.0.0",
        description=(
            "In-process cloud & SaaS attack-surface intelligence: cloud "
            "providers, accounts, regions, resources, services, endpoints "
            "(control/data/identity plane), environments, identity & IAM "
            "indicators, SaaS platforms & integrations, webhooks, third-party "
            "dependencies, storage/compute/container/Kubernetes/database/CI-CD "
            "resource indicators and secret-management indicators from static "
            "material. Intelligence & discovery only; never authenticates, "
            "never accesses cloud resources and never retrieves secrets."
        ),
        entrypoint="hunterx.tools.cloud.analyzer:CloudAnalyzerAdapter",
        targets=("host", "domain", "url", "http-snapshot", "script", "document"),
        capabilities=(
            "cloud-intelligence",
            "saas-intelligence",
            "cloud-attack-surface-intelligence",
        ),
        permissions=("none",),
        parameters={
            "cloud_input": {
                "type": "object",
                "description": "Static cloud intelligence input bundle (DNS records, TLS, headers, scripts, docs).",
            },
            "domain": {"type": "string", "description": "Owning domain of the target."},
            "records": {"type": "array", "description": "DNS records with cname_target/value."},
            "certificates": {"type": "array", "description": "TLS certificate metadata."},
            "headers": {"type": "object", "description": "HTTP response headers."},
            "technologies": {"type": "array", "description": "Technology observations."},
            "observed_urls": {"type": "array", "description": "Observed URLs."},
            "documents": {"type": "array", "description": "Infrastructure documentation fragments."},
        },
    )

    def analyze(self, bundle: CloudInput) -> list[Any]:
        """Analyze a static-material bundle into typed cloud observations."""
        return CloudAnalyzer().analyze(bundle).all_observations()
