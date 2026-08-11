# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Cloud intelligence classification.

Deterministic classification helpers for cloud subjects: service categories,
endpoint plane classification (control/data/identity/management/developer),
exposure classification, environment classification and SaaS integration types.
Every classifier is a pure function of observable evidence; no randomness and no
inference from branding alone.
"""

from __future__ import annotations

import re

from hunterx.domain.cloud.models import (
    CloudPlane,
    CloudProviderKind,
    EnvironmentKind,
    ExposureIndicatorKind,
    ServiceCategory,
)

#: Environment signals evaluated in deterministic priority order. A subject is
#: classified by the strongest signal it matches; ``("production", ...)`` is
#: never derived from a single weak naming indicator.
_ENVIRONMENT_SIGNALS: list[tuple[str, tuple[str, ...]]] = [
    ("production", ("production", "prod", "live", "prd")),
    ("staging", ("staging", "stg", "staging-", "-staging")),
    ("development", ("development", "dev", "-dev", "develop", "localhost")),
    ("testing", ("testing", "test", "-test", "qa")),
    ("qa", ("qa-", "-qa")),
    ("sandbox", ("sandbox", "sandbox-")),
    ("preview", ("preview", "preview-", "-preview", "pr-")),
    ("dr", ("dr", "disaster-recovery", "-dr")),
]

_ENVIRONMENT_PRIORITY: dict[str, int] = {
    "production": 0,
    "staging": 1,
    "development": 2,
    "testing": 3,
    "qa": 4,
    "sandbox": 5,
    "preview": 6,
    "dr": 7,
}

#: Service names whose families are unambiguous across providers.
_SERVICE_CATEGORY: dict[str, str] = {
    # compute / serverless
    "ec2": ServiceCategory.COMPUTE.value,
    "compute-engine": ServiceCategory.COMPUTE.value,
    "droplets": ServiceCategory.COMPUTE.value,
    "app-service": ServiceCategory.COMPUTE.value,
    "app-engine": ServiceCategory.COMPUTE.value,
    "elasticbeanstalk": ServiceCategory.COMPUTE.value,
    "lambda": ServiceCategory.SERVERLESS.value,
    "cloud-functions": ServiceCategory.SERVERLESS.value,
    "azure-functions": ServiceCategory.SERVERLESS.value,
    "cloud-run": ServiceCategory.SERVERLESS.value,
    "workers": ServiceCategory.SERVERLESS.value,
    "edge-functions": ServiceCategory.SERVERLESS.value,
    "vercel": ServiceCategory.SERVERLESS.value,
    # storage
    "s3": ServiceCategory.STORAGE.value,
    "cloud-storage": ServiceCategory.STORAGE.value,
    "blob-storage": ServiceCategory.STORAGE.value,
    "file-storage": ServiceCategory.STORAGE.value,
    "spaces": ServiceCategory.STORAGE.value,
    "pages": ServiceCategory.STORAGE.value,
    "object-storage": ServiceCategory.STORAGE.value,
    "netlify": ServiceCategory.STORAGE.value,
    # database
    "rds": ServiceCategory.DATABASE.value,
    "dynamodb": ServiceCategory.DATABASE.value,
    "elasticache": ServiceCategory.DATABASE.value,
    "aurora": ServiceCategory.DATABASE.value,
    "cosmos-db": ServiceCategory.DATABASE.value,
    "azure-sql": ServiceCategory.DATABASE.value,
    "cloud-sql": ServiceCategory.DATABASE.value,
    "firestore": ServiceCategory.DATABASE.value,
    "bigquery": ServiceCategory.DATABASE.value,
    "supabase": ServiceCategory.DATABASE.value,
    # container / kubernetes
    "ecs": ServiceCategory.CONTAINER.value,
    "ecr": ServiceCategory.CONTAINER.value,
    "container-registry": ServiceCategory.CONTAINER.value,
    "artifact-registry": ServiceCategory.CONTAINER.value,
    "docker-hub": ServiceCategory.CONTAINER.value,
    "docker-registry": ServiceCategory.CONTAINER.value,
    "eks": ServiceCategory.KUBERNETES.value,
    "aks": ServiceCategory.KUBERNETES.value,
    "gke": ServiceCategory.KUBERNETES.value,
    "kubernetes": ServiceCategory.KUBERNETES.value,
    "kube-apiserver": ServiceCategory.KUBERNETES.value,
    # networking / edge
    "cloudfront": ServiceCategory.NETWORKING.value,
    "cdn": ServiceCategory.NETWORKING.value,
    "api-gateway": ServiceCategory.NETWORKING.value,
    "api-management": ServiceCategory.NETWORKING.value,
    "load-balancing": ServiceCategory.NETWORKING.value,
    "elastic-load-balancing": ServiceCategory.NETWORKING.value,
    "elb": ServiceCategory.NETWORKING.value,
    "application-gateway": ServiceCategory.NETWORKING.value,
    "front-door": ServiceCategory.NETWORKING.value,
    "traffic-manager": ServiceCategory.NETWORKING.value,
    "fastly": ServiceCategory.NETWORKING.value,
    "akamai": ServiceCategory.NETWORKING.value,
    "cloudflare": ServiceCategory.NETWORKING.value,
    # identity
    "cognito": ServiceCategory.IDENTITY.value,
    "entra": ServiceCategory.IDENTITY.value,
    "iam": ServiceCategory.IDENTITY.value,
    "cloud-identity": ServiceCategory.IDENTITY.value,
    "identity-platform": ServiceCategory.IDENTITY.value,
    # monitoring / logging
    "cloudwatch": ServiceCategory.MONITORING.value,
    "monitor": ServiceCategory.MONITORING.value,
    "cloud-monitoring": ServiceCategory.MONITORING.value,
    "datadog": ServiceCategory.MONITORING.value,
    "sentry": ServiceCategory.MONITORING.value,
    "pagerduty": ServiceCategory.MONITORING.value,
    # messaging
    "sqs": ServiceCategory.MESSAGING.value,
    "sns": ServiceCategory.MESSAGING.value,
    "eventbridge": ServiceCategory.MESSAGING.value,
    "pub/sub": ServiceCategory.MESSAGING.value,
    "pubsub": ServiceCategory.MESSAGING.value,
    "service-bus": ServiceCategory.MESSAGING.value,
    "event-grid": ServiceCategory.MESSAGING.value,
    # ci/cd
    "codebuild": ServiceCategory.CI_CD.value,
    "codepipeline": ServiceCategory.CI_CD.value,
    "cloud-build": ServiceCategory.CI_CD.value,
    "devops": ServiceCategory.CI_CD.value,
    "github": ServiceCategory.CI_CD.value,
    "gitlab": ServiceCategory.CI_CD.value,
    "jenkins": ServiceCategory.CI_CD.value,
    "circleci": ServiceCategory.CI_CD.value,
    # secret management
    "secrets-manager": ServiceCategory.SECRET.value,
    "key-vault": ServiceCategory.SECRET.value,
    "secret-manager": ServiceCategory.SECRET.value,
    # security
    "waf": ServiceCategory.SECURITY.value,
    "shield": ServiceCategory.SECURITY.value,
}

_PLANE_SIGNALS: dict[str, str] = {
    "console.": CloudPlane.MANAGEMENT.value,
    "management.": CloudPlane.MANAGEMENT.value,
    "control.": CloudPlane.CONTROL.value,
    "admin.": CloudPlane.MANAGEMENT.value,
    "api.": CloudPlane.DATA.value,
    "identity.": CloudPlane.IDENTITY.value,
    "iam.": CloudPlane.IDENTITY.value,
    "sts.": CloudPlane.IDENTITY.value,
    "cognito": CloudPlane.IDENTITY.value,
    "login.": CloudPlane.IDENTITY.value,
    "auth.": CloudPlane.IDENTITY.value,
    "dev.": CloudPlane.DEVELOPER.value,
    "scm.": CloudPlane.DEVELOPER.value,
    "docs.": CloudPlane.DEVELOPER.value,
    "developer.": CloudPlane.DEVELOPER.value,
}

#: Well-known management/control endpoints classified without hostname hints.
_MANAGEMENT_ENDPOINTS: tuple[tuple[str, str], ...] = (
    ("console.aws.amazon.com", CloudPlane.MANAGEMENT.value),
    ("console.azure.com", CloudPlane.MANAGEMENT.value),
    ("console.cloud.google.com", CloudPlane.MANAGEMENT.value),
    ("portal.azure.com", CloudPlane.MANAGEMENT.value),
    ("dash.cloudflare.com", CloudPlane.MANAGEMENT.value),
    ("cloud.oracle.com", CloudPlane.MANAGEMENT.value),
)


class CloudClassifier:
    """Deterministic classification helpers for cloud subjects."""

    def service_category(self, service: str) -> str:
        """Return the canonical service family for a service name."""
        return _SERVICE_CATEGORY.get(str(service).lower(), ServiceCategory.UNKNOWN.value)

    def classify_plane(self, endpoint: str, service: str = "", provider: str = "", hint: str = "") -> str:
        """Classify an endpoint into a canonical plane.

        A signature-provided ``hint`` wins when it is known; management/control
        consoles are classified by well-known hosts next; then hostname/URL
        signals; then the owning service's family; defaulting to ``unknown``.
        """
        host = str(endpoint).strip().lower()
        if hint and hint != CloudPlane.UNKNOWN.value:
            return hint
        if not host:
            return CloudPlane.UNKNOWN.value
        for known_host, plane in _MANAGEMENT_ENDPOINTS:
            if host == known_host or host.startswith(f"{known_host}/"):
                return plane
        for signal, plane in _PLANE_SIGNALS.items():
            if signal in host:
                return plane
        if service:
            category = self.service_category(service)
            if category in (ServiceCategory.IDENTITY.value,):
                return CloudPlane.IDENTITY.value
            if category in (ServiceCategory.CI_CD.value,):
                return CloudPlane.DEVELOPER.value
            if category in (
                ServiceCategory.STORAGE.value,
                ServiceCategory.DATABASE.value,
                ServiceCategory.NETWORKING.value,
            ):
                return CloudPlane.DATA.value
        return CloudPlane.UNKNOWN.value

    def classify_exposure(self, endpoint: str, provider: str = "", public_hint: bool = False) -> str:
        """Classify a cloud endpoint/resource exposure.

        ``public_hint`` comes from a signature (e.g. a well-known public CDN or
        storage hostname); a hostname reaching the public DNS otherwise implies
        a public indicator, while private/loopback ranges imply private
        indicators. Exposure is intelligence metadata, never a verdict.
        """
        host = str(endpoint).strip().lower()
        if host in ("", "unknown"):
            return "unknown"
        if public_hint:
            return "public"
        if _is_private_host(host):
            return "private-indicator"
        if provider:
            return "public-indicator"
        return "unknown"

    def classify_environment(self, *subjects: str) -> str:
        """Classify the environment from one or more evidence subjects.

        The strongest signal (lowest priority index) wins; a bare ``prod``-like
        token is recorded as production only when it is the strongest observed
        signal and is never upgraded by weak naming alone.
        """
        best: str = EnvironmentKind.UNKNOWN.value
        best_priority = 99
        for subject in subjects:
            lowered = str(subject or "").lower()
            for kind, signals in _ENVIRONMENT_SIGNALS:
                if any(signal in lowered for signal in signals):
                    priority = _ENVIRONMENT_PRIORITY[kind]
                    if priority < best_priority:
                        best = kind
                        best_priority = priority
        return best

    def classify_exposure_indicator(
        self,
        *,
        resource_kind: str = "",
        public: str = "unknown",
        admin: bool = False,
        debug: bool = False,
        documented: bool = False,
        dangling: bool = False,
    ) -> str:
        """Return a canonical exposure-indicator kind (never a vulnerability)."""
        if dangling:
            return ExposureIndicatorKind.DANGLING_RESOURCE.value
        if debug:
            return ExposureIndicatorKind.DEBUG_ENDPOINT.value
        if admin and public in ("public", "public-indicator"):
            return ExposureIndicatorKind.PUBLIC_ADMIN_INTERFACE.value
        if resource_kind == "storage" and public in ("public", "public-indicator"):
            return ExposureIndicatorKind.PUBLIC_STORAGE.value
        if documented:
            return ExposureIndicatorKind.DOCUMENTED_RESOURCE.value
        if public in ("public", "public-indicator"):
            return ExposureIndicatorKind.UNUSUAL_EXPOSURE.value
        return ExposureIndicatorKind.UNKNOWN.value

    def normalize_provider(self, provider: str) -> str:
        """Return the canonical provider name for a raw label."""
        lowered = str(provider).strip().lower()
        aliases: dict[str, str] = {
            "amazon web services": "aws",
            "amazon": "aws",
            "awss3": "aws",
            "amazons3": "aws",
            "amazonaws": "aws",
            "microsoft azure": "azure",
            "microsoft": "azure",
            "azuread": "azure",
            "google cloud": "gcp",
            "google": "gcp",
            "gcloud": "gcp",
            "googlecloud": "gcp",
            "oracle cloud": "oci",
            "oracle": "oci",
            "digital ocean": "digitalocean",
            "fly": "fly.io",
        }
        normalized = aliases.get(lowered, lowered)
        try:
            return CloudProviderKind(normalized).value
        except ValueError:
            return normalized


def _is_private_host(host: str) -> bool:
    """Return ``True`` for clearly internal/private hostnames."""
    lowered = host.lower()
    if lowered in ("localhost", "internal", "private", "metadata"):
        return True
    if lowered.startswith(("10.", "172.", "192.168.", "169.254.", "127.")):
        return True
    if lowered.endswith((".local", ".internal", ".lan", ".home", ".arpa")):
        return True
    if "metadata.google.internal" in lowered or "169.254.169.254" in lowered:
        return True
    return bool(re.search(r"\b(foo|bar|internal|private|local)\b", lowered))
