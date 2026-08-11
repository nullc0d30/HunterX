# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Cloud & SaaS provider detection registry.

Evidence-based signature matching that turns fragmented observations (DNS
records, hostnames, HTTP headers, TLS certificate metadata, technology
observations, JavaScript SDK references and documentation text) into typed
provider/service/resource detections. Provider is never inferred from branding
alone: every match is a deterministic, explainable signature with a strength
and a region/resource extraction.

Security boundary: matching only. No requests, no authentication, no resource
access.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from hunterx.domain.cloud.models import (
    CloudPlane,
    CloudProviderKind,
    EvidenceStrength,
    ServiceCategory,
)


@dataclass(frozen=True, slots=True)
class ProviderMatch:
    """A single deterministic provider detection from one piece of evidence.

    Attributes:
        provider: canonical provider name.
        display_name: human provider label.
        service: canonical service name (``""`` for provider-only).
        category: canonical service category.
        plane: canonical endpoint plane classification.
        region: extracted region code when the signature carries one.
        resource_kind: resource family when the signature identifies one.
        exposure: exposure classification when observable.
        strength: relative evidence strength.
        evidence_type: the evidence family that matched.
        matched_on: the raw value that matched.
        detail: human-readable match explanation.

    """

    provider: str
    display_name: str
    service: str = ""
    category: str = ServiceCategory.UNKNOWN.value
    plane: str = CloudPlane.UNKNOWN.value
    region: str = ""
    resource_kind: str = ""
    exposure: str = "unknown"
    strength: EvidenceStrength = EvidenceStrength.MODERATE
    evidence_type: str = "other"
    matched_on: str = ""
    detail: str = ""


@dataclass(frozen=True, slots=True)
class ProviderSignature:
    """One signature inside the provider catalog.

    Attributes:
        provider: canonical provider name.
        service: canonical service name.
        category: canonical service category.
        kind: evidence family (``hostname``/``header``/``tls-org``/
            ``technology``/``js``/``documentation``/``url``).
        match: lowercase substring (or ``regex:``-prefixed pattern) to match.
        plane: endpoint plane classification.
        resource_kind: resource family when the signature identifies one.
        exposure: exposure classification when observable.
        region: optional literal region.
        region_regex: optional regex (group 1) extracting a region from a host.
        strength: relative evidence strength.
        display_name: human provider label.

    """

    provider: str
    service: str
    category: str = ServiceCategory.UNKNOWN.value
    kind: str = "hostname"
    match: str = ""
    plane: str = CloudPlane.UNKNOWN.value
    resource_kind: str = ""
    exposure: str = "unknown"
    region: str = ""
    region_regex: str = ""
    strength: EvidenceStrength = EvidenceStrength.MODERATE
    display_name: str = ""


# -- region extraction patterns -----------------------------------------------

_BOUNDARY = r"(?:\.|^|[-/\\\s])"

_AWS_REGION = re.compile(
    _BOUNDARY
    + r"((?:ap|eu|us|sa|ca|me|af|il|mx|cn|gov)-(?:east|west|north|south|southeast|southwest|northeast|northwest|central)-\d)"
)
_GCP_REGION = re.compile(
    _BOUNDARY
    + r"((?:us|europe|asia|australia|southamerica|me|africa)-(?:central|east|west|north|south|northeast|northwest|southeast|southwest)[-\d]*\d?)"
)
_AZURE_REGION = re.compile(
    _BOUNDARY
    + r"((?:eastus|eastus2|westus|westus2|westus3|centralus|northcentralus|southcentralus|northeurope|westeurope|uksouth|ukwest|eastasia|southeastasia|japaneast|japanwest|australiaeast|australiasoutheast|canadacentral|canadaeast|brazilsouth|centralindia|southindia|westindia|koreacentral|koreasouth|southafricanorth|southafricawest|uaenorth|uaecentral|germanywestcentral|francecentral|francesouth|switzerlandnorth|norwayeast|swedencentral))"
)
_OCI_REGION = re.compile(_BOUNDARY + r"((?:[a-z]{2}-[a-z]+-\d))")


def extract_region(provider: str, host: str) -> str:
    """Extract a canonical region code from a hostname when possible."""
    for regex in (_AWS_REGION, _GCP_REGION, _AZURE_REGION, _OCI_REGION):
        match = regex.search(host.lower())
        if match:
            region = match.group(1)
            # OCI region code within an AWS-like pattern would be a false hit.
            if provider == "oci" and not region.startswith(("us-", "eu-", "ap-", "sa-")):
                continue
            return region
    return ""


# -- hostname signatures ------------------------------------------------------
# (provider, service, category, hostname pattern, plane, resource_kind)

_HOSTNAME_SIGNATURES: list[ProviderSignature] = [
    # -- AWS ----------------------------------------------------------------
    ProviderSignature(
        "aws",
        "s3",
        ServiceCategory.STORAGE.value,
        "hostname",
        "s3.amazonaws.com",
        CloudPlane.DATA.value,
        "bucket",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "aws",
        "s3",
        ServiceCategory.STORAGE.value,
        "hostname",
        ".s3.",
        CloudPlane.DATA.value,
        "bucket",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "aws",
        "s3",
        ServiceCategory.STORAGE.value,
        "hostname",
        ".s3-",
        CloudPlane.DATA.value,
        "bucket",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "aws",
        "cloudfront",
        ServiceCategory.NETWORKING.value,
        "hostname",
        ".cloudfront.net",
        CloudPlane.DATA.value,
        "cdn",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "aws",
        "api-gateway",
        ServiceCategory.NETWORKING.value,
        "hostname",
        "execute-api.",
        CloudPlane.CONTROL.value,
        "api-gateway",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "aws",
        "elastic-load-balancing",
        ServiceCategory.NETWORKING.value,
        "hostname",
        ".elb.amazonaws.com",
        CloudPlane.DATA.value,
        "load-balancer",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "aws",
        "elastic-load-balancing",
        ServiceCategory.NETWORKING.value,
        "hostname",
        ".elb.amazonaws.com.cn",
        CloudPlane.DATA.value,
        "load-balancer",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "aws",
        "lambda",
        ServiceCategory.SERVERLESS.value,
        "hostname",
        "lambda-url.",
        CloudPlane.DATA.value,
        "function",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "aws",
        "lambda",
        ServiceCategory.SERVERLESS.value,
        "hostname",
        ".lambda-url.",
        CloudPlane.DATA.value,
        "function",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "aws",
        "ec2",
        ServiceCategory.COMPUTE.value,
        "hostname",
        ".compute.amazonaws.com",
        CloudPlane.DATA.value,
        "instance",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "aws",
        "ec2",
        ServiceCategory.COMPUTE.value,
        "hostname",
        ".compute-1.amazonaws.com",
        CloudPlane.DATA.value,
        "instance",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "aws",
        "rds",
        ServiceCategory.DATABASE.value,
        "hostname",
        ".rds.amazonaws.com",
        CloudPlane.DATA.value,
        "database",
        "private-indicator",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "aws",
        "elasticbeanstalk",
        ServiceCategory.COMPUTE.value,
        "hostname",
        ".elasticbeanstalk.com",
        CloudPlane.DATA.value,
        "application",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "aws",
        "elasticache",
        ServiceCategory.DATABASE.value,
        "hostname",
        ".cache.amazonaws.com",
        CloudPlane.DATA.value,
        "database",
        "private-indicator",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "aws",
        "redshift",
        ServiceCategory.DATABASE.value,
        "hostname",
        ".redshift.amazonaws.com",
        CloudPlane.DATA.value,
        "database",
        "private-indicator",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "aws",
        "dynamodb",
        ServiceCategory.DATABASE.value,
        "hostname",
        "dynamodb.",
        CloudPlane.DATA.value,
        "database",
        "private-indicator",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "aws",
        "ecs",
        ServiceCategory.CONTAINER.value,
        "hostname",
        ".ecs.",
        CloudPlane.CONTROL.value,
        "container",
        "private-indicator",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "aws",
        "ecr",
        ServiceCategory.CONTAINER.value,
        "hostname",
        ".ecr.",
        CloudPlane.DATA.value,
        "registry",
        "private-indicator",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "aws",
        "elb",
        ServiceCategory.NETWORKING.value,
        "hostname",
        ".elb.",
        CloudPlane.DATA.value,
        "load-balancer",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "aws",
        "sqs",
        ServiceCategory.MESSAGING.value,
        "hostname",
        "sqs.",
        CloudPlane.DATA.value,
        "queue",
        "private-indicator",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "aws",
        "sns",
        ServiceCategory.MESSAGING.value,
        "hostname",
        "sns.",
        CloudPlane.DATA.value,
        "topic",
        "private-indicator",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "aws",
        "iot",
        ServiceCategory.MESSAGING.value,
        "hostname",
        ".iot.",
        CloudPlane.DATA.value,
        "message-infrastructure",
        "private-indicator",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "aws",
        "amazonaws",
        ServiceCategory.UNKNOWN.value,
        "hostname",
        ".amazonaws.com",
        CloudPlane.UNKNOWN.value,
        "",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "aws",
        "route53",
        ServiceCategory.NETWORKING.value,
        "hostname",
        ".amazonaws.com",
        CloudPlane.CONTROL.value,
        "dns",
        "public",
        strength=EvidenceStrength.WEAK,
    ),
    # -- Azure --------------------------------------------------------------
    ProviderSignature(
        "azure",
        "app-service",
        ServiceCategory.COMPUTE.value,
        "hostname",
        ".azurewebsites.net",
        CloudPlane.DATA.value,
        "application",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "azure",
        "blob-storage",
        ServiceCategory.STORAGE.value,
        "hostname",
        ".blob.core.windows.net",
        CloudPlane.DATA.value,
        "storage",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "azure",
        "blob-storage",
        ServiceCategory.STORAGE.value,
        "hostname",
        ".blob.core.usgovcloudapi.net",
        CloudPlane.DATA.value,
        "storage",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "azure",
        "cdn",
        ServiceCategory.NETWORKING.value,
        "hostname",
        ".azureedge.net",
        CloudPlane.DATA.value,
        "cdn",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "azure",
        "front-door",
        ServiceCategory.NETWORKING.value,
        "hostname",
        ".azurefd.net",
        CloudPlane.DATA.value,
        "cdn",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "azure",
        "api-management",
        ServiceCategory.NETWORKING.value,
        "hostname",
        ".azure-api.net",
        CloudPlane.CONTROL.value,
        "api-gateway",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "azure",
        "app-service",
        ServiceCategory.COMPUTE.value,
        "hostname",
        ".scm.azurewebsites.net",
        CloudPlane.DEVELOPER.value,
        "application",
        "public-indicator",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "azure",
        "app-service",
        ServiceCategory.COMPUTE.value,
        "hostname",
        ".trafficmanager.net",
        CloudPlane.DATA.value,
        "load-balancer",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "azure",
        "app-service",
        ServiceCategory.COMPUTE.value,
        "hostname",
        ".azurewebsites.net",
        CloudPlane.DATA.value,
        "application",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "azure",
        "cosmos-db",
        ServiceCategory.DATABASE.value,
        "hostname",
        ".documents.azure.com",
        CloudPlane.DATA.value,
        "database",
        "private-indicator",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "azure",
        "azure-sql",
        ServiceCategory.DATABASE.value,
        "hostname",
        ".database.windows.net",
        CloudPlane.DATA.value,
        "database",
        "private-indicator",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "azure",
        "azure-sql",
        ServiceCategory.DATABASE.value,
        "hostname",
        ".database.secure.windows.net",
        CloudPlane.DATA.value,
        "database",
        "private-indicator",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "azure",
        "container-registry",
        ServiceCategory.CONTAINER.value,
        "hostname",
        ".azurecr.io",
        CloudPlane.DATA.value,
        "registry",
        "private-indicator",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "azure",
        "app-service",
        ServiceCategory.COMPUTE.value,
        "hostname",
        ".azurefd.net",
        CloudPlane.DATA.value,
        "load-balancer",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "azure",
        "devops",
        ServiceCategory.CI_CD.value,
        "hostname",
        ".visualstudio.com",
        CloudPlane.DEVELOPER.value,
        "ci-cd",
        "public-indicator",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "azure",
        "devops",
        ServiceCategory.CI_CD.value,
        "hostname",
        "dev.azure.com",
        CloudPlane.DEVELOPER.value,
        "ci-cd",
        "public-indicator",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "azure",
        "app-service",
        ServiceCategory.COMPUTE.value,
        "hostname",
        ".azurestaticapps.net",
        CloudPlane.DATA.value,
        "application",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "azure",
        "azure-functions",
        ServiceCategory.SERVERLESS.value,
        "hostname",
        ".azurewebsites.net",
        CloudPlane.DATA.value,
        "function",
        "public",
        strength=EvidenceStrength.WEAK,
    ),
    ProviderSignature(
        "azure",
        "azure",
        ServiceCategory.UNKNOWN.value,
        "hostname",
        ".azure.com",
        CloudPlane.UNKNOWN.value,
        "",
        "unknown",
        strength=EvidenceStrength.WEAK,
    ),
    # -- Google Cloud --------------------------------------------------------
    ProviderSignature(
        "gcp",
        "app-engine",
        ServiceCategory.COMPUTE.value,
        "hostname",
        ".appspot.com",
        CloudPlane.DATA.value,
        "application",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "gcp",
        "cloud-functions",
        ServiceCategory.SERVERLESS.value,
        "hostname",
        ".cloudfunctions.net",
        CloudPlane.DATA.value,
        "function",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "gcp",
        "cloud-run",
        ServiceCategory.SERVERLESS.value,
        "hostname",
        ".run.app",
        CloudPlane.DATA.value,
        "function",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "gcp",
        "cloud-storage",
        ServiceCategory.STORAGE.value,
        "hostname",
        ".storage.googleapis.com",
        CloudPlane.DATA.value,
        "storage",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "gcp",
        "cloud-storage",
        ServiceCategory.STORAGE.value,
        "hostname",
        ".storage-download.googleapis.com",
        CloudPlane.DATA.value,
        "storage",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "gcp",
        "firebase",
        ServiceCategory.STORAGE.value,
        "hostname",
        ".firebasestorage.googleapis.com",
        CloudPlane.DATA.value,
        "storage",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "gcp",
        "cloud-cdn",
        ServiceCategory.NETWORKING.value,
        "hostname",
        ".cdn.cloudflare.net",
        CloudPlane.DATA.value,
        "cdn",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "gcp",
        "load-balancing",
        ServiceCategory.NETWORKING.value,
        "hostname",
        ".googleusercontent.com",
        CloudPlane.DATA.value,
        "load-balancer",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "gcp",
        "cloud-sql",
        ServiceCategory.DATABASE.value,
        "hostname",
        ".sql.googleusercontent.com",
        CloudPlane.DATA.value,
        "database",
        "private-indicator",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "gcp",
        "cloud-apis",
        ServiceCategory.UNKNOWN.value,
        "hostname",
        ".googleapis.com",
        CloudPlane.CONTROL.value,
        "",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "gcp",
        "gke",
        ServiceCategory.KUBERNETES.value,
        "hostname",
        ".gke.",
        CloudPlane.CONTROL.value,
        "cluster",
        "private-indicator",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "gcp",
        "firebase",
        ServiceCategory.STORAGE.value,
        "hostname",
        ".firebaseapp.com",
        CloudPlane.DATA.value,
        "application",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "gcp",
        "firebase",
        ServiceCategory.STORAGE.value,
        "hostname",
        ".web.app",
        CloudPlane.DATA.value,
        "application",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "gcp",
        "cloud-functions",
        ServiceCategory.SERVERLESS.value,
        "hostname",
        ".cloudfunctions.net",
        CloudPlane.DATA.value,
        "function",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "gcp",
        "artifact-registry",
        ServiceCategory.CONTAINER.value,
        "hostname",
        ".pkg.dev",
        CloudPlane.DATA.value,
        "registry",
        "private-indicator",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "gcp",
        "cloud-build",
        ServiceCategory.CI_CD.value,
        "hostname",
        ".cloudbuild.",
        CloudPlane.DEVELOPER.value,
        "ci-cd",
        "private-indicator",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "gcp",
        "gcp",
        ServiceCategory.UNKNOWN.value,
        "hostname",
        ".cloud.goog",
        CloudPlane.UNKNOWN.value,
        "",
        "unknown",
        strength=EvidenceStrength.WEAK,
    ),
    # -- Oracle Cloud --------------------------------------------------------
    ProviderSignature(
        "oci",
        "object-storage",
        ServiceCategory.STORAGE.value,
        "hostname",
        ".objectstorage.",
        CloudPlane.DATA.value,
        "storage",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "oci",
        "object-storage",
        ServiceCategory.STORAGE.value,
        "hostname",
        ".oci.customer-oci.com",
        CloudPlane.DATA.value,
        "storage",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "oci",
        "oci",
        ServiceCategory.UNKNOWN.value,
        "hostname",
        ".oraclecloud.com",
        CloudPlane.UNKNOWN.value,
        "",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "oci",
        "oci",
        ServiceCategory.UNKNOWN.value,
        "hostname",
        ".oci.",
        CloudPlane.UNKNOWN.value,
        "",
        "private-indicator",
        strength=EvidenceStrength.MODERATE,
    ),
    # -- Cloudflare ----------------------------------------------------------
    ProviderSignature(
        "cloudflare",
        "cloudflare",
        ServiceCategory.NETWORKING.value,
        "hostname",
        ".cloudflare.net",
        CloudPlane.DATA.value,
        "cdn",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "cloudflare",
        "workers",
        ServiceCategory.SERVERLESS.value,
        "hostname",
        ".workers.dev",
        CloudPlane.DATA.value,
        "function",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "cloudflare",
        "pages",
        ServiceCategory.STORAGE.value,
        "hostname",
        ".pages.dev",
        CloudPlane.DATA.value,
        "application",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    # -- DigitalOcean --------------------------------------------------------
    ProviderSignature(
        "digitalocean",
        "spaces",
        ServiceCategory.STORAGE.value,
        "hostname",
        ".digitaloceanspaces.com",
        CloudPlane.DATA.value,
        "storage",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "digitalocean",
        "droplets",
        ServiceCategory.COMPUTE.value,
        "hostname",
        ".ondigitalocean.app",
        CloudPlane.DATA.value,
        "application",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "digitalocean",
        "digitalocean",
        ServiceCategory.UNKNOWN.value,
        "hostname",
        ".digitalocean.com",
        CloudPlane.UNKNOWN.value,
        "",
        "public",
        strength=EvidenceStrength.WEAK,
    ),
    # -- Akamai --------------------------------------------------------------
    ProviderSignature(
        "akamai",
        "akamai",
        ServiceCategory.NETWORKING.value,
        "hostname",
        ".akamaiedge.net",
        CloudPlane.DATA.value,
        "cdn",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "akamai",
        "akamai",
        ServiceCategory.NETWORKING.value,
        "hostname",
        ".akamaihd.net",
        CloudPlane.DATA.value,
        "cdn",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "akamai",
        "akamai",
        ServiceCategory.NETWORKING.value,
        "hostname",
        ".edgesuite.net",
        CloudPlane.DATA.value,
        "cdn",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    # -- Fastly --------------------------------------------------------------
    ProviderSignature(
        "fastly",
        "fastly",
        ServiceCategory.NETWORKING.value,
        "hostname",
        ".fastly.net",
        CloudPlane.DATA.value,
        "cdn",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "fastly",
        "fastly",
        ServiceCategory.NETWORKING.value,
        "hostname",
        ".fastlylb.net",
        CloudPlane.DATA.value,
        "load-balancer",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    # -- Vercel --------------------------------------------------------------
    ProviderSignature(
        "vercel",
        "vercel",
        ServiceCategory.SERVERLESS.value,
        "hostname",
        ".vercel.app",
        CloudPlane.DATA.value,
        "application",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "vercel",
        "vercel",
        ServiceCategory.SERVERLESS.value,
        "hostname",
        ".vercel.sh",
        CloudPlane.DATA.value,
        "application",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    # -- Netlify -------------------------------------------------------------
    ProviderSignature(
        "netlify",
        "netlify",
        ServiceCategory.STORAGE.value,
        "hostname",
        ".netlify.app",
        CloudPlane.DATA.value,
        "application",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    # -- Heroku --------------------------------------------------------------
    ProviderSignature(
        "heroku",
        "heroku",
        ServiceCategory.COMPUTE.value,
        "hostname",
        ".herokuapp.com",
        CloudPlane.DATA.value,
        "application",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    # -- Render --------------------------------------------------------------
    ProviderSignature(
        "render",
        "render",
        ServiceCategory.COMPUTE.value,
        "hostname",
        ".onrender.com",
        CloudPlane.DATA.value,
        "application",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    # -- Fly.io --------------------------------------------------------------
    ProviderSignature(
        "fly.io",
        "fly",
        ServiceCategory.SERVERLESS.value,
        "hostname",
        ".fly.dev",
        CloudPlane.DATA.value,
        "application",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    # -- Supabase ------------------------------------------------------------
    ProviderSignature(
        "supabase",
        "supabase",
        ServiceCategory.DATABASE.value,
        "hostname",
        ".supabase.co",
        CloudPlane.DATA.value,
        "database",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "supabase",
        "supabase",
        ServiceCategory.DATABASE.value,
        "hostname",
        ".supabase.in",
        CloudPlane.DATA.value,
        "database",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    # -- Firebase ------------------------------------------------------------
    ProviderSignature(
        "firebase",
        "firebase",
        ServiceCategory.DATABASE.value,
        "hostname",
        ".firebaseio.com",
        CloudPlane.DATA.value,
        "database",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "firebase",
        "firebase",
        ServiceCategory.DATABASE.value,
        "hostname",
        ".firebasedatabase.app",
        CloudPlane.DATA.value,
        "database",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    # -- Kubernetes ----------------------------------------------------------
    ProviderSignature(
        "kubernetes",
        "kube-apiserver",
        ServiceCategory.KUBERNETES.value,
        "hostname",
        "kube-apiserver",
        CloudPlane.CONTROL.value,
        "apiserver",
        "private-indicator",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "kubernetes",
        "kubernetes",
        ServiceCategory.KUBERNETES.value,
        "hostname",
        ".k8s.",
        CloudPlane.UNKNOWN.value,
        "cluster",
        "private-indicator",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "kubernetes",
        "kubernetes",
        ServiceCategory.KUBERNETES.value,
        "hostname",
        ".k8s.io",
        CloudPlane.UNKNOWN.value,
        "cluster",
        "private-indicator",
        strength=EvidenceStrength.MODERATE,
    ),
    # -- Docker --------------------------------------------------------------
    ProviderSignature(
        "docker",
        "docker-hub",
        ServiceCategory.CONTAINER.value,
        "hostname",
        "hub.docker.com",
        CloudPlane.DATA.value,
        "registry",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "docker",
        "docker-registry",
        ServiceCategory.CONTAINER.value,
        "hostname",
        ".docker.io",
        CloudPlane.DATA.value,
        "registry",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
]

# -- header signatures --------------------------------------------------------

_HEADER_SIGNATURES: list[ProviderSignature] = [
    ProviderSignature(
        "aws",
        "s3",
        ServiceCategory.STORAGE.value,
        "header",
        "amazons3",
        CloudPlane.DATA.value,
        "storage",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "aws",
        "cloudfront",
        ServiceCategory.NETWORKING.value,
        "header",
        "cloudfront",
        CloudPlane.DATA.value,
        "cdn",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "aws",
        "s3",
        ServiceCategory.STORAGE.value,
        "header",
        "x-amz-",
        CloudPlane.DATA.value,
        "storage",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "aws",
        "s3",
        ServiceCategory.STORAGE.value,
        "header",
        "x-amz-bucket-region",
        CloudPlane.DATA.value,
        "storage",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "aws",
        "elastic-load-balancing",
        ServiceCategory.NETWORKING.value,
        "header",
        "awselb",
        CloudPlane.DATA.value,
        "load-balancer",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "aws",
        "api-gateway",
        ServiceCategory.NETWORKING.value,
        "header",
        "x-amzn-apigateway",
        CloudPlane.CONTROL.value,
        "api-gateway",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "aws",
        "waf",
        ServiceCategory.SECURITY.value,
        "header",
        "awswaf",
        CloudPlane.CONTROL.value,
        "waf",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "azure",
        "azure",
        ServiceCategory.UNKNOWN.value,
        "header",
        "x-ms-",
        CloudPlane.UNKNOWN.value,
        "",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "azure",
        "app-service",
        ServiceCategory.COMPUTE.value,
        "header",
        "microsoft-azure-application-gateway",
        CloudPlane.DATA.value,
        "gateway",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "azure",
        "azure-front-door",
        ServiceCategory.NETWORKING.value,
        "header",
        "x-azure-ref",
        CloudPlane.DATA.value,
        "cdn",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "gcp",
        "cloud-apis",
        ServiceCategory.UNKNOWN.value,
        "header",
        "x-goog-",
        CloudPlane.CONTROL.value,
        "",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "gcp",
        "cloud-storage",
        ServiceCategory.STORAGE.value,
        "header",
        "x-goog-generation",
        CloudPlane.DATA.value,
        "storage",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "gcp",
        "google-frontend",
        ServiceCategory.NETWORKING.value,
        "header",
        "google frontend",
        CloudPlane.DATA.value,
        "cdn",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "cloudflare",
        "cloudflare",
        ServiceCategory.NETWORKING.value,
        "header",
        "cf-ray",
        CloudPlane.DATA.value,
        "cdn",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "cloudflare",
        "cloudflare",
        ServiceCategory.NETWORKING.value,
        "header",
        "cf-cache-status",
        CloudPlane.DATA.value,
        "cdn",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "cloudflare",
        "cloudflare",
        ServiceCategory.NETWORKING.value,
        "header",
        "cloudflare",
        CloudPlane.DATA.value,
        "cdn",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "cloudflare",
        "cloudflare",
        ServiceCategory.NETWORKING.value,
        "header",
        "__cfduid",
        CloudPlane.DATA.value,
        "cdn",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "fastly",
        "fastly",
        ServiceCategory.NETWORKING.value,
        "header",
        "x-served-by",
        CloudPlane.DATA.value,
        "cdn",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "fastly",
        "fastly",
        ServiceCategory.NETWORKING.value,
        "header",
        "fastly",
        CloudPlane.DATA.value,
        "cdn",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "akamai",
        "akamai",
        ServiceCategory.NETWORKING.value,
        "header",
        "x-akamai",
        CloudPlane.DATA.value,
        "cdn",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "vercel",
        "vercel",
        ServiceCategory.SERVERLESS.value,
        "header",
        "x-vercel-",
        CloudPlane.DATA.value,
        "application",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "vercel",
        "vercel",
        ServiceCategory.SERVERLESS.value,
        "header",
        "vercel",
        CloudPlane.DATA.value,
        "application",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "netlify",
        "netlify",
        ServiceCategory.STORAGE.value,
        "header",
        "x-nf-request-id",
        CloudPlane.DATA.value,
        "application",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "netlify",
        "netlify",
        ServiceCategory.STORAGE.value,
        "header",
        "netlify",
        CloudPlane.DATA.value,
        "application",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "heroku",
        "heroku",
        ServiceCategory.COMPUTE.value,
        "header",
        "x-heroku-",
        CloudPlane.DATA.value,
        "application",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "heroku",
        "heroku",
        ServiceCategory.COMPUTE.value,
        "header",
        "heroku",
        CloudPlane.DATA.value,
        "application",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "kubernetes",
        "ingress-nginx",
        ServiceCategory.KUBERNETES.value,
        "header",
        "nginx-ingress",
        CloudPlane.DATA.value,
        "ingress",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "kubernetes",
        "kubernetes",
        ServiceCategory.KUBERNETES.value,
        "header",
        "kube",
        CloudPlane.CONTROL.value,
        "cluster",
        "private-indicator",
        strength=EvidenceStrength.WEAK,
    ),
]

# -- TLS organization signatures ----------------------------------------------

_TLS_SIGNATURES: list[ProviderSignature] = [
    ProviderSignature(
        "aws", "amazon", ServiceCategory.UNKNOWN.value, "tls-org", "amazon", strength=EvidenceStrength.MODERATE
    ),
    ProviderSignature(
        "aws", "amazon", ServiceCategory.UNKNOWN.value, "tls-org", "awstrust", strength=EvidenceStrength.MODERATE
    ),
    ProviderSignature(
        "azure", "microsoft", ServiceCategory.UNKNOWN.value, "tls-org", "microsoft", strength=EvidenceStrength.MODERATE
    ),
    ProviderSignature(
        "gcp", "google", ServiceCategory.UNKNOWN.value, "tls-org", "google", strength=EvidenceStrength.MODERATE
    ),
    ProviderSignature(
        "cloudflare",
        "cloudflare",
        ServiceCategory.NETWORKING.value,
        "tls-org",
        "cloudflare",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "fastly", "fastly", ServiceCategory.NETWORKING.value, "tls-org", "fastly", strength=EvidenceStrength.STRONG
    ),
    ProviderSignature(
        "akamai", "akamai", ServiceCategory.NETWORKING.value, "tls-org", "akamai", strength=EvidenceStrength.STRONG
    ),
    ProviderSignature(
        "vercel", "vercel", ServiceCategory.SERVERLESS.value, "tls-org", "vercel", strength=EvidenceStrength.MODERATE
    ),
    ProviderSignature(
        "netlify", "netlify", ServiceCategory.STORAGE.value, "tls-org", "netlify", strength=EvidenceStrength.MODERATE
    ),
    ProviderSignature(
        "heroku", "heroku", ServiceCategory.COMPUTE.value, "tls-org", "heroku", strength=EvidenceStrength.MODERATE
    ),
    ProviderSignature(
        "digitalocean",
        "digitalocean",
        ServiceCategory.UNKNOWN.value,
        "tls-org",
        "digitalocean",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "supabase",
        "supabase",
        ServiceCategory.DATABASE.value,
        "tls-org",
        "supabase",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "oci", "oracle", ServiceCategory.UNKNOWN.value, "tls-org", "oracle", strength=EvidenceStrength.MODERATE
    ),
]

# -- technology signatures -----------------------------------------------------

_TECHNOLOGY_SIGNATURES: list[ProviderSignature] = [
    ProviderSignature(
        "aws", "aws", ServiceCategory.UNKNOWN.value, "technology", "aws", strength=EvidenceStrength.MODERATE
    ),
    ProviderSignature(
        "aws",
        "amazon web services",
        ServiceCategory.UNKNOWN.value,
        "technology",
        "amazon web services",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "aws",
        "amazon s3",
        ServiceCategory.STORAGE.value,
        "technology",
        "amazon s3",
        CloudPlane.DATA.value,
        "storage",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "aws",
        "amazon cloudfront",
        ServiceCategory.NETWORKING.value,
        "technology",
        "cloudfront",
        CloudPlane.DATA.value,
        "cdn",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "aws",
        "amazon ec2",
        ServiceCategory.COMPUTE.value,
        "technology",
        "amazon ec2",
        CloudPlane.DATA.value,
        "instance",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "aws",
        "amazon api gateway",
        ServiceCategory.NETWORKING.value,
        "technology",
        "amazon api gateway",
        CloudPlane.CONTROL.value,
        "api-gateway",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "azure",
        "azure",
        ServiceCategory.UNKNOWN.value,
        "technology",
        "microsoft azure",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "azure", "azure", ServiceCategory.UNKNOWN.value, "technology", "azure", strength=EvidenceStrength.MODERATE
    ),
    ProviderSignature(
        "azure",
        "azure blob storage",
        ServiceCategory.STORAGE.value,
        "technology",
        "azure blob",
        CloudPlane.DATA.value,
        "storage",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "azure",
        "azure functions",
        ServiceCategory.SERVERLESS.value,
        "technology",
        "azure functions",
        CloudPlane.DATA.value,
        "function",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "gcp",
        "google cloud",
        ServiceCategory.UNKNOWN.value,
        "technology",
        "google cloud",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "gcp", "google cloud", ServiceCategory.UNKNOWN.value, "technology", "gcp", strength=EvidenceStrength.MODERATE
    ),
    ProviderSignature(
        "gcp",
        "google app engine",
        ServiceCategory.COMPUTE.value,
        "technology",
        "google app engine",
        CloudPlane.DATA.value,
        "application",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "gcp",
        "google cloud storage",
        ServiceCategory.STORAGE.value,
        "technology",
        "cloud storage",
        CloudPlane.DATA.value,
        "storage",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "cloudflare",
        "cloudflare",
        ServiceCategory.NETWORKING.value,
        "technology",
        "cloudflare",
        CloudPlane.DATA.value,
        "cdn",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "vercel",
        "vercel",
        ServiceCategory.SERVERLESS.value,
        "technology",
        "vercel",
        CloudPlane.DATA.value,
        "application",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "netlify",
        "netlify",
        ServiceCategory.STORAGE.value,
        "technology",
        "netlify",
        CloudPlane.DATA.value,
        "application",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "heroku",
        "heroku",
        ServiceCategory.COMPUTE.value,
        "technology",
        "heroku",
        CloudPlane.DATA.value,
        "application",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "digitalocean",
        "digitalocean",
        ServiceCategory.UNKNOWN.value,
        "technology",
        "digitalocean",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "fastly",
        "fastly",
        ServiceCategory.NETWORKING.value,
        "technology",
        "fastly",
        CloudPlane.DATA.value,
        "cdn",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "akamai",
        "akamai",
        ServiceCategory.NETWORKING.value,
        "technology",
        "akamai",
        CloudPlane.DATA.value,
        "cdn",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "kubernetes",
        "kubernetes",
        ServiceCategory.KUBERNETES.value,
        "technology",
        "kubernetes",
        CloudPlane.CONTROL.value,
        "cluster",
        "private-indicator",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "docker",
        "docker",
        ServiceCategory.CONTAINER.value,
        "technology",
        "docker",
        CloudPlane.DATA.value,
        "container",
        "private-indicator",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "docker",
        "docker",
        ServiceCategory.CONTAINER.value,
        "technology",
        "harbor",
        CloudPlane.DATA.value,
        "registry",
        "private-indicator",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "supabase",
        "supabase",
        ServiceCategory.DATABASE.value,
        "technology",
        "supabase",
        CloudPlane.DATA.value,
        "database",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "firebase",
        "firebase",
        ServiceCategory.UNKNOWN.value,
        "technology",
        "firebase",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "oci",
        "oracle cloud",
        ServiceCategory.UNKNOWN.value,
        "technology",
        "oracle cloud",
        strength=EvidenceStrength.MODERATE,
    ),
]

# -- JavaScript signatures -----------------------------------------------------

_JS_SIGNATURES: list[ProviderSignature] = [
    ProviderSignature(
        "aws", "aws-sdk", ServiceCategory.UNKNOWN.value, "js", "aws-sdk", strength=EvidenceStrength.STRONG
    ),
    ProviderSignature(
        "aws", "aws-sdk", ServiceCategory.UNKNOWN.value, "js", "@aws-sdk", strength=EvidenceStrength.STRONG
    ),
    ProviderSignature(
        "aws",
        "cognito",
        ServiceCategory.IDENTITY.value,
        "js",
        "amazoncognitoidentity",
        CloudPlane.IDENTITY.value,
        "identity",
        "public-indicator",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "aws",
        "cognito",
        ServiceCategory.IDENTITY.value,
        "js",
        "cognito",
        CloudPlane.IDENTITY.value,
        "identity",
        "public-indicator",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "azure", "azure-sdk", ServiceCategory.UNKNOWN.value, "js", "@azure/", strength=EvidenceStrength.STRONG
    ),
    ProviderSignature(
        "azure",
        "azure-storage",
        ServiceCategory.STORAGE.value,
        "js",
        "azurestorage",
        CloudPlane.DATA.value,
        "storage",
        "public-indicator",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "azure",
        "entra",
        ServiceCategory.IDENTITY.value,
        "js",
        "msal",
        CloudPlane.IDENTITY.value,
        "identity",
        "public-indicator",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "azure",
        "entra",
        ServiceCategory.IDENTITY.value,
        "js",
        "@azure/msal",
        CloudPlane.IDENTITY.value,
        "identity",
        "public-indicator",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "gcp", "google-cloud", ServiceCategory.UNKNOWN.value, "js", "@google-cloud/", strength=EvidenceStrength.STRONG
    ),
    ProviderSignature(
        "gcp", "firebase", ServiceCategory.UNKNOWN.value, "js", "firebase", strength=EvidenceStrength.STRONG
    ),
    ProviderSignature(
        "gcp", "firebase", ServiceCategory.UNKNOWN.value, "js", "firebase/app", strength=EvidenceStrength.STRONG
    ),
    ProviderSignature(
        "gcp", "firebase", ServiceCategory.UNKNOWN.value, "js", "@firebase/", strength=EvidenceStrength.STRONG
    ),
    ProviderSignature(
        "supabase",
        "supabase",
        ServiceCategory.DATABASE.value,
        "js",
        "@supabase/",
        CloudPlane.DATA.value,
        "database",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "supabase",
        "supabase",
        ServiceCategory.DATABASE.value,
        "js",
        "supabase",
        CloudPlane.DATA.value,
        "database",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "cloudflare",
        "cloudflare",
        ServiceCategory.NETWORKING.value,
        "js",
        "cloudflare",
        CloudPlane.DATA.value,
        "cdn",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "vercel",
        "vercel",
        ServiceCategory.SERVERLESS.value,
        "js",
        "@vercel/",
        CloudPlane.DATA.value,
        "application",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
]

# -- documentation / generic text signatures -----------------------------------

_DOCUMENTATION_SIGNATURES: list[ProviderSignature] = [
    ProviderSignature(
        "aws",
        "aws",
        ServiceCategory.UNKNOWN.value,
        "documentation",
        "amazon web services",
        strength=EvidenceStrength.WEAK,
    ),
    ProviderSignature(
        "azure",
        "azure",
        ServiceCategory.UNKNOWN.value,
        "documentation",
        "microsoft azure",
        strength=EvidenceStrength.WEAK,
    ),
    ProviderSignature(
        "gcp", "gcp", ServiceCategory.UNKNOWN.value, "documentation", "google cloud", strength=EvidenceStrength.WEAK
    ),
    ProviderSignature(
        "kubernetes",
        "kubernetes",
        ServiceCategory.KUBERNETES.value,
        "documentation",
        "kubernetes",
        CloudPlane.CONTROL.value,
        "cluster",
        "private-indicator",
        strength=EvidenceStrength.WEAK,
    ),
    ProviderSignature(
        "docker", "docker", ServiceCategory.CONTAINER.value, "documentation", "docker", strength=EvidenceStrength.WEAK
    ),
]

# -- SaaS hostname signatures --------------------------------------------------
# A SaaS provider is recorded separately from a cloud provider so we never
# confuse a third-party service the target depends on with the platform that
# hosts the target itself.

_SAAS_HOSTNAME_SIGNATURES: list[ProviderSignature] = [
    ProviderSignature(
        "github",
        "github-pages",
        ServiceCategory.CI_CD.value,
        "hostname",
        ".github.io",
        CloudPlane.DATA.value,
        "application",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "github",
        "github",
        ServiceCategory.CI_CD.value,
        "hostname",
        "github.com",
        CloudPlane.DEVELOPER.value,
        "ci-cd",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "github",
        "github",
        ServiceCategory.CI_CD.value,
        "hostname",
        "api.github.com",
        CloudPlane.DATA.value,
        "api",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "gitlab",
        "gitlab",
        ServiceCategory.CI_CD.value,
        "hostname",
        "gitlab.com",
        CloudPlane.DEVELOPER.value,
        "ci-cd",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "slack",
        "slack",
        ServiceCategory.COMMUNICATION.value,
        "hostname",
        "slack.com",
        CloudPlane.DATA.value,
        "communication",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "slack",
        "slack-webhooks",
        ServiceCategory.COMMUNICATION.value,
        "hostname",
        "hooks.slack.com",
        CloudPlane.DATA.value,
        "webhook",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "microsoft-365",
        "microsoft-365",
        ServiceCategory.UNKNOWN.value,
        "hostname",
        "login.microsoftonline.com",
        CloudPlane.IDENTITY.value,
        "identity",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "microsoft-365",
        "microsoft-365",
        ServiceCategory.UNKNOWN.value,
        "hostname",
        "office.com",
        CloudPlane.DATA.value,
        "application",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "google-workspace",
        "google-workspace",
        ServiceCategory.UNKNOWN.value,
        "hostname",
        "workspace.google.com",
        CloudPlane.DATA.value,
        "application",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "google-workspace",
        "google-workspace",
        ServiceCategory.UNKNOWN.value,
        "hostname",
        "accounts.google.com",
        CloudPlane.IDENTITY.value,
        "identity",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "atlassian",
        "jira",
        ServiceCategory.SUPPORT.value,
        "hostname",
        ".atlassian.net",
        CloudPlane.DATA.value,
        "application",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "atlassian",
        "confluence",
        ServiceCategory.SUPPORT.value,
        "hostname",
        "confluence",
        CloudPlane.DATA.value,
        "application",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "notion",
        "notion",
        ServiceCategory.UNKNOWN.value,
        "hostname",
        "notion.so",
        CloudPlane.DATA.value,
        "application",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "salesforce",
        "salesforce",
        ServiceCategory.CRM.value,
        "hostname",
        "salesforce.com",
        CloudPlane.DATA.value,
        "crm",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "salesforce",
        "salesforce",
        ServiceCategory.CRM.value,
        "hostname",
        "force.com",
        CloudPlane.DATA.value,
        "crm",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "hubspot",
        "hubspot",
        ServiceCategory.CRM.value,
        "hostname",
        "hubspot.com",
        CloudPlane.DATA.value,
        "crm",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "zendesk",
        "zendesk",
        ServiceCategory.SUPPORT.value,
        "hostname",
        "zendesk.com",
        CloudPlane.DATA.value,
        "support",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "zendesk",
        "zendesk",
        ServiceCategory.SUPPORT.value,
        "hostname",
        ".zendesk.com",
        CloudPlane.DATA.value,
        "support",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "datadog",
        "datadog",
        ServiceCategory.MONITORING.value,
        "hostname",
        "datadoghq.com",
        CloudPlane.DATA.value,
        "monitoring",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "sentry",
        "sentry",
        ServiceCategory.MONITORING.value,
        "hostname",
        "sentry.io",
        CloudPlane.DATA.value,
        "error-tracking",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "pagerduty",
        "pagerduty",
        ServiceCategory.MONITORING.value,
        "hostname",
        "pagerduty.com",
        CloudPlane.DATA.value,
        "monitoring",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "twilio",
        "twilio",
        ServiceCategory.COMMUNICATION.value,
        "hostname",
        "twilio.com",
        CloudPlane.DATA.value,
        "communication",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "sendgrid",
        "sendgrid",
        ServiceCategory.EMAIL.value,
        "hostname",
        "sendgrid.net",
        CloudPlane.DATA.value,
        "email",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "sendgrid",
        "sendgrid",
        ServiceCategory.EMAIL.value,
        "hostname",
        "api.sendgrid.com",
        CloudPlane.DATA.value,
        "email",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "mailgun",
        "mailgun",
        ServiceCategory.EMAIL.value,
        "hostname",
        "mailgun.net",
        CloudPlane.DATA.value,
        "email",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "stripe",
        "stripe",
        ServiceCategory.PAYMENT.value,
        "hostname",
        "stripe.com",
        CloudPlane.DATA.value,
        "payment",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "stripe",
        "stripe",
        ServiceCategory.PAYMENT.value,
        "hostname",
        "js.stripe.com",
        CloudPlane.DATA.value,
        "payment",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "shopify",
        "shopify",
        ServiceCategory.PAYMENT.value,
        "hostname",
        "shopify.com",
        CloudPlane.DATA.value,
        "payment",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "auth0",
        "auth0",
        ServiceCategory.IDENTITY.value,
        "hostname",
        "auth0.com",
        CloudPlane.IDENTITY.value,
        "identity",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "okta",
        "okta",
        ServiceCategory.IDENTITY.value,
        "hostname",
        "okta.com",
        CloudPlane.IDENTITY.value,
        "identity",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "google-analytics",
        "google-analytics",
        ServiceCategory.ANALYTICS.value,
        "hostname",
        "google-analytics.com",
        CloudPlane.DATA.value,
        "analytics",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "google-tag-manager",
        "google-tag-manager",
        ServiceCategory.ANALYTICS.value,
        "hostname",
        "googletagmanager.com",
        CloudPlane.DATA.value,
        "analytics",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "meta",
        "facebook-pixel",
        ServiceCategory.ANALYTICS.value,
        "hostname",
        "connect.facebook.net",
        CloudPlane.DATA.value,
        "analytics",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "intercom",
        "intercom",
        ServiceCategory.SUPPORT.value,
        "hostname",
        "intercom.io",
        CloudPlane.DATA.value,
        "support",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "hotjar",
        "hotjar",
        ServiceCategory.ANALYTICS.value,
        "hostname",
        "hotjar.com",
        CloudPlane.DATA.value,
        "analytics",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "segment",
        "segment",
        ServiceCategory.ANALYTICS.value,
        "hostname",
        "segment.com",
        CloudPlane.DATA.value,
        "analytics",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "mixpanel",
        "mixpanel",
        ServiceCategory.ANALYTICS.value,
        "hostname",
        "mixpanel.com",
        CloudPlane.DATA.value,
        "analytics",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "amplitude",
        "amplitude",
        ServiceCategory.ANALYTICS.value,
        "hostname",
        "amplitude.com",
        CloudPlane.DATA.value,
        "analytics",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "fullstory",
        "fullstory",
        ServiceCategory.ANALYTICS.value,
        "hostname",
        "fullstory.com",
        CloudPlane.DATA.value,
        "analytics",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "new-relic",
        "new-relic",
        ServiceCategory.MONITORING.value,
        "hostname",
        "newrelic.com",
        CloudPlane.DATA.value,
        "monitoring",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "elastic",
        "elastic-apm",
        ServiceCategory.MONITORING.value,
        "hostname",
        "elastic.co",
        CloudPlane.DATA.value,
        "monitoring",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "cloudflare",
        "cloudflare",
        ServiceCategory.NETWORKING.value,
        "hostname",
        "cdnjs.cloudflare.com",
        CloudPlane.DATA.value,
        "cdn",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
]

# -- SaaS JavaScript signatures ------------------------------------------------

_SAAS_JS_SIGNATURES: list[ProviderSignature] = [
    ProviderSignature(
        "github", "github", ServiceCategory.CI_CD.value, "js", "@octokit", strength=EvidenceStrength.STRONG
    ),
    ProviderSignature(
        "stripe",
        "stripe",
        ServiceCategory.PAYMENT.value,
        "js",
        "stripe",
        CloudPlane.DATA.value,
        "payment",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "stripe",
        "stripe-js",
        ServiceCategory.PAYMENT.value,
        "js",
        "stripe.js",
        CloudPlane.DATA.value,
        "payment",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "stripe",
        "stripe",
        ServiceCategory.PAYMENT.value,
        "js",
        "pk_live",
        CloudPlane.DATA.value,
        "payment",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "stripe",
        "stripe",
        ServiceCategory.PAYMENT.value,
        "js",
        "pk_test",
        CloudPlane.DATA.value,
        "payment",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "sentry",
        "sentry",
        ServiceCategory.MONITORING.value,
        "js",
        "@sentry/",
        CloudPlane.DATA.value,
        "error-tracking",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "sentry",
        "sentry",
        ServiceCategory.MONITORING.value,
        "js",
        "sentry",
        CloudPlane.DATA.value,
        "error-tracking",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "datadog",
        "datadog",
        ServiceCategory.MONITORING.value,
        "js",
        "@datadog/",
        CloudPlane.DATA.value,
        "monitoring",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "datadog",
        "datadog-rum",
        ServiceCategory.MONITORING.value,
        "js",
        "datadog-rum",
        CloudPlane.DATA.value,
        "monitoring",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "auth0",
        "auth0",
        ServiceCategory.IDENTITY.value,
        "js",
        "auth0",
        CloudPlane.IDENTITY.value,
        "identity",
        "public",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "okta",
        "okta",
        ServiceCategory.IDENTITY.value,
        "js",
        "okta",
        CloudPlane.IDENTITY.value,
        "identity",
        "public",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "segment", "segment", ServiceCategory.ANALYTICS.value, "js", "@segment/", strength=EvidenceStrength.STRONG
    ),
    ProviderSignature(
        "segment", "segment", ServiceCategory.ANALYTICS.value, "js", "analytics.js", strength=EvidenceStrength.MODERATE
    ),
    ProviderSignature(
        "mixpanel", "mixpanel", ServiceCategory.ANALYTICS.value, "js", "mixpanel", strength=EvidenceStrength.MODERATE
    ),
    ProviderSignature(
        "amplitude", "amplitude", ServiceCategory.ANALYTICS.value, "js", "amplitude", strength=EvidenceStrength.MODERATE
    ),
    ProviderSignature(
        "fullstory", "fullstory", ServiceCategory.ANALYTICS.value, "js", "fullstory", strength=EvidenceStrength.MODERATE
    ),
    ProviderSignature(
        "hotjar", "hotjar", ServiceCategory.ANALYTICS.value, "js", "hotjar", strength=EvidenceStrength.MODERATE
    ),
    ProviderSignature(
        "intercom", "intercom", ServiceCategory.SUPPORT.value, "js", "intercom", strength=EvidenceStrength.MODERATE
    ),
    ProviderSignature(
        "zendesk", "zendesk", ServiceCategory.SUPPORT.value, "js", "zendesk", strength=EvidenceStrength.MODERATE
    ),
    ProviderSignature(
        "google-analytics",
        "google-analytics",
        ServiceCategory.ANALYTICS.value,
        "js",
        "gtag(",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "google-analytics",
        "google-analytics",
        ServiceCategory.ANALYTICS.value,
        "js",
        "ga(",
        strength=EvidenceStrength.WEAK,
    ),
    ProviderSignature(
        "google-tag-manager",
        "google-tag-manager",
        ServiceCategory.ANALYTICS.value,
        "js",
        "googletagmanager",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "facebook", "facebook-pixel", ServiceCategory.ANALYTICS.value, "js", "fbq(", strength=EvidenceStrength.MODERATE
    ),
    ProviderSignature(
        "facebook",
        "facebook-pixel",
        ServiceCategory.ANALYTICS.value,
        "js",
        "facebook_pixel",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "twilio", "twilio", ServiceCategory.COMMUNICATION.value, "js", "twilio", strength=EvidenceStrength.MODERATE
    ),
    ProviderSignature(
        "sendgrid", "sendgrid", ServiceCategory.EMAIL.value, "js", "@sendgrid/", strength=EvidenceStrength.STRONG
    ),
    ProviderSignature(
        "mailgun", "mailgun", ServiceCategory.EMAIL.value, "js", "mailgun", strength=EvidenceStrength.MODERATE
    ),
    ProviderSignature(
        "shopify", "shopify", ServiceCategory.PAYMENT.value, "js", "shopify", strength=EvidenceStrength.MODERATE
    ),
]

# -- SaaS technology signatures ------------------------------------------------

_SAAS_TECHNOLOGY_SIGNATURES: list[ProviderSignature] = [
    ProviderSignature(
        "github", "github", ServiceCategory.CI_CD.value, "technology", "github", strength=EvidenceStrength.STRONG
    ),
    ProviderSignature(
        "gitlab", "gitlab", ServiceCategory.CI_CD.value, "technology", "gitlab", strength=EvidenceStrength.STRONG
    ),
    ProviderSignature(
        "jenkins", "jenkins", ServiceCategory.CI_CD.value, "technology", "jenkins", strength=EvidenceStrength.STRONG
    ),
    ProviderSignature(
        "circleci",
        "circleci",
        ServiceCategory.CI_CD.value,
        "technology",
        "circleci",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "sentry", "sentry", ServiceCategory.MONITORING.value, "technology", "sentry", strength=EvidenceStrength.STRONG
    ),
    ProviderSignature(
        "datadog",
        "datadog",
        ServiceCategory.MONITORING.value,
        "technology",
        "datadog",
        strength=EvidenceStrength.STRONG,
    ),
    ProviderSignature(
        "new-relic",
        "new-relic",
        ServiceCategory.MONITORING.value,
        "technology",
        "new relic",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "elastic",
        "elastic-apm",
        ServiceCategory.MONITORING.value,
        "technology",
        "elastic",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "auth0", "auth0", ServiceCategory.IDENTITY.value, "technology", "auth0", strength=EvidenceStrength.STRONG
    ),
    ProviderSignature(
        "okta", "okta", ServiceCategory.IDENTITY.value, "technology", "okta", strength=EvidenceStrength.STRONG
    ),
    ProviderSignature(
        "stripe", "stripe", ServiceCategory.PAYMENT.value, "technology", "stripe", strength=EvidenceStrength.STRONG
    ),
    ProviderSignature(
        "shopify", "shopify", ServiceCategory.PAYMENT.value, "technology", "shopify", strength=EvidenceStrength.MODERATE
    ),
    ProviderSignature(
        "wordpress",
        "wordpress",
        ServiceCategory.UNKNOWN.value,
        "technology",
        "wordpress",
        strength=EvidenceStrength.MODERATE,
    ),
    ProviderSignature(
        "cloudflare",
        "cloudflare",
        ServiceCategory.NETWORKING.value,
        "technology",
        "cloudflare",
        strength=EvidenceStrength.STRONG,
    ),
]

# -- integration-type inference (not signatures) --------------------------------

_SAAS_CATEGORY_TO_INTEGRATION: dict[str, str] = {
    "payment": "payment",
    "email": "email",
    "monitoring": "monitoring",
    "error-tracking": "error-tracking",
    "crm": "crm",
    "support": "support",
    "communication": "communication",
    "identity": "identity",
    "ci-cd": "ci-cd",
    "analytics": "analytics",
    "cloud-storage": "cloud-storage",
}


def _display_name(provider: str) -> str:
    """Return a human label for a canonical provider name."""
    try:
        return CloudProviderKind(provider).value
    except ValueError:
        return provider


class ProviderCatalog:
    """The canonical signature catalog and matcher.

    Matching is pure and deterministic: for a given piece of evidence the
    catalog returns zero or more :class:`ProviderMatch` results sorted by
    strength (strongest first).
    """

    def __init__(self) -> None:
        self._hostname: list[ProviderSignature] = _HOSTNAME_SIGNATURES
        self._header: list[ProviderSignature] = _HEADER_SIGNATURES
        self._tls: list[ProviderSignature] = _TLS_SIGNATURES
        self._technology: list[ProviderSignature] = _TECHNOLOGY_SIGNATURES
        self._js: list[ProviderSignature] = _JS_SIGNATURES
        self._documentation: list[ProviderSignature] = _DOCUMENTATION_SIGNATURES
        self._saas_hostname: list[ProviderSignature] = _SAAS_HOSTNAME_SIGNATURES
        self._saas_js: list[ProviderSignature] = _SAAS_JS_SIGNATURES
        self._saas_technology: list[ProviderSignature] = _SAAS_TECHNOLOGY_SIGNATURES

    # -- public matchers ----------------------------------------------------

    def match_hostname(self, hostname: str) -> list[ProviderMatch]:
        """Match a hostname against cloud-provider signatures."""
        host = str(hostname).strip().lower()
        if not host:
            return []
        return self._match(host, self._hostname, evidence_type="dns-hostname", region_provider="auto")

    def match_header(self, name: str, value: str) -> list[ProviderMatch]:
        """Match an HTTP header name/value pair against cloud signatures."""
        combined = f"{name.lower()} {str(value).lower()}"
        matches = self._match(combined, self._header, evidence_type="http-header")
        # Re-bind matched_on to the header value so downstream host extraction
        # works on a real value instead of the combined name+value string.
        return [
            ProviderMatch(
                provider=match.provider,
                display_name=match.display_name,
                service=match.service,
                category=match.category,
                plane=match.plane,
                region=match.region,
                resource_kind=match.resource_kind,
                exposure=match.exposure,
                strength=match.strength,
                evidence_type=match.evidence_type,
                matched_on=str(value).strip(),
                detail=match.detail,
            )
            for match in matches
        ]

    def match_tls(self, certificate: dict[str, Any]) -> list[ProviderMatch]:
        """Match TLS certificate metadata against cloud signatures."""
        candidates: list[str] = []
        for key in ("subject_org", "issuer_org", "organization", "issuer"):
            value = certificate.get(key)
            if value:
                candidates.append(str(value).lower())
        matches: list[ProviderMatch] = []
        for candidate in candidates:
            matches.extend(self._match(candidate, self._tls, evidence_type="tls"))
        return _dedupe_matches(matches)

    def match_technology(self, technology: dict[str, Any]) -> list[ProviderMatch]:
        """Match a technology observation against cloud-provider signatures."""
        name = str(technology.get("name") or "").lower()
        return self._match(name, self._technology, evidence_type="technology")

    def match_saas_technology(self, technology: dict[str, Any]) -> list[ProviderMatch]:
        """Match a technology observation against SaaS-platform signatures."""
        name = str(technology.get("name") or "").lower()
        return self._match(name, self._saas_technology, evidence_type="technology")

    def match_javascript(self, content: str) -> list[ProviderMatch]:
        """Match script content against cloud-provider SDK signatures."""
        return self._match(str(content).lower(), self._js, evidence_type="javascript")

    def match_documentation(self, text: str) -> list[ProviderMatch]:
        """Match documentation/infra text against provider signatures (weak)."""
        lowered = str(text).lower()
        return self._match(lowered, self._documentation, evidence_type="documentation")

    def match_saas_hostname(self, hostname: str) -> list[ProviderMatch]:
        """Match a hostname against SaaS-platform signatures."""
        host = str(hostname).strip().lower()
        if not host:
            return []
        return self._match(host, self._saas_hostname, evidence_type="dns-hostname")

    def match_saas_javascript(self, content: str) -> list[ProviderMatch]:
        """Match script content against SaaS SDK signatures."""
        return self._match(str(content).lower(), self._saas_js, evidence_type="javascript")

    # -- internal -----------------------------------------------------------

    def _match(
        self,
        text: str,
        signatures: Iterable[ProviderSignature],
        *,
        evidence_type: str,
        region_provider: str = "none",
    ) -> list[ProviderMatch]:
        lowered = text.lower()
        matches: list[ProviderMatch] = []
        for signature in signatures:
            if not signature.match:
                continue
            if _text_contains(lowered, signature.match):
                region = signature.region
                if not region and signature.region_regex or not region and region_provider == "auto":
                    region = extract_region(signature.provider, lowered)
                matches.append(
                    ProviderMatch(
                        provider=signature.provider,
                        display_name=_display_name(signature.provider),
                        service=signature.service,
                        category=signature.category,
                        plane=signature.plane,
                        region=region,
                        resource_kind=signature.resource_kind,
                        exposure=signature.exposure,
                        strength=signature.strength,
                        evidence_type=evidence_type,
                        matched_on=text[:256],
                        detail=f"{signature.provider} {signature.service or 'service'} via {signature.kind} signature",
                    )
                )
        matches.sort(key=lambda m: _STRENGTH_ORDER[m.strength])
        return matches


_STRENGTH_ORDER: dict[EvidenceStrength, int] = {
    EvidenceStrength.STRONG: 0,
    EvidenceStrength.MODERATE: 1,
    EvidenceStrength.WEAK: 2,
}


def _text_contains(text: str, match: str) -> bool:
    """Return ``True`` when ``match`` is contained in ``text`` (regex-aware)."""
    if match.startswith("regex:"):
        pattern = match[len("regex:") :]
        try:
            return re.search(pattern, text) is not None
        except re.error:
            return False
    return match in text


def _dedupe_matches(matches: Iterable[ProviderMatch]) -> list[ProviderMatch]:
    """Dedupe matches sharing provider+service+evidence family."""
    seen: set[tuple[str, str]] = set()
    unique: list[ProviderMatch] = []
    for match in matches:
        key = (match.provider, match.service)
        if key in seen:
            continue
        seen.add(key)
        unique.append(match)
    return unique


# -- account / identity / permission extraction patterns -----------------------

_AWS_ACCOUNT_RE = re.compile(r"\b(\d{12})\b")
_AWS_ROLE_ARN_RE = re.compile(r"arn:aws[^:]*:iam::(\d{12}):role/([A-Za-z0-9+=.@_-]+)")
_AWS_USER_ARN_RE = re.compile(r"arn:aws[^:]*:iam::(\d{12}):user/([A-Za-z0-9+=.@_-]+)")
_AZURE_SUBSCRIPTION_RE = re.compile(r"\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b")
_GCP_PROJECT_RE = re.compile(r"\bprojects/([a-z0-9][a-z0-9-]{3,28}[a-z0-9])\b")
_GCP_PROJECT_ID_RE = re.compile(r"\b([a-z][a-z0-9-]{4,28}[a-z0-9]):[a-z]+\b")
_COGNITO_POOL_RE = re.compile(r"\b(?:[a-z0-9-]+)-(?:[a-z0-9-]+)?_?\b[a-z0-9]{26}\b")


def extract_aws_account(text: str) -> str:
    """Return the first 12-digit AWS account id found (``""`` when absent)."""
    match = _AWS_ACCOUNT_RE.search(str(text))
    if match and len(match.group(1)) == 12:
        return match.group(1)
    return ""


def extract_aws_role(text: str) -> tuple[str, str]:
    """Return ``(account_id, role_name)`` from an ARN when present."""
    match = _AWS_ROLE_ARN_RE.search(str(text))
    if match:
        return match.group(1), match.group(2)
    return "", ""


def extract_aws_user(text: str) -> tuple[str, str]:
    """Return ``(account_id, user_name)`` from an ARN when present."""
    match = _AWS_USER_ARN_RE.search(str(text))
    if match:
        return match.group(1), match.group(2)
    return "", ""


def extract_azure_subscription(text: str) -> str:
    """Return the first Azure subscription/tenant GUID found (``""`` when absent)."""
    match = _AZURE_SUBSCRIPTION_RE.search(str(text))
    return match.group(1) if match else ""


def extract_gcp_project(text: str) -> str:
    """Return the first GCP project id found (``""`` when absent)."""
    match = _GCP_PROJECT_RE.search(str(text))
    return match.group(1) if match else ""


def infer_integration_type(provider: str, category: str) -> str:
    """Map a SaaS provider/category to an integration type."""
    from hunterx.domain.cloud.models import IntegrationType

    if category in _SAAS_CATEGORY_TO_INTEGRATION:
        return _SAAS_CATEGORY_TO_INTEGRATION[category]
    if provider in ("github", "gitlab", "jenkins", "circleci", "azure-devops", "aws-codebuild"):
        return IntegrationType.CI_CD.value
    if provider in ("slack", "teams"):
        return IntegrationType.COMMUNICATION.value
    if provider in ("stripe", "shopify", "paypal"):
        return IntegrationType.PAYMENT.value
    if provider in ("auth0", "okta", "keycloak", "microsoft-365", "google-workspace"):
        return IntegrationType.IDENTITY_FEDERATION.value
    return IntegrationType.API.value


def is_secret_reference(text: str) -> bool:
    """Return ``True`` when ``text`` looks like a secret reference (never a value)."""
    lowered = str(text).lower()
    refs = (
        "aws_secret_access_key",
        "aws_access_key_id",
        "azure_storage_connection_string",
        "azure_cosmos_connection_string",
        "google_application_credentials",
        "firebase_api_key",
        "supabase_anon_key",
        "supabase_service_role",
        "database_url",
        "connection_string",
        "access_token",
        "refresh_token",
        "api_key",
        "secret_key",
        "client_secret",
        "private_key",
        "password",
        "x-hub-signature",
        "webhook_secret",
        "signing_secret",
        "slack_signing_secret",
    )
    return any(ref in lowered for ref in refs)
