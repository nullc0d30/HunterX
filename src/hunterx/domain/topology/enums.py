# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Topology enums.

Canonical relationship types, entity kinds and derived-state enums for the
network-mapping & attack-surface topology capability. Pure values shared by the
domain, application and persistence layers.
"""

from __future__ import annotations

from enum import StrEnum


class RelationshipType(StrEnum):
    """Canonical directed relationship types between topology entities."""

    RESOLVES_TO = "resolves_to"
    POINTS_TO = "points_to"
    HOSTED_ON = "hosted_on"
    BELONGS_TO = "belongs_to"
    PART_OF = "part_of"
    ROUTES_TO = "routes_to"
    ANNOUNCED_BY = "announced_by"
    USES = "uses"
    EXPOSES = "exposes"
    SERVES = "serves"
    CERTIFICATE_FOR = "certificate_for"
    SIGNED_BY = "signed_by"
    DELEGATED_TO = "delegated_to"
    MAILS_TO = "mails_to"
    RELATED_TO = "related_to"
    DISCOVERED_BY = "discovered_by"
    OBSERVED_WITH = "observed_with"
    SHARES_INFRASTRUCTURE_WITH = "shares_infrastructure_with"
    SHARES_CERTIFICATE_WITH = "shares_certificate_with"
    SHARES_IP_WITH = "shares_ip_with"
    SHARES_NAMESERVER_WITH = "shares_nameserver_with"
    CONTAINS = "contains"
    HOSTS = "hosts"
    AFFECTS = "affects"
    HAS_VULNERABILITY = "has_vulnerability"
    REFERENCES_CVE = "references_cve"
    RELATES_TO_CWE = "relates_to_cwe"


class EntityKind(StrEnum):
    """Canonical kinds a topology node can take."""

    ORGANIZATION = "organization"
    PROGRAM = "program"
    TARGET = "target"
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    HOSTNAME = "hostname"
    IP = "ip"
    CIDR = "cidr"
    ASN = "asn"
    PORT = "port"
    SERVICE = "service"
    CERTIFICATE = "certificate"
    NAMESERVER = "nameserver"
    MX = "mx"
    DNS_RECORD = "dns_record"
    ROUTE = "route"
    TOOL = "tool"
    TECHNOLOGY = "technology"
    CMS = "cms"
    WEB_SERVER = "web_server"
    APPLICATION_SERVER = "application_server"
    FRAMEWORK = "framework"
    FRONTEND_FRAMEWORK = "frontend_framework"
    BACKEND_FRAMEWORK = "backend_framework"
    JAVASCRIPT = "javascript"
    PROGRAMMING_LANGUAGE = "programming_language"
    RUNTIME = "runtime"
    DATABASE = "database"
    OPERATING_SYSTEM = "operating_system"
    CDN = "cdn"
    WAF = "waf"
    REVERSE_PROXY = "reverse_proxy"
    LOAD_BALANCER = "load_balancer"
    CLOUD_PLATFORM = "cloud_platform"
    HOSTING_PROVIDER = "hosting_provider"
    WEB_ORIGIN = "web_origin"
    URL = "url"
    API_ENDPOINT = "api_endpoint"
    WEBSOCKET_ENDPOINT = "websocket_endpoint"
    GRAPHQL_ENDPOINT = "graphql_endpoint"
    AUTH_BOUNDARY = "auth_boundary"
    AUTH_SURFACE = "auth_surface"
    AUTH_ENDPOINT = "auth_endpoint"
    IDENTITY_PROVIDER = "identity_provider"
    AUTHENTICATION_SCHEME = "authentication_scheme"
    SESSION = "session"
    AUTHORIZATION_SUBJECT = "authorization_subject"
    AUTHORIZATION_ROLE = "authorization_role"
    AUTHORIZATION_PERMISSION = "authorization_permission"
    AUTHORIZATION_SCOPE = "authorization_scope"
    AUTHORIZATION_POLICY = "authorization_policy"
    AUTHORIZATION_RESOURCE = "authorization_resource"
    AUTHORIZATION_ACTION = "authorization_action"
    AUTHORIZATION_TENANT = "authorization_tenant"
    ADMIN_SURFACE = "admin_surface"
    AUTHORIZATION_ENDPOINT = "authorization_endpoint"
    CLOUD_PROVIDER = "cloud_provider"
    CLOUD_ACCOUNT = "cloud_account"
    CLOUD_REGION = "cloud_region"
    CLOUD_RESOURCE = "cloud_resource"
    CLOUD_SERVICE = "cloud_service"
    CLOUD_ENDPOINT = "cloud_endpoint"
    CLOUD_ENVIRONMENT = "cloud_environment"
    CLOUD_IDENTITY = "cloud_identity"
    SAAS_PROVIDER = "saas_provider"
    SAAS_INTEGRATION = "saas_integration"
    WEBHOOK = "webhook"
    STORAGE_RESOURCE = "storage_resource"
    COMPUTE_RESOURCE = "compute_resource"
    CONTAINER_RESOURCE = "container_resource"
    KUBERNETES_RESOURCE = "kubernetes_resource"
    DATABASE_RESOURCE = "database_resource"
    API_GATEWAY = "api_gateway"
    CI_CD_RESOURCE = "ci_cd_resource"
    ASSET = "asset"
    REPOSITORY = "repository"
    VULNERABILITY = "vulnerability"
    CVE = "cve"
    CWE = "cwe"
    PRODUCT = "product"
    VENDOR = "vendor"
    KNOWLEDGE_SOURCE = "knowledge_source"


class TopologyMode(StrEnum):
    """Build mode: full recompute vs incremental refresh."""

    FULL = "full"
    INCREMENTAL = "incremental"


class ClusterType(StrEnum):
    """Cluster categories detected by shared-infrastructure analysis."""

    SAME_IP = "same_ip"
    SAME_CERT = "same_cert"
    SAME_NAMESERVER = "same_nameserver"
    SAME_ASN = "same_asn"
    SAME_CIDR = "same_cidr"
    ROUTE_PATH = "route_path"
    SERVICE = "service"


class ConflictType(StrEnum):
    """Conflict categories preserved by the correlator."""

    VALUE = "value"
    SOURCE_ENTITY = "source_entity"
    TARGET_ENTITY = "target_entity"
    RELATIONSHIP_TYPE = "relationship_type"


class ChangeType(StrEnum):
    """Temporal change categories for a topology subject."""

    NEW = "new"
    REMOVED = "removed"
    CHANGED = "changed"


class TopologyStatus(StrEnum):
    """Build run status."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"
