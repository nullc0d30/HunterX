from __future__ import annotations

from enum import Enum
from typing import Dict, List, Set


class SkillCapability(str, Enum):
    TECHNOLOGY_DETECTION = "technology_detection"
    HTTP_HEADER_ANALYSIS = "http_header_analysis"
    TLS_ANALYSIS = "tls_analysis"
    COOKIE_ANALYSIS = "cookie_analysis"
    AUTH_ANALYSIS = "auth_analysis"
    JWT_ANALYSIS = "jwt_analysis"
    OAUTH_ANALYSIS = "oauth_analysis"
    CORS_ANALYSIS = "cors_analysis"
    CSP_ANALYSIS = "csp_analysis"
    CSRF_ANALYSIS = "csrf_analysis"
    CLICKJACKING_ANALYSIS = "clickjacking_analysis"
    OPEN_REDIRECT = "open_redirect"
    DIRECTORY_ENUMERATION = "directory_enumeration"
    FILE_UPLOAD = "file_upload"
    LFI = "lfi"
    RFI = "rfi"
    SSRF = "ssrf"
    XXE = "xxe"
    SSTI = "ssti"
    SQL_INJECTION = "sql_injection"
    NOSQL_INJECTION = "nosql_injection"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    DESERIALIZATION = "deserialization"
    GRAPHQL = "graphql"
    WEBSOCKET = "websocket"
    REST_API = "rest_api"
    OPENAPI = "openapi"
    GRPC = "grpc"
    DNS_INTELLIGENCE = "dns_intelligence"
    SUBDOMAIN_ENUM = "subdomain_enum"
    WAF_FINGERPRINT = "waf_fingerprint"
    FINGERPRINT_CORRELATION = "fingerprint_correlation"
    SECRETS_DETECTION = "secrets_detection"
    CLOUD_METADATA = "cloud_metadata"
    S3_ANALYSIS = "s3_analysis"
    AZURE_BLOB = "azure_blob"
    GCP_STORAGE = "gcp_storage"
    KUBERNETES = "kubernetes"
    DOCKER = "docker"
    CI_CD_SECRETS = "ci_cd_secrets"
    GENERIC = "generic"
    RECON = "recon"
    SCANNER = "scanner"
    ENUMERATOR = "enumerator"
    FUZZER = "fuzzer"
    BRUTEFORCE = "bruteforce"
    SPIDER = "spider"


class SkillCapabilityRegistry:
    _capabilities: Dict[str, Set[SkillCapability]] = {}

    @classmethod
    def register(cls, skill_id: str, capabilities: List[SkillCapability]) -> None:
        cls._capabilities[skill_id] = set(capabilities)

    @classmethod
    def unregister(cls, skill_id: str) -> None:
        cls._capabilities.pop(skill_id, None)

    @classmethod
    def get(cls, skill_id: str) -> Set[SkillCapability]:
        return cls._capabilities.get(skill_id, set())

    @classmethod
    def find_by_capability(cls, capability: SkillCapability) -> List[str]:
        return [sid for sid, caps in cls._capabilities.items() if capability in caps]

    @classmethod
    def clear(cls) -> None:
        cls._capabilities.clear()
