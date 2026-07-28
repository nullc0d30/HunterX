from __future__ import annotations

from typing import List, Optional

from ..reasoning.goals import Goal
from .capability import SkillCapability, SkillCapabilityRegistry
from .registry import SkillRegistry


class SkillPlanner:
    def __init__(self, registry: Optional[SkillRegistry] = None):
        self._registry = registry or SkillRegistry()

    def plan_for_goal(self, goal: Goal) -> List[str]:
        goal_type_str = goal.type.value
        for capability in SkillCapability:
            if capability.value == goal_type_str:
                return list(SkillCapabilityRegistry.find_by_capability(capability))
            if goal_type_str in capability.value:
                return list(SkillCapabilityRegistry.find_by_capability(capability))
        return []

    def plan_for_objective(self, objective: str) -> List[str]:
        objective_lower = objective.lower()
        capability_map = {
            "technology": [SkillCapability.TECHNOLOGY_DETECTION],
            "header": [SkillCapability.HTTP_HEADER_ANALYSIS],
            "tls": [SkillCapability.TLS_ANALYSIS],
            "cookie": [SkillCapability.COOKIE_ANALYSIS],
            "auth": [SkillCapability.AUTH_ANALYSIS, SkillCapability.JWT_ANALYSIS, SkillCapability.OAUTH_ANALYSIS],
            "jwt": [SkillCapability.JWT_ANALYSIS],
            "oauth": [SkillCapability.OAUTH_ANALYSIS],
            "cors": [SkillCapability.CORS_ANALYSIS],
            "csp": [SkillCapability.CSP_ANALYSIS],
            "csrf": [SkillCapability.CSRF_ANALYSIS],
            "clickjack": [SkillCapability.CLICKJACKING_ANALYSIS],
            "redirect": [SkillCapability.OPEN_REDIRECT],
            "directory": [SkillCapability.DIRECTORY_ENUMERATION],
            "upload": [SkillCapability.FILE_UPLOAD],
            "lfi": [SkillCapability.LFI],
            "rfi": [SkillCapability.RFI],
            "ssrf": [SkillCapability.SSRF],
            "xxe": [SkillCapability.XXE],
            "ssti": [SkillCapability.SSTI],
            "sql": [SkillCapability.SQL_INJECTION],
            "nosql": [SkillCapability.NOSQL_INJECTION],
            "command": [SkillCapability.COMMAND_INJECTION],
            "path": [SkillCapability.PATH_TRAVERSAL],
            "deserialize": [SkillCapability.DESERIALIZATION],
            "graphql": [SkillCapability.GRAPHQL],
            "websocket": [SkillCapability.WEBSOCKET],
            "rest": [SkillCapability.REST_API, SkillCapability.OPENAPI],
            "grpc": [SkillCapability.GRPC],
            "dns": [SkillCapability.DNS_INTELLIGENCE],
            "subdomain": [SkillCapability.SUBDOMAIN_ENUM],
            "waf": [SkillCapability.WAF_FINGERPRINT],
            "fingerprint": [SkillCapability.FINGERPRINT_CORRELATION],
            "secret": [SkillCapability.SECRETS_DETECTION],
            "cloud": [SkillCapability.CLOUD_METADATA, SkillCapability.S3_ANALYSIS, SkillCapability.AZURE_BLOB, SkillCapability.GCP_STORAGE],
            "s3": [SkillCapability.S3_ANALYSIS],
            "azure": [SkillCapability.AZURE_BLOB],
            "gcp": [SkillCapability.GCP_STORAGE],
            "kubernetes": [SkillCapability.KUBERNETES],
            "docker": [SkillCapability.DOCKER],
            "ci": [SkillCapability.CI_CD_SECRETS],
        }

        skills: List[str] = []
        for keyword, caps in capability_map.items():
            if keyword in objective_lower:
                for cap in caps:
                    skills.extend(SkillCapabilityRegistry.find_by_capability(cap))
        return list(set(skills))

    def recommend_skills(self, technologies: List[str]) -> List[str]:
        tech_map = {
            "nginx": ["http_header_analysis", "tls_analysis"],
            "apache": ["http_header_analysis", "directory_enumeration"],
            "iis": ["http_header_analysis"],
            "cloudflare": ["waf_fingerprint"],
            "aws": ["s3_analysis", "cloud_metadata"],
            "azure": ["azure_blob", "cloud_metadata"],
            "gcp": ["gcp_storage", "cloud_metadata"],
            "kubernetes": ["kubernetes"],
            "docker": ["docker"],
            "jwt": ["jwt_analysis"],
            "oauth": ["oauth_analysis"],
            "graphql": ["graphql"],
            "websocket": ["websocket"],
        }

        skills: List[str] = []
        for tech in technologies:
            tech_lower = tech.lower()
            for key, caps in tech_map.items():
                if key in tech_lower:
                    for cap_name in caps:
                        cap = SkillCapability(cap_name)
                        skills.extend(SkillCapabilityRegistry.find_by_capability(cap))
        return list(set(skills))


