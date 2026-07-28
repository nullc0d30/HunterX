# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from .knowledge_graph import KnowledgeGraph, NodeType
from .utils import logger


class AssetType(str, Enum):
    WEB_APPLICATION = "web_application"
    API_ENDPOINT = "api_endpoint"
    DATABASE = "database"
    AUTH_SERVICE = "auth_service"
    FILE_STORAGE = "file_storage"
    DNS_SERVICE = "dns_service"
    CDN = "cdn"
    LOAD_BALANCER = "load_balancer"
    CACHE = "cache"
    QUEUE = "queue"
    THIRD_PARTY = "third_party"
    CLOUD_SERVICE = "cloud_service"


class TrustLevel(str, Enum):
    UNTRUSTED = "untrusted"
    SEMI_TRUSTED = "semi_trusted"
    TRUSTED = "trusted"
    HIGHLY_TRUSTED = "highly_trusted"


@dataclass
class DataFlow:
    id: str
    name: str
    source: str
    destination: str
    protocol: str = "HTTP"
    data_types: List[str] = field(default_factory=list)
    authentication: Optional[str] = None
    encryption: Optional[str] = None
    is_encrypted: bool = False
    trust_boundary_crossed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "source": self.source,
            "destination": self.destination,
            "protocol": self.protocol,
            "data_types": self.data_types,
            "authentication": self.authentication,
            "encryption": self.encryption,
            "is_encrypted": self.is_encrypted,
            "trust_boundary_crossed": self.trust_boundary_crossed,
        }


@dataclass
class Asset:
    id: str
    name: str
    asset_type: AssetType
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    entry_points: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    criticality: float = 0.5
    exposed_ports: List[int] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "asset_type": self.asset_type.value,
            "trust_level": self.trust_level.value,
            "entry_points": self.entry_points,
            "dependencies": self.dependencies,
            "criticality": self.criticality,
            "exposed_ports": self.exposed_ports,
            "technologies": self.technologies,
            "findings": self.findings,
        }


@dataclass
class ThreatModel:
    id: str
    target: str
    created_at: datetime = field(default_factory=datetime.utcnow)
    assets: Dict[str, Asset] = field(default_factory=dict)
    data_flows: Dict[str, DataFlow] = field(default_factory=dict)
    entry_points: List[str] = field(default_factory=list)
    trust_boundaries: List[Dict[str, Any]] = field(default_factory=list)
    authentication_zones: List[Dict[str, Any]] = field(default_factory=list)
    attack_surface: List[str] = field(default_factory=list)
    critical_components: List[str] = field(default_factory=list)
    threat_vectors: List[Dict[str, Any]] = field(default_factory=list)

    def add_asset(self, asset: Asset) -> None:
        self.assets[asset.id] = asset

    def add_data_flow(self, flow: DataFlow) -> None:
        self.data_flows[flow.id] = flow

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target,
            "created_at": self.created_at.isoformat(),
            "assets": [a.to_dict() for a in self.assets.values()],
            "data_flows": [f.to_dict() for f in self.data_flows.values()],
            "entry_points": self.entry_points,
            "trust_boundaries": self.trust_boundaries,
            "authentication_zones": self.authentication_zones,
            "attack_surface": self.attack_surface,
            "critical_components": self.critical_components,
            "threat_vectors": self.threat_vectors,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class ThreatModelEngine:
    def __init__(self):
        self._entry_point_patterns = [
            "/login", "/signin", "/auth", "/oauth", "/api", "/graphql",
            "/rest", "/v1", "/v2", "/ws", "/websocket", "/callback",
            "/webhook", "/upload", "/search", "/query",
        ]
        self._trust_boundary_indicators = [
            "redirect", "external", "third.party", "sso", "oauth",
            "api/", "webhook", "callback",
        ]

    def build(
        self,
        target_url: str,
        findings: List[Dict],
        context: Any = None,
        knowledge_graph: Optional[KnowledgeGraph] = None,
    ) -> ThreatModel:
        model = ThreatModel(
            id=str(uuid.uuid4()),
            target=target_url,
        )

        web_app = Asset(
            id=f"asset-{uuid.uuid4().hex[:8]}",
            name=target_url,
            asset_type=AssetType.WEB_APPLICATION,
            trust_level=TrustLevel.SEMI_TRUSTED,
            entry_points=[target_url],
            criticality=0.8,
        )
        model.add_asset(web_app)

        cats_found: Set[str] = set()
        for finding in findings:
            cat = finding.get("payload_category", "GENERIC")
            cats_found.add(cat)
            if cat not in web_app.findings:
                web_app.findings.append(cat)

            if finding.get("findings"):
                for f_text in finding.get("findings", []):
                    if any(indicator in str(f_text).lower() for indicator in self._trust_boundary_indicators):
                        if not any(tb.get("name") == str(f_text) for tb in model.trust_boundaries):
                            model.trust_boundaries.append({
                                "name": str(f_text),
                                "severity": "warning",
                                "evidence": str(f_text),
                            })

        if context:
            headers = getattr(context, "headers", {})
            if isinstance(headers, dict):
                auth_header = headers.get("Authorization", headers.get("authorization", ""))
                if auth_header:
                    model.authentication_zones.append({
                        "name": "Bearer Auth",
                        "type": "token",
                        "location": "Authorization header",
                    })

            cookies = getattr(context, "cookies", {})
            if isinstance(cookies, dict):
                for cookie_name in cookies:
                    model.entry_points.append(f"cookie:{cookie_name}")

        for cat in cats_found:
            if cat in ("LFI", "FILE_DISCLOSURE", "RCE", "SQLI", "SSTI"):
                model.critical_components.append(f"{cat} vulnerability in {target_url}")

            if cat in ("XSS", "OPEN_REDIRECT", "CRLF"):
                if cat.lower() not in [ep.lower() for ep in model.entry_points]:
                    model.entry_points.append(cat)

            attack_surface_item = f"{cat} via {target_url}"
            if attack_surface_item not in model.attack_surface:
                model.attack_surface.append(attack_surface_item)

        if "SQLI" in cats_found:
            db_asset = Asset(
                id=f"asset-{uuid.uuid4().hex[:8]}",
                name="Backend Database",
                asset_type=AssetType.DATABASE,
                trust_level=TrustLevel.TRUSTED,
                criticality=0.9,
            )
            model.add_asset(db_asset)
            model.data_flows[db_asset.id] = DataFlow(
                id=f"flow-{uuid.uuid4().hex[:8]}",
                name="Web to Database",
                source=web_app.id,
                destination=db_asset.id,
                protocol="SQL",
                data_types=["user_data", "credentials", "application_data"],
                authentication="database_credentials",
                is_encrypted=False,
                trust_boundary_crossed=True,
            )

        if "XSS" in cats_found or "SESSION_HIJACKING" in cats_found:
            model.authentication_zones.append({
                "name": "Client-side storage",
                "type": "cookie",
                "location": "Browser",
                "risk": "XSS can access cookies if HttpOnly is not set",
            })

        model.threat_vectors = [
            {
                "source": "Untrusted User Input",
                "target": asset.name,
                "vector": "Injection",
                "risk": "High" if any(f in cats_found for f in ["SQLI", "SSTI", "RCE"]) else "Medium",
            }
            for asset in model.assets.values()
        ]

        if knowledge_graph:
            self._enrich_from_graph(model, knowledge_graph)

        logger.info(f"ThreatModelEngine: built model with {len(model.assets)} assets, "
                     f"{len(model.data_flows)} data flows, {len(model.entry_points)} entry points")
        return model

    def _enrich_from_graph(self, model: ThreatModel, graph: KnowledgeGraph) -> None:
        for node in graph.nodes.values():
            if node.node_type == NodeType.ENDPOINT:
                ep = str(node.label)
                if ep not in model.entry_points:
                    model.entry_points.append(ep)

            if node.node_type == NodeType.AUTHENTICATION:
                if not any(z.get("name") == node.label for z in model.authentication_zones):
                    model.authentication_zones.append({
                        "name": node.label,
                        "type": node.properties.get("auth_type", "unknown"),
                        "location": node.properties.get("location", "unknown"),
                    })

            if node.node_type == NodeType.WAF:
                model.trust_boundaries.append({
                    "name": f"WAF: {node.label}",
                    "severity": "info",
                    "evidence": "WAF detected at boundary",
                })

    def identify_entry_points(self, context: Any) -> List[str]:
        entry_points = []
        headers = getattr(context, "headers", {})
        if isinstance(headers, dict):
            for header_name in headers.keys():
                entry_points.append(f"header:{header_name}")
        return entry_points

    def analyze_attack_surface(self, model: ThreatModel) -> List[str]:
        surface = list(model.attack_surface)
        for asset in model.assets.values():
            for ep in asset.entry_points:
                surface.append(f"{asset.name}:{ep}")
        return list(set(surface))
