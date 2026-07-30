# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List

from ..utils.utils import logger


@dataclass
class MITREMapping:
    finding_category: str
    technique_id: str
    technique_name: str
    tactics: List[str] = field(default_factory=list)
    platform: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    capec_ids: List[str] = field(default_factory=list)
    owasp_top10: List[str] = field(default_factory=list)
    owasp_asvs: List[str] = field(default_factory=list)
    nist_controls: List[str] = field(default_factory=list)
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_category": self.finding_category,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactics": self.tactics,
            "platforms": self.platform,
            "cwe_ids": self.cwe_ids,
            "capec_ids": self.capec_ids,
            "owasp_top10": self.owasp_top10,
            "owasp_asvs": self.owasp_asvs,
            "nist_controls": self.nist_controls,
            "confidence": self.confidence,
        }


MAPPING_DATABASE: Dict[str, Dict[str, Any]] = {
    "RCE": {
        "technique_id": "T1203",
        "technique_name": "Exploitation for Client Execution",
        "tactics": ["execution"],
        "platforms": ["Windows", "Linux", "macOS"],
        "cwe_ids": ["CWE-78", "CWE-94", "CWE-77"],
        "capec_ids": ["CAPEC-88", "CAPEC-136"],
        "owasp_top10": ["A03:2021-Injection"],
        "owasp_asvs": ["V5-Sanitization"],
        "nist_controls": ["SI-10", "SI-11"],
    },
    "SQLI": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactics": ["initial-access"],
        "platforms": ["Windows", "Linux", "macOS"],
        "cwe_ids": ["CWE-89"],
        "capec_ids": ["CAPEC-66", "CAPEC-7"],
        "owasp_top10": ["A03:2021-Injection"],
        "owasp_asvs": ["V5-Sanitization"],
        "nist_controls": ["SI-10", "SI-11"],
    },
    "LFI": {
        "technique_id": "T1005",
        "technique_name": "Data from Local System",
        "tactics": ["collection"],
        "platforms": ["Windows", "Linux", "macOS"],
        "cwe_ids": ["CWE-22", "CWE-73"],
        "capec_ids": ["CAPEC-126", "CAPEC-128"],
        "owasp_top10": ["A01:2021-Broken Access Control"],
        "owasp_asvs": ["V4-Access Control"],
        "nist_controls": ["AC-3", "AC-6"],
    },
    "XSS": {
        "technique_id": "T1059.007",
        "technique_name": "Command and Scripting Interpreter: JavaScript",
        "tactics": ["execution"],
        "platforms": ["Windows", "Linux", "macOS"],
        "cwe_ids": ["CWE-79"],
        "capec_ids": ["CAPEC-86", "CAPEC-588"],
        "owasp_top10": ["A03:2021-Injection"],
        "owasp_asvs": ["V5-Sanitization"],
        "nist_controls": ["SI-10", "SI-11"],
    },
    "SSTI": {
        "technique_id": "T1203",
        "technique_name": "Exploitation for Client Execution",
        "tactics": ["execution"],
        "platforms": ["Windows", "Linux", "macOS"],
        "cwe_ids": ["CWE-94", "CWE-1336"],
        "capec_ids": ["CAPEC-136"],
        "owasp_top10": ["A03:2021-Injection"],
        "owasp_asvs": ["V5-Sanitization"],
        "nist_controls": ["SI-10"],
    },
    "SSRF": {
        "technique_id": "T1595.002",
        "technique_name": "Active Scanning: Vulnerability Scanning",
        "tactics": ["reconnaissance"],
        "platforms": ["Windows", "Linux", "macOS"],
        "cwe_ids": ["CWE-918"],
        "capec_ids": ["CAPEC-230"],
        "owasp_top10": ["A10:2021-SSRF"],
        "owasp_asvs": ["V11-Business Logic"],
        "nist_controls": ["AC-4", "SC-7"],
    },
    "OPEN_REDIRECT": {
        "technique_id": "T1204.001",
        "technique_name": "User Execution: Malicious Link",
        "tactics": ["execution"],
        "platforms": ["Windows", "Linux", "macOS"],
        "cwe_ids": ["CWE-601"],
        "capec_ids": ["CAPEC-227"],
        "owasp_top10": ["A01:2021-Broken Access Control"],
        "owasp_asvs": ["V4-Access Control"],
        "nist_controls": ["AC-3"],
    },
    "CRLF": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactics": ["initial-access"],
        "platforms": ["Windows", "Linux", "macOS"],
        "cwe_ids": ["CWE-93", "CWE-113"],
        "capec_ids": ["CAPEC-105"],
        "owasp_top10": ["A03:2021-Injection"],
        "owasp_asvs": ["V5-Sanitization"],
        "nist_controls": ["SI-10"],
    },
    "INFO_LEAK": {
        "technique_id": "T1589",
        "technique_name": "Gather Victim Identity Information",
        "tactics": ["reconnaissance"],
        "platforms": ["Windows", "Linux", "macOS"],
        "cwe_ids": ["CWE-200", "CWE-209"],
        "capec_ids": ["CAPEC-116"],
        "owasp_top10": ["A01:2021-Broken Access Control"],
        "owasp_asvs": ["V3-Session Management"],
        "nist_controls": ["SC-8", "SC-13"],
    },
    "FILE_DISCLOSURE": {
        "technique_id": "T1005",
        "technique_name": "Data from Local System",
        "tactics": ["collection"],
        "platforms": ["Windows", "Linux", "macOS"],
        "cwe_ids": ["CWE-22", "CWE-552"],
        "capec_ids": ["CAPEC-126"],
        "owasp_top10": ["A01:2021-Broken Access Control"],
        "owasp_asvs": ["V4-Access Control"],
        "nist_controls": ["AC-3", "AC-6"],
    },
    "WAF_BYPASS": {
        "technique_id": "T1562.001",
        "technique_name": "Impair Defenses: Disable or Modify Tools",
        "tactics": ["defense-evasion"],
        "platforms": ["Windows", "Linux", "macOS"],
        "cwe_ids": ["CWE-693"],
        "capec_ids": ["CAPEC-541"],
        "owasp_top10": [],
        "owasp_asvs": [],
        "nist_controls": ["SI-4"],
    },
    "GENERIC": {
        "technique_id": "T1580",
        "technique_name": "Gather Victim Network Information",
        "tactics": ["reconnaissance"],
        "platforms": ["Windows", "Linux", "macOS"],
        "cwe_ids": [],
        "capec_ids": [],
        "owasp_top10": [],
        "owasp_asvs": [],
        "nist_controls": [],
    },
}


class MITREMapper:
    def __init__(self):
        self._database = MAPPING_DATABASE
        self._custom_mappings: Dict[str, Dict[str, Any]] = {}

    def register_mapping(
        self, category: str, mapping: Dict[str, Any]
    ) -> None:
        self._custom_mappings[category] = mapping
        logger.info(f"MITREMapper: registered custom mapping for {category}")

    def map_finding(self, finding: Dict[str, Any]) -> MITREMapping:
        category = finding.get("payload_category", "GENERIC")
        return self.map_category(category)

    def map_category(self, category: str) -> MITREMapping:
        entry = self._database.get(category)
        if entry is None:
            entry = self._custom_mappings.get(category, self._database["GENERIC"])

        return MITREMapping(
            finding_category=category,
            technique_id=entry.get("technique_id", "T1580"),
            technique_name=entry.get("technique_name", "Gather Victim Network Information"),
            tactics=entry.get("tactics", ["reconnaissance"]),
            platform=entry.get("platforms", ["Windows", "Linux", "macOS"]),
            cwe_ids=entry.get("cwe_ids", []),
            capec_ids=entry.get("capec_ids", []),
            owasp_top10=entry.get("owasp_top10", []),
            owasp_asvs=entry.get("owasp_asvs", []),
            nist_controls=entry.get("nist_controls", []),
            confidence=1.0 if category in self._database else 0.5,
        )

    def map_findings(self, findings: List[Dict[str, Any]]) -> List[MITREMapping]:
        seen: set = set()
        mappings = []
        for finding in findings:
            cat = finding.get("payload_category", "GENERIC")
            if cat not in seen:
                seen.add(cat)
                mappings.append(self.map_finding(finding))
        return mappings

    def get_mitre_attack_matrix(self, findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        matrix: Dict[str, List[Dict[str, Any]]] = {}
        for mapping in self.map_findings(findings):
            for tactic in mapping.tactics:
                if tactic not in matrix:
                    matrix[tactic] = []
                matrix[tactic].append({
                    "technique_id": mapping.technique_id,
                    "technique_name": mapping.technique_name,
                    "finding_category": mapping.finding_category,
                    "cwe": mapping.cwe_ids,
                })
        return matrix

    def get_coverage(self) -> Dict[str, Any]:
        return {
            "total_categories_mapped": len(self._database),
            "total_custom_mappings": len(self._custom_mappings),
            "mitre_techniques": len(set(e["technique_id"] for e in self._database.values())),
            "cwe_ids": len(set(cwe for e in self._database.values() for cwe in e.get("cwe_ids", []))),
            "capec_ids": len(set(c for e in self._database.values() for c in e.get("capec_ids", []))),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mappings": [m.to_dict() for m in [
                MITREMapping(cat, e["technique_id"], e["technique_name"],
                             tactics=e.get("tactics", []),
                             cwe_ids=e.get("cwe_ids", []),
                             capec_ids=e.get("capec_ids", []),
                             owasp_top10=e.get("owasp_top10", []))
                for cat, e in self._database.items()
            ]],
            "coverage": self.get_coverage(),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
