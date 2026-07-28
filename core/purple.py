# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .mitre import MITREMapping, MITREMapper
from .utils import logger


class PurpleTeamOutput:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        self._rules: Dict[str, List[str]] = {
            "sigma": [],
            "yara": [],
            "suricata": [],
            "elastic": [],
            "splunk": [],
            "sentinel": [],
            "qradar": [],
        }

    def generate_all(
        self,
        findings: List[Dict[str, Any]],
        mitre_mappings: Optional[List[MITREMapping]] = None,
        save: bool = True,
    ) -> Dict[str, List[str]]:
        self._rules["sigma"] = self._generate_sigma_rules(findings, mitre_mappings)
        self._rules["yara"] = self._generate_yara_rules(findings, mitre_mappings)
        self._rules["suricata"] = self._generate_suricata_rules(findings, mitre_mappings)
        self._rules["elastic"] = self._generate_elastic_rules(findings, mitre_mappings)
        self._rules["splunk"] = self._generate_splunk_searches(findings, mitre_mappings)
        self._rules["sentinel"] = self._generate_sentinel_rules(findings, mitre_mappings)
        self._rules["qradar"] = self._generate_qradar_rules(findings, mitre_mappings)

        if save:
            self._save_all()

        for fmt, rules in self._rules.items():
            logger.info(f"PurpleTeamOutput: generated {len(rules)} {fmt} rules")

        return self._rules

    def _get_mappings(
        self, findings: List[Dict], mitre_mappings: Optional[List[MITREMapping]]
    ) -> Dict[str, MITREMapping]:
        if mitre_mappings:
            return {m.finding_category: m for m in mitre_mappings}

        mapper = MITREMapper()
        result = {}
        for finding in findings:
            cat = finding.get("payload_category", "GENERIC")
            if cat not in result:
                result[cat] = mapper.map_finding(finding)
        return result

    def _generate_sigma_rules(
        self, findings: List[Dict], mitre_mappings: Optional[List[MITREMapping]] = None
    ) -> List[str]:
        rules = []
        mapped = self._get_mappings(findings, mitre_mappings)

        for finding in findings:
            cat = finding.get("payload_category", "GENERIC")
            payload = finding.get("payload", "")
            technique_id = mapped.get(cat, MITREMapper().map_finding(finding)).technique_id if mapped else "T1580"

            rule = f"""title: HunterX Detection - {cat}
id: {hash(cat + payload) % 10**8}
status: experimental
description: Automated detection rule generated from HunterX scan
author: HunterX Framework
date: {datetime.now().strftime("%Y/%m/%d")}
tags:
  - attack.{technique_id.lower().replace(".", "_")}
logsource:
  category: webserver
  product: generic
detection:
  selection:
    http.url|contains: '{payload[:50] if payload else cat.lower()}'
  condition: selection
falsepositives:
  - Unknown
level: {'high' if any(k in cat for k in ['RCE', 'SQLI', 'SSTI']) else 'medium'}
"""
            rules.append(rule)
        return rules

    def _generate_yara_rules(
        self, findings: List[Dict], mitre_mappings: Optional[List[MITREMapping]] = None
    ) -> List[str]:
        rules = []
        for finding in findings:
            cat = finding.get("payload_category", "GENERIC")
            payload = finding.get("payload", "")
            findings_list = finding.get("findings", [])
            strings_section = []
            strings_section.append(f'        $payload = "{payload[:80]}"' if payload else '        $payload = ""')

            for i, f_text in enumerate(findings_list[:5]):
                safe = str(f_text).replace('"', '\\"')[:80]
                strings_section.append(f'        $finding{i} = "{safe}"')

            strings_block = "\n".join(strings_section)
            rule = f"""rule hunterx_{cat.lower().replace("-", "_")}_{hash(payload) % 10**6}
{{
    meta:
        description = "HunterX detection rule for {cat}"
        author = "HunterX Framework"
        date = "{datetime.now().strftime("%Y-%m-%d")}"
        severity = "{'critical' if any(k in cat for k in ['RCE', 'SQLI']) else 'high'}"

    strings:
{strings_block}

    condition:
        any of them
}}
"""
            rules.append(rule)
        return rules

    def _generate_suricata_rules(
        self, findings: List[Dict], mitre_mappings: Optional[List[MITREMapping]] = None
    ) -> List[str]:
        rules = []
        for finding in findings:
            cat = finding.get("payload_category", "GENERIC")
            payload = finding.get("payload", "")
            sid = hash(cat + payload) % 10**7
            severity = 1 if any(k in cat for k in ["RCE", "SQLI", "SSTI"]) else 2

            rule = f"""alert http any any -> any any (
    msg:"HunterX - {cat} Detected";
    content:"{payload[:100] if payload else cat.lower()}"; http_uri;
    classtype:web-application-attack;
    sid:{sid};
    rev:1;
    priority:{severity};
)
"""
            rules.append(rule)
        return rules

    def _generate_elastic_rules(
        self, findings: List[Dict], mitre_mappings: Optional[List[MITREMapping]] = None
    ) -> List[str]:
        rules = []
        for finding in findings:
            cat = finding.get("payload_category", "GENERIC")
            payload = finding.get("payload", "")

            rule = f"""rule:
  api_version: 3
  name: HunterX - {cat} Detection
  severity: {'critical' if any(k in cat for k in ['RCE', 'SQLI']) else 'high'}
  type: query
  query: |
    http.url.text: *{payload[:50] if payload else cat.lower()}*
  tags:
    - hunterx
    - {cat.lower()}
    - web-application
"""
            rules.append(rule)
        return rules

    def _generate_splunk_searches(
        self, findings: List[Dict], mitre_mappings: Optional[List[MITREMapping]] = None
    ) -> List[str]:
        searches = []
        for finding in findings:
            cat = finding.get("payload_category", "GENERIC")
            payload = finding.get("payload", "")

            search = f"""`web_logs` uri="*{payload[:50] if payload else cat.lower()}*"
| stats count by src_ip, uri, status
| where count > 0
| eval alert="HunterX - {cat}"
| eval severity="{'critical' if any(k in cat for k in ['RCE', 'SQLI']) else 'high'}"
| table src_ip, uri, status, count, alert, severity
"""
            searches.append(search)
        return searches

    def _generate_sentinel_rules(
        self, findings: List[Dict], mitre_mappings: Optional[List[MITREMapping]] = None
    ) -> List[str]:
        rules = []
        for finding in findings:
            cat = finding.get("payload_category", "GENERIC")
            payload = finding.get("payload", "")

            rule = f"""let HunterX_{cat.replace("-", "_")} = materialized_view(function () {{
    AWSLoadBalancerLogs
    | where url contains "{payload[:50] if payload else cat.lower()}"
    | project TimeGenerated, src_ip, url, http_method
    | extend alert = "HunterX - {cat}"
    | extend severity = "{'Critical' if any(k in cat for k in ['RCE', 'SQLI']) else 'High'}"
}})
"""
            rules.append(rule)
        return rules

    def _generate_qradar_rules(
        self, findings: List[Dict], mitre_mappings: Optional[List[MITREMapping]] = None
    ) -> List[str]:
        rules = []
        for finding in findings:
            cat = finding.get("payload_category", "GENERIC")
            payload = finding.get("payload", "")

            rule = f"""// QRadar Rule: HunterX - {cat}
// Generated by HunterX Framework

when any of these Network Events occur:
    - URL {payload[:80] if payload else cat.lower()}
then:
    Create Offense with severity {'9' if any(k in cat for k in ['RCE', 'SQLI']) else '7'}
    Add to Reference Set: HunterX_Findings
"""
            rules.append(rule)
        return rules

    def _save_all(self) -> None:
        base = os.path.join(self.output_dir, "purple_team")
        os.makedirs(base, exist_ok=True)

        format_map = {
            "sigma": ("sigma_rules.yml", "\n---\n".join(self._rules["sigma"])),
            "yara": ("yara_rules.yar", "\n\n".join(self._rules["yara"])),
            "suricata": ("suricata_rules.rules", "\n".join(self._rules["suricata"])),
            "elastic": ("elastic_rules.yml", "\n---\n".join(self._rules["elastic"])),
            "splunk": ("splunk_searches.spl", "\n\n".join(self._rules["splunk"])),
            "sentinel": ("sentinel_rules.kql", "\n\n".join(self._rules["sentinel"])),
            "qradar": ("qradar_rules.txt", "\n\n".join(self._rules["qradar"])),
        }

        for fmt, (fname, content) in format_map.items():
            fpath = os.path.join(base, fname)
            with open(fpath, "w") as f:
                f.write(content + "\n")

        manifest = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "generator": "HunterX PurpleTeamOutput",
            "rules": {fmt: len(rules) for fmt, rules in self._rules.items()},
        }
        with open(os.path.join(base, "manifest.json"), "w") as f:
            json.dump(manifest, f, indent=2)

        logger.info(f"PurpleTeamOutput: saved all rules to {base}/")

    def get_rules_summary(self) -> Dict[str, int]:
        return {fmt: len(rules) for fmt, rules in self._rules.items()}
