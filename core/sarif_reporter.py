# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# All Rights Reserved.
#
# HunterX — AI-Assisted Vulnerability Hunter
import json
from datetime import datetime, timezone
from typing import List, Dict
from .legal import get_copyright_text, REPOSITORY_URL


class SARIFReporter:
    """Generates SARIF 2.1 format output for GitHub CodeQL / VS Code integration."""

    def __init__(self, tool_name: str = "HunterX", tool_version: str = "4.0"):
        self.tool_name = tool_name
        self.tool_version = tool_version

    def generate(self, results: List[Dict], target: str) -> dict:
        copyright_notice = get_copyright_text()
        sarif_runs = []
        rules = {}
        rule_index = 0
        sarif_results = []

        for res in results:
            findings = res.get("findings", [])
            if not findings:
                continue

            for finding in findings:
                rule_id = f"HX-{res.get('payload_category', 'GEN')}-{rule_index}"
                rules[rule_id] = {
                    "id": rule_id,
                    "name": finding,
                    "shortDescription": {"text": finding},
                    "fullDescription": {"text": f"Payload: {res.get('payload', '')}"},
                    "defaultConfiguration": {"level": "error"},
                }

                sarif_results.append({
                    "ruleId": rule_id,
                    "message": {"text": finding},
                    "level": "error",
                    "locations": [{
                        "physicalLocation": {
                            "address": {"fullyQualifiedName": target},
                            "artifactLocation": {"uri": target},
                        }
                    }],
                    "properties": {
                        "payload": res.get("payload", ""),
                        "category": res.get("payload_category", ""),
                        "diff_score": res.get("diff_score", 0),
                    },
                })
                rule_index += 1

        sarif_runs.append({
            "tool": {
                "driver": {
                    "name": self.tool_name,
                    "version": self.tool_version,
                    "informationUri": REPOSITORY_URL,
                    "rules": list(rules.values()),
                }
            },
            "results": sarif_results,
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": datetime.now(timezone.utc).isoformat(),
            }],
            "properties": {
                "copyright": copyright_notice,
            },
        })

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": sarif_runs,
        }

    def save(self, results: List[Dict], target: str, output_path: str):
        sarif = self.generate(results, target)
        with open(output_path, "w") as f:
            json.dump(sarif, f, indent=2)
