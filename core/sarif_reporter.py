import json
from datetime import datetime, timezone
from typing import List, Dict


class SARIFReporter:
    """Generates SARIF 2.1 format output for GitHub CodeQL / VS Code integration."""

    def __init__(self, tool_name: str = "HunterX", tool_version: str = "4.0"):
        self.tool_name = tool_name
        self.tool_version = tool_version

    def generate(self, results: List[Dict], target: str) -> dict:
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
                    "informationUri": "https://github.com/nullc0d30/HunterX",
                    "rules": list(rules.values()),
                }
            },
            "results": sarif_results,
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": datetime.now(timezone.utc).isoformat(),
            }],
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
