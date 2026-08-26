#!/usr/bin/env python3
"""
Juice Shop Benchmark Harness
============================

Evaluates a HunterX mission's validated findings against the official
OWASP Juice Shop challenge solution catalog (aggregated at challenge-CLASS level).

Usage:
    python juice_shop_benchmark.py --mission-id <id> [--json]

Outputs benchmark report with detection/validated coverage per class.
"""

from __future__ import annotations

import json
import sys

sys.path.insert(0, "/opt/hunterx/venv/lib/python3.12/site-packages")

from hunterx.config.loader import load_default_settings
from hunterx.platform import build_platform


# Juice Shop challenge classes mapped from HunterX vulnerability classes
JUICE_SHOP_CHALLENGE_CLASSES = {
    "sql_injection": {
        "label": "SQL Injection",
        "hx_classes": {"sql_injection", "sql-injection", "nosql-injection", "nosql_injection"},
        "official_ids": [
            "Challenge.SqlInjection",
            "Challenge.SqlInjectionLogin",
            "Challenge.SqlInjectionUnion",
        ],
    },
    "xss": {
        "label": "Cross-Site Scripting",
        "hx_classes": {"xss"},
        "official_ids": ["Challenge.XSS", "Challenge.DomXSS", "Challenge.StoredXSS"],
    },
    "ssrf": {
        "label": "Server-Side Request Forgery",
        "hx_classes": {"ssrf"},
        "official_ids": ["Challenge.SSRF"],
    },
    "idor_access_control": {
        "label": "IDOR / Broken Access Control",
        "hx_classes": {"idor", "broken_access_control", "authorization"},
        "official_ids": ["Challenge.IDOR", "Challenge.AccessControl"],
    },
    "auth_weakness": {
        "label": "Authentication Flaws",
        "hx_classes": {"authentication", "authentication_flaws"},
        "official_ids": ["Challenge.WeakPassword", "Challenge.TwoFactorBypass"],
    },
    "session_management": {
        "label": "Session Management",
        "hx_classes": {"session_management", "jwt_security"},
        "official_ids": ["Challenge.SessionFixation", "Challenge.JWTSecret"],
    },
    "sensitive_data_exposure": {
        "label": "Sensitive Data Exposure",
        "hx_classes": {"secret_exposure", "sensitive_information_exposure"},
        "official_ids": ["Challenge.DirectoryListing", "Challenge.BackupFile"],
    },
    "security_misconfiguration": {
        "label": "Security Misconfiguration",
        "hx_classes": {"security_misconfiguration", "cors_misconfiguration"},
        "official_ids": ["Challenge.MissingHeaders", "Challenge.CORS"],
    },
    "open_redirect": {
        "label": "Open Redirect",
        "hx_classes": {"open_redirect"},
        "official_ids": ["Challenge.OpenRedirect"],
    },
    "path_traversal_lfi": {
        "label": "Path Traversal / LFI",
        "hx_classes": {"lfi", "path_traversal", "rfi"},
        "official_ids": ["Challenge.LFI", "Challenge.PathTraversal"],
    },
    "command_injection_rce": {
        "label": "Command Injection / RCE",
        "hx_classes": {"rce", "command_injection"},
        "official_ids": ["Challenge.RCE"],
    },
    "template_injection": {
        "label": "Template Injection (SSTI)",
        "hx_classes": {"ssti", "ssti"},
        "official_ids": ["Challenge.SSTI"],
    },
    "xxe": {
        "label": "XXE",
        "hx_classes": {"xxe"},
        "official_ids": ["Challenge.XXE"],
    },
    "csrf": {
        "label": "CSRF",
        "hx_classes": {"csrf"},
        "official_ids": ["Challenge.CSRF"],
    },
    "cors": {
        "label": "CORS Misconfiguration",
        "hx_classes": {"cors_misconfiguration"},
        "official_ids": ["Challenge.CORS"],
    },
    "business_logic": {
        "label": "Business Logic Flaws",
        "hx_classes": {"business_logic", "api_security", "graphql_security"},
        "official_ids": ["Challenge.ForcedCoupon", "Challenge.NegativeQuantity"],
    },
    "information_disclosure": {
        "label": "Information Disclosure",
        "hx_classes": {"information_disclosure"},
        "official_ids": ["Challenge.ErrorHandling", "Challenge.StackTrace"],
    },
}


def evaluate_mission(mission_id: str) -> dict:
    """Load a mission from platform and score against Juice Shop classes."""
    settings = load_default_settings()
    platform = build_platform(settings, persistence=True)
    service = platform.mission_orchestration_query_service
    mission = service.get(mission_id)

    findings = list(getattr(mission.context, "findings", []) or [])
    hypotheses = list(service.engine.get(mission_id).hypotheses)

    # Map validated findings to Juice Shop classes
    validated = [f for f in findings if f.get("stage") in ("verified", "report_ready", "proven")]
    detected_classes = set()
    validated_classes = set()

    for finding in findings:
        vuln_class = finding.get("vulnerability_class", "").lower()
        for class_id, spec in JUICE_SHOP_CHALLENGE_CLASSES.items():
            if vuln_class in spec["hx_classes"]:
                detected_classes.add(class_id)

    for finding in validated:
        vuln_class = finding.get("vulnerability_class", "").lower()
        for class_id, spec in JUICE_SHOP_CHALLENGE_CLASSES.items():
            if vuln_class in spec["hx_classes"]:
                validated_classes.add(class_id)

    # Hypotheses can provide DETECTION evidence (not validation)
    for h in hypotheses:
        provenance = getattr(h, "provenance", {}) or {}
        vuln_class = str(provenance.get("vulnerability_class") or "").lower()
        state = str(getattr(h, "state", ""))
        for class_id, spec in JUICE_SHOP_CHALLENGE_CLASSES.items():
            if vuln_class in spec["hx_classes"] and state in ("validated", "supported", "proposed"):
                detected_classes.add(class_id)

    total = len(JUICE_SHOP_CHALLENGE_CLASSES)
    detection_cov = len(detected_classes) / total
    validated_cov = len(validated_classes) / total

    return {
        "mission_id": mission_id,
        "benchmark_total": total,
        "detected": sorted(detected_classes),
        "validated": sorted(validated_classes),
        "detection_coverage": round(detection_cov, 4),
        "validated_coverage": round(validated_cov, 4),
        "detection_count": len(detected_classes),
        "validated_count": len(validated_classes),
        "classes": {
            class_id: {
                "label": spec["label"],
                "detected": class_id in detected_classes,
                "validated": class_id in validated_classes,
            }
            for class_id, spec in JUICE_SHOP_CHALLENGE_CLASSES.items()
        },
        "ai": getattr(platform.mission_execution_service, "ai_attribution", lambda: {})(),
    }


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Juice Shop benchmark evaluator")
    parser.add_argument("--mission-id", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    report = evaluate_mission(args.mission_id)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"Mission: {report['mission_id']}")
        print(f"Benchmark classes: {report['benchmark_total']}")
        print(f"Detected:  {report['detection_count']}/{report['benchmark_total']} ({report['detection_coverage']:.0%})")
        print(f"Validated: {report['validated_count']}/{report['benchmark_total']} ({report['validated_coverage']:.0%})")
        print("\nPer-class:")
        for row in report["classes"].values():
            mark = "VALIDATED" if row["validated"] else ("DETECTED" if row["detected"] else "-")
            print(f"  {row['label']:<40} {mark}")

        passed = report["validated_coverage"] >= 0.8
        print(f"\nAcceptance (>=80% validated): {'PASS' if passed else 'FAIL'}")
        sys.exit(0 if passed else 1)


if __name__ == "__main__":
    sys.exit(main())