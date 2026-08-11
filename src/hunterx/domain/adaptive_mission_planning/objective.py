# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission objective catalog.

Each canonical :class:`MissionObjective` maps to a deterministic, explainable
spec: coverage priorities, allowed capabilities, validation depth, proof
requirements, risk tolerance and completion criteria. The catalog is the
single source of truth for how objectives shape planning.
"""

from __future__ import annotations

from hunterx.domain.adaptive_mission_planning.enums import (
    MissionMode,
    MissionObjective,
    ValidationLevel,
)
from hunterx.domain.adaptive_mission_planning.models import MissionObjectiveSpec


def default_objective_catalog() -> dict[MissionObjective, MissionObjectiveSpec]:
    """Return the canonical objective catalog."""
    specs: dict[MissionObjective, MissionObjectiveSpec] = {}
    for objective in MissionObjective:
        specs[objective] = MissionObjectiveSpec(objective=objective, description=f"{objective.value} objective")
    specs[MissionObjective.ATTACK_SURFACE_DISCOVERY] = MissionObjectiveSpec(
        objective=MissionObjective.ATTACK_SURFACE_DISCOVERY,
        coverage_priorities=(
            "asset_discovery",
            "subdomain_enumeration",
            "port_discovery",
            "service_detection",
            "technology_fingerprint",
            "endpoint_enumeration",
        ),
        allowed_capabilities=(
            "asset_discovery",
            "subdomain_enumeration",
            "dns_enumeration",
            "port_discovery",
            "service_detection",
            "technology_fingerprint",
            "endpoint_enumeration",
            "certificate_enumeration",
        ),
        validation_depth=ValidationLevel.DISCOVERY,
        proof_required=False,
        risk_tolerance=0.3,
        completion_criteria=("coverage_ratio>=0.9", "no_open_discovery_gaps"),
        description="Map the authorized attack surface as completely as possible.",
    )
    specs[MissionObjective.WEB_SECURITY_ASSESSMENT] = MissionObjectiveSpec(
        objective=MissionObjective.WEB_SECURITY_ASSESSMENT,
        coverage_priorities=(
            "endpoint_enumeration",
            "parameter_discovery",
            "technology_fingerprint",
            "vulnerability_scanning",
            "sql_injection",
            "xss",
        ),
        allowed_capabilities=(
            "endpoint_enumeration",
            "parameter_discovery",
            "technology_fingerprint",
            "vulnerability_scanning",
            "sql_injection",
            "xss",
            "ssti",
            "xxe",
            "lfi",
            "rce",
            "idor",
        ),
        validation_depth=ValidationLevel.VALIDATION,
        proof_required=False,
        risk_tolerance=0.5,
        completion_criteria=("hypotheses_validated", "coverage_ratio>=0.8"),
        description="Assess web application security with validated findings.",
    )
    specs[MissionObjective.API_SECURITY_ASSESSMENT] = MissionObjectiveSpec(
        objective=MissionObjective.API_SECURITY_ASSESSMENT,
        coverage_priorities=(
            "api_mapping",
            "endpoint_enumeration",
            "parameter_discovery",
            "authentication_analysis",
            "authorization_analysis",
            "api_security",
            "graphql_security",
        ),
        allowed_capabilities=(
            "api_mapping",
            "graphql_enumeration",
            "endpoint_enumeration",
            "parameter_discovery",
            "authentication_analysis",
            "authorization_analysis",
            "api_security",
            "graphql_security",
            "idor",
        ),
        validation_depth=ValidationLevel.VALIDATION,
        proof_required=False,
        risk_tolerance=0.5,
        completion_criteria=("api_surface_mapped", "authorization_tested"),
        description="Assess API security including authentication and authorization boundaries.",
    )
    specs[MissionObjective.CLOUD_SECURITY_ASSESSMENT] = MissionObjectiveSpec(
        objective=MissionObjective.CLOUD_SECURITY_ASSESSMENT,
        coverage_priorities=(
            "cloud_ownership_mapping",
            "asset_discovery",
            "secret_detection",
            "vulnerability_scanning",
        ),
        allowed_capabilities=(
            "cloud_ownership_mapping",
            "asset_discovery",
            "secret_detection",
            "vulnerability_scanning",
        ),
        validation_depth=ValidationLevel.VALIDATION,
        proof_required=False,
        risk_tolerance=0.4,
        completion_criteria=("cloud_surface_mapped", "exposures_assessed"),
        description="Assess cloud and SaaS attack-surface exposure.",
    )
    specs[MissionObjective.NETWORK_SECURITY_ASSESSMENT] = MissionObjectiveSpec(
        objective=MissionObjective.NETWORK_SECURITY_ASSESSMENT,
        coverage_priorities=(
            "asset_discovery",
            "port_discovery",
            "service_detection",
            "technology_fingerprint",
            "vulnerability_scanning",
        ),
        allowed_capabilities=(
            "asset_discovery",
            "port_discovery",
            "service_detection",
            "technology_fingerprint",
            "vulnerability_scanning",
        ),
        validation_depth=ValidationLevel.VALIDATION,
        proof_required=False,
        risk_tolerance=0.6,
        completion_criteria=("coverage_ratio>=0.9", "services_identified"),
        description="Assess network-exposed services and their vulnerabilities.",
    )
    specs[MissionObjective.VULNERABILITY_DISCOVERY] = MissionObjectiveSpec(
        objective=MissionObjective.VULNERABILITY_DISCOVERY,
        coverage_priorities=(
            "technology_fingerprint",
            "vulnerability_scanning",
            "dependency_check",
        ),
        allowed_capabilities=(
            "technology_fingerprint",
            "vulnerability_scanning",
            "dependency_check",
        ),
        validation_depth=ValidationLevel.VALIDATION,
        proof_required=False,
        risk_tolerance=0.6,
        completion_criteria=("hypotheses_ranked", "high_confidence_hypotheses_validated"),
        description="Discover candidate vulnerabilities across the surface.",
    )
    specs[MissionObjective.BUG_BOUNTY_ASSESSMENT] = MissionObjectiveSpec(
        objective=MissionObjective.BUG_BOUNTY_ASSESSMENT,
        coverage_priorities=(
            "endpoint_enumeration",
            "parameter_discovery",
            "vulnerability_scanning",
            "proof_validation",
        ),
        allowed_capabilities=(
            "endpoint_enumeration",
            "parameter_discovery",
            "vulnerability_scanning",
            "sql_injection",
            "xss",
            "ssrf",
            "ssti",
            "xxe",
            "lfi",
            "idor",
            "proof_validation",
        ),
        validation_depth=ValidationLevel.PROOF,
        proof_required=True,
        risk_tolerance=0.2,
        completion_criteria=("scope_correct", "high_confidence_proved", "report_ready_evidence"),
        description="Optimize for scope correctness, low noise, reproducibility and minimal-impact proof.",
    )
    specs[MissionObjective.PENTEST_ASSESSMENT] = MissionObjectiveSpec(
        objective=MissionObjective.PENTEST_ASSESSMENT,
        coverage_priorities=(
            "asset_discovery",
            "port_discovery",
            "service_detection",
            "endpoint_enumeration",
            "vulnerability_scanning",
            "proof_validation",
        ),
        allowed_capabilities=(
            "asset_discovery",
            "port_discovery",
            "service_detection",
            "technology_fingerprint",
            "endpoint_enumeration",
            "parameter_discovery",
            "vulnerability_scanning",
            "sql_injection",
            "xss",
            "ssrf",
            "ssti",
            "xxe",
            "lfi",
            "rce",
            "idor",
            "proof_validation",
        ),
        validation_depth=ValidationLevel.PROOF,
        proof_required=True,
        risk_tolerance=0.7,
        completion_criteria=("attack_paths_analyzed", "validated_findings", "remediation_ready_reporting"),
        description="Optimize for coverage, attack-path discovery, validation and remediation-ready reporting.",
    )
    specs[MissionObjective.RED_TEAM_SIMULATION] = MissionObjectiveSpec(
        objective=MissionObjective.RED_TEAM_SIMULATION,
        coverage_priorities=(
            "asset_discovery",
            "endpoint_enumeration",
            "authorization_analysis",
            "proof_validation",
        ),
        allowed_capabilities=(
            "asset_discovery",
            "subdomain_enumeration",
            "port_discovery",
            "endpoint_enumeration",
            "parameter_discovery",
            "authorization_analysis",
            "vulnerability_scanning",
            "proof_validation",
        ),
        validation_depth=ValidationLevel.VALIDATION,
        proof_required=False,
        risk_tolerance=0.8,
        completion_criteria=("objectives_reached", "detection_opportunities_documented"),
        description="Authorized simulation prioritizing objectives and attack paths under policy controls.",
    )
    specs[MissionObjective.TARGET_MONITORING] = MissionObjectiveSpec(
        objective=MissionObjective.TARGET_MONITORING,
        coverage_priorities=(
            "asset_discovery",
            "subdomain_enumeration",
            "dns_enumeration",
            "technology_fingerprint",
        ),
        allowed_capabilities=(
            "asset_discovery",
            "subdomain_enumeration",
            "dns_enumeration",
            "technology_fingerprint",
            "certificate_enumeration",
        ),
        validation_depth=ValidationLevel.DISCOVERY,
        proof_required=False,
        risk_tolerance=0.2,
        completion_criteria=("changes_detected", "history_maintained"),
        description="Continuously monitor the target for change.",
    )
    specs[MissionObjective.FINDING_VALIDATION] = MissionObjectiveSpec(
        objective=MissionObjective.FINDING_VALIDATION,
        coverage_priorities=(
            "vulnerability_scanning",
            "proof_validation",
        ),
        allowed_capabilities=(
            "vulnerability_scanning",
            "sql_injection",
            "xss",
            "ssrf",
            "ssti",
            "xxe",
            "lfi",
            "rce",
            "idor",
            "proof_validation",
            "replay",
        ),
        validation_depth=ValidationLevel.PROOF,
        proof_required=True,
        risk_tolerance=0.3,
        completion_criteria=("findings_validated", "false_positives_filtered"),
        description="Validate candidate findings against the evidence lifecycle.",
    )
    specs[MissionObjective.PROOF_COLLECTION] = MissionObjectiveSpec(
        objective=MissionObjective.PROOF_COLLECTION,
        coverage_priorities=(
            "proof_validation",
            "replay",
        ),
        allowed_capabilities=(
            "proof_validation",
            "replay",
        ),
        validation_depth=ValidationLevel.PROOF,
        proof_required=True,
        risk_tolerance=0.3,
        completion_criteria=("proof_replay_validated", "report_ready_evidence"),
        description="Collect, replay and validate minimal-impact proof for candidate findings.",
    )
    return specs


#: Mission modes → additive score weights applied to the explainable ranking.
#: Modes adjust priorities only; they never touch authorization or safety.
MODE_WEIGHTS: dict[MissionMode, dict[str, float]] = {
    MissionMode.FAST: {
        "information_gain": 1.2,
        "coverage_improvement": 1.1,
        "execution_cost": 2.0,
        "execution_risk": 1.2,
        "redundancy": 1.5,
    },
    MissionMode.BALANCED: {},
    MissionMode.DEEP: {
        "information_gain": 1.3,
        "hypothesis_relevance": 1.3,
        "evidence_value": 1.2,
        "proof_value": 1.2,
        "execution_cost": 0.7,
    },
    MissionMode.STEALTH: {
        "execution_risk": 3.0,
        "execution_cost": 0.8,
        "redundancy": 1.2,
        "information_gain": 0.8,
    },
    MissionMode.COVERAGE_FIRST: {
        "coverage_improvement": 2.5,
        "information_gain": 1.4,
        "execution_risk": 0.8,
    },
    MissionMode.EVIDENCE_FIRST: {
        "evidence_value": 2.5,
        "hypothesis_relevance": 1.3,
        "proof_value": 1.1,
    },
    MissionMode.PROOF_FIRST: {
        "proof_value": 3.0,
        "evidence_value": 1.5,
        "hypothesis_relevance": 1.2,
    },
    MissionMode.BUG_BOUNTY: {
        "evidence_value": 1.4,
        "proof_value": 1.6,
        "execution_risk": 1.8,
        "redundancy": 1.3,
        "coverage_improvement": 0.9,
    },
    MissionMode.PENTEST: {
        "coverage_improvement": 1.4,
        "evidence_value": 1.2,
        "proof_value": 1.2,
        "execution_risk": 0.9,
    },
    MissionMode.RED_TEAM_SIMULATION: {
        "mission_priority": 1.4,
        "asset_criticality": 1.3,
        "execution_risk": 0.8,
    },
}
