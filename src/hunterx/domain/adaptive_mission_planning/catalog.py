# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Deterministic planning policies.

The system must remain fully functional without AI. These policies provide the
deterministic planning behaviors for asset discovery, coverage completion,
hypothesis validation, proof completion, recovery, replanning and novel
behaviour investigation. AI is an enhancement, never a single point of
failure.
"""

from __future__ import annotations

from hunterx.domain.adaptive_mission_planning.enums import (
    FailureClass,
    MissionObjective,
    ReplanTrigger,
)

#: Deterministic discovery chains per objective.
_DISCOVERY_CHAINS: dict[MissionObjective, tuple[str, ...]] = {
    MissionObjective.ATTACK_SURFACE_DISCOVERY: (
        "subdomain_enumeration",
        "dns_enumeration",
        "port_discovery",
        "service_detection",
        "technology_fingerprint",
        "certificate_enumeration",
        "endpoint_enumeration",
    ),
    MissionObjective.WEB_SECURITY_ASSESSMENT: (
        "endpoint_enumeration",
        "content_discovery",
        "parameter_discovery",
        "technology_fingerprint",
        "vulnerability_scanning",
    ),
    MissionObjective.API_SECURITY_ASSESSMENT: (
        "api_mapping",
        "endpoint_enumeration",
        "parameter_discovery",
        "authentication_analysis",
        "authorization_analysis",
    ),
    MissionObjective.CLOUD_SECURITY_ASSESSMENT: (
        "cloud_ownership_mapping",
        "asset_discovery",
        "secret_detection",
        "vulnerability_scanning",
    ),
    MissionObjective.NETWORK_SECURITY_ASSESSMENT: (
        "asset_discovery",
        "port_discovery",
        "service_detection",
        "technology_fingerprint",
        "vulnerability_scanning",
    ),
    MissionObjective.VULNERABILITY_DISCOVERY: (
        "technology_fingerprint",
        "endpoint_enumeration",
        "content_discovery",
        "parameter_discovery",
        "vulnerability_scanning",
        "dependency_check",
    ),
    MissionObjective.BUG_BOUNTY_ASSESSMENT: (
        "endpoint_enumeration",
        "content_discovery",
        "parameter_discovery",
        "vulnerability_scanning",
    ),
    MissionObjective.PENTEST_ASSESSMENT: (
        "asset_discovery",
        "endpoint_enumeration",
        "content_discovery",
        "parameter_discovery",
        "vulnerability_scanning",
    ),
    MissionObjective.RED_TEAM_SIMULATION: (
        "asset_discovery",
        "endpoint_enumeration",
        "authorization_analysis",
    ),
    MissionObjective.TARGET_MONITORING: ("asset_discovery", "subdomain_enumeration", "technology_fingerprint"),
    MissionObjective.FINDING_VALIDATION: ("vulnerability_scanning", "proof_validation"),
    MissionObjective.PROOF_COLLECTION: ("proof_validation", "replay"),
}

#: Hypothesis type → validation capability chain.
_HYPOTHESIS_VALIDATION: dict[str, tuple[str, ...]] = {
    "injection": ("sql_injection", "proof_validation"),
    "xss": ("xss", "proof_validation"),
    "ssrf": ("ssrf", "proof_validation"),
    "ssti": ("ssti", "proof_validation"),
    "xxe": ("xxe", "proof_validation"),
    "lfi": ("lfi", "proof_validation"),
    "rfi": ("lfi", "proof_validation"),
    "rce": ("rce", "proof_validation"),
    "idor": ("idor", "proof_validation"),
    "authorization_issue": ("authorization_analysis", "proof_validation"),
    "authentication_issue": ("authentication_analysis", "proof_validation"),
    "api_security": ("api_security", "proof_validation"),
    "graphql_security": ("graphql_security", "proof_validation"),
    "cloud_exposure": ("cloud_ownership_mapping", "proof_validation"),
    "secret_exposure": ("secret_detection", "proof_validation"),
    "dependency_vulnerability": ("dependency_check", "proof_validation"),
    "known_vulnerability": ("vulnerability_scanning", "proof_validation"),
    "unknown_behavior": ("asset_discovery", "vulnerability_scanning", "proof_validation"),
    "novel_variant": ("asset_discovery", "vulnerability_scanning", "proof_validation"),
}


class DeterministicPlanner:
    """Deterministic planning policies used without AI."""

    def discovery_chain(self, objective: MissionObjective) -> tuple[str, ...]:
        """Return the deterministic discovery chain for ``objective``."""
        return _DISCOVERY_CHAINS.get(objective, _DISCOVERY_CHAINS[MissionObjective.ATTACK_SURFACE_DISCOVERY])

    def coverage_completion(self, uncovered_capabilities: list[str]) -> tuple[str, ...]:
        """Return capabilities that would close the given coverage gaps."""
        order = [
            "asset_discovery",
            "subdomain_enumeration",
            "port_discovery",
            "service_detection",
            "technology_fingerprint",
            "endpoint_enumeration",
            "content_discovery",
            "parameter_discovery",
            "api_mapping",
            "vulnerability_scanning",
            "proof_validation",
        ]
        return tuple(cap for cap in order if cap in uncovered_capabilities)

    def hypothesis_validation(self, hypothesis_types: list[str]) -> tuple[str, ...]:
        """Return the validation chain for the given hypothesis types."""
        chain: list[str] = []
        for hypothesis_type in hypothesis_types:
            for capability in _HYPOTHESIS_VALIDATION.get(hypothesis_type, ("vulnerability_scanning",)):
                if capability not in chain:
                    chain.append(capability)
        return tuple(chain)

    def proof_completion(self, finding_classes: list[str]) -> tuple[str, ...]:
        """Return the proof chain for candidate findings."""
        chain: list[str] = []
        for finding_class in finding_classes:
            for capability in _HYPOTHESIS_VALIDATION.get(finding_class, ("vulnerability_scanning", "proof_validation")):
                if capability not in chain:
                    chain.append(capability)
        chain.extend(("replay",))
        return tuple(chain)

    def recovery(self, failure_class: FailureClass) -> tuple[str, ...]:
        """Return the capabilities to re-plan after a classified failure."""
        if failure_class is FailureClass.TIMEOUT:
            return ("asset_discovery",)
        if failure_class is FailureClass.TARGET_CHANGED:
            return ("asset_discovery", "subdomain_enumeration")
        if failure_class is FailureClass.POLICY_BLOCK:
            return ()
        return ("asset_discovery",)

    def replanning_capability(self, trigger: ReplanTrigger) -> tuple[str, ...]:
        """Return the capabilities needed to respond to ``trigger``."""
        mapping: dict[ReplanTrigger, tuple[str, ...]] = {
            ReplanTrigger.NEW_ASSET_DISCOVERED: ("port_discovery", "service_detection"),
            ReplanTrigger.NEW_TECHNOLOGY_DISCOVERED: ("vulnerability_scanning",),
            ReplanTrigger.NEW_ENDPOINT_DISCOVERED: ("parameter_discovery",),
            ReplanTrigger.NEW_PARAMETER_DISCOVERED: ("vulnerability_scanning",),
            ReplanTrigger.NEW_HYPOTHESIS_CREATED: ("vulnerability_scanning", "proof_validation"),
            ReplanTrigger.PROOF_FAILED: ("vulnerability_scanning",),
            ReplanTrigger.CONFLICTING_EVIDENCE: ("asset_discovery",),
            ReplanTrigger.UNKNOWN_BEHAVIOR_OBSERVED: ("asset_discovery", "vulnerability_scanning"),
            ReplanTrigger.SCOPE_CHANGED: (),
        }
        return mapping.get(trigger, ("asset_discovery",))

    def unknown_behavior_investigation(self) -> tuple[str, ...]:
        """Return the investigation chain for unknown behavior."""
        return ("asset_discovery", "vulnerability_scanning", "proof_validation", "replay")
