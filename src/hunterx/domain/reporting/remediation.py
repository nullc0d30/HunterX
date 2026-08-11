# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Remediation engine.

Generates evidence-based remediation guidance that is technically relevant to
the actual root cause. Generic advice such as "sanitize input" is avoided when
the evidence indicates a specific architectural problem: the catalog keys
remediation on the vulnerability class and, when provided, the root cause, and
always produces immediate, short-term, long-term, configuration, code,
monitoring and validation recommendations.
"""

from __future__ import annotations

from dataclasses import dataclass

from hunterx.domain.reporting.models import RemediationPlan


@dataclass(frozen=True, slots=True)
class RemediationInput:
    """Inputs for the remediation engine.

    Attributes:
        finding_id: owning finding.
        vulnerability_class: canonical class.
        root_cause: root-cause description when known.
        root_cause_id: root-cause identifier when known.
        affected_components: affected component names.
        evidence_refs: supporting evidence references.

    """

    finding_id: str = ""
    vulnerability_class: str = "unknown_behavior"
    root_cause: str = ""
    root_cause_id: str = ""
    affected_components: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()


class RemediationEngine:
    """Deterministic, root-cause-aware remediation generator."""

    def build(self, inp: RemediationInput) -> RemediationPlan:
        """Build a remediation plan for ``inp``.

        Returns:
            An evidence-based :class:`RemediationPlan`.

        """
        cls = inp.vulnerability_class or "unknown_behavior"
        entries = _CATALOG.get(cls, _CATALOG["unknown_behavior"])
        components = ", ".join(inp.affected_components) if inp.affected_components else "the affected endpoint"
        if inp.root_cause:
            entries = _with_root_cause_note(entries, inp.root_cause, components)
        return RemediationPlan(
            finding_id=inp.finding_id,
            root_cause_id=inp.root_cause_id,
            immediate_mitigations=entries["immediate"],
            short_term_fixes=entries["short"],
            long_term_fixes=entries["long"],
            configuration_changes=entries["config"],
            code_remediation=entries["code"],
            monitoring_recommendations=entries["monitoring"],
            validation_recommendations=entries["validation"],
            evidence_refs=inp.evidence_refs,
            created_at=_now(),
        )


def _now() -> str:
    """Return the current UTC ISO-8601 timestamp."""
    from hunterx.shared.time import utcnow_iso

    return utcnow_iso()


def _with_root_cause_note(
    entries: dict[str, tuple[str, ...]], root_cause: str, components: str
) -> dict[str, tuple[str, ...]]:
    """Prepend a root-cause-aware note to the long-term fixes."""
    note = (
        f"Because the evidence indicates a shared root cause ('{root_cause}'), "
        f"fix the root cause once and verify every affected component ({components}) "
        "rather than patching individual symptoms."
    )
    return {
        **entries,
        "long": (note, *entries.get("long", ())),
    }


#: Remediation catalog keyed by vulnerability class.
_CATALOG: dict[str, dict[str, tuple[str, ...]]] = {
    "sql_injection": {
        "immediate": ("Restrict database account privileges used by the application to least privilege.", "Place the endpoint behind a WAF rule while the fix lands."),
        "short": ("Move to parameterized queries / prepared statements for every dynamic SQL path.", "Enforce strict allow-list input validation at the API boundary."),
        "long": ("Adopt an ORM and remove string-concatenated SQL entirely from the codebase.", "Add positive application-layer input validation at the framework boundary."),
        "config": ("Disable verbose database error messages that reveal query structure.",),
        "code": ("Replace f-string/concatenation SQL construction with bind parameters.", "Treat the query as untrusted input: no user-controlled value may become SQL structure."),
        "monitoring": ("Alert on SQL error patterns and slow anomalous queries tied to the endpoint.",),
        "validation": ("Replay the original PoC after the fix and verify the differential database behavior disappears.", "Re-run the validation chain and re-confirm the controlled callback no longer fires."),
    },
    "xss": {
        "immediate": ("Apply Content-Security-Policy and disable inline script where feasible.", "Escape the affected output context as a temporary mitigation."),
        "short": ("Context-aware encoding for the affected sink.", "Use framework-native auto-escaping templates."),
        "long": ("Adopt a strict CSP and refactor dynamic output through a single escaping layer.",),
        "config": ("Set secure cookie flags and CSP headers at the host level.",),
        "code": ("Encode output at every reflection sink; never trust stored user data as markup.",),
        "monitoring": ("Monitor for reflected payload signatures in access logs.",),
        "validation": ("Replay the reflection PoC and confirm the payload renders as text, not markup.",),
    },
    "ssrf": {
        "immediate": ("Block outbound requests to internal ranges from the application tier at the network boundary.", "Disable the vulnerable fetch feature if not business-critical."),
        "short": ("Allow-list destination hosts/ports for server-side fetch operations.", "Reject redirects that escape the allow-list."),
        "long": ("Route outbound fetches through a dedicated proxy with allow-list and DNS rebinding protection.",),
        "config": ("Apply egress firewall rules denying access to link-local and private ranges.",),
        "code": ("Validate and canonicalize the destination before the fetch; resolve DNS and re-validate the resolved IP.",),
        "monitoring": ("Alert on outbound requests from the application to unexpected internal hosts.",),
        "validation": ("Re-run the controlled-callback PoC and confirm no internal callback fires.",),
    },
    "ssti": {
        "immediate": ("Disable the template engine's sandbox bypass features if the template input is user-controlled.", "Restrict template editing to trusted administrators."),
        "short": ("Never evaluate user input as a template; use static template selection.",),
        "long": ("Separate user data from template structure entirely.",),
        "config": ("Lock template paths and disable dynamic template compilation.",),
        "code": ("Replace dynamic template evaluation with a fixed template plus bind parameters.",),
        "monitoring": ("Monitor template compilation errors for anomalous user content.",),
        "validation": ("Replay the template-injection PoC and confirm expression evaluation no longer executes.",),
    },
    "idor": {
        "immediate": ("Temporarily restrict the endpoint to administrators while the authorization fix lands.",),
        "short": ("Add object-level authorization checks to the affected resource handler.", "Use ownership checks against the authenticated subject."),
        "long": ("Centralize object-level authorization in middleware so no handler can forget the check.", "Adopt UUID/hard-to-guess identifiers only as defense-in-depth, not as the control."),
        "config": ("Enable framework authorization policies on the affected routes.",),
        "code": ("Authorize against the authenticated principal before returning any resource by key.",),
        "monitoring": ("Alert on cross-tenant resource access attempts by the same account.",),
        "validation": ("Replay the differential authorization-state PoC: an unprivileged account must no longer receive the resource.",),
    },
    "broken_access_control": {
        "immediate": ("Temporarily disable the misconfigured access path while the fix lands.",),
        "short": ("Enforce function-level authorization on every administrative route.",),
        "long": ("Centralize an authorization policy layer and default-deny new routes.",),
        "config": ("Fix the misconfigured access-control policy/roles.",),
        "code": ("Apply authorization decorators/checks on every handler, not just the frontend.",),
        "monitoring": ("Alert on privilege-boundary crossings detected in audit logs.",),
        "validation": ("Replay the authorization-state comparison and confirm the unauthorized request is denied.",),
    },
    "rce": {
        "immediate": ("Isolate the vulnerable component and restrict its network access.", "Apply vendor patches if available."),
        "short": ("Prevent user input from reaching the execution primitive; validate against an allow-list.",),
        "long": ("Remove the code-evaluation surface entirely or move it to a sandboxed service.",),
        "config": ("Run the application with least privilege; block outbound network from the process.",),
        "code": ("Never pass user input to eval/exec/system; use fixed command templates with validated arguments.",),
        "monitoring": ("Monitor for child-process spawns from the application with anomalous arguments.",),
        "validation": ("Replay the execution PoC in a controlled environment and confirm no code executes; verify with a benign marker only.",),
    },
    "cloud_exposure": {
        "immediate": ("Restrict the exposed resource policy to the least privilege required.", "If internet-exposed, move the resource behind a private network or VPN."),
        "short": ("Enforce deny-by-default IAM/resource policies and add explicit allow rules.", "Enable encryption in transit and at rest for the resource."),
        "long": ("Centralize cloud security posture management and automated policy drift detection.",),
        "config": ("Fix bucket/container/queue policy allowing public access; disable anonymous write.",),
        "code": ("Use signed URLs and short-lived credentials for programmatic access.",),
        "monitoring": ("Alert on public-exposure indicators and anonymous access events.",),
        "validation": ("Re-run the exposure validation and confirm anonymous access is denied.",),
    },
    "secret_exposure": {
        "immediate": ("Rotate the exposed secret immediately.", "Revoke the leaked credential/API key/token."),
        "short": ("Scan the repository and runtime for other occurrences of the same secret.", "Move secrets to a managed secret store."),
        "long": ("Enforce secret scanning in CI and block commits containing secrets.", "Adopt short-lived credentials and automated rotation."),
        "config": ("Remove hard-coded credentials from configuration; load from environment/secret vault.",),
        "code": ("Inject secrets at runtime from a secret manager; never embed them in code or config.",),
        "monitoring": ("Alert on unauthorized use of the rotated secret identity.",),
        "validation": ("Verify the old credential no longer authenticates and the exposed reference is redacted in reports.",),
    },
    "business_logic": {
        "immediate": ("Pause the affected business flow while the logic flaw is corrected.",),
        "short": ("Enforce the missing business rule server-side at the affected transition.",),
        "long": ("Model business invariants in the domain layer so they cannot be bypassed by direct calls.",),
        "config": ("Configure server-side limits/validations for the affected process.",),
        "code": ("Validate state transitions against business invariants on the server, not the client.",),
        "monitoring": ("Monitor for anomalous business-flow sequences (rate, order, value).",),
        "validation": ("Replay the state-transition PoC and confirm the invalid transition is rejected.",),
    },
    "unknown_behavior": {
        "immediate": ("Treat the behavior as unverified; do not report as a vulnerability without validation.",),
        "short": ("Investigate the behavior under controlled conditions and gather differential evidence.",),
        "long": ("Extend the validation catalog with a reproducible hypothesis before any fix.",),
        "config": ("None applicable until the behavior is classified.",),
        "code": ("Await classification before prescribing code changes.",),
        "monitoring": ("Capture the observed behavior for further analysis.",),
        "validation": ("Confirm the behavior is reproducible and evidence-backed before reporting.",),
    },
}


__all__ = ["RemediationEngine", "RemediationInput"]
