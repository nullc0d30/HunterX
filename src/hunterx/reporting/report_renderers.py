# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Professional report renderers.

Renderers convert a :class:`~hunterx.domain.reporting.models.ReportDocument`
into a concrete output format (Markdown, HTML, JSON, SARIF, PDF, structured
package). The renderers stay format-focused and never fabricate facts: they
only present the evidence-backed data of the report document.
"""

from __future__ import annotations

import html as _html
import json
from typing import Any

from hunterx.domain.reporting.models import ReportDocument

_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

_LEVEL_BY_SEVERITY = {
    "informational": "note",
    "low": "note",
    "medium": "warning",
    "high": "error",
    "critical": "error",
}


def render_markdown(document: ReportDocument) -> str:
    """Render ``document`` as professional Markdown."""
    lines: list[str] = [f"# {document.title}", ""]
    lines += [f"**Report ID:** `{document.report_id}`", f"**Finding:** `{document.finding_id}`"]
    lines += [f"**Template:** {document.template.value} v{document.template_version}"]
    lines += [f"**Status:** {document.status}", f"**Generated:** {document.generated_at}", ""]

    exec_summary = document.executive_summary
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- Findings: {exec_summary.finding_count}")
    if exec_summary.severity_distribution:
        lines.append(
            "- Severity distribution: "
            + ", ".join(f"{count} {severity}" for severity, count in sorted(exec_summary.severity_distribution.items()) if count)
        )
    if exec_summary.critical_assets:
        lines.append(f"- Critical assets: {', '.join(exec_summary.critical_assets)}")
    if exec_summary.major_attack_paths:
        lines.append(f"- Major attack paths: {', '.join(exec_summary.major_attack_paths)}")
    if exec_summary.root_causes:
        lines.append(f"- Root causes: {', '.join(exec_summary.root_causes)}")
    if exec_summary.risk_concentration:
        lines.append(f"- Risk concentration: {', '.join(exec_summary.risk_concentration)}")
    if exec_summary.remediation_priorities:
        lines.append("- Remediation priorities:")
        for priority in exec_summary.remediation_priorities:
            lines.append(f"  - {priority}")
    if exec_summary.validated_impact:
        lines.append(f"- Validated impact on: {', '.join(exec_summary.validated_impact)}")
    lines.append("")

    lines.append("## Finding")
    lines.append("")
    lines += [
        f"**Title:** {document.intelligence.title if document.intelligence else document.title}",
        f"**Vulnerability class:** {document.classification.vulnerability_class}",
        f"**Severity:** {document.severity.severity} (risk score {document.severity.risk_score})",
        f"**Confidence:** {document.intelligence.confidence if document.intelligence else 0.0}",
        f"**Priority:** {document.priority.priority.value.upper()}",
        f"**Quality:** {document.quality.quality_score:.2f} ({document.quality.quality_grade.value.upper()})",
        f"**Reportability:** {document.reportability.status.value}",
        f"**Finding state:** {document.intelligence.finding_state if document.intelligence else 'unknown'}",
    ]
    lines.append("")

    if document.classification.cwes:
        lines.append("### Classification")
        lines.append("")
        for cwe in document.classification.cwes:
            lines.append(f"- {cwe.cwe_id} ({cwe.title}) - confidence {cwe.confidence:.2f}")
        for owasp in document.classification.owasp:
            lines.append(f"- OWASP {owasp.framework.value} {owasp.item_id} ({owasp.title})")
        for attack in document.classification.attack:
            lines.append(f"- ATT&CK {attack.technique_id} ({attack.technique_name}) [{attack.tactic}]")
        if document.classification.cve_ids:
            lines.append(f"- CVEs: {', '.join(document.classification.cve_ids)}")
        if document.classification.cvss:
            cvss = document.classification.cvss
            lines.append(f"- CVSS v{cvss.version} {cvss.vector} = {cvss.base_score}")
        lines.append("")

    lines.append("### Severity Rationale")
    lines.append("")
    for reason in document.severity.reasoning:
        lines.append(f"- {reason}")
    lines.append("")

    lines.append("### Quality Explanation")
    lines.append("")
    lines.append(document.quality.quality_explanation)
    lines.append("")

    lines.append("### Impact")
    lines.append("")
    impact = document.impact
    if impact.dimensions:
        for impact_type, level in sorted(impact.dimensions.items()):
            if level not in ("none", ""):
                lines.append(f"- {impact_type.value}: {level}")
    else:
        lines.append("- No impact dimensions assessed.")
    lines.append("")

    if document.reproduction:
        lines.append("### Reproduction")
        lines.append("")
        reproduction = document.reproduction
        lines += [
            f"- Target: `{reproduction.target}`",
            f"- Endpoint: `{reproduction.endpoint}`",
            f"- Method: {reproduction.method}",
            f"- Parameter: `{reproduction.parameter}`",
            f"- Expected behavior: {reproduction.expected_behavior}",
            f"- Observed behavior: {reproduction.observed_behavior}",
        ]
        if reproduction.request:
            lines.append("")
            lines.append("```")
            lines.append(reproduction.request)
            lines.append("```")
        lines.append("")

    if document.poc:
        lines.append("### Proof of Concept")
        lines.append("")
        poc = document.poc
        lines += [
            f"- Type: {poc.poc_type}",
            f"- Purpose: {poc.purpose}",
            f"- Validation status: {poc.validation_status}",
            f"- Replay status: {poc.replay_status}",
        ]
        lines.append("")

    if document.remediation:
        lines.append("### Remediation")
        lines.append("")
        remediation = document.remediation
        sections = {
            "Immediate mitigations": remediation.immediate_mitigations,
            "Short-term fixes": remediation.short_term_fixes,
            "Long-term fixes": remediation.long_term_fixes,
            "Configuration changes": remediation.configuration_changes,
            "Code remediation": remediation.code_remediation,
            "Monitoring": remediation.monitoring_recommendations,
            "Validation": remediation.validation_recommendations,
        }
        for title, items in sections.items():
            if items:
                lines.append(f"**{title}:**")
                for item in items:
                    lines.append(f"- {item}")
                lines.append("")

    if document.retest:
        lines.append("### Retest Plan")
        lines.append("")
        retest = document.retest
        lines += [f"- State: {retest.state.value}"]
        for what in retest.what_must_change:
            lines.append(f"- What must change: {what}")
        for endpoint in retest.endpoints:
            lines.append(f"- Endpoint to test: `{endpoint}`")
        for behavior in retest.behaviors_to_disappear:
            lines.append(f"- Behavior that must disappear: {behavior}")
        for proof in retest.proofs_to_fail:
            lines.append(f"- Proof that must fail: {proof}")
        for criterion in retest.acceptance_criteria:
            lines.append(f"- Acceptance: {criterion}")
        lines.append("")

    lines.append("### Timeline")
    lines.append("")
    for entry in document.timeline.entries:
        lines.append(f"- {entry.occurred_at} {entry.event}: {entry.detail}")
    lines.append("")

    lines.append("### Evidence")
    lines.append("")
    bundle = document.evidence_bundle
    lines.append(f"- Bundle: `{bundle.bundle_id}` (hash `{bundle.bundle_hash}`)")
    for artifact in bundle.artifacts:
        lines.append(f"- {artifact.kind} `{artifact.artifact_id}` hash `{artifact.content_hash}` source `{artifact.source}`")
    lines.append("")

    lines.append("### Claims")
    lines.append("")
    for claim in document.claims:
        lines.append(f"- [{claim.verification_state.value}] {claim.claim_text} (sources: {len(claim.source_refs)})")
    lines.append("")

    lines.append("### QA")
    lines.append("")
    lines.append(f"- Verdict: {document.qa.verdict.value}")
    for check in document.qa.checks:
        lines.append(f"- [{check.verdict.value}] {check.name}: {check.detail}")
    lines.append("")

    if document.redaction.applied:
        lines.append("### Redaction")
        lines.append("")
        for record in document.redaction.records:
            lines.append(f"- {record.secret_type}: {record.masked_value}")
        lines.append("")

    lines.append("### Provenance")
    lines.append("")
    for provenance in document.tool_provenance:
        lines.append(
            f"- {provenance.tool} {provenance.version} (execution `{provenance.execution_id}`) "
            f"reliability {provenance.reliability.value}"
        )
    lines.append("")

    if document.references:
        lines.append("### References")
        lines.append("")
        for reference in document.references:
            lines.append(f"- {reference}")
        lines.append("")
    return "\n".join(lines) + "\n"


def render_html(document: ReportDocument) -> str:
    """Render ``document`` as a self-contained HTML page."""
    markdown = render_markdown(document)
    pre = _html.escape(markdown)
    return (
        "<!DOCTYPE html>\n"
        "<html><head><meta charset='utf-8'><title>"
        + _html.escape(document.title)
        + "</title></head><body>\n"
        f"<h1>{_html.escape(document.title)}</h1>\n"
        "<main>\n"
        f"<pre>{pre}</pre>\n"
        "</main>\n"
        "<footer><p>HunterX professional report</p></footer>\n"
        "</body></html>\n"
    )


def render_json(document: ReportDocument) -> str:
    """Render ``document`` as a structured JSON document."""
    return json.dumps(document.to_dict(), indent=2, default=str)


def render_sarif(document: ReportDocument) -> str:
    """Render ``document`` as a SARIF 2.1.0 result.

    HunterX-specific evidence references are preserved in the ``properties``
    of each result.
    """
    finding_id = document.finding_id
    severity = document.severity.severity
    rule_id = f"HX-{document.classification.vulnerability_class.upper()}"
    cwes = [cwe.cwe_id for cwe in document.classification.cwes]
    description = document.intelligence.description if document.intelligence else document.title
    payload: dict[str, Any] = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "HunterX",
                        "semanticVersion": "7.1.1",
                        "informationUri": "https://github.com/nullc0d30/HunterX",
                        "rules": [
                            {
                                "id": rule_id,
                                "name": document.classification.vulnerability_class,
                                "shortDescription": {"text": document.title},
                                "fullDescription": {"text": description},
                                "properties": {
                                    "cwes": cwes,
                                    "owasp": [owasp.item_id for owasp in document.classification.owasp],
                                    "attack": [attack.technique_id for attack in document.classification.attack],
                                    "priority": document.priority.priority.value,
                                    "quality": document.quality.quality_score,
                                    "confidence": document.intelligence.confidence if document.intelligence else 0.0,
                                },
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": rule_id,
                        "level": _LEVEL_BY_SEVERITY.get(severity, "warning"),
                        "message": {"text": description},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": document.target_id or finding_id},
                                }
                            }
                        ],
                        "partialFingerprints": {
                            "primaryLocationLineHash": document.evidence_bundle.bundle_hash
                        },
                        "properties": {
                            "findingId": finding_id,
                            "reportId": document.report_id,
                            "severity": severity,
                            "evidenceBundle": document.evidence_bundle.bundle_id,
                            "evidenceHashes": [artifact.content_hash for artifact in document.evidence_bundle.artifacts],
                            "claims": [claim.claim_text for claim in document.claims],
                            "qaVerdict": document.qa.verdict.value,
                            "status": document.status,
                        },
                    }
                ],
            }
        ],
    }
    return json.dumps(payload, indent=2, default=str)


def render_pdf(document: ReportDocument) -> str:
    """Render ``document`` as a minimal, deterministic PDF document.

    The generator produces a valid single-page PDF using only the standard
    library (no optional dependencies). Text is the professional report
    content, escaped per the PDF text-string rules.
    """
    markdown = render_markdown(document)
    text_lines = [line for line in markdown.splitlines() if line and not line.startswith("#")]
    # A PDF text object per line; keep the page from overflowing.
    body_lines = text_lines[:48]

    def esc(value: str) -> str:
        return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    stream_parts: list[str] = ["BT", "/F1 9 Tf", "50 740 Td", "14 TL"]
    for line in body_lines:
        clipped = line[:120]
        stream_parts.append(f"({esc(clipped)}) Tj")
        stream_parts.append("T*")
    stream_parts.append("ET")
    stream = "\n".join(stream_parts).encode("latin-1", "replace")
    length = len(stream)

    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length " + str(length).encode() + b" >>\nstream\n" + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    return _assemble_pdf(objects)


def _assemble_pdf(objects: list[bytes]) -> str:
    """Assemble PDF objects into a minimal valid PDF document."""
    out = bytearray(b"%PDF-1.4\n")
    offsets: list[int] = []
    for index, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{index} 0 obj\n".encode()
        out += body
        out += b"\nendobj\n"
    xref_pos = len(out)
    out += b"xref\n"
    out += f"0 {len(objects) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode()
    trailer = (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n"
    )
    out += trailer.encode()
    return out.decode("latin-1")


def render_package(document: ReportDocument) -> str:
    """Render ``document`` as the structured HunterX finding package.

    This is the canonical machine-readable representation of the report
    document.
    """
    return render_json(document)


def render(document: ReportDocument, *, fmt: str) -> str:
    """Dispatch ``document`` to the renderer for ``fmt``.

    Raises:
        ValueError: when ``fmt`` is not a supported export format.

    """
    renderers = {
        "markdown": render_markdown,
        "html": render_html,
        "json": render_json,
        "sarif": render_sarif,
        "pdf": render_pdf,
        "package": render_package,
    }
    renderer = renderers.get(fmt)
    if renderer is None:
        raise ValueError(f"unsupported report export format '{fmt}'")
    return renderer(document)


__all__ = [
    "render",
    "render_html",
    "render_json",
    "render_markdown",
    "render_package",
    "render_pdf",
    "render_sarif",
]
