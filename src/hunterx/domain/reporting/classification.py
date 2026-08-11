# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Finding classification engine.

Maps findings onto the canonical vulnerability taxonomy: CWE, OWASP
(Top 10 / API Top 10 / ASVS / Testing Guide), CAPEC, CVE and MITRE ATT&CK.
Mappings are evidence-backed and carry an explicit confidence and rationale;
ATT&CK mappings are only produced where a technique genuinely applies and are
never forced onto a finding. CVE identifiers are only attached when the
finding evidence references them — HunterX never invents CVEs.
"""

from __future__ import annotations

from hunterx.domain.reporting.enums import OwaspFramework
from hunterx.domain.reporting.models import (
    AttackMapping,
    Classification,
    CvssAssessment,
    CweMapping,
    OwaspMapping,
)
from hunterx.domain.vulnerability.cvss import parse_vector

#: CWE mapping per HunterX vulnerability class.
_CWE_BY_CLASS: dict[str, tuple[str, str, str]] = {
    "sql_injection": ("CWE-89", "Improper Neutralization of Special Elements used in an SQL Command", "Injection"),
    "xss": ("CWE-79", "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", "Injection"),
    "ssrf": ("CWE-918", "Server-Side Request Forgery (SSRF)", "Injection"),
    "ssti": ("CWE-1336", "Improper Neutralization of Special Elements Used in a Template Engine", "Injection"),
    "lfi": ("CWE-98", "Improper Control of Filename for Include/Require Statement in PHP Program", "CWE Research Concepts"),
    "rfi": ("CWE-98", "Improper Control of Filename for Include/Require Statement in PHP Program", "CWE Research Concepts"),
    "xxe": ("CWE-611", "Improper Restriction of XML External Entity Reference", "CWE Research Concepts"),
    "rce": ("CWE-94", "Improper Control of Generation of Code ('Code Injection')", "CWE Research Concepts"),
    "command_injection": ("CWE-78", "Improper Neutralization of Special Elements used in an OS Command", "Injection"),
    "path_traversal": ("CWE-22", "Improper Limitation of a Pathname to a Restricted Directory", "CWE Research Concepts"),
    "open_redirect": ("CWE-601", "URL Redirection to Untrusted Site", "CWE Research Concepts"),
    "csrf": ("CWE-352", "Cross-Site Request Forgery (CSRF)", "CWE Research Concepts"),
    "cors_misconfiguration": ("CWE-942", "Permissive Cross-domain Policy with Untrusted Domains", "CWE Research Concepts"),
    "host_header_injection": ("CWE-644", "Improper Neutralization of HTTP Headers for Scripting Syntax", "CWE Research Concepts"),
    "http_request_smuggling": ("CWE-444", "Inconsistent Interpretation of HTTP Requests", "CWE Research Concepts"),
    "jwt_weakness": ("CWE-345", "Insufficient Verification of Data Authenticity", "CWE Research Concepts"),
    "idor": ("CWE-639", "Authorization Bypass Through User-Controlled Key", "CWE Research Concepts"),
    "broken_access_control": ("CWE-284", "Improper Access Control", "Access Control"),
    "api_authorization": ("CWE-863", "Incorrect Authorization", "Access Control"),
    "graphql_authorization": ("CWE-863", "Incorrect Authorization", "Access Control"),
    "authentication_flaws": ("CWE-287", "Improper Authentication", "Authentication"),
    "cloud_exposure": ("CWE-668", "Exposure of Resource to Wrong Sphere", "CWE Research Concepts"),
    "secret_exposure": ("CWE-798", "Use of Hard-coded Credentials", "CWE Research Concepts"),
    "known_cve": ("CWE-710", "Improper Adherence to Coding Standards", "CWE Research Concepts"),
    "business_logic": ("CWE-840", "Business Logic Errors", "CWE Research Concepts"),
    "unknown_behavior": ("CWE-710", "Improper Adherence to Coding Standards", "CWE Research Concepts"),
}

#: OWASP Top 10 (2021) mapping per class.
_OWASP_TOP10: dict[str, tuple[str, str]] = {
    "sql_injection": ("A03", "Injection"),
    "xss": ("A03", "Injection"),
    "ssti": ("A03", "Injection"),
    "xxe": ("A03", "Injection"),
    "command_injection": ("A03", "Injection"),
    "idor": ("A01", "Broken Access Control"),
    "broken_access_control": ("A01", "Broken Access Control"),
    "api_authorization": ("A01", "Broken Access Control"),
    "graphql_authorization": ("A01", "Broken Access Control"),
    "cors_misconfiguration": ("A05", "Security Misconfiguration"),
    "security_misconfiguration": ("A05", "Security Misconfiguration"),
    "authentication_flaws": ("A07", "Identification and Authentication Failures"),
    "jwt_weakness": ("A07", "Identification and Authentication Failures"),
    "ssrf": ("A10", "Server-Side Request Forgery"),
    "lfi": ("A03", "Injection"),
    "rfi": ("A03", "Injection"),
    "rce": ("A03", "Injection"),
    "path_traversal": ("A01", "Broken Access Control"),
    "open_redirect": ("A01", "Broken Access Control"),
    "csrf": ("A01", "Broken Access Control"),
    "host_header_injection": ("A03", "Injection"),
    "http_request_smuggling": ("A04", "Insecure Design"),
    "cloud_exposure": ("A05", "Security Misconfiguration"),
    "secret_exposure": ("A07", "Identification and Authentication Failures"),
    "business_logic": ("A04", "Insecure Design"),
    "unknown_behavior": ("A04", "Insecure Design"),
}

#: OWASP API Top 10 (2023) mapping per class (only where the class is an API
#: authorization/injection class).
_API_MAP: dict[str, tuple[str, str]] = {
    "idor": ("API1", "Broken Object Level Authorization"),
    "broken_access_control": ("API5", "Broken Function Level Authorization"),
    "api_authorization": ("API5", "Broken Function Level Authorization"),
    "graphql_authorization": ("API5", "Broken Function Level Authorization"),
    "authentication_flaws": ("API2", "Broken Authentication"),
    "business_logic": ("API6", "Unrestricted Resource Consumption"),
    "ssrf": ("API8", "Security Misconfiguration"),
}

#: MITRE ATT&CK mapping per class (only where the technique genuinely applies).
_ATTACK_BY_CLASS: dict[str, tuple[str, str, str, str]] = {
    "rce": ("T1190", "", "Initial Access", "Exploit Public-Facing Application"),
    "known_cve": ("T1190", "", "Initial Access", "Exploit Public-Facing Application"),
    "sql_injection": ("T1190", "", "Initial Access", "Exploit Public-Facing Application"),
    "command_injection": ("T1190", "", "Initial Access", "Exploit Public-Facing Application"),
    "ssrf": ("T1595", "", "Reconnaissance", "Active Scanning"),
    "secret_exposure": ("T1552", "", "Credential Access", "Unsecured Credentials"),
    "cloud_exposure": ("T1552", "", "Credential Access", "Unsecured Credentials"),
}

#: CAPEC mapping per class.
_CAPEC_BY_CLASS: dict[str, tuple[str, ...]] = {
    "sql_injection": ("CAPEC-66",),
    "xss": ("CAPEC-63",),
    "ssrf": ("CAPEC-664",),
    "ssti": ("CAPEC-666",),
    "lfi": ("CAPEC-463",),
    "xxe": ("CAPEC-221",),
    "rce": ("CAPEC-242",),
    "command_injection": ("CAPEC-248",),
    "path_traversal": ("CAPEC-126",),
    "open_redirect": ("CAPEC-38",),
    "csrf": ("CAPEC-62",),
    "idor": ("CAPEC-64",),
    "broken_access_control": ("CAPEC-180",),
}


class ClassificationEngine:
    """Deterministic, evidence-driven classification of a finding.

    ``classify`` never attaches a CVE unless the finding references it, and
    never forces an ATT&CK mapping onto a finding.
    """

    def classify(
        self,
        *,
        vulnerability_class: str,
        cve_ids: tuple[str, ...] = (),
        cvss_vector: str | None = None,
        cvss_version: str = "3.1",
        reasoning_context: str = "",
    ) -> Classification:
        """Classify a finding across the canonical taxonomy.

        Args:
            vulnerability_class: HunterX canonical vulnerability class.
            cve_ids: CVE identifiers actually referenced by finding evidence.
            cvss_vector: CVSS vector when actually provided by evidence/tools.
            cvss_version: CVSS release version for the vector.
            reasoning_context: free-form context appended to rationales.

        Returns:
            The finding classification.

        """
        cls = vulnerability_class or "unknown_behavior"
        cwes: list[CweMapping] = []
        cwe = _CWE_BY_CLASS.get(cls)
        if cwe:
            cwe_id, title, category = cwe
            cwes.append(
                CweMapping(
                    cwe_id=cwe_id,
                    category=category,
                    title=title,
                    confidence=0.9,
                    rationale=f"canonical weakness for HunterX class '{cls}'{_ctx(reasoning_context)}",
                )
            )
        if cls == "known_cve" and cve_ids:
            cwes.append(
                CweMapping(
                    cwe_id="CWE-710",
                    category="CWE Research Concepts",
                    title="Improper Adherence to Coding Standards",
                    confidence=0.6,
                    rationale="class known_cve: CWE derived from the matched CVE, treat as a category marker",
                )
            )

        owasp: list[OwaspMapping] = []
        top10 = _OWASP_TOP10.get(cls)
        if top10:
            item_id, title = top10
            owasp.append(
                OwaspMapping(
                    framework=OwaspFramework.TOP_10,
                    item_id=f"2021-{item_id}",
                    title=title,
                    confidence=0.85,
                    rationale=f"OWASP Top 10 2021 category for class '{cls}'",
                )
            )
        api = _API_MAP.get(cls)
        if api:
            item_id, title = api
            owasp.append(
                OwaspMapping(
                    framework=OwaspFramework.API_TOP_10,
                    item_id=item_id,
                    title=title,
                    confidence=0.7,
                    rationale=f"OWASP API Top 10 2023 category for class '{cls}'",
                )
            )

        attack: list[AttackMapping] = []
        mapped = _ATTACK_BY_CLASS.get(cls)
        if mapped:
            technique_id, sub_id, tactic, name = mapped
            attack.append(
                AttackMapping(
                    technique_id=technique_id,
                    sub_technique_id=sub_id,
                    tactic=tactic,
                    technique_name=name,
                    confidence=0.5,
                    rationale=(
                        f"ATT&CK mapping only applies to the post-exploitation framing of '{cls}'; "
                        "it does not imply that the mapped stage was achieved"
                    ),
                )
            )

        cvss = None
        if cvss_vector:
            parsed = parse_vector(cvss_vector, version=cvss_version)
            cvss = CvssAssessment(
                version=parsed.version,
                vector=parsed.vector or "",
                base_score=parsed.base_score,
                severity=parsed.severity,
                source="finding.evidence",
                explanation="CVSS vector taken from finding evidence/tool output; not fabricated",
            )

        return Classification(
            vulnerability_class=cls,
            cwes=tuple(cwes),
            owasp=tuple(owasp),
            attack=tuple(attack),
            capecs=_CAPEC_BY_CLASS.get(cls, ()),
            cve_ids=tuple(dict.fromkeys(cve_ids)),
            cvss=cvss,
        )


def _ctx(context: str) -> str:
    """Append a reasoning context suffix when present."""
    return f" ({context})" if context else ""


__all__ = ["ClassificationEngine"]
