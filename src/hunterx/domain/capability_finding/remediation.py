# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Class-specific remediation guidance.

Remediation is never generic: every vulnerability class has its own concrete
mitigation steps, and the guide adapts to the candidate's evidence (e.g. an
error-signal injection finding adds error-suppression steps, a reflected
signal adds output-encoding steps).
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.capability_finding.models import CapabilityCandidate, Remediation

#: Class-specific remediation guides (title + concrete steps + references).
_GUIDES: dict[str, dict[str, Any]] = {
    "sql_injection": {
        "title": "Use parameterized queries / prepared statements",
        "steps": (
            "Replace string-built SQL with parameterized queries or prepared statements for every SQL statement",
            "Apply least-privilege database accounts; never run application queries as the schema owner",
            "Validate and whitelist inputs against the expected type/length before binding",
            "Suppress database error messages from responses; log them server-side only",
        ),
        "references": ("CWE-89", "OWASP A03:2021 - Injection"),
    },
    "nosql_injection": {
        "title": "Sanitize and validate NoSQL query inputs",
        "steps": (
            "Reject operator-bearing input (e.g. '$', '{', '}') for string parameters",
            "Use schema-bound validation libraries that escape query operators",
            "Treat all query parameters as data, never as query fragments",
            "Suppress database error details from responses",
        ),
        "references": ("CWE-943", "OWASP A03:2021 - Injection"),
    },
    "xss": {
        "title": "Encode output and adopt a content security policy",
        "steps": (
            "Context-appropriate encode all user-controlled output (HTML, attribute, JS, CSS, URL)",
            "Set a strict Content-Security-Policy and disable inline script execution",
            "Use a framework that auto-escapes templates (e.g. EJS with escape, React, Vue)",
            "Set HttpOnly + Secure + SameSite attributes on all session cookies",
        ),
        "references": ("CWE-79", "OWASP A03:2021 - Injection"),
    },
    "ssrf": {
        "title": "Restrict outbound requests to an allowlist",
        "steps": (
            "Resolve the target host and validate it against an allowlist of internal services",
            "Block access to loopback, link-local and metadata addresses (169.254.169.254, 127.0.0.0/8)",
            "Disable redirects for server-side fetches or re-validate each hop",
            "Run server-side fetch logic in a segmented network with egress filtering",
        ),
        "references": ("CWE-918", "OWASP A10:2021 - SSRF"),
    },
    "ssti": {
        "title": "Never render user input as a template",
        "steps": (
            "Treat user input as data; use template engines with automatic escaping",
            "Disable template introspection and sandboxed functions when server-side rendering is required",
            "Whitelist allowed template variables and functions",
            "Keep the template engine patched against known expression-injection CVEs",
        ),
        "references": ("CWE-1336", "OWASP A03:2021 - Injection"),
    },
    "lfi": {
        "title": "Validate paths against an allowlist, never against user input",
        "steps": (
            "Map user-supplied file names to a server-side allowlist of permitted files",
            "Normalize and canonicalize paths; reject any path escaping the base directory",
            "Do not expose filesystem paths in URLs; use identifiers instead",
            "Run the application with the least privileges needed to read required files",
        ),
        "references": ("CWE-98", "OWASP A01:2021 - Broken Access Control"),
    },
    "rfi": {
        "title": "Block remote file inclusion",
        "steps": (
            "Disable remote file inclusion for all include/require functions",
            "Serve uploads from an isolated domain never reachable through include paths",
            "Validate file sources against an allowlist of trusted hosts",
            "Use content delivery via dedicated endpoints, never through include directives",
        ),
        "references": ("CWE-98", "OWASP A01:2021 - Broken Access Control"),
    },
    "xxe": {
        "title": "Disable external entity processing in XML parsers",
        "steps": (
            "Configure the XML parser with external entities and DTDs disabled",
            "Use a JSON parser instead of XML wherever the data model allows",
            "Validate and limit the size and depth of parsed documents",
            "Suppress parser error details from responses",
        ),
        "references": ("CWE-611", "OWASP A05:2021 - Security Misconfiguration"),
    },
    "rce": {
        "title": "Never execute user input as code",
        "steps": (
            "Remove any code-evaluation path that consumes user input (eval, exec, dynamic includes)",
            "Run the application in an unprivileged, sandboxed runtime",
            "Apply operating-system and runtime security patches",
            "Instrument execution paths for anomalous child processes",
        ),
        "references": ("CWE-94", "OWASP A03:2021 - Injection"),
    },
    "command_injection": {
        "title": "Do not build OS commands from input",
        "steps": (
            "Replace OS command execution with library/API calls",
            "If a shell is unavoidable, pass arguments as a fixed token list and never concatenate input",
            "Run command execution under a dedicated low-privilege service account",
            "Suppress command output details from responses",
        ),
        "references": ("CWE-78", "OWASP A03:2021 - Injection"),
    },
    "path_traversal": {
        "title": "Canonicalize and constrain file access",
        "steps": (
            "Canonicalize the resolved path and verify it stays within the allowed base directory",
            "Reject absolute paths, drive letters and '..' segments before lookup",
            "Map user input to identifiers rather than filesystem paths",
            "Serve files through a dedicated handler with no direct filesystem access",
        ),
        "references": ("CWE-22", "OWASP A01:2021 - Broken Access Control"),
    },
    "idor": {
        "title": "Authorize object access on every request",
        "steps": (
            "Authorize each object access against the caller's session, never against a client-supplied id alone",
            "Use unpredictable identifiers (UUIDs) for external references",
            "Apply the same authorization check in list, detail, update and delete endpoints",
            "Add audit logging for cross-tenant access attempts",
        ),
        "references": ("CWE-639", "OWASP A01:2021 - Broken Access Control"),
    },
    "broken_access_control": {
        "title": "Enforce authorization server-side on every endpoint",
        "steps": (
            "Implement a centralized authorization layer; deny by default",
            "Never trust client-supplied role/ACL fields",
            "Test every endpoint with multiple roles and anonymous sessions",
            "Revoke tokens/sessions on role changes",
        ),
        "references": ("CWE-284", "OWASP A01:2021 - Broken Access Control"),
    },
    "authorization": {
        "title": "Centralize and enforce authorization decisions",
        "steps": (
            "Move authorization decisions to a single policy service used by all endpoints",
            "Default-deny: explicit allow rules per role and resource",
            "Include object-level checks in addition to endpoint-level checks",
            "Log and monitor denied attempts for abuse patterns",
        ),
        "references": ("CWE-862", "OWASP A01:2021 - Broken Access Control"),
    },
    "authentication_flaws": {
        "title": "Harden the authentication flow",
        "steps": (
            "Enforce strong password policy, MFA and account lockout with rate limiting",
            "Use a well-tested authentication library; do not hand-roll credential checks",
            "Secure session tokens (HttpOnly, Secure, SameSite; rotate on privilege change)",
            "Implement account-recovery flows with the same scrutiny as login",
        ),
        "references": ("CWE-287", "OWASP A07:2021 - Identification and Authentication Failures"),
    },
    "authentication": {
        "title": "Replace weak or bypassable authentication",
        "steps": (
            "Eliminate hardcoded, guessable or reusable credentials and backdoor tokens",
            "Route every protected resource through the same authentication middleware",
            "Reject blank, default and well-known credential combinations",
            "Enforce session expiry and revocation on logout",
        ),
        "references": ("CWE-287", "OWASP A07:2021 - Identification and Authentication Failures"),
    },
    "open_redirect": {
        "title": "Validate redirect targets against an allowlist",
        "steps": (
            "Only redirect to relative paths or hostnames on the application's allowlist",
            "Treat the 'next'/'return' parameter as data; resolve it server-side",
            "Add a warning page for external redirects when they must exist",
        ),
        "references": ("CWE-601", "OWASP A03:2021 - Injection"),
    },
    "csrf": {
        "title": "Bind state-changing requests to the session",
        "steps": (
            "Use synchronizer tokens or double-submit cookies on every state-changing request",
            "Verify the Origin/Sec-Fetch-Site header server-side as defense in depth",
            "Set SameSite=Strict or Lax on session cookies",
            "Require re-authentication for high-impact actions",
        ),
        "references": ("CWE-352", "OWASP A01:2021 - Broken Access Control"),
    },
    "cors_misconfiguration": {
        "title": "Restrict cross-origin access",
        "steps": (
            "Reflect only trusted origins in Access-Control-Allow-Origin; never '*' with credentials",
            "Validate the Origin header against an explicit allowlist",
            "Keep Access-Control-Allow-Credentials limited to endpoints that need it",
            "Review preflight behavior for sensitive methods",
        ),
        "references": ("CWE-942", "OWASP A05:2021 - Security Misconfiguration"),
    },
    "security_misconfiguration": {
        "title": "Harden server and framework configuration",
        "steps": (
            "Disable default accounts, sample content, directory listings and verbose error pages",
            "Set secure response headers (HSTS, X-Content-Type-Options, CSP, X-Frame-Options)",
            "Run the framework with production settings and patched versions",
            "Audit configuration files for secrets and permissive defaults",
        ),
        "references": ("CWE-16", "OWASP A05:2021 - Security Misconfiguration"),
    },
    "host_header_injection": {
        "title": "Validate the Host header against an allowlist",
        "steps": (
            "Accept requests only for known hostnames; reject unknown Host values",
            "Generate absolute URLs from a configuration value, never from the Host header",
            "Do not reflect the Host header into password-reset links or redirects",
        ),
        "references": ("CWE-644", "OWASP A05:2021 - Security Misconfiguration"),
    },
    "http_request_smuggling": {
        "title": "Normalize HTTP parsing across proxies and backends",
        "steps": (
            "Reject conflicting Content-Length/Transfer-Encoding handling; use one canonical path",
            "Disable request body buffering inconsistencies at the reverse proxy",
            "Run a single, hardened HTTP parser fronting the application",
            "Test smuggling patterns in every release pipeline",
        ),
        "references": ("CWE-444", "OWASP A04:2021 - Insecure Design"),
    },
    "jwt_weakness": {
        "title": "Harden JSON Web Token verification",
        "steps": (
            "Verify the token algorithm explicitly; never accept 'none' or algorithm confusion",
            "Use short-lived tokens with secure, rotated signing keys",
            "Validate audience, issuer and expiry on every request",
            "Enforce key length and algorithm policy (e.g. RS256 with >= 2048-bit keys)",
        ),
        "references": ("CWE-347", "OWASP A07:2021 - Identification and Authentication Failures"),
    },
    "graphql_authorization": {
        "title": "Authorize every GraphQL field",
        "steps": (
            "Apply field-level authorization resolvers; schema-level checks are not enough",
            "Prevent introspection of sensitive fields in production",
            "Rate-limit and depth-limit queries to prevent abuse",
            "Deny batched queries that cross authorization boundaries",
        ),
        "references": ("CWE-284", "OWASP A01:2021 - Broken Access Control"),
    },
    "graphql_security": {
        "title": "Harden the GraphQL API surface",
        "steps": (
            "Disable introspection and debug endpoints in production",
            "Enforce query depth, complexity and batch limits",
            "Apply authentication and field-level authorization consistently",
            "Validate and coerce all input arguments server-side",
        ),
        "references": ("CWE-284", "OWASP A01:2021 - Broken Access Control"),
    },
    "api_authorization": {
        "title": "Enforce per-resource authorization on every API route",
        "steps": (
            "Apply object-level authorization checks to every API handler",
            "Do not infer authorization from object ids in the request",
            "Document and test role-based access matrices for each endpoint",
            "Rotate and scope API tokens to the least privilege",
        ),
        "references": ("CWE-862", "OWASP A01:2021 - Broken Access Control"),
    },
    "api_security": {
        "title": "Harden the API surface",
        "steps": (
            "Apply rate limiting, authentication and input validation to every endpoint",
            "Use API schemas (OpenAPI) with strict validation of request and response shapes",
            "Hide error details and stack traces from API responses",
            "Restrict unused HTTP methods and endpoints",
        ),
        "references": ("CWE-693", "OWASP A05:2021 - Security Misconfiguration"),
    },
    "cloud_exposure": {
        "title": "Close exposed cloud resources",
        "steps": (
            "Restrict security-group and bucket policies to required sources; never 0.0.0.0/0",
            "Enable encryption and access logging on storage and databases",
            "Remove public endpoints from management services",
            "Audit cloud identity policies for over-privileged roles",
        ),
        "references": ("CWE-668", "OWASP A05:2021 - Security Misconfiguration"),
    },
    "secret_exposure": {
        "title": "Rotate and remove exposed secrets",
        "steps": (
            "Rotate every credential, token and key exposed by the finding immediately",
            "Move secrets to a vault with short-lived, scoped credentials",
            "Scan the repository and history for secrets; enable secret-scanning on commit",
            "Redact secrets from logs, responses and error pages",
        ),
        "references": ("CWE-798", "OWASP A07:2021 - Identification and Authentication Failures"),
    },
    "sensitive_information_exposure": {
        "title": "Stop exposing sensitive data",
        "steps": (
            "Remove sensitive fields (PII, tokens, internal details) from API responses and pages",
            "Encrypt data at rest and in transit; apply field-level redaction",
            "Enforce authorization before any sensitive field is returned",
            "Redact logs and error messages",
        ),
        "references": ("CWE-200", "OWASP A01:2021 - Broken Access Control"),
    },
    "known_cve": {
        "title": "Patch the vulnerable component",
        "steps": (
            "Upgrade to the fixed version of the vulnerable component",
            "Apply vendor workarounds or mitigations until the patch is deployed",
            "Enumerate all instances of the component in the estate",
            "Monitor advisories for follow-up patches",
        ),
        "references": ("CWE-1035", "OWASP A06:2021 - Vulnerable and Outdated Components"),
    },
    "known_vulnerable_component": {
        "title": "Replace or patch the known-vulnerable component",
        "steps": (
            "Upgrade the component to a version without known vulnerabilities",
            "If unavailable, apply the vendor mitigation and isolate the component",
            "Inventory the component across all environments",
            "Subscribe to vulnerability advisories for the component",
        ),
        "references": ("CWE-1104", "OWASP A06:2021 - Vulnerable and Outdated Components"),
    },
    "dependency_vulnerability": {
        "title": "Update vulnerable dependencies",
        "steps": (
            "Upgrade the affected dependency to the patched version",
            "Run dependency scanning in CI and fail on known-vulnerable versions",
            "Remove unused dependencies to shrink the attack surface",
            "Pin and review transitive dependency versions",
        ),
        "references": ("CWE-1104", "OWASP A06:2021 - Vulnerable and Outdated Components"),
    },
    "business_logic": {
        "title": "Enforce business rules server-side",
        "steps": (
            "Move business-rule enforcement to the server; never trust client state",
            "Add server-side rate and volume limits on high-value operations",
            "Track and alert on anomalous business flows",
            "Version business rules and test them against abuse cases",
        ),
        "references": ("CWE-840", "OWASP A01:2021 - Broken Access Control"),
    },
    "http_access_differential": {
        "title": "Close the authenticated/anonymous access differential",
        "steps": (
            "Apply consistent authorization to the affected resource for all sessions",
            "Remove any anonymous path that returns authenticated data",
            "Audit the resource for response differences that leak internal state",
        ),
        "references": ("CWE-284", "OWASP A01:2021 - Broken Access Control"),
    },
    "unknown_behavior": {
        "title": "Investigate the anomalous behavior",
        "steps": (
            "Review the affected endpoint for unexplained behavioral differences",
            "Trace the response difference to a code path and confirm the cause",
            "Apply class-appropriate hardening once the behavior is classified",
        ),
        "references": ("OWASP Top 10", "CWE-20 - Improper Input Validation"),
    },
}


class RemediationGuide:
    """Provide class-specific remediation guidance for a candidate."""

    def guide(self, candidate: CapabilityCandidate) -> Remediation:
        """Return the evidence-adapted remediation for the candidate's class."""
        entry = _GUIDES.get(candidate.finding_class)
        if entry is None:
            entry = _GUIDES["unknown_behavior"]
        steps = list(entry["steps"])
        signal = str(candidate.evidence.get("signal") or "")
        if "error" in signal:
            steps.append("Suppress verbose error output revealed by the differential signal")
        if "reflection" in signal or "content" in signal:
            steps.append("Encode or neutralize the reflected content observed in the differential signal")
        return Remediation(
            vulnerability_class=candidate.finding_class,
            title=str(entry["title"]),
            steps=tuple(steps),
            references=tuple(entry["references"]),
            rationale=f"guide selected for {candidate.finding_class}; evidence signal '{signal or 'none'}'",
        )


__all__ = ["RemediationGuide"]
