<!-- Copyright (c) 2026 Ahmed Awad (NullC0d3). SPDX-License-Identifier: Apache-2.0. -->

# Security Policy

HunterX takes the security of the tool and its users seriously. This document outlines the vulnerability reporting process, supported versions, and security features.

---

## Scope

This security policy covers the **HunterX tool itself** — its source code, dependencies, and official distribution channels.

Vulnerabilities in third-party AI providers, skills contributed by the community, or systems being tested should be reported to the respective maintainers or vendors.

---

## Responsible Disclosure

**Do not open public GitHub issues for security vulnerabilities.** Please use GitHub's Private Vulnerability Reporting feature.

We ask that you:

- Allow time for a fix to be developed before disclosing the vulnerability publicly.
- Provide sufficient detail to reproduce and understand the issue.
- Do not exploit the vulnerability beyond what is necessary to demonstrate the issue.

---

## Reporting Process

1. **Report** — Submit a vulnerability report via [GitHub Private Vulnerability Reporting](https://github.com/nullc0d30/HunterX/security/advisories/new).
2. **Acknowledgment** — The maintainers will acknowledge receipt within 72 hours.
3. **Investigation** — The maintainers will investigate and determine severity, impact, and fix approach.
4. **Fix** — A patch is developed and tested. For critical issues, a patch release is expedited.
5. **Release** — The fix is released in a new version with a changelog entry.
6. **Disclosure** — After the fix is released, the vulnerability is publicly disclosed with credit to the reporter.

---

## Response Times

| Severity | Acknowledgment | Patch Target |
|----------|---------------|--------------|
| Critical | Within 72 hours | Within 14 days |
| High     | Within 72 hours | Within 30 days |
| Medium   | Within 1 week  | Within 60 days |
| Low      | Within 1 week  | Next release |

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| v7.0.1  | Yes       |
| v7.0.0  | Yes       |
| < v7.0.0 | No       |

Only the latest stable release receives security patches. Users are strongly encouraged to keep HunterX up to date.

---

## Recognition

Contributors who report valid security vulnerabilities will be credited in the release notes for the version containing the fix, unless they prefer to remain anonymous.

---

## Security Features

HunterX includes multiple layers of safety guardrails:

- **Policy Levels** — Five-level policy system controlling what actions skills and agents can perform: `default`, `prompt`, `auto`, `ask`, and `prohibited`.
- **Destructive Blocklist** — Commands and operations classified as destructive are blocked by policy, preventing accidental or malicious system modification.
- **WAF Detection** — Web application firewall pattern detection identifies and flags potentially malicious payloads before they reach AI providers or skills.
- **Rate Limiting** — Configurable rate limiting on AI provider requests prevents abuse and excessive resource consumption.
- **SSL Verification** — All outbound HTTPS connections validate SSL certificates by default. Verification can be disabled in development environments only.

These features work together to provide defense-in-depth, ensuring that even if one layer is bypassed, others remain active.