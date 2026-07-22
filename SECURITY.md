---
Copyright (c) 2026 Ahmed Awad (NullC0d3)
SPDX-License-Identifier: Apache-2.0
---

# Security Policy

## Responsible Vulnerability Disclosure

HunterX is a security assessment framework. We take the security of our tool and its users seriously. If you discover a security vulnerability within HunterX itself (as opposed to using HunterX to test targets), we encourage you to report it responsibly.

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| 4.x (latest) | ✅ Full support |
| 3.x | ❌ End of life |
| < 3.0 | ❌ End of life |

Only the latest major release receives security patches. Users are strongly encouraged to keep their installations up to date.

---

## Reporting a Security Vulnerability

**Do NOT report security vulnerabilities through public GitHub issues, discussions, or pull requests.**

Please report vulnerabilities through one of these channels:

### Option 1: GitHub Private Vulnerability Reporting (Recommended)

The repository has **Private Vulnerability Reporting** enabled. This is the preferred reporting method:

1. Navigate to the repository's **Security** tab
2. Click **Report a vulnerability**
3. Fill out the form with details

### Option 2: Email via Issue

If you cannot use private reporting, open a regular issue asking for a secure contact method. **Do not include vulnerability details in the public issue.**

---

## What to Include

When reporting, please provide:

- **Type of vulnerability** (e.g., XSS, command injection, privilege escalation)
- **Affected component** (file path, function, version)
- **Steps to reproduce** — minimal, complete, reproducible
- **Expected vs actual behavior**
- **Impact assessment** — what an attacker could achieve
- **Suggested fix** (optional but appreciated)
- **Your contact information** (for follow-up)

---

## Response Timeline

| Timeframe | Action |
|-----------|--------|
| Within 72 hours | Acknowledgment of receipt |
| Within 1 week | Initial assessment and triage |
| Within 2 weeks | Fix in progress or mitigation identified |
| Within 30 days | Patch released (depending on severity) |
| After patch | Coordinated public disclosure |

---

## Coordinated Disclosure

We practice **coordinated (responsible) disclosure**:

1. Reporter submits vulnerability privately
2. We acknowledge, assess, and develop a fix
3. We release a patched version
4. We agree on a disclosure date with the reporter
5. We publish an advisory with credit to the reporter (if desired)

We aim to complete this process within **30 days** for high-severity issues.

---

## Scope

### In Scope

- Source code vulnerabilities in `core/`, `api/`, `plugins/`, and `hunterx.py`
- Docker image vulnerabilities
- CI/CD pipeline vulnerabilities
- Dependency vulnerabilities affecting the tool

### Out of Scope

- Vulnerabilities discovered by using HunterX on targets
- Third-party tools or libraries (report those upstream)
- Social engineering attacks on maintainers
- Denial of service against the repository or infrastructure

---

## Safe Harbor

We will not pursue legal action against individuals who:

- Report vulnerabilities through our private channels
- Follow our disclosure policy
- Act in good faith to improve the security of the project
- Do not access or modify user data without permission
- Do not disrupt the project's infrastructure

---

## Recognition

We maintain a **Security Researchers Hall of Fame** in our release notes. With your permission, we will credit you for your finding.

---

## Recommendations for Users

- Always use the **latest version** of HunterX
- Verify image signatures for Docker deployments
- Review dependencies regularly for known CVEs
- Run with least-privilege user accounts (default in Docker)
- Isolate HunterX executions in containers or VMs

---

*Thank you for helping keep HunterX and its community safe.*
