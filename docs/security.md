---
layout: default
title: Security Policy — HunterX
description: >-
  HunterX security policy: responsible use, vulnerability disclosure,
  supported versions, and security-related configuration for the security
  orchestration and intelligence platform.
---

## Responsible Use

**HunterX is an authorized cybersecurity testing and research platform.** It is
designed to be used only against systems you own or are explicitly authorized
to test. You are responsible for:

- Obtaining **appropriate written authorization** before testing any system.
- Complying with all applicable laws, regulations, and terms of service.
- Keeping HunterX and its capabilities out of the hands of unauthorized users.

The developer/author is **not responsible** for misuse, unauthorized access,
illegal activity, damage, or any other unethical use of the software. See the
[Responsible Use & Legal Notice](/responsible-use/) for the full statement.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 7.x | ✅ |
| 6.x | ❌ (archived) |
| < 6 | ❌ |

## Reporting a Vulnerability

HunterX takes security seriously. If you discover a security vulnerability in
HunterX itself (not a target being scanned), please report it privately:

1. **GitHub Private Vulnerability Reporting**: Use the "Security" tab in the
   repository
2. **Email**: Open a public issue requesting a secure communication channel
   (do NOT include vulnerability details)

Do NOT report security vulnerabilities in public GitHub issues.

## Disclosure Policy

- We will acknowledge receipt within 48 hours
- We will provide an estimated timeline for a fix
- We will coordinate disclosure with you
- We will credit you in the changelog (if desired)

## Security Model in HunterX v7

HunterX v7 is designed for safe, evidence-driven, authorized assessment:

- **Scope and authorization guards** — missions carry authorization contexts and
  scope policies; targets outside scope are rejected.
- **Sandboxing** — plugins and tool execution run in an isolated sandbox with
  timeout and resource limits.
- **Evidence-gated confidence** — findings require reproducible, controlled
  evidence; PoC replay never treats a bare HTTP 200 as success.
- **Secret masking** — credentials and tokens are masked and never persisted in
  findings or reports.
- **Safe XML parsing** — `defusedxml` hardens all XML parsing (no XXE / entity
  expansion).
- **Non-root Docker** — the container runs as a non-root user.
- **Rate limiting** — token-bucket algorithm prevents accidental DoS.
- **Opt-in API authentication** — the REST API supports API-key auth with
  admin/read-only roles.

See [Responsible Use](/responsible-use/) and the
[Security Pipeline](/v7-security-pipeline/) guide for details.
