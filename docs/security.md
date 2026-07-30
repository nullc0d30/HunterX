---
layout: default
title: Security Policy — HunterX
description: >-
  HunterX security policy: vulnerability disclosure, responsible reporting,
  supported versions, and security-related configuration for the open-source
  vulnerability scanner.
---

## Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 4.0.x | ✅ |
| < 4.0 | ❌ |

## Reporting a Vulnerability

HunterX takes security seriously. If you discover a security vulnerability in HunterX itself (not a target being scanned), please report it privately:

1. **GitHub Private Vulnerability Reporting**: Use the "Security" tab in the repository
2. **Email**: Open a public issue requesting a secure communication channel (do NOT include vulnerability details)

Do NOT report security vulnerabilities in public GitHub issues.

## Disclosure Policy

- We will acknowledge receipt within 48 hours
- We will provide an estimated timeline for a fix
- We will coordinate disclosure with you
- We will credit you in the changelog (if desired)

## Security Features in HunterX

HunterX includes several security-by-design features:

- **Destructive payload blocklist**: Hard-coded, non-bypassable blocklist prevents dangerous payloads
- **Operator profiles**: Bounty and Gov profiles constrain request volume and disable destructive payloads
- **Rate limiting**: Token-bucket algorithm prevents accidental DoS
- **Non-root Docker**: Container runs as non-root user
- **Timeout controls**: Configurable connect, read, and overall timeouts
