---
layout: default
title: HunterX vs OpenVAS — Comparison
description: >-
  Technical comparison between HunterX (web application scanner) and OpenVAS
  (network vulnerability scanner). Architecture, focus area, deployment, and
  use case analysis.
---

# HunterX vs OpenVAS

| Dimension | HunterX | OpenVAS (Greenbone) |
|-----------|---------|---------------------|
| **Focus** | Web application security | Network vulnerability scanning |
| **Detection** | 4-stage reasoning pipeline | NASL script-based matching |
| **Coverage** | HTTP/HTTPS, WebSocket, GraphQL | Network protocols, ports, services |
| **License** | Apache 2.0 | GPL-2.0 |
| **Language** | Python | C, Python |
| **Deployment** | CLI, API, Docker (<1 min) | Full VM, Docker (complex) |
| **Plugin System** | Python decorator plugins | NASL scripts |
| **Operator Profiles** | Internal, Bounty, Gov, Custom | None |
| **CVE Coverage** | Exploit-focused (via probing) | Broad CVE database (100k+) |
| **Auth Scanning** | Basic, Bearer, Cookie, Form Login | SNMP, SSH credentials |
| **Startup Time** | <1s | 2-5 minutes |
| **Memory** | ~78 MB | ~2-4 GB |
| **CI/CD** | SARIF, API-first | Limited |

## When to Use HunterX

- Web application penetration testing
- CI/CD pipeline security scanning
- API and GraphQL security testing
- AI-assisted vulnerability analysis
- Rapid deployment (Docker, CLI)

## When to Use OpenVAS

- Network vulnerability scanning (port-based)
- Broad CVE coverage across network services
- Compliance scanning (PCI DSS, HIPAA)
- Internal network infrastructure assessment

## Complementary Use

- **OpenVAS** for network-level vulnerability discovery and compliance
- **HunterX** for deep web application security testing and CI/CD integration

Both tools complement each other in a comprehensive security assessment program.
