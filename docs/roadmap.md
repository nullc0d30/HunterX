---
layout: default
title: Roadmap — HunterX Development Plan
description: >-
  Release roadmap for HunterX vulnerability scanner covering v4.x through v5.x
  with planned features including gRPC testing, OAuth2, persistent job queue,
  TUI, autonomous agent mode, and cloud scanning.
---

# Roadmap

> *Last updated: July 2026*

---

## Current: v4.0.1

**Focus:** Apache 2.0 open-source licensing, Docker optimization, security patches

## Upcoming

| Version | Focus | Target |
|---------|-------|--------|
| **v4.1** | gRPC, OAuth2, Redis queue, TUI, i18n | Q3 2026 |
| **v4.5** | RBAC, SIEM, Scheduled scans, Compliance reporting | Q4 2026 |
| **v5.0** | Autonomous agent, Cloud scanning, SDK | H1 2027 |

---

## v4.1 — Community Edition (Q3 2026)

| Feature | Description |
|---------|-------------|
| gRPC protocol testing | Reflection, message fuzzing |
| OAuth2 auth flow | Full OAuth2 / OIDC support |
| Persistent job queue | Redis-backed queue for API mode |
| Payload marketplace | Community-contributed payload packs |
| Interactive TUI | Text-based user interface with live dashboards |
| Multi-report format | PDF, HTML, DOCX export via plugins |
| Internationalization | i18n foundation for CLI and reports |

---

## v4.5 — Enterprise (Q4 2026)

| Feature | Description |
|---------|-------------|
| Team collaboration | Multi-user API with RBAC |
| SIEM integration | Splunk, ELK, QRadar connectors |
| Scheduled scanning | Cron-based recurring assessments |
| Advanced AI models | Local LLM fine-tuning, RAG pipelines |
| Attack graph generation | Full kill-chain visualization |
| Compliance reporting | PCI-DSS, HIPAA, SOC2 report templates |

---

## v5.0 — Horizon (H1 2027)

| Area | Initiative |
|------|-----------|
| Autonomous Agent | AI-driven autonomous penetration testing |
| Cloud Scanner | Native AWS, Azure, GCP scanning profiles |
| SDK & API v2 | Official client libraries for Python, Go, JS |
| Bug Bounty Integration | Direct API connections to HackerOne, Bugcrowd |

---

## Community Goals

| Goal | Target |
|------|--------|
| 100 GitHub stars | Q3 2026 |
| 500 GitHub stars | Q4 2026 |
| 20+ contributors | Q4 2026 |
| 50+ plugin ecosystem | H1 2027 |
| OWASP Integration | v4.5 |

---

## Performance Targets

| Metric | Current (v4.0.1) | Target (v5.0) |
|--------|-----------------|---------------|
| Requests per second | ~10 | 100+ |
| Memory per scan | ~150MB | < 50MB |
| Cold start time | ~2s | < 500ms |
| Test coverage | 78% | 95%+ |
| Plugin load time | ~100ms | < 10ms |
