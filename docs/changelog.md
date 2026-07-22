---
layout: default
title: Changelog — HunterX Release History
description: >-
  HunterX version history and changelog. v4.0.1, v4.0.0, and earlier releases
  with features, fixes, and breaking changes.
---

# Changelog

> Full changelog maintained at [CHANGELOG.md](https://github.com/nullc0d30/HunterX/blob/main/CHANGELOG.md).

## v4.0.1 (2026-07-22)

### License Change
- **License changed from Proprietary to Apache 2.0** — HunterX is now fully open source
- All source files updated to `SPDX-License-Identifier: Apache-2.0`
- All documentation files updated to `SPDX-License-Identifier: Apache-2.0`
- NOTICE file added with third-party dependency attributions
- CONTRIBUTING.md updated with DCO (Developer Certificate of Origin) requirement

### Documentation
- GitHub Pages documentation site created under `docs/`
- SEO-optimized with Jekyll, JSON-LD structured data, Open Graph, Twitter Cards
- Client-side search with Lunr.js
- Full documentation covering all features, API, configuration, Docker, plugins, profiles, authentication

### Project Infrastructure
- GitHub labels, issue templates, PR templates updated for Apache 2.0
- Docker Hub image pushed as `nullc0d30/hunterx:4.0.1` and `:latest`
- Optimized multi-stage Docker build (271MB)

## v4.0.0 (2026-07-20)

- Initial public release (Proprietary license)
- 4-stage reasoning pipeline (Passive → Probe → Confirm → Verify)
- 200+ vulnerability signatures (LFI, RCE, SQLi, SSTI, SSRF, XSS, Open Redirect, XXE)
- 50+ WAF detection signatures with auto-abort
- Payload mutation engine (encoding, SQL, LFI variants)
- Token-bucket rate limiting with configurable RPS
- Operator profiles (Internal, Bounty, Gov, Custom)
- Authentication support (Basic, Bearer, Cookie, Form Login)
- Reporting: Markdown, JSON, SARIF 2.1, HTML, ZIP
- FastAPI REST server with scan job management
- Plugin system (detector, reporter, hook decorators)
- OOB detection with configurable collaborator
- WebSocket endpoint detection and testing
- GraphQL introspection and batch attack testing
- Optional AI/ML integration (Ollama LLM, DBSCAN clustering)
- 76 passing tests, 100% ruff lint compliance
- Multi-stage Docker build (271MB)
