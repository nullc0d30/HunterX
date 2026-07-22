---
Copyright (c) 2026 Ahmed Awad (NullC0d3)
SPDX-License-Identifier: Apache-2.0
---

# Supporting HunterX

Welcome! We're glad you're using HunterX. This guide explains how to get help, report issues, and find resources.

---

## Table of Contents

- [Getting Help](#getting-help)
- [Reporting Issues](#reporting-issues)
- [Self-Help Resources](#self-help-resources)
- [Frequently Asked Questions](#frequently-asked-questions)
- [Best Practices](#best-practices)
- [Community](#community)

---

## Getting Help

| Channel | Purpose | Response Time |
|---------|---------|---------------|
| [GitHub Issues](https://github.com/nullc0d30/HunterX/issues) | Bug reports, feature requests | 3–5 business days |
| [GitHub Discussions](https://github.com/nullc0d30/HunterX/discussions) | Questions, ideas, community help | Community-driven |
| [Documentation](README.md) | Quick start, usage, configuration | Always available |
| [Security Reports](SECURITY.md) | Vulnerability disclosure | Within 72 hours |

---

## Reporting Issues

### Before Reporting

1. **Search** existing issues and discussions for similar topics
2. **Check** the [FAQ](#frequently-asked-questions) below
3. **Read** the [documentation](README.md) to ensure proper usage

### How to Report

- **Bugs:** Use the [Bug Report template](.github/ISSUE_TEMPLATE/Bug_Report.md)
- **Features:** Use the [Feature Request template](.github/ISSUE_TEMPLATE/Feature_Request.md)
- **Security:** Follow our [Security Policy](SECURITY.md) disclosure process

---

## Self-Help Resources

| Resource | Description |
|----------|-------------|
| [README.md](README.md) | Installation, quick start, full audit |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution guidelines |
| [ROADMAP.md](ROADMAP.md) | Planned features and timeline |
| [Docker Guide](README.docker.md) | Docker-specific usage |
| [Docker Hub](https://hub.docker.com/r/nullc0d30/hunterx) | Docker images and tags |

---

## Frequently Asked Questions

### Is HunterX a replacement for Burp Suite / ZAP?

No. HunterX is a specialized, reasoning-driven orchestration framework designed for Red Team operations. It complements traditional scanners by providing context-aware, non-destructive verification.

### Can I use HunterX on production systems without permission?

**Absolutely not.** HunterX is designed for authorized security assessments only. Using it against systems without explicit permission is illegal and unethical.

### Does HunterX modify files or execute payloads?

No. HunterX employs a **non-destructive verification** model. Destructive payloads are blocked at the code level. The framework observes, hypothesizes, probes, and verifies — it does not exploit.

### What Python version is required?

Python 3.11 or higher is required.

### Does HunterX require Ollama or scikit-learn?

No. AI/ML features are optional and gracefully disabled when dependencies are not available.

---

## Best Practices

### For Operators

- Always obtain **written authorization** before testing
- Use the `--stealth` flag for production environments
- Enable `--passive-only` for initial recon
- Review reports thoroughly before sharing

### For Developers

- Run `ruff check` before committing
- Write tests for new functionality
- Follow the commit message convention
- Keep pull requests focused and small

### For Docker Users

- Mount a volume for reports: `-v $(pwd)/reports:/data`
- Use tagged images, not `latest`, in production
- The container runs as non-root user `hunterx`

---

## Community

- ⭐ **Star the repo** to show support
- 🍴 **Fork the repo** to contribute
- 🐛 **Report bugs** to help us improve
- 💡 **Suggest features** to shape the roadmap
- 📖 **Improve docs** to help others
- ❤️ **Help others** in issues and discussions

---

*HunterX is maintained by Ahmed Awad (NullC0d3). Support is provided on a best-effort basis. We appreciate your patience and contributions.*
