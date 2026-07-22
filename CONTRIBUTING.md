---
Copyright (c) 2026 Ahmed Awad (NullC0d3)
All Rights Reserved.
---

# Contributing to HunterX

**Welcome!** Thank you for your interest in contributing to HunterX — the AI-Assisted Vulnerability Hunter.

HunterX is an open-source, reasoning-driven Red Team orchestration framework. We believe that security tools should be safe, explainable, and community-owned. Whether you are a security researcher, Python developer, documentarian, or enthusiast, your contributions are valued.

---

## Table of Contents

- [Project Vision](#project-vision)
- [Ways to Contribute](#ways-to-contribute)
- [Getting Started](#getting-started)
- [Fork Workflow](#fork-workflow)
- [Pull Request Workflow](#pull-request-workflow)
- [Branch Naming Convention](#branch-naming-convention)
- [Commit Message Convention](#commit-message-convention)
- [Coding Style](#coding-style)
- [Testing Requirements](#testing-requirements)
- [Documentation Guidelines](#documentation-guidelines)
- [Issue Reporting](#issue-reporting)
- [Feature Requests](#feature-requests)
- [Bug Reporting](#bug-reporting)
- [Security Vulnerability Reporting](#security-vulnerability-reporting)
- [Review Process](#review-process)
- [Community Expectations](#community-expectations)

---

## Project Vision

HunterX aims to become the industry standard for **safe, reasoning-based vulnerability assessment**. We envision a tool that:

- Prioritizes **safety** — non-destructive verification only
- Empowers **Red Teams** with context-aware intelligence
- Leverages **AI/ML** for smarter, faster analysis
- Builds a **community-driven** payload and plugin ecosystem
- Remains **free and open** for defensive security research

---

## Ways to Contribute

| Icon | Contribution Area | Description |
|------|------------------|-------------|
| ⭐ | Star the repo | Increases visibility and reach |
| 🐛 | Report bugs | File detailed bug reports |
| 💡 | Suggest features | Propose enhancements via issues |
| 🔧 | Submit PRs | Fix bugs, add features, improve code |
| 📖 | Improve docs | Fix typos, add examples, clarify |
| 🌐 | Translate | Help with internationalization |
| 🛡 | Security research | Report vulnerabilities responsibly |
| ⚡ | Optimize | Improve performance and reliability |
| ❤️ | Community support | Help others in issues and discussions |

---

## Getting Started

1. **Read the README** — Understand the project scope and architecture
2. **Check open issues** — Look for `good first issue` or `help wanted` labels
3. **Join discussions** — Share ideas in GitHub Discussions
4. **Set up your environment**:

```bash
git clone https://github.com/nullc0d30/HunterX.git
cd HunterX
pip install -r requirements.txt
python hunterx.py --help
```

---

## Fork Workflow

1. Fork the repository on GitHub
2. Clone your fork locally:

```bash
git clone https://github.com/YOUR_USERNAME/HunterX.git
cd HunterX
```

3. Add the upstream repository:

```bash
git remote add upstream https://github.com/nullc0d30/HunterX.git
```

4. Create a feature branch (see branch naming below)
5. Make your changes
6. Push to your fork
7. Submit a Pull Request to the `main` branch

---

## Pull Request Workflow

1. **Ensure your fork is up to date** with upstream `main`
2. **Run tests** before submitting
3. **Open a PR** against the `main` branch
4. **Fill out the PR template** completely
5. **Link related issues** (e.g., `Closes #42`)
6. **Wait for review** — maintainers will review within 3–5 business days
7. **Address feedback** — make requested changes
8. **Merge** — once approved, a maintainer will merge your PR

> **Note:** All PRs must pass CI (lint + tests) before merging.

---

## Branch Naming Convention

Use descriptive, hyphen-separated names with a type prefix:

| Prefix | Purpose | Example |
|--------|---------|---------|
| `feat/` | New feature | `feat/websocket-fuzzer` |
| `fix/` | Bug fix | `fix/crash-on-empty-target` |
| `docs/` | Documentation | `docs/api-examples` |
| `refactor/` | Code refactoring | `refactor/detector-engine` |
| `test/` | Testing | `test/add-oob-tests` |
| `perf/` | Performance | `perf/cache-payloads` |
| `chore/` | Maintenance | `chore/update-deps` |
| `security/` | Security fix | `security/sql-injection-escape` |

---

## Commit Message Convention

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short summary>

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`, `security`

Examples:

```
feat(protocols): add gRPC reflection probing
fix(detector): handle None response in header scan
docs(readme): update docker usage examples
test(auth): add OAuth2 refresh flow test
```

---

## Coding Style

- **Language:** Python 3.11+
- **Formatter:** [Ruff](https://docs.astral.sh/ruff/)
- **Line length:** 120 characters
- **Imports:** Standard library, third-party, local (grouped)
- **Type hints:** Required for all function signatures
- **Docstrings:** Google-style for public APIs
- **Naming:** `snake_case` for functions/variables, `PascalCase` for classes, `UPPER_CASE` for constants
- **Comments:** Minimal — code should be self-documenting

Run the linter before submitting:

```bash
ruff check core/ hunterx.py api/ plugins/ tests/ --ignore=E501
```

---

## Testing Requirements

- All contributions must include or update tests
- We use **pytest** as the test framework
- Tests reside in the `tests/` directory
- Minimum **80% coverage** for new code
- Run the full suite before submitting:

```bash
python -m pytest tests/ -v
```

---

## Documentation Guidelines

- Use **Markdown** for all documentation
- Place module docs in docstrings (Google-style)
- Update `README.md` for user-facing changes
- Include **code examples** where applicable
- Keep language **clear and professional**
- Check spelling and grammar

---

## Issue Reporting

- Search existing issues before creating a new one
- Use the appropriate issue template
- Be specific and provide reproducible examples
- Include environment details (OS, Python version, etc.)

---

## Feature Requests

- Explain the **problem** you want to solve
- Describe the **proposed solution**
- Mention **alternatives** you considered
- Tag with `enhancement` label

---

## Bug Reporting

- Use the **Bug Report** template
- Include **steps to reproduce**
- Provide **expected vs actual behavior**
- Attach **logs or screenshots** if applicable
- Mention your **environment** (OS, Python, dependencies)

---

## Security Vulnerability Reporting

**Do NOT open public issues for security vulnerabilities.**

Instead, follow our [Security Policy](SECURITY.md) and report via:

- **GitHub Private Vulnerability Reporting** — enabled on this repository
- **Email:** Open an issue requesting a secure channel

We practice **responsible disclosure** and will acknowledge reports within 72 hours.

---

## Review Process

1. **Automated checks** — CI runs lint + tests automatically
2. **Code review** — At least one maintainer reviews
3. **Feedback** — We aim to provide initial feedback within 3 business days
4. **Approval** — Two approvals required for significant changes
5. **Merge** — Squash merge preferred for clean history

---

## Community Expectations

- **Be respectful** — We follow the [Code of Conduct](CODE_OF_CONDUCT.md)
- **Be patient** — Maintainers are volunteers
- **Be constructive** — Focus on solutions, not blame
- **Be inclusive** — Everyone is welcome regardless of background
- **Be professional** — This is a security tool; professionalism matters

---

## Need Help?

- Check [SUPPORT.md](SUPPORT.md) for resources
- Ask in GitHub Discussions
- Read the [README.md](README.md) for quick start

---

*Thank you for contributing to HunterX! Together, we build safer security tools.*
