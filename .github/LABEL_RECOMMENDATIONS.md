---
Copyright (c) 2026 Ahmed Awad (NullC0d3)
SPDX-License-Identifier: Apache-2.0
---

# GitHub Label Recommendations

The following labels are recommended for this repository. They should be created in the GitHub repository settings.

---

## Issue Type Labels

| Label | Color | Description |
|-------|-------|-------------|
| `bug` | `#d73a4a` | Something isn't working as expected |
| `enhancement` | `#a2eeef` | New feature or improvement request |
| `documentation` | `#0075ca` | Documentation improvements |
| `question` | `#d876e3` | Further information is needed |
| `security` | `#e11d21` | Security vulnerability report |
| `discussion` | `#b6b6f7` | Open-ended discussion or design proposal |

---

## Priority Labels

| Label | Color | Description |
|-------|-------|-------------|
| `priority:critical` | `#b60205` | Must fix immediately — blocks release |
| `priority:high` | `#d93f0b` | Should be addressed in current milestone |
| `priority:medium` | `#fbca04` | Important but not urgent |
| `priority:low` | `#0e8a16` | Nice-to-have, no immediate pressure |

---

## Status Labels

| Label | Color | Description |
|-------|-------|-------------|
| `status:confirmed` | `#c5def5` | Bug has been reproduced and confirmed |
| `status:in-progress` | `#0052cc` | Currently being worked on |
| `status:blocked` | `#1d76db` | Blocked by another issue or dependency |
| `status:needs-repro` | `#f9d0c4` | Needs reproduction steps from reporter |
| `status:needs-design` | `#fef2c0` | Needs design discussion before implementation |
| `status:duplicate` | `#cfd3d7` | Already reported — link to original |
| `status:wontfix` | `#ffffff` | Will not be addressed |
| `status:invalid` | `#e4e669` | Not a valid issue or not reproducible |

---

## Community Labels

| Label | Color | Description |
|-------|-------|-------------|
| `good first issue` | `#7057ff` | Good entry point for new contributors |
| `help wanted` | `#008672` | Extra attention or expertise needed |
| `hacktoberfest` | `#ff7518` | Eligible for Hacktoberfest contributions |
| `beginner friendly` | `#7f35fc` | Suitable for first-time contributors |

---

## Scope Labels

| Label | Color | Description |
|-------|-------|-------------|
| `area:core` | `#bfdadc` | Core engine or pipeline |
| `area:api` | `#bfd4f2` | REST API server |
| `area:plugins` | `#d4c5f9` | Plugin system or individual plugins |
| `area:detection` | `#f9d0c4` | Detection signatures or logic |
| `area:protocols` | `#c2e0c6` | Protocol implementations (WS, GraphQL, etc.) |
| `area:ai` | `#fef2c0` | AI/ML modules |
| `area:auth` | `#e8d1f5` | Authentication providers |
| `area:reporting` | `#d5e8d4` | Report generation (JSON, MD, SARIF, HTML) |
| `area:docker` | `#0db7ed` | Docker-related |
| `area:ci` | `#bfe5bf` | CI/CD pipelines |
| `area:docs` | `#f0f0f0` | Documentation |

---

## Applying Labels

### Best Practices

1. Every issue should have at least one **type** label
2. Bug reports should also have a **priority** label
3. Consider adding **scope** labels for larger projects
4. Use **community** labels to encourage contributions
5. Use **status** labels to communicate progress

### Automation

GitHub Actions can be configured to auto-label based on:

- Issue title patterns (e.g., `[BUG]` → `bug`)
- File paths changed in PRs (e.g., `api/*` → `area:api`)
- Issue body content
- Issue author role

---

*Labels help organize, triage, and prioritize work. A consistent labeling system makes the repository more maintainable and contributor-friendly.*
