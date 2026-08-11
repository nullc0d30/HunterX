# Roadmap

HunterX v7 is the current architecture: an AI-powered security orchestration
and intelligence platform. This roadmap outlines planned development.

---

## Short-Term (v7.x)

- **More tool adapters** — expand the 100+ registered security tools with new
  execution adapters and knowledge contracts
- **Mission orchestration hardening** — resumable orchestrator state across
  process restarts
- **Performance** — retire legacy N+1 SQL repository patterns
- **Runtime resilience** — database failover and pre-ping hooks for production
  deployments

## Medium-Term (v7.x)

- **Native CI/CD integrations** — GitHub Actions, GitLab CI, Jenkins
- **SIEM connectors** — Splunk, Elasticsearch, QRadar
- **Ticketing integration** — Jira, ServiceNow
- **Collaborative multi-user missions**
- **Community plugin registry** — hosted registry for user-contributed plugins
  with validation
- **Advanced reporting templates** — executive summaries, compliance reports
  (PCI-DSS, SOC2, HIPAA)

## Long-Term

- **Community detection rules**
- **Interactive in-app tutorials**
- **Enterprise features** — RBAC, audit logging, SSO/LDAP
- **Packaging** — Homebrew, Chocolatey, and Linux package managers (apt, dnf)

---

## How to Contribute

| Area | How to Help |
|---|---|
| **Tool adapters** | Add adapters for open-source security tools. See the [Toolchain Intelligence](docs/v7-full-toolchain-intelligence.md) guide. |
| **Mission orchestration** | Improve planning, execution and recovery. |
| **Documentation** | Improve existing docs, fix typos, translate guides. |
| **Tests** | Write tests for new capabilities and edge cases. |
| **Community** | Answer questions in GitHub Discussions, review PRs, triage issues. |

See [CONTRIBUTING.md](CONTRIBUTING.md) for full details.
