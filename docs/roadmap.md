# Roadmap

HunterX v6.0.0 is feature-complete. This roadmap shifts focus from feature development to ecosystem growth, community adoption, and enterprise readiness.

---

## Ecosystem Roadmap

- **Skills Marketplace Growth** — Expand the skills registry with community-contributed skills, curated quality checks, and versioning support.
- **New AI Providers** — Add support for additional AI backends (Anthropic, Google Gemini, local models via Ollama/LM Studio, Azure OpenAI, AWS Bedrock).
- **Community Plugins** — Establish a plugin SDK and registry for third-party detectors, reporters, and agents.
- **SIEM/SOAR Integrations** — Native output formatting and webhook support for Splunk, Elastic, Palo Alto XSOAR, and Sentinel.
- **CI/CD Pipeline Integrations** — Official GitHub Action, GitLab CI template, Jenkins plugin, and Azure DevOps extension.

---

## Short Term

- New skills contributions (cloud misconfigurations, API security, dependency confusion).
- Provider contributions (Ollama stability, OpenAI streaming, Azure OpenAI support).
- Documentation improvements (API reference, skill authoring guide, provider configuration guide).
- Performance optimization (caching tuning, reduced memory footprint, faster payload loading).

---

## Medium Term

- **Community Plugin Registry** — A hosted registry for user-contributed plugins with automated validation and publishing.
- **CI/CD Integration Pack** — Official integrations for major CI/CD platforms with example pipelines and best-practice templates.
- **Advanced Reporting Templates** — Executive summaries, compliance reports (PCI-DSS, SOC2, HIPAA mappings), and trend analysis.
- **Training Data for AI Models** — Curated datasets for fine-tuning security-focused AI models, released under open licenses.

---

## Long Term

- **Dedicated Documentation Site** — Standalone documentation portal with search, versioned docs, and interactive guides.
- **Package Managers** — Distribution via Homebrew, Chocolatey, and Linux package managers (apt, dnf).
- **Enterprise Integrations** — SSO/LDAP authentication, role-based access control, audit logging, and multi-tenant support.
- **Research Collaborations** — Partnerships with academic and industry research groups for advancing AI-assisted security testing.

---

## How to Contribute

| Area | How to Help |
|------|-------------|
| **Skills** | Write skills for new vulnerability classes or attack vectors. See the skill authoring guide. |
| **Providers** | Add support for new AI providers. See the provider development guide. |
| **Documentation** | Improve existing docs, fix typos, translate guides. |
| **Tests** | Write tests for skills, providers, and core components. Aim for no regressions. |
| **Community** | Answer questions in GitHub Discussions, review pull requests, triage issues. |

See [CONTRIBUTING.md](./CONTRIBUTING.md) for full details.