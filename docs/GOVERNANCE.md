---
layout: default
title: Governance — HunterX v7
description: >-
  Governance model for HunterX open-source security project. Community
  guidelines, decision-making, and contribution process for the Linux security
  tool and red team framework.
permalink: /governance/
---

## Governance

This document describes the governance model for the HunterX project.

---

## Project Leadership

HunterX operates under a **BDFL (Benevolent Dictator for Life)** model.

- **BDFL:** Ahmed Awad (NullC0d3)
- The BDFL has final authority on project decisions, including feature acceptance, architectural direction, and community management.
- The BDFL is expected to consult the community, consider input from contributors and maintainers, and act in the best interest of the project.

---

## License

HunterX is released under the **Apache 2.0** license. All contributions are accepted under the same license. See [LICENSE](./LICENSE) for the full text.

---

## Developer Certificate of Origin

All contributions must include a DCO sign-off (`Signed-off-by:` in commit messages). This certifies that the contributor has the right to submit the code under the Apache 2.0 license. See [CONTRIBUTING.md](./CONTRIBUTING.md) for details.

---

## Roles

### User

Anyone who uses HunterX. Users are encouraged to:

- Report bugs via GitHub Issues
- Ask questions and share ideas via GitHub Discussions
- Provide feedback on features and usability

### Contributor

Anyone who contributes code, documentation, tests, or other improvements. Contributors:

- Submit pull requests following the contribution guidelines
- Participate in code review
- Engage respectfully with the community

Contributors become eligible for maintainer status after a history of quality contributions.

### Maintainer

Trusted contributors with direct commit access and responsibilities:

- Review and merge pull requests
- Triage and respond to issues
- Guide contributors through the PR process
- Ensure code quality, test coverage, and documentation standards
- Participate in release preparation

Maintainers are appointed by the BDFL and can be removed for sustained inactivity or conduct violations.

---

## Decision-Making Process

1. **Minor changes** (bug fixes, documentation, tests) — Pull requests are reviewed and merged by maintainers.
2. **Feature additions** — Should be discussed in a GitHub issue before implementation. The BDFL or a maintainer must approve the design.
3. **Architectural changes** — Require a design document and discussion. The BDFL makes the final decision.
4. **Governance changes** — Require community discussion and BDFL approval.

---

## Conflict Resolution

Disagreements are expected in any open project. The resolution process is:

1. **Direct discussion** — The parties involved discuss the issue respectfully.
2. **Maintainer mediation** — If direct discussion fails, a maintainer mediates.
3. **BDFL decision** — If mediation fails, the BDFL makes a final decision.

All participants are expected to follow the Code of Conduct. Harassment, personal attacks, or other unacceptable behavior will not be tolerated.

---

## Release Process

HunterX follows **semantic versioning** (MAJOR.MINOR.PATCH):

1. **Development** occurs on the `main` branch.
2. **Release candidates** are tagged as `vMAJOR.MINOR.PATCH-rc.N` for testing.
3. **Stable releases** are tagged as `vMAJOR.MINOR.PATCH`.
4. **Changelog** — All notable changes are documented in `CHANGELOG.md`.
5. **Release notes** — Each release includes notes summarizing changes, new contributors, and migration instructions.

---

## Community Guidelines

- Be respectful and constructive
- Assume good faith
- Help others learn and grow
- Focus on the best interest of the project and its users
- Follow the Code of Conduct

See [CODE_OF_CONDUCT](/CODE_OF_CONDUCT/) for full details.