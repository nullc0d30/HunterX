# Contributing to HunterX

Thank you for your interest in contributing to HunterX. This document outlines the process for contributing code, documentation, and other improvements.

All contributions are welcome — whether fixing a typo, adding a skill, writing tests, or implementing a new provider.

---

## Welcome

HunterX is released under the **Apache 2.0** license. All contributors must agree to the **Developer Certificate of Origin (DCO)**. Every commit must include a `Signed-off-by` line.

---

## Getting Started

1. Fork the repository on GitHub.
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/HunterX.git
   ```
3. Add the upstream remote:
   ```bash
   git remote add upstream https://github.com/nullc0d30/HunterX.git
   ```
4. Create a branch for your work (see [Branch Naming](#branch-naming)).
5. Make your changes.
6. Run tests locally before pushing.

---

## Development Setup

```bash
pip install -r requirements.txt
```

Install pre-commit hooks to automatically check code style:

```bash
pre-commit install
```

Pre-commit hooks run Ruff and other checks on every commit.

---

## Code Style

- **Linter:** Ruff
- **Line length:** 120 characters
- **Target Python:** 3.11+
- **Type hints:** Required for all function signatures and public methods.

Run the linter before committing:

```bash
ruff check .
```

---

## Testing

All contributions must maintain or increase the test pass rate. There are currently **623 tests** in the test suite.

Run tests:

```bash
pytest tests/ -v
```

No regressions are allowed. If your change fixes a bug, add a test that reproduces the bug and verify it passes.

---

## Pull Request Process

1. Ensure your branch is up to date with `main`.
2. Open a pull request against the `main` branch.
3. Use the pull request template — fill in all sections.
4. Link the issue your PR addresses (if applicable).
5. Add a changelog entry in `CHANGELOG.md` under the appropriate section.
6. Ensure all commits include a DCO sign-off (`Signed-off-by:`).
7. Ensure all CI checks pass (lint, test, build).

A maintainer will review your PR. You may be asked to make changes before it is merged.

---

## Commit Messages

Use **Conventional Commits** format:

```
<type>: <short description>

<optional body>
```

Types:

| Type       | Usage                          |
|------------|--------------------------------|
| `feat:`    | A new feature                  |
| `fix:`     | A bug fix                      |
| `docs:`    | Documentation changes          |
| `test:`    | Adding or updating tests       |
| `refactor:`| Code refactoring               |
| `chore:`   | Maintenance, tooling, CI       |

Example:

```
feat: add AWS S3 bucket enumeration skill
```

---

## Branch Naming

Use descriptive branch names with a type prefix:

- `feat/description` — new features
- `fix/description` — bug fixes
- `docs/description` — documentation changes

Examples: `feat/s3-enumeration`, `fix/ollama-timeout`, `docs/api-reference`

---

## Code Review

Reviewers will check for:

- Correctness: Does the code do what it claims?
- Security: Are there any injection vectors or unsafe patterns?
- Style: Does it follow Ruff conventions and type hints?
- Tests: Are there sufficient tests covering the change?
- Documentation: Are public APIs and behaviors documented?
- Performance: Is the approach efficient for the expected workloads?

Be prepared to iterate. All reviews are conducted respectfully and constructively.

---

## DCO (Developer Certificate of Origin)

Every commit must include a `Signed-off-by` line in the commit message, certifying that you have the right to submit the code under the project's license.

To sign off a commit:

```bash
git commit -s -m "feat: add S3 bucket enumeration skill"
```

This adds:

```
Signed-off-by: Your Name <your.email@example.com>
```

For more information, see [developercertificate.org](https://developercertificate.org/).

---

## Resources

- [Documentation Site](https://nullc0d30.github.io/HunterX/)
- [CLI Reference](https://nullc0d30.github.io/HunterX/cli/)
- [REST API Reference](https://nullc0d30.github.io/HunterX/api/)
- [Skill SDK](docs/SKILL_SDK.md)
- [Plugin Development Guide](docs/PLUGIN_DEVELOPMENT.md)
- [Issue Tracker](https://github.com/nullc0d30/HunterX/issues)
- [Discussions](https://github.com/nullc0d30/HunterX/discussions)