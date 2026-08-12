---
layout: default
title: Contributing — HunterX v7
description: >-
  Guide to contributing to the HunterX v7 security orchestration and
  intelligence platform: fork workflow, commit conventions, DCO sign-off, and
  development setup.
permalink: /contributing/
---

## Contributing

HunterX is Apache 2.0 licensed and welcomes contributions of all forms.

---

## Getting Started

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/HunterX.git
cd HunterX

# Create a virtual environment
python -m venv venv
source venv/bin/activate

# Install in editable mode with all extras
pip install -e ".[all]"

# Create a feature branch
git checkout -b feat/your-feature
```

---

## Development Workflow

1. **Fork** the repository on GitHub
2. **Clone** your fork locally
3. **Create a feature branch** from `main`
4. **Make your changes** following the [Development Bible]({{ '/bible/' | relative_url }}) conventions
5. **Run tests** to verify nothing is broken
6. **Run linting** to ensure code style
7. **Commit with DCO sign-off** (`git commit -s`)
8. **Push** to your fork
9. **Open a pull request** against the `main` branch

---

## Testing

The v7 test suite lives under `tests/{unit,component,integration,architecture,
golden,security,acceptance,performance,engineering}`:

```bash
# Run the full default suite
pytest -m "not tools"

# Run a specific area
pytest tests/unit tests/component

# Run with coverage
pytest --cov=src/hunterx tests/unit tests/component tests/architecture
```

## Code Style

```bash
# Check code style (v7 source in src/, eng/, tests/)
ruff check src eng tests alembic
ruff format --check .
```

## Quality Gates

Contributions must keep the quality gates green — see
[Quality Gates]({{ '/v7-quality-gates/' | relative_url }}):

```bash
python -m eng.gates        # ruff, mypy, pytest, coverage, security, docs, ...
```

---

## Commit Conventions

Use conventional commit messages:

```
feat(area): concise description
fix(area): concise description
docs(area): concise description
refactor(area): concise description
test(area): concise description
chore(area): concise description
```

Example areas: `cli`, `api`, `mission`, `tools`, `findings`, `reporting`,
`domain`, `infrastructure`, `eng`, `docs`

All commits must include a **DCO (Developer Certificate of Origin) sign-off**:

```bash
git commit -s -m "feat(tools): add a new tool adapter"
```

---

## Pull Request Guidelines

- Keep PRs focused on a single change
- Add tests for new functionality
- Update documentation if needed
- Ensure CI passes (tests + linting + quality gates)
- Reference related issues in the description

---

## How to Help

| Area | How to Help |
|---|---|
| **Tool adapters** | Add adapters for open-source security tools |
| **Mission orchestration** | Improve planning, execution and recovery |
| **Documentation** | Improve existing docs, fix typos |
| **Tests** | Write tests for new capabilities and edge cases |
| **Community** | Answer discussions, review PRs, triage issues |

---

## Resources

- [Full contribution guide on GitHub](https://github.com/nullc0d30/HunterX/blob/main/CONTRIBUTING.md)
- [Development Bible]({{ '/bible/' | relative_url }}) — engineering standards
- [Architecture Enforcement]({{ '/architecture/' | relative_url }}) — layering and dependency rules
- [Governance]({{ '/governance/' | relative_url }})
