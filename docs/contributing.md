---
layout: default
title: Contributing — HunterX v6.0.0
description: >-
  Guide to contributing to HunterX open-source vulnerability scanner. Fork
  workflow, commit conventions, DCO sign-off, and development setup.
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
4. **Make your changes** following code conventions
5. **Run tests** to verify nothing is broken
6. **Run linting** to ensure code style
7. **Commit with DCO sign-off** (`git commit -s`)
8. **Push** to your fork
9. **Open a pull request** against the `main` branch

---

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_scanner.py -v

# Run with coverage
pytest tests/ --cov=hunterx
```

## Code Style

```bash
# Check code style
ruff check .
ruff format --check .
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

Example areas: `cli`, `api`, `skills`, `agents`, `reasoning`, `payload`, `reporting`, `core`, `docs`

All commits must include a **DCO (Developer Certificate of Origin) sign-off**:

```bash
git commit -s -m "feat(skills): add new cloud enumeration skill"
```

---

## Pull Request Guidelines

- Keep PRs focused on a single change
- Add tests for new functionality
- Update documentation if needed
- Ensure CI passes (tests + linting)
- Reference related issues in the description

---

## How to Help

| Area | How to Help |
|---|---|
| **Skills** | Write skills for new vulnerability classes |
| **Providers** | Add support for new AI providers |
| **Documentation** | Improve existing docs, fix typos |
| **Tests** | Write tests for skills, providers, and core |
| **Community** | Answer discussions, review PRs, triage issues |

---

## Resources

- [Full contribution guide on GitHub](https://github.com/nullc0d30/HunterX/blob/main/CONTRIBUTING.md)
- [Plugin Development Guide](plugin-development)
- [Skill SDK](skill-sdk)
- [Design Decisions](design-decisions)
- [Governance](governance)
