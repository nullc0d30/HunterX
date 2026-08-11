# 23 — Development Workflow

**Status:** Ratified
**Version:** 1.0.0
**Applies to:** All contributors, maintainers, CI/CD, releases

---

## 1. Git Workflow

HunterX uses a **trunk-based development** model with short-lived feature
branches and protected `main`. (Stable releases are cut from `main` via
release branches.)

```
feature/xxx ──► PR ──► main ──► release/x.y.z ──► tag vX.Y.Z ──► publish
hotfix/xxx  ──► PR (patch) ──► main (+ backport)
```

---

## 2. Branch Strategy

| Branch | Purpose | Protected |
|--------|---------|-----------|
| `main` | Integration branch; always releasable | yes |
| `release/x.y.z` | Freeze branch for a release | yes |
| `feature/<slug>` | New work (from `main`) | no |
| `fix/<slug>` | Bug fix | no |
| `docs/<slug>` | Documentation | no |
| `deps/<slug>` | Dependency updates | no |
| `backport/x.y.z` | Hotfix backports | no |

Rules:

- No direct pushes to `main`; only merge via PR.
- PRs must be up to date with `main` (rebase/merge before review).
- Long-lived branches (> 2 weeks) are discouraged; break work into stacked PRs.
- `main` must always pass CI and be deployable.

---

## 3. Conventional Commits

Commit messages follow Conventional Commits:

```
<type>(<scope>): <subject>

<body>
footer (BREAKING CHANGE, issue refs)
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `perf`, `chore`, `build`,
`ci`, `style`, `security`, `revert`.

- `feat` → minor release; `BREAKING CHANGE`/`feat!` → major; `fix` → patch.
- Scope examples: `mission`, `workflow`, `tool(nuclei)`, `ai`, `schema`, `api`, `cli`.
- Changelog generated from commits (`CHANGELOG.md`).

---

## 4. Pull Request Standards

Every PR MUST:

- Reference an issue (or be a clearly-described task).
- Include a description: what, why, risks, test plan.
- Pass all CI gates (`15` §11).
- Update affected documentation (`16` §10 — behavior change without doc change fails).
- Include tests for new/changed behavior (bug fix → regression test).
- Not exceed a reviewable size; large work split into sequential PRs.
- Follow `04` code standards (lint, mypy, architecture gates).

PR title: `<type>(<scope>): <summary>` (mirrors commit).

---

## 5. Code Review

- At least **one approval** required (two for core/architecture/security changes).
- Review focuses on: correctness, security, architecture compliance, testing,
  performance, docs.
- Review checklist: see `24 - Quality Assurance.md` §5.
- Reviewers may request changes; CI must be green before merge.
- Reviewer = owner gate for: schema changes, architecture decisions,
  security-sensitive changes (dedicated Security review).

---

## 6. CI/CD Pipeline

GitHub Actions (or equivalent) — see `15` §11 for the test matrix:

```
PR: lint → format → types → architecture → unit → golden → component →
    security → (integration if services) → coverage gates → build check
Merge to main: everything above + build packages + SBOM + image build
Release: all + acceptance (sandboxed targets) + performance smoke +
         publish (PyPI/container) + docs site
```

Quality gates fail → blocked merge/publish.

---

## 7. Semantic Versioning

SemVer 2.0.0 (`MAJOR.MINOR.PATCH`), derived from Conventional Commits:

| Change | Bump |
|--------|------|
| Breaking API/schema/behavior change | MAJOR |
| New backward-compatible feature | MINOR |
| Bug fix, docs, internal | PATCH |
| Pre-release | `-alpha.N`, `-beta.N`, `-rc.N` |

Versioned artifacts:

- Core package version (`pyproject.toml`).
- **Schema version** (`08`) — independently versioned, changes tracked.
- **SDK version** (plugin/adapter ABI) — independently versioned.
- **Knowledge base** — versioned as a corpus.
- REST API (`/api/vN`).
- Report template versions (`21` §9).

---

## 8. Release Process

```
1. Freeze: create release/x.y.z from main
2. Validation: full CI + acceptance + performance smoke on freeze branch
3. Changelog: verify CHANGELOG completeness; update docs site
4. Tag: vX.Y.Z (signed tag)
5. Publish: PyPI package (sdist+wheel), container images (signed), SBOM
6. Docs: rebuild docs site for the tag
7. Announce: release notes (RELEASE_NOTES)
8. Hotfix path: fix → PR → release branch → backport to main
```

Release checklist: see `RELEASE_CHECKLIST.md`.

---

## 9. Definition of Ready / Done

**Ready (start work):** issue has clear acceptance criteria, linked scope
(engagement-free), impacted Bible docs identified.

**Done:** `01 - Vision.md` §9 + `24` §3 (team checklist) + CI green + docs
updated + changelog entry.

---

## 10. Environment Hygiene

- Local dev: `.env.example` (no real secrets); secrets only via secret store.
- Pre-commit hooks (`.pre-commit-config.yaml`): ruff, format, secret scan,
  import-linter, trailing whitespace.
- Never commit: generated artifacts, `*.pyc`, caches, local data, credentials.
- `.gitignore` enforced; `git secrets` scan in CI.

---

## 11. References

- `15 - Testing Standards.md` §11 (CI matrix)
- `24 - Quality Assurance.md` (review & gates)
- `04 - Coding Standards.md` §14 (code review gates)
