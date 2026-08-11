# HunterX v7 — Sprint 034.1
# FINAL RELEASE GATE — Phase 1: Repository Integrity & V6/V7 Contamination Audit

**Date:** 2026-08-10
**Phase:** 034.1 (integrity audit only — no feature development)
**Author:** Principal Release Engineer (Phase 034.1)
**Scope:** Repository inventory, V6 contamination audit, runtime path, configuration,
packaging, CI/CD, documentation, database artifacts, classification, safe repairs, validation.

---

## 1. Executive Summary

HunterX v7 (`src/`-layout, `pyproject.toml` `version = "7.0.0"`) is implemented,
runs, and passes its full test suite, but the repository is **still contaminated by
V6-era implementation, packaging, documentation, and runtime paths**, and the
entire V7 delivery is currently **untracked in git**.

Key conclusions:

1. **V7 is the real runtime** — verified end-to-end:
   `hunterx version` → `HunterX v7.0.0`; `hunterx platform` → full composition;
   API factory `hunterx.api.app:create_app` (FastAPI, `/health`); mission creation
   via `hunterx mission create` / `hunterx hunt`.
2. **V6 contamination vectors exist and were repaired where unambiguous:**
   the root `hunterx.py` shim dispatched to the V6 CLI; the Dockerfile baked in
   `VERSION=6.0.0`, a `hunterx doctor` health check (a command V7 does not have),
   and V6 `hunterx.yaml`/`payloads/` copies; `install.sh` downloaded
   `hunterx-6.0.0.tar.gz` from PyPI and verified with V6-only commands;
   **12 SQLite database artifacts were tracked in git**.
3. **One P0 remains:** the entire V7 tree (`src/`, `tests/{unit,…}`, `eng/`,
   `alembic/`, `config/`, `capabilities/`, V7 workflows, `requirements.lock`,
   V7 docs) is **uncommitted**. A clean clone of `main` today contains only the
   retired V6 flat package. The release gate cannot be closed until the V7 tree
   is staged/committed (034.2 decision — not performed here per instructions).
4. Known, classified, carry-over issues are listed in §10 (P0–P3) for 034.2.

**Phase gate: PASS (with one P0 carry-over that blocks the release gate until
the V7 tree is committed).**

---

## 2. Repository Inventory

### 2.1 Active (V7) paths

| Path | Role | Status |
|---|---|---|
| `src/hunterx/` | V7 clean-architecture package (domain, application, infrastructure, engines, tools, api, cli, platform) | Active — **untracked** |
| `tests/unit|component|architecture|integration|golden|security|acceptance|performance|engineering|framework` | V7 test suites | Active — **untracked** |
| `eng/` | Engineering platform (gates, security, sbom, packaging, readiness, release) | Active — **untracked** |
| `alembic/` + `alembic.ini` | V7 migrations (23 version scripts) | Active — **untracked** |
| `config/` (`architecture.yaml`, `api_baseline.json`, `vulture_allowlist.py`, `config/capabilities/*.json`) | Architecture matrix, baseline, capability manifests | Active — **untracked** |
| `capabilities/` | V7 capability manifests (11 JSON) | Active — **untracked** |
| `.github/workflows/*` (14 new) | V7 CI/CD | Active — **untracked** |
| `requirements.lock` | V7 locked dependency set | Active — **untracked** |
| `docs/v7-*.md`, `docs/{architecture,bible,cli,configuration,features,installation,use-cases}` | V7 design + reference docs | Active — **untracked** |
| `docs/_includes/seo.html`, `docs/_layouts/{post,tutorial}.html`, `docs/_redirects` | V7 doc-site infra | Active — **untracked** |

### 2.2 Obsolete / V6 paths

| Path | Role | Status |
|---|---|---|
| `hunterx/` (245 files) | Retired V6 flat package (`cli.py`, `core/`, `modules/`, `engines/`, `api/`, `reporting/`, `utils/`) | Tracked — preserved in-tree by design (pyproject documents "intentionally NOT packaged") |
| `hunterx/assets/data/*.db`, `hunterx/data/ai_cache.db`, `hunterx/modules/data/*.db`, `data/*.db` | V6 SQLite runtime DBs (ai cache, payload index/provenance, adaptive memory) | **Were tracked — untracked this phase (repair)** |
| `api/`, `core/`, `plugins/` (top-level) | V6-era duplicate/orphan modules (`core/` is an empty stub; `api/` duplicates `hunterx/api`) | Tracked — dead |
| `payloads/` (42 files), `data/` | V6 payload corpus + DB data | Tracked — unused by V7 |
| `hunterx.yaml` (root) | V6 config schema | Tracked — merged inertly by V7 loader from cwd |
| `hunterx.py` (root) | V6 CLI shim | Tracked — **repaired to delegate to V7** |
| `requirements.txt` | V6 dependency set (requests, bs4, lxml, websocket-client) | Tracked — conflicts with V7 pyproject/lock |
| `install.sh`, `Dockerfile`, `docker-compose.yml` | V6-era install/image/compose | Tracked — Dockerfile + install.sh repaired; compose flagged |
| `awesome-*.md`, `awesome-pentest`, `pentest.md`, `temp_cli_apps.md` | V6-era clutter | Tracked — P2 |
| `tests/test_*.py` (~36) + `tests/conftest.py` (root) | V6 flat tests | Tracked — excluded from suite by pyproject (documented) |
| `docs/*.md`, `docs/_posts`, `docs/_tutorials`, `docs/cli`, `docs/features`, `docs/configuration`, `docs/installation` | V6 documentation | Tracked/untracked — see §8 |

### 2.3 Orphans, duplicates, dead paths

- **Orphan modules:** top-level `core/` (empty `__init__`), `api/`, `plugins/`
  (duplicates of `hunterx/*`). Not packaged, not referenced by V7.
- **Duplicate config:** capability manifests live in **two** locations —
  `capabilities/*.json` (11) and `config/capabilities/*.json` (7). Neither is
  referenced by code.
- **Duplicate DB artifacts:** `data/*.db` are byte-identical copies of
  `hunterx/assets/data/*.db`.
- **Dead paths:** `hunterx/core/reasoning_engine_old.py` (explicitly "old"),
  `scripts/__init__.py` (empty package), `alembic/versions/__pycache__/*.pyc`
  referencing migration files no longer in source (`tmp_vuln_migration`,
  `dryrun_check`, `schemacheck`, three old `api_intelligence_tables` variants).
- **Duplicate entry points:** `python hunterx.py`, `python -m hunterx`,
  `hunterx` console script, `hunterx.cli:main` vs V6 `hunterx/cli.py:main`.

---

## 3. V6 Contamination Findings

### 3.1 In `src/` (V7)
**None.** Grep for `from hunterx.core|modules|utils|engines` inside `src/`
returns zero matches. The V7 package is internally clean.

### 3.2 Runtime entry points (VERIFIED)
- `python -c "import hunterx"` **from the repo root** resolves to the **V6**
  flat package (`hunterx/__init__.py`, `__version__ = "6.0.0"`) because the repo
  root (cwd) sits ahead of the `src` editable path on `sys.path`.
- `python -m hunterx` from the repo root runs the **V6 CLI**
  ("AI-Assisted Vulnerability Hunter | v6.0.0", commands: scan/module/doctor/…).
- `python hunterx.py` previously ran the **V6 CLI** — **repaired this phase** to
  insert `src/` first (now prints `HunterX v7.0.0`).
- `hunterx` console script (editable install) runs **V7** (`hunterx version` →
  `v7.0.0`, `hunterx platform` → composition JSON). ✔ V7 is the installed runtime.
- Stale root `hunterx.egg-info/` (PKG-INFO `6.0.0`) confused
  `importlib.metadata` (reported v6.0.0) — **deleted this phase**; metadata now
  correctly reports 7.0.0.

### 3.3 Environment prefixes
- V7: `HUNTERX_*` (declared in `src/hunterx/config/loader.py`; secrets layer uses
  `HUNTERX_SECRET_*`; sandbox injects `HUNTERX_EXECUTION_ID` etc.).
- V6: `HX_*` (`HX_TIMEOUT`, `HX_THREADS`, `HX_MAX_RPS`, `HX_AI_*`, …) — only in
  V6 code (`hunterx/config/config.py`) and the excluded root `tests/test_config.py`.
- Docker/Compose still referenced `HX_*` — **Dockerfile repaired**; compose flagged.

### 3.4 Configuration schema
Two distinct schemas exist: root `hunterx.yaml` (V6: `profile/stealth/auth/ai/oob/
presets`) and `src/hunterx/config/hunterx.yaml` (V7: `app_name/environment/database/
cache/queue/security/api`). The V7 loader reads a cwd `hunterx.yaml` as a profile;
the V6 file is merged and its unknown keys are ignored by pydantic (inert, but a
latent trap).

### 3.5 CLI command surface
V6 commands (`scan`, `module`, `doctor`, `payload`, `agents`, `skills`,
`workflow`, `reasoning`, `api`, `update`, `ai`) **do not exist in V7**. V7 exposes
`version/help/config/platform`, `mission *`, `hunt *`, `finding *`, `report *`,
`target *`, `campaign *`, `tools *`. Docker healthcheck `hunterx doctor` and
install.sh smoke/help text used V6 commands — **repaired**.

### 3.6 CI / Docker references
No workflow hardcodes `6.0.0`. The Dockerfile's `ARG VERSION=6.0.0` default,
`COPY hunterx.yaml`/`COPY payloads/` and `hunterx doctor` healthcheck were V6 —
**repaired**. `docker-compose.yml` remains fully V6 (see §10 P1-02).

---

## 4. Active Runtime Path (verified end-to-end)

1. **Install:** `pip install .` → `pyproject.toml` → `[tool.setuptools.packages.find]
   where=["src"]` → only `src/hunterx` is packaged → console scripts `hunterx` and
   `hunterx-arch`.
2. **CLI startup:** `hunterx` → `hunterx.cli:main`
   (`src/hunterx/cli/__init__.py`) → `CliApplication` + `register_default_commands`
   → `build_platform()`.
3. **API startup:** `hunterx.api.app:create_app` (FastAPI, `version="7.0.0"`,
   `/health` + mission/finding/report/target-memory/tools/orchestration routers).
4. **Platform construction:** `build_platform()` assembles the `Platform`
   composition root — 30+ application services, four facades (TIP, Tool Integration
   SDK, Tool Integration Factory, Mission Planning), CoreEngine, observability
   stack, in-memory default adapters, optional SQL repositories.
5. **Mission creation/execution:** `hunterx mission create` →
   `MissionOrchestrationService.create_mission` → `MissionOrchestrator`
   (`hunterx.domain.mission_orchestration.orchestrator`); `hunterx hunt` creates
   + starts a full-spectrum mission via `MissionDashboardService`.

**V7 is the actual runtime.** The only contamination paths to V6 were the repo-root
`hunterx.py`/`python -m hunterx`/`import hunterx` shadowing (root on `sys.path`) and
V6 packaging/Docker/install artifacts — all addressed in §9 except the documented
repo-root shadowing caveat (P1-01) and compose (P1-02).

---

## 5. Configuration Audit

| Source | Authoritative? |
|---|---|
| `src/hunterx/config/hunterx.yaml` (bundled default profile) | ✔ **Authoritative default** |
| `src/hunterx/config/settings.py` (`Settings`, pydantic) | ✔ **Schema authority** |
| `src/hunterx/config/loader.py` `load_default_settings()` | ✔ **Loader authority** |
| cwd `hunterx.yaml` (root, V6 schema) | Legacy — merged inertly |
| `HUNTERX_CONFIG` env var | Supported (points to a profile file) |
| `HUNTERX_*` env vars | **Declared but NOT implemented** (see finding) |
| Root `hunterx.yaml` (V6), `hunterx/config/hunterx.yaml` (V6) | Legacy |
| `docker-compose.yml` `HX_*` env | Legacy — inert/broken |
| Alembic `HUNTERX_DB_URL` | V7 migration env override |

**Precedence (as documented in `loader.py`):** bundled defaults → user profile
(`HUNTERX_CONFIG` or cwd `hunterx.yaml`) → environment (`HUNTERX_*`).

**Finding (P1-06):** the environment step is **not implemented**.
`Settings` is a plain pydantic `BaseModel` with no `model_config`/`SettingsConfigDict`;
`load_default_settings()` merges YAML only. Verified: `HUNTERX_ENVIRONMENT=dev`,
`HUNTERX_LOG_LEVEL=DEBUG` have no effect. The docstrings in `settings.py`/`loader.py`
promise auto env mapping that does not exist. This also means the Dockerfile's
`HUNTERX_LOG_LEVEL` (renamed this phase) is inert until 034.2 implements env support.

---

## 6. Packaging Audit

- **`pyproject.toml`** — V7 correct: `version=7.0.0`, `requires-python>=3.11`,
  `[project.scripts] hunterx = hunterx.cli:main`, `hunterx-arch = hunterx.architecture.cli:main`,
  `packages.find where=["src"]`, `package-data` ships `py.typed`, `config/*.yaml`,
  `reporting/templates/*`. Comments explicitly document the V6 flat package is
  not packaged. ✔
- **Entry points** (`src/hunterx.egg-info/entry_points.txt`) match pyproject. ✔
- **`requirements.lock`** — V7 locked set (mirrors pyproject deps); consumed by
  CI caching, pip-audit, SBOM, license checks. ✔
- **`requirements.txt`** — V6 dependency set (`requests`, `beautifulsoup4`, `lxml`,
  `websocket-client` — not in pyproject). **STALE/conflicting** (P2-05); still
  watched by `dependency-review.yml` and managed by Renovate (`pip_requirements`).
- **`Dockerfile`** — **Repaired this phase** to V7 (VERSION default 7.0.0,
  healthcheck `hunterx version`, no V6 `hunterx.yaml`/`payloads/` copies,
  `HUNTERX_LOG_LEVEL`, EXPOSE 8080). Multi-stage src-layout build verified sound.
- **`install.sh`** — **Repaired this phase** (7.0.0 sdist URL, banner, V7 smoke
  `hunterx version`, V7 help text). Remaining caveat: the wrapper fallback
  `python -m hunterx` needs a V7 `__main__.py` (P2-09); the PyPI path assumes
  hunterx 7.0.0 exists on PyPI.
- **`.dockerignore`** — **Repaired this phase** to exclude the V6 tree, DBs,
  caches, artifacts and non-runtime trees from the build context.
- **`docker-compose.yml`** — fully V6 (see P1-02).

---

## 7. CI/CD Reference Audit

Reviewed 19 workflows (`release`, `test`, `ci`, `build`, `unit-tests`,
`integration-tests`, `security-tests`, `performance-tests`, `architecture-tests`,
`compliance`, `cosign-sign`, `dependency-review`, `docs-validation`,
`packaging-validation`, `readiness`, `sbom`, `docker-publish`, `pypi-publish`) +
`.pre-commit-config.yaml`, `renovate.json`, `dependabot.yml`, `CODEOWNERS`.

- **No workflow hardcodes `6.0.0`/`v6.0.0`.** All workflows target the V7 paths:
  `tests/{unit,component,architecture,integration,golden,security}`,
  `src/hunterx`, `eng/*`, `requirements.lock`, `hunterx-arch`/`python -m hunterx.architecture`.
- `dependency-review.yml` still watches root `requirements.txt` + `**/requirements*.txt`
  (V6 file) alongside `requirements.lock` (P2-05).
- Docker workflows build via the (now V7) Dockerfile; `packaging-validation.yml`
  also smoke-tests `hunterx --help` / `hunterx-arch --help` (V7 entry points). ✔
- `.pre-commit-config.yaml` local hook uses `hunterx-arch` with `language: system`
  — silently no-ops if the package isn't installed in the local env (P3-01).
- **Live gate results (run locally, ruff 0.15.22):**
  `mypy` PASS, `docs` PASS (7/7 after repair), `hygiene` PASS, `compliance` PASS,
  `architecture` (hunterx-arch lint) PASS — but **`ruff` FAIL (77 pre-existing
  violations in `src/hunterx`)**, so the mandatory ruff gate (test.yml/ci.yml) is
  currently red. Pre-existing tech debt, not V6-related (P2-08).

No CI changes were made this phase (per instructions).

---

## 8. Documentation Consistency Audit

Classified by category (full per-file audit was performed; highlights below).

- **ACTIVE V7:** `docs/architecture/*`, all `docs/v7-*.md` (design corpus + sprint
  033 report), `THIRD_PARTY_NOTICES`, `docs/_redirects`.
- **HISTORICAL V6:** `RELEASE_NOTES_v6.0.0.md`, `docs/archive/*` audit reports,
  `docs/features/*`, `docs/_posts/*` (dated blog posts, unlabeled), `docs/_tutorials/*`.
- **STALE (V6 content on live pages):** `README.md`, `docs/index.md`, `docs/features.md`,
  `docs/modules.md`, `docs/api.md`, `docs/configuration.md`, `docs/cli.md`,
  `docs/authentication.md`, `docs/Docker_Guide.md`, `docs/profiles.md`, `docs/faq.md`,
  `docs/systemd.md`, `docs/AI_PROVIDER_GUIDE.md`, `docs/Reference_Guide.md`,
  `docs/PLUGIN_DEVELOPMENT.md`, `docs/SKILL_SDK.md`, `docs/AGENTS.md`, `docs/ARCHITECTURE.md`,
  `docs/REASONING_ENGINE.md`, `docs/SECURITY_SKILLS_FRAMEWORK.md`, `docs/quickstart.md`,
  `docs/documentation.md`, `docs/installation/index.md`, `docs/releases/index.md`,
  `docs/tutorials/index.md`, `docs/use-cases/*`, `docs/examples/*`, `docs/comparisons/*`,
  root `CHANGELOG.md`, `ROADMAP.md`, `SECURITY.md`, `CONTRIBUTING.md`,
  `RELEASE_CHECKLIST.md`, `SUPPORTED_PLATFORMS.md`, `CITATION.cff`.
- **CONTRADICTORY:** README config/layout sections vs V7; `docs/ARCHITECTURE.md`
  vs `docs/architecture/README.md` (same permalink `/architecture/`); `docs/cli.md`
  vs `docs/cli/index.md` (same permalink `/cli/`); `CHANGELOG.md`/`ROADMAP.md`/
  `CITATION.cff`/`SECURITY.md` version claims (6.0.0 vs 7.0.0).
- **BROKEN:** `docs/_config.yml` fails YAML parsing (mixed `defaults:` indentation);
  `docs/_layouts/default.html` has no `{{ content }}`/`<body>`; `nav.html` links
  `/Docker_Guide`, `/arch`; `robots.txt` sitemap URL points to the deleted
  `sitemap.xml`; `seo.html`/`tutorial.html`/`post.html` Liquid syntax errors;
  every `docs/cli/*.md` has malformed single-line front matter; `CITATION.cff`
  has malformed YAML; `docs/quickstart.md` references non-existent `hunterx setup`/
  `hunterx feeds update`; `docs/contributing.md` references non-existent
  `tests/test_scanner.py`.
- **Repaired this phase:** the single link that failed the `docs` gate —
  `docs/v7-api-intelligence-implementation-plan.md` → `./v7-api-intelligence.md`
  (file does not exist). Gate now 7/7. All other docs issues are classified for
  034.2 (docs rewrites are content work, not integrity repairs).

---

## 9. Database / Artifact Audit

| Artifact | Location | Tracked? | Notes |
|---|---|---|---|
| V6 SQLite DBs (ai_cache, payload_index, payload_provenance, adaptive_memory) | `data/*.db` (4), `hunterx/assets/data/*.db` (4), `hunterx/data/ai_cache.db` (1), `hunterx/modules/data/*.db` (3) | **Were tracked → untracked (repair)** | Binary cache/index DBs; `data/*` are byte-identical copies |
| V7 runtime DB | `hunterx.db` (root, ~10 MB, 22 V7 tables) | Untracked | Now gitignored |
| Test/build artifacts | `artifacts/` (coverage, SBOM, gates, benchmarks, security reports) | Untracked | Now gitignored |
| Caches | `.mypy_cache/`, `.ruff_cache/`, `.benchmarks/`, `.pytest_cache/` | Untracked | Now gitignored |
| Build output | `dist/`, `build/`, `hunterx.egg-info/`, `src/hunterx.egg-info/` | Untracked | Root `hunterx.egg-info/` (V6 metadata) deleted this phase |
| Google site verification | `googlea591cd58e85d83b3.html` | Tracked | Public verification token — benign |
| Credentials/private keys/secrets | — | None found | No private keys, `.env`, or API keys in tracked files; `sk-`/`AKIA` matches in V6 payload JSON (`ghdb.json`, detector test vectors) are test payloads, not real secrets |

**Conclusion:** the repo previously shipped 12 binary SQLite DBs in git (now
untracked, on disk only), and no credential material was found. DBs are not
included in release artifacts (src-only packaging).

---

## 10. Issue Classification

### P0 — RELEASE BLOCKER
| ID | Issue | State |
|---|---|---|
| P0-01 | **Entire V7 delivery is untracked**: `src/`, V7 `tests/`, `eng/`, `alembic/`, `config/`, `capabilities/`, V7 workflows, `requirements.lock`, V7 docs, `THIRD_PARTY_NOTICES`, `CODEOWNERS`, `dependabot.yml`. A clean `main` clone has only the V6 flat package. Release tagging/packaging cannot proceed from a committed state. | Open — needs staging/commit decision in 034.2 |

### P1 — MUST FIX
| ID | Issue | State |
|---|---|---|
| P1-01 | Repo-root shadowing: `import hunterx` / `python -m hunterx` from the repo root resolve to the V6 flat package (root precedes `src` on `sys.path`). Only `tests/conftest.py` compensates. | Open — structural (needs V6 tree relocation or documented mitigation) |
| P1-02 | `docker-compose.yml` is entirely V6: `VERSION: 6.0.0`, `HX_*` env, mounts V6 `hunterx.yaml`, `command: ["api", "--port", "8443"]` (no such V7 command). Broken for V7. | Open — needs V7 API startup design (034.2) |
| P1-03 | Tracked SQLite DB artifacts (12 files) in git. | **Repaired** (`git rm --cached` + gitignore) |
| P1-04 | `hunterx.py` shim dispatched to the V6 CLI. | **Repaired** (now delegates to `src/`) |
| P1-05 | Dockerfile V6 markers (`VERSION=6.0.0`, `hunterx doctor` healthcheck, V6 `hunterx.yaml`/`payloads/` copies, `HX_LOG_LEVEL`, EXPOSE 8443). | **Repaired** |
| P1-06 | V7 env-var precedence declared but not implemented (`HUNTERX_*` has no effect; verified). | Open — implement in 034.2 |
| P1-07 | `install.sh` V6 markers (sdist 6.0.0 URL, banner, V6-only smoke/help commands). | **Repaired** (version strings + V7 commands); wrapper `python -m hunterx` fallback still needs V7 `__main__.py` (see P2-09) |

### P2 — TECHNICAL DEBT
| ID | Issue |
|---|---|
| P2-01 | Retired V6 flat package `hunterx/` (245 files) retained at repo root; root-shadowing risk (see P1-01). Recommend relocation to a `legacy/` tree. |
| P2-02 | Orphan top-level `api/`, `core/` (empty stub), `plugins/` — dead V6 duplicates; not packaged, unreferenced. |
| P2-03 | Root `hunterx.yaml` (V6 schema) tracked; V7 loader merges it inertly. Recommend removal or conversion. |
| P2-04 | `capabilities/` vs `config/capabilities/` duplicate manifest locations; neither referenced by code. |
| P2-05 | `requirements.txt` (V6 deps) conflicts with pyproject/lock; watched by dependency-review + Renovate. |
| P2-06 | V6 payload corpus `payloads/` (42 tracked files) unused by V7. |
| P2-07 | V6 clutter at root: `awesome-*.md`, `awesome-pentest`, `pentest.md`, `temp_cli_apps.md`, `summary.txt`. |
| P2-08 | Ruff gate red: 77 pre-existing violations in `src/hunterx` (D102×25, F401×16, I001×8, B023×7, etc.) under ruff 0.15.x. Mandatory CI ruff gate fails. Pre-existing, non-V6. |
| P2-09 | No `src/hunterx/__main__.py` → `python -m hunterx` unsupported for installed V7 (console script is official entry). A `__main__.py` was drafted but reverted because `hunterx-arch` classified it as a `legacy→cli` boundary violation (ARCH-001); classify it as `cli` layer when added. |
| P2-10 | V6 flat tests at `tests/` root (~36 files) — excluded from suite (documented in pyproject). |
| P2-11 | Doc-site broken: `docs/_config.yml` YAML parse failure; `default.html` missing `{{ content }}`; broken nav/sitemap; malformed `docs/cli/*` front matter. |
| P2-12 | Stale version claims across `CHANGELOG.md`, `ROADMAP.md`, `CITATION.cff`, `SECURITY.md`, `SUPPORTED_PLATFORMS.md` (6.0.0 vs 7.0.0). |
| P2-13 | V6-era docs still describing `scan/module/doctor/payload/agents` commands and `HX_*` env on live pages (README, docs index, features, cli, configuration, Docker_Guide, faq, systemd, tutorials, posts). |

### P3 — POST-RELEASE
| ID | Issue |
|---|---|
| P3-01 | `.pre-commit-config.yaml` `hunterx-arch` local hook with `language: system` silently no-ops if uninstalled. |
| P3-02 | `CODEOWNERS` gaps for `src/hunterx/{cli,platform,architecture,api,security,knowledge}`. |
| P3-03 | Orphaned `.pyc` files in `alembic/versions/__pycache__` for deleted migrations. |
| P3-04 | `googlea591cd58e85d83b3.html` tracked (public token, benign) — confirm intent. |

---

## 11. Repairs Performed (validated)

1. **`.gitignore`** — added `*.db`, `*.sqlite`, `*.sqlite3`, `hunterx.db`, `/data/`,
   `/artifacts/`, `.mypy_cache/`, `.ruff_cache/`, `.benchmarks/`.
2. **Untracked 12 V6 SQLite DBs** (`git rm --cached`; files kept on disk) —
   verified no `.db` files remain tracked.
3. **Deleted stale root `hunterx.egg-info/`** (V6.0.0 metadata). Verified
   `importlib.metadata.distribution("hunterx")` now reports **7.0.0**.
4. **`hunterx.py`** — now inserts `src/` ahead of the repo root and delegates to
   V7 (`python hunterx.py version` → `HunterX v7.0.0`).
5. **`Dockerfile`** — `ARG VERSION=7.0.0`; HEALTHCHECK `hunterx version`;
   removed `COPY hunterx.yaml`/`COPY payloads/`; `HX_LOG_LEVEL`→`HUNTERX_LOG_LEVEL`;
   `EXPOSE 8080`. No `6.0.0`/`HX_`/`doctor` markers remain.
6. **`install.sh`** — sdist URL `hunterx-7.0.0.tar.gz`; banner `v7`;
   smoke test `hunterx version`; help text uses V7 commands.
7. **`.dockerignore`** — exclude V6 tree (`hunterx/`, `payloads/`, `core/`, `api/`,
   `plugins/`, `awesome-pentest/`), DBs, caches, `artifacts/`, `data/`, and
   non-runtime trees (`alembic/`, `eng/`, `capabilities/`, `config/`).
8. **`docs/v7-api-intelligence-implementation-plan.md`** — removed the broken link
   to the nonexistent `v7-api-intelligence.md`; `docs` gate now 7/7.

---

## 12. Validation Results

| Check | Result |
|---|---|
| `hunterx version` (console script) | `HunterX v7.0.0`, exit 0 ✔ |
| `hunterx platform` | Full composition JSON ✔ |
| `hunterx help` | V7 command surface only (no scan/doctor/module) ✔ |
| `python hunterx.py version` | `HunterX v7.0.0`, exit 0 ✔ |
| `python -c "import hunterx"` (repo root) | V6 (documented caveat, P1-01) |
| `pytest tests/unit` | **2008 passed** |
| `pytest tests/component` | **86 passed** |
| `pytest tests/architecture` | **129 passed** |
| `pytest tests/integration tests/golden tests/acceptance tests/security` | **704 passed, 8 skipped** |
| `hunterx-arch lint --root .` | Exit 0 (green) ✔ |
| `mypy eng src/hunterx/shared` | Clean ✔ |
| `python -m eng gates --gate docs` | 7/7 PASS ✔ |
| `python -m eng gates --gate hygiene` | PASS ✔ |
| `python -m eng gates --gate compliance` | PASS ✔ |
| `ruff check src` | 77 pre-existing violations (gate red — P2-08) |
| Docker build | Not executed (no Docker daemon); Dockerfile statically verified |
| `.gitignore` / `.dockerignore` | Applied; DB files remain on disk, untracked |

---

## 13. Final Phase Verdict

**Phase 034.1 — PASS, with one P0 release blocker carried forward.**

- ✔ V7 runtime path identified (console script → `hunterx.cli:main` →
  `build_platform()`; API via `hunterx.api.app:create_app`; missions via
  `hunterx mission`/`hunt`).
- ✔ No unknown V6 runtime contamination remains in the *packaged* path. All
  known V6 runtime vectors were either repaired (hunterx.py, Dockerfile,
  install.sh, egg-info, tracked DBs) or are explicitly tracked as remaining
  (repo-root shadowing P1-01, docker-compose P1-02).
- ✔ Configuration authority identified (`src/hunterx/config/hunterx.yaml` +
  `Settings` via `loader.load_default_settings`); env precedence noted as
  unimplemented (P1-06).
- ✔ Packaging path verified (src-layout, entry points, requirements.lock,
  repaired Dockerfile).
- ✔ CI problems identified (ruff gate red P2-08; dependency-review V6 watch
  P2-05; no `6.0.0` hardcodes).
- ✔ Stale documentation classified (ACTIVE V7 / HISTORICAL V6 / STALE /
  CONTRADICTORY / BROKEN) and the failing docs link repaired.
- ✔ Database artifacts identified (12 tracked V6 DBs untracked; V7 `hunterx.db`
  gitignored; no credentials found).
- ✔ Release blockers classified (P0-01 untracked V7 tree — the sole P0).
- ✔ Repairs validated (full test suite green; gates green except pre-existing ruff).
- ✔ Report generated (`docs/v7-sprint-034.1-repository-integrity.md`).

**STOP — Phase 034.1 complete. Do not proceed to 034.2 automatically.**
