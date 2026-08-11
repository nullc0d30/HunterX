# 19 — CLI Standards

**Status:** Ratified
**Version:** 1.0.0
**Applies to:** `hunterx` command-line interface

---

## 1. Purpose

The CLI is a **first-class interface** (equal to the REST API). It must be:
discoverable (`--help`), scriptable (machine-parseable output), deterministic,
and safe. It is implemented with a modern argument parser framework (Typer/Click).

---

## 2. Command Model

Command hierarchy (groups):

```
hunterx
├── mission          # create, plan, start, approve, list, show, abort, status, archive
├── workflow         # list, show, run, cancel, resume, checkpoint
├── scan             # ad-hoc single scan (fast path, single target)
├── report           # generate, list, show, export, evidence
├── tool             # list, install, update, health, docs, run
├── plugin           # list, install, remove, update, ban, scaffold, package, test
├── knowledge        # list, show, sync, index, validate
├── payload          # sync, index, search, stats
├── config           # show, validate, get, set (scoped), doctor
├── secret           # set, get (masked), list, rotate, unset
├── api              # serve, token, status
├── admin            # users, roles, audit, maintenance, telemetry
├── completion       # generate shell completions
├── doctor           # environment diagnostics
└── version / self-update
```

### 2.1 Command Grammar

- `hunterx <group> <action> [options] [args]`
- Actions are verbs; objects are nouns.
- Every command has a `--help` with: summary, usage, options, examples.

---

## 3. Global Flags

| Flag | Purpose |
|------|---------|
| `--config <path>` | Override config file |
| `--profile <name>` | Mission/tool profile preset |
| `--output <format>` | `text` (default) \| `json` \| `yaml` \| `csv` |
| `--quiet` / `-q` | Reduce output to errors + results |
| `--verbose` / `-v` | Increase verbosity (repeatable) |
| `--no-color` | Disable ANSI (also auto-detected when non-TTY) |
| `--yes` / `-y` | Skip interactive confirmation (non-interactive mode) |
| `--correlation-id <id>` | Override request correlation id |
| `--version` | Print version and exit |

---

## 4. Flags & Options Conventions

- Long flags `--kebab-case`; short aliases only for common flags (`-o`, `-f`,
  `-v`, `-q`, `-y`).
- Boolean flags: positive form only (`--destructive`); negation via `--no-<x>`
  where a default-true option exists.
- Values: `--flag value` or `--flag=value` (both accepted).
- Repeated flags accumulate into lists (`--tag a --tag b`).
- Enums validated with helpful error listing allowed values.
- No ambiguous abbreviations (Typer default disallows).

---

## 5. Profiles

- `--profile` selects a **profile preset** that layers over config:
  `fast`, `thorough`, `stealth`, `quiet`, plus mission profiles
  (`12 - Mission Profiles.md`).
- Profiles are declared in config (`config/profiles/`) and validated.
- `hunterx config show --profile fast` previews the effective settings.
- Custom profiles: `hunterx config set` under `profiles.<name>` (scoped).

---

## 6. Output Formatting

- **Text (default):** human-oriented; tables with `rich`; progress bars for
  long operations; collapsed by default with `--verbose` expansion.
- **JSON:** stable envelope for every command:

  ```json
  {
    "command": "mission list",
    "ok": true,
    "data": {...},
    "warnings": [],
    "meta": {"correlation_id": "...", "duration_ms": 12}
  }
  ```

- **YAML / CSV:** for data commands (findings, tools, plugins).
- Machine formats are **always** emitted, never rendered, never colored.
- `--output json` is guaranteed stable within a minor version
  (schema pinned in docs).

---

## 7. Colors

- ANSI colors only on TTY; auto-disabled on pipes/CI (`NO_COLOR`, `--no-color`).
- Color semantics fixed:
  - Critical/high findings: red
  - Medium: yellow
  - Low/info: blue
  - Success: green
  - Errors: red bold
- Color is decoration; never conveys the only meaning (also text markers).

---

## 8. Errors & Exit Codes

Exit code table (stable contract):

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General runtime error |
| 2 | Usage error (bad flags/args) |
| 3 | Validation error (invalid input/target) |
| 4 | Configuration error |
| 5 | Not authorized / forbidden |
| 6 | Target out of scope |
| 7 | Tool/plugin missing or unavailable |
| 8 | Timeout |
| 9 | AI provider unavailable |
| 10 | Resource limits exceeded |
| 20–29 | Reserved for specific tool/plugin errors |
| 130 | Interrupted (SIGINT) |

Error output format (text):
```
error: <code> <safe message>
hint: <remediation or docs link>
```

With `--output json`, the error envelope is `{"ok": false, "error": {...}}`
per `17` §9.

---

## 9. Help & Discoverability

- `hunterx --help` lists groups; `hunterx <group> --help` lists actions;
  `hunterx <group> <action> --help` shows full usage with examples.
- `hunterx` with no args prints a concise overview + tip to run `--help`.
- Help text is sourced from docstrings (single source; no duplication).
- `hunterx doctor` validates environment (tools, providers, DB, config) and
  prints a pass/fail table.

---

## 10. Autocomplete

- `hunterx completion <shell>` generates completions for bash/zsh/fish.
- Installed via `hunterx completion install`.
- Completions cover groups, actions, flags, and dynamic values
  (mission ids, tool ids) where cheap to compute.

---

## 11. Interactive vs Non-Interactive

- Interactive prompts (confirmations, selections) only when TTY.
- Non-TTY: fail fast with a clear message suggesting flags (`--yes`, explicit args).
- Confirmations required for: destructive tool runs, scope-expanding actions,
  approval-level steps (see `12` §5).

---

## 12. Safety & Determinism

- CLI never prints secrets; `secret get` prints masked values unless
  `--reveal` explicitly requested.
- Piped output is deterministic (sorted where ordering matters, locale-independent).
- Long-running commands print a job id and stream progress; interruptible.
- `hunterx mission start` prints the mission id and the plan id for
  reproducibility.

---

## 13. CLI ↔ API Parity

- The CLI calls the same **application services** as the API (composition
  root shares use-cases). No CLI-only logic path diverges from API semantics.
- `hunterx api serve` runs the API from the same codebase/config.

---

## 14. References

- `04 - Coding Standards.md` §7 (composition root)
- `17 - Error Handling Standards.md` §9 (operator-facing errors)
- `20 - REST API Standards.md` (parity)
