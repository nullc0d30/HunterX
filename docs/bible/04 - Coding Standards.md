# 04 — HunterX Coding Standards

**Status:** Ratified
**Version:** 1.0.0
**Applies to:** All Python code in `src/hunterx/`, `plugins/`, `tools/`, `tests/`, `scripts/`
**Baseline config:** `pyproject.toml` (`ruff`, line-length 120, target py311, `E501` ignored)

---

## 1. Language & Runtime

- Python **>= 3.11**, targeting 3.11–3.13 (see classifiers in `pyproject.toml`).
- Async-first where I/O-bound (network, DB, subprocess, AI). Compute-bound
  work must not block the event loop (use executor pools).
- Type annotations are **mandatory** on all public functions, methods, and
  module-level variables (PEP 484 / PEP 604 syntax, `X | None`).

---

## 2. Type Hints

- Always annotate arguments and return types. `-> None` for side-effect-only.
- Prefer structural typing (`Protocol`) for ports/interfaces over ABC where
  possible; ABC is acceptable where a base implementation is shared.
- Use `TypedDict` for dict-shaped config/JSON payloads; `dataclasses` for value
  objects and entities; `Enum` (or `StrEnum`) for closed sets.
- Use `pydantic` models only in delivery/application boundaries (CLI, API,
  config, plugin manifests). Domain layer uses dataclasses + `TypeGuard`s.
- `Any` is forbidden in public signatures except at the external boundary with
  an explicit comment justifying it.
- Generic types: prefer `Sequence`, `Mapping`, `Iterable` over concrete
  `list`/`dict` in interfaces; concrete types in implementations.
- `Final` for module-level constants; `Self` for fluent/static factories.
- Annotate exceptions in `raises:` via documentation; enforce with a custom
  lint rule where available.
- **Never** use `# type: ignore` without a comment referencing an issue; adding
  ignores is a code-review flag.

```python
from typing import Protocol, TypeGuard

class ResolvesTargets(Protocol):
    def resolve(self, scope: Scope) -> Sequence[Host]: ...

def is_authorized(actor: Actor, action: Action) -> TypeGuard[AuthorizedActor]:
    return actor.can(action)
```

---

## 3. Naming Conventions

| Category | Convention | Example |
|----------|-----------|---------|
| Packages/modules | `snake_case`, short | `hunterx/engines/` |
| Classes | `PascalCase` | `WorkflowEngine` |
| Functions/methods | `snake_case`, verb-first | `resolve_targets()` |
| Variables | `snake_case` | `finding_ids` |
| Constants | `UPPER_SNAKE_CASE` | `MAX_RETRIES` |
| Private members | single leading `_` | `_normalize()` |
| Protected (plugin SDK) | public, documented | `execute()`, `parse()` |
| Type aliases | `PascalCase` suffix `Type` | `FindingId = str` |
| Exceptions | `PascalCase` suffix `Error` | `ScopeViolationError` |
| Protocol types | `PascalCase` (adjectival) | `ResolvesTargets` |
| Enum members | `UPPER_SNAKE_CASE` | `Severity.CRITICAL` |
| Test functions | `test_<behavior>_<condition>` | `test_parse_handles_missing_fields()` |
| Bool getters | `is_`, `has_`, `can_` | `is_reachable()`, `can_execute()` |

Forbidden:

- Hungarian notation, single-letter names (except loop vars), abbreviations
  beyond established ones (`stdout`, `http`, `ip`, `dns`).
- Leading/trailing underscores in public APIs.

---

## 4. Logging

- Logging is **structured, never string-concatenated prose**:
  ```python
  logger.info("tool.completed", tool="nmap", target_id=target_id, duration_ms=12_340)
  ```
  (Key-value pairs, not f-strings in the message.)
- Use `structlog`-style keyword logging or the project JSON logger; plain
  `logging` `%`-style with zero context fields is **not** acceptable.
- Levels: `debug` (detail), `info` (state transitions), `warning` (degradation),
  `error` (recoverable failure), `critical` (service-down).
- Never log secrets, credentials, tokens, cookies, or full request bodies.
  Use `masking` helpers (`src/hunterx/shared/masking.py`).
- Every log line emitted inside a workflow/tool run carries
  `correlation_id` and `span_id` (bound via contextvars).
- See `18 - Logging Standards.md` for the field contract.

---

## 5. Exceptions

- Define a domain exception hierarchy rooted at `HunterXError`
  (`src/hunterx/domain/exceptions/`).
- **Never** `except Exception` without either re-raising or converting to a
  domain exception with context.
- **Never** swallow exceptions silently; at minimum log with context.
- Catch at the boundary (CLI/API/worker), translate to user-facing error
  codes, and record the full trace with `correlation_id`.
- Prefer explicit exception types over `assert` in production paths
  (`assert` disabled under `-O`).
- Distinguish by *retryability*: `TransientError` (retry) vs
  `PermanentError` (do not retry). See `17 - Error Handling Standards.md`.
- Custom exceptions carry a stable machine code:
  ```python
  class ScopeViolationError(HunterXError):
      code = "HX-SCOPE-001"
  ```

---

## 6. Architecture Rules

1. **Dependency rule:** `domain` imports only stdlib + `shared` value types.
   `application` imports `domain`. `infrastructure` implements domain `ports`.
   Delivery (CLI/API) composes at the root. Enforced in CI.
2. **No framework imports in domain:** no `fastapi`, `sqlalchemy`, `pydantic`,
   `redis`, `requests`, `aiohttp`, `structlog`, `typer`, `click` in `domain/`.
3. **AI isolation:** only `infrastructure/ai` and `engines/reasoning.py` may
   import AI SDKs. Agents, skills, tools must go through the abstraction.
4. **DB isolation:** only `infrastructure/db` may import ORM/driver SDKs.
   Engines use `StorePort`.
5. **Tool execution isolation:** tool binaries are executed via
   `tools/sandbox.py`; adapters never shell out directly.
6. **Events over imports:** cross-subsystem communication uses the Event Bus,
   not direct imports of another subsystem's internals.
7. **No business logic in delivery:** CLI/API handlers are thin; they validate,
   call use-cases, and render.
8. **No `import *`** anywhere; no cyclic imports (enforced with import-linter).

---

## 7. Dependency Injection

- Constructor injection everywhere. No hidden global singletons in domain logic.
- A single **composition root** builds the object graph (CLI entry, API startup,
  worker entry).
- Interfaces are `Protocol`s defined in `domain/ports/`; implementations are
  chosen by config + environment.
- Provide `NullObject` implementations for tests and degraded modes
  (e.g., `NullReporter`, `NullQueue`).
- Dependency resolution is **explicit and deterministic**; no runtime
  metaclass magic.

---

## 8. SOLID

| Principle | Practice |
|-----------|----------|
| S — SRP | One class, one responsibility; controllers stay thin |
| O — OCP | Extend via plugins/adapters; never fork core for a feature |
| L — LSP | Subclasses honor base contracts; `Protocol` implementations satisfy behavior |
| I — ISP | Small focused ports (`ResolvesTargets` ≠ `StoresTargets`) |
| D — DIP | Depend on abstractions; inject concrete at composition root |

---

## 9. Clean Architecture Concretely

- **Entities & value objects:** immutable where possible (`frozen=True`
  dataclasses); domain invariants live in the model, not the caller.
- **Use cases:** one class per use case where logic is non-trivial; input
  validation at boundary; domain rule checks inside domain services.
- **Ports & adapters:** an adapter may implement multiple ports but a port is
  never bound to one adapter.
- **The `shared/result.py` types** (`Success`, `Failure`) replace bare
  `(ok, value)` tuples; errors are values that can be returned and tested.

---

## 10. Async & Concurrency

- Use `asyncio` for I/O concurrency. Do **not** use threads for I/O; use
  `asyncio.to_thread`/executors only for CPU-bound or blocking third-party calls.
- Never block the event loop: no `time.sleep`, no synchronous DB/HTTP calls
  inside coroutines (use async drivers or `to_thread`).
- Use `asyncio.create_task` with explicit `TaskGroup` management; every task
  has a reference held to avoid GC cancellation.
- Cancellation: use `asyncio.CancelledError` handling at boundaries to
  propagate clean shutdown (close sessions, release locks).
- Rate limiting is applied at the tool/queue layer, not scattered in callers.

---

## 11. Thread Safety

- Immutable by default; shared mutable state only behind explicit
  synchronization (`asyncio.Lock`, `threading.RLock` as appropriate).
- Contextvars for request-scoped context (`correlation_id`, `actor`,
  `scope`) — never module-global mutable singletons.
- Singletons allowed **only** for infrastructure identity (registry, event
  bus) and must be documented as such with thread-safe access.
- Never mutate a config object after startup; config is immutable post-load.
- Cache access is atomic; use `get_or_set` semantics.

---

## 12. Performance

- Streaming for large tool outputs: iterate lines/chunks; never slurp
  multi-MB tool output into memory. (See `14 - Performance Standards.md`.)
- Bounded caches (TTL + max entries + eviction). LRU for hot paths.
- Lazy imports inside heavy branches where startup latency matters
  (accepted at module-level only with justification).
- Precompute deterministic hashes (finding, plan) once; reuse.
- SQL: use indexes defined in `09 - Database Design.md`; avoid N+1;
  batch inserts via executemany/bulk APIs.
- Profile before optimizing. Benchmarks live in `tests/performance/`.

---

## 13. Configuration

- Config is loaded via the loader, validated against JSON Schema, and exposed
  as an immutable typed object (`Config` dataclass).
- Access config only through injection; never `import config; config.x` from
  deep modules.
- Secrets are not config; secrets come from `SecretPort`.
- Config precedence: defaults < file < environment < CLI < remote.
- Every config field has a documented default and a test.

---

## 14. Code Review Gates

Code is **not merged** unless:

- `ruff check .` and `ruff format --check .` pass (120 cols).
- `mypy --strict` passes on `src/hunterx`.
- Import linter passes (domain purity, acyclic).
- Unit + integration tests pass; no new coverage regression below the gate
  (see `15 - Testing Standards.md` §9).
- No `Any`, no uncommented `type: ignore`, no TODO/FIXME in shipped code.
- New public APIs have docstrings with params, returns, and raises.

---

## 15. Docstrings

- Module docstring: one line purpose + references to related docs.
- Public class/function: Google-style summary, params, returns, raises.
- No docstring duplication; code is self-documenting via naming.
- Examples only where non-obvious; prefer doctests in `tests/`.

---

## 16. Compatibility & Portability

- Linux-first; platform guards (`sys.platform`) for Windows/macOS paths.
- No reliance on shell-specific features in Python (subprocess always
  explicit with `shlex`-safe argument lists).
- Time: UTC internally, ISO 8601 with `Z`; convert at render boundary.
- Paths: `pathlib` everywhere; no raw string concatenation.
