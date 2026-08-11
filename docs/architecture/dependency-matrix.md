---
layout: default
title: Dependency Matrix & Layer Rules
description: >-
  The HunterX v7 ratified dependency matrix: what every layer may import, the
  direction rule, shared contracts, waivers and known cycles.
permalink: /architecture/dependency-matrix/
---

# Dependency Matrix & Layer Rules

**Status:** Ratified (Sprint 006.7)
**Version:** 1.0.0
**Owner:** HunterX Architecture Council

This document is the human-readable explanation of the machine-readable matrix
in `config/architecture.yaml`. That file is the single source of truth; where
this document conflicts with it, the YAML wins (the linter reads only the YAML).

## Direction rule

Dependencies point **inward**. A module may only import a module from the same
layer or a more foundational layer. There is exactly one way to read the
matrix: `rules[source_layer]` lists every target layer `source_layer` is
allowed to reach. **Any edge not listed is a violation (ARCH-001)** unless it
matches a `conditional_imports` rule or a `waivers` entry.

Foundational layers are foundational **in the sense of the dependency arrow
only** — for example `shared` and `domain` are the purest layers, while
`platform` is the composition root that may reach everything.

## Layer catalogue

| Layer | Prefix | Responsibility | Owner |
|---|---|---|---|
| `shared` | `hunterx.shared` | Cross-cutting helpers, importable by all | Architecture Council |
| `domain` | `hunterx.domain` | Pure entities, value objects, ports, services, events, exceptions | Architecture Council |
| `config` | `hunterx.config` | Configuration loading and typed settings | Platform Team |
| `security` | `hunterx.security` | Cross-cutting security services | Security Team |
| `infrastructure` | `hunterx.infrastructure` | Adapters implementing domain ports | Platform Team |
| `application` | `hunterx.application` | Use-case services and DTOs | Application Team |
| `knowledge` | `hunterx.knowledge` | Knowledge base runtime, knowledge graph client | Intelligence Team |
| `reporting` | `hunterx.reporting` | Report views, renderers, evidence packaging | Reporting Team |
| `scheduler` | `hunterx.scheduler` | Mission scheduling and job definitions | Platform Team |
| `engines` | `hunterx.engines` | Engine facades (mission, workflow, planner, ...) | Engine Team |
| `tools` | `hunterx.tools` | Tool runtime, Tool Integration Factory, Tool Intelligence, SDK | Tooling Team |
| `plugins` | `hunterx.plugins` | Plugin host, registry, loader, public plugin SDK | Plugin Team |
| `agents` | `hunterx.agents` | Multi-agent platform | AI Team |
| `api` | `hunterx.api` | REST API framework | API Team |
| `cli` | `hunterx.cli` | CLI framework and command registry | CLI Team |
| `platform` | `hunterx.platform` | Composition root, wires every subsystem | Architecture Council |
| `architecture` | `hunterx.architecture` | This enforcement framework (leaf) | Architecture Council |
| `facade` | package-root facade modules | Convenience re-export modules | Architecture Council |
| `root` | `hunterx` | The package itself (side-effect-free) | Architecture Council |

## The matrix

```
shared:        shared
domain:        domain, shared
config:        config, domain, shared
security:      security, domain, shared, infrastructure
infrastructure:infrastructure, domain, shared, config
application:   application, domain, shared, engines, tools
knowledge:     knowledge, domain, shared
reporting:     reporting, domain, shared
scheduler:     scheduler, domain, shared
engines:       engines, domain, shared, tools, reporting, infrastructure, application
tools:         tools, domain, shared, plugins
plugins:       plugins, domain, shared
agents:        agents, domain, shared
api:           api, domain, shared, config, platform, application, engines
cli:           cli, domain, shared, config, platform, application, engines
platform:      platform, domain, shared, config, security, infrastructure,
               application, knowledge, reporting, scheduler, engines, tools,
               plugins, agents, api, cli, facade
facade:        facade, domain, shared, infrastructure, managers, config
architecture:  architecture
```

Notes:

- **`domain` is pure**: it may only reach `shared`. Anything that needs domain
  types must depend on them, never the other way around.
- **`engines` orchestrate**: they may reach tools, reporting, infrastructure
  and application but not the delivery layers (`api`, `cli`) and not the
  composition root.
- **`api` / `cli` may reach `platform`** so delivery commands can ask the
  composition root to build real objects; they must not re-wire subsystems
  themselves.
- **`tools` may reach `plugins`** (the Tool SDK builds on plugin SDK types).
- The **`legacy`** resolution: any module outside `src/hunterx` that does not
  match a declared prefix (e.g. `core.*`) resolves to the `legacy` layer, which
  no shipping v7 module may import (ARCH-002, `blocked_prefixes`).

## Shared contracts

Contracts deliberately importable across layer boundaries:

- `hunterx.domain.ports` — abstract ports implemented by infrastructure
  adapters.
- `hunterx.domain.exceptions` — the exception hierarchy and error codes.
- `hunterx.shared` — ids, masking, time, result, DI helpers.

## Conditional imports

Fine-grained module-level exceptions to the matrix (ARCH-001 does not fire):

- `hunterx.shared.di → hunterx.domain.exceptions` — the DI container raises
  domain exceptions for registration errors.

## Waivers (known issues, time-boxed)

Waivers never fail CI while active but appear in every report; expired waivers
fail CI (ARCH-011).

| ID | Code | Module → Target | Reason |
|---|---|---|---|
| ARCH-W-001 | ARCH-001 | `hunterx.domain.execution` → `hunterx.plugins.sdk.results` | Domain references SDK result types; contracts should move into domain (tracked debt). |

## Known cycles (benign wiring, time-boxed)

Two existing cycles are recorded and excluded. Any **new** cycle fails CI
(ARCH-003).

- **ARCH-W-002** — `hunterx.tools.sdk` / `sdk.engine` / `sdk.pipeline`: package
  `__init__` re-export wiring, harmless at runtime.
- **ARCH-W-003** — `hunterx.cli` / `cli.app` / `cli.commands`: wiring cycle,
  resolve by moving `main()` into a leaf module.

## Changing the matrix

The matrix is Architecture Council territory. To propose a change:

1. Edit `config/architecture.yaml` (rules / conditional_imports / waivers).
2. Update this document so the two stay consistent.
3. Record the reason, and for waivers a deadline, in the YAML.
4. Run `hunterx-arch lint` and `hunterx-arch report` to confirm the intended
   effect.
