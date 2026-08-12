---
layout: default
title: Configuration — HunterX v7
keywords: HunterX Configuration, settings, environment variables
description: >-
  HunterX v7 configuration reference: bundled YAML defaults, profile files, and
  HUNTERX_* environment overrides.
---

# Configuration

HunterX v7 resolves settings in order of increasing precedence:

1. Built-in defaults.
2. The bundled `hunterx.yaml` default profile (in the package).
3. A user profile file (`HUNTERX_CONFIG` or `hunterx.yaml` in the current
   directory).
4. `HUNTERX_*` environment variables.

The result is a validated, typed settings object shown by `hunterx config`.

## Environment variables

Top-level settings map directly: `HUNTERX_ENVIRONMENT`, `HUNTERX_LOG_LEVEL`,
`HUNTERX_APP_NAME`, `HUNTERX_TELEMETRY_ENABLED`. Nested sections use an
underscore separator:

| Variable | Setting |
|---|---|
| `HUNTERX_DATABASE_URL` | `database.url` |
| `HUNTERX_DATABASE_ECHO` | `database.echo` |
| `HUNTERX_CACHE_BACKEND` / `HUNTERX_CACHE_URL` | `cache.backend` / `cache.url` |
| `HUNTERX_QUEUE_BACKEND` / `HUNTERX_QUEUE_URL` | `queue.backend` / `queue.url` |
| `HUNTERX_SECURITY_SANDBOX_ENABLED` | `security.sandbox_enabled` |
| `HUNTERX_API_HOST` / `HUNTERX_API_PORT` | `api.host` / `api.port` |
| `HUNTERX_API_AUTH_ENABLED` | `api.auth_enabled` |
| `HUNTERX_API_KEY` / `HUNTERX_API_READ_ONLY_KEY` | `api.api_key` / `api.read_only_key` |

Unknown `HUNTERX_*` variables (for example `HUNTERX_SECRET_*` carried into
sandboxed tool environments) are ignored by the loader.

## Profile file

```bash
# Point at a profile file
export HUNTERX_CONFIG=/etc/hunterx/hunterx.yaml
# or place hunterx.yaml in the working directory
hunterx config
```

## Database

```bash
export HUNTERX_DATABASE_URL="postgresql+psycopg://user:pass@host/hunterx"
alembic upgrade head
```

Default: `sqlite:///hunterx.db`. Migrations live under `alembic/` and are
managed with `alembic upgrade head` / `alembic downgrade`.

## See also

- [Quickstart]({{ '/quickstart/' | relative_url }}) — getting started
- [CLI Reference]({{ '/cli/' | relative_url }}) — `hunterx config` and friends
- [Persistence (TIDB)]({{ '/v7-tidb/' | relative_url }}) — database design and migrations
