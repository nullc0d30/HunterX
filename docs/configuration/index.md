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
4. `HUNTERX_*` environment variables — including values loaded from a local
   `.env` file (real environment variables win over the file).

The result is a validated, typed settings object shown by `hunterx config`.

## AI configuration (optional)

AI is optional. With no provider configured, HunterX uses a safe
`NullAIClient` fallback and stays fully functional; AI-dependent operations
report that no AI provider is configured when invoked.

When you want AI, configure it **externally** — you never need to edit files
under `src/`. Create a private `.env` from the template and set the provider,
model and API key:

```bash
cp .env.example .env
```

```env
HUNTERX_AI_PROVIDER=openrouter
HUNTERX_AI_MODEL=deepseek/deepseek-chat
HUNTERX_AI_OPENROUTER_KEY=YOUR_API_KEY
```

`.env` is local and private, ignored by Git and must **never** be committed.
The same values can be supplied directly as environment variables (Docker
`--env-file`, CI, Kubernetes secrets). API keys are masked everywhere and never
written back to diagnostics.

The current live provider adapter is **OpenRouter**; the configuration layer
also accepts keys for OpenAI, Anthropic, Gemini, DeepSeek and Grok for future
adapters.

Full setup, Docker usage and troubleshooting are on the dedicated
[AI Configuration]({{ '/configuration/ai/' | relative_url }}) page.

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

Default: `sqlite:///hunterx.db` (the sentinel resolved at runtime to
`<application root>/data/hunterx.db` via `hunterx.config.paths`). Set
`HUNTERX_DATA_DIR` to relocate the data directory, or override the URL
entirely with `HUNTERX_DATABASE_URL`. Migrations live under `alembic/` and are
managed with `alembic upgrade head` / `alembic downgrade`.

## See also

- [AI Configuration]({{ '/configuration/ai/' | relative_url }}) — enable AI
  with `.env`, Docker and troubleshooting
- [Quickstart]({{ '/quickstart/' | relative_url }}) — getting started
- [CLI Reference]({{ '/cli/' | relative_url }}) — `hunterx config` and friends
- [Persistence (TIDB)]({{ '/v7-tidb/' | relative_url }}) — database design and migrations
