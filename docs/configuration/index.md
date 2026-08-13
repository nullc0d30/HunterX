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

HunterX runs fine without any AI provider. When you want AI features, configure
them **externally** — you never need to edit files under `src/`.

### Quick setup (`.env`)

```bash
# 1. Copy the template
cp .env.example .env

# 2. Edit .env
HUNTERX_AI_PROVIDER=openrouter
HUNTERX_AI_MODEL=deepseek/deepseek-chat
HUNTERX_AI_OPENROUTER_KEY=YOUR_KEY

# 3. Run HunterX normally
hunterx ...
```

Notes:

- `.env` is local and private. It is ignored by Git and must **never** be
  committed.
- The same values can be supplied directly as environment variables by
  Docker (`docker run --env-file .env ...`), CI, or Kubernetes secrets —
  HunterX does not care where the value came from.
- AI configuration is optional: with no provider configured, HunterX uses a
  safe `NullAIClient` fallback and stays fully functional.
- API keys are masked everywhere (settings dumps, CLI `config` output,
  `repr()`, logs); they are never written back to diagnostics.

### Supported environment variables

| Variable | Setting | Purpose |
|---|---|---|
| `HUNTERX_AI_PROVIDER` | `ai.provider` | Provider name: `openrouter` (others reserved) |
| `HUNTERX_AI_MODEL` | `ai.model` | Default model id, e.g. `deepseek/deepseek-chat` |
| `HUNTERX_AI_OPENROUTER_KEY` | `ai.openrouter_key` | OpenRouter API key |
| `HUNTERX_AI_OPENAI_KEY` | `ai.openai_key` | OpenAI API key (reserved) |
| `HUNTERX_AI_ANTHROPIC_KEY` | `ai.anthropic_key` | Anthropic API key (reserved) |
| `HUNTERX_AI_GEMINI_KEY` | `ai.gemini_key` | Gemini API key (reserved) |
| `HUNTERX_AI_DEEPSEEK_KEY` | `ai.deepseek_key` | DeepSeek API key (reserved) |
| `HUNTERX_AI_GROK_KEY` | `ai.grok_key` | Grok API key (reserved) |

If `HUNTERX_AI_PROVIDER` is empty or unset, AI stays disabled. Selecting a
provider without its API key raises a clear configuration error (the key value
is never shown).

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
