---
layout: default
title: AI Configuration — HunterX v7
keywords: HunterX AI configuration, OpenRouter, AI provider, API key, .env, HUNTERX_AI_PROVIDER, HUNTERX_AI_MODEL, HUNTERX_AI_OPENROUTER_KEY, NullAIClient
description: >-
  Enable AI in HunterX v7. Configure AI providers, models and API keys with a
  local .env file, run HunterX with AI enabled, use the same configuration with
  Docker, keep API keys secure, and troubleshoot common problems. Supported
  runtime providers: OpenAI, Anthropic/Claude, DeepSeek, OpenRouter, Gemini and
  xAI/Grok.
---

# AI Configuration

AI configuration in HunterX is **optional** and **external**. You do not edit
any source files to enable it — you create a private `.env` file (or set
environment variables) and HunterX picks the values up automatically.

This guide covers:

- what the AI integration does
- how to enable it with a `.env` file
- which providers and models you can configure
- how to run HunterX with AI enabled (locally and with Docker)
- how to keep your API key secure
- how to troubleshoot common problems

## What the AI integration does

HunterX uses a configurable AI provider for **AI-assisted reasoning** during
missions: hypothesis generation, adaptive mission planning, next-best-action
selection and explainable analysis. AI output is advisory and evidence-driven —
a model's answer is never treated as proof. Findings, PoCs and reports always
require real evidence, validation and reproducibility.

## AI is optional

HunterX works without an AI API key. If you do nothing, HunterX uses a safe
fallback (the `NullAIClient`) and stays fully functional. Only when an
AI-dependent operation is actually invoked will HunterX report that no AI
provider is configured:

> No AI provider is configured. Set `HUNTERX_AI_PROVIDER` and the matching
> `HUNTERX_AI_*_KEY` (see `.env.example`) to enable AI features.

That message means HunterX is running correctly — it just has no AI configured.

## Provider, model and API key

Three different values work together:

```text
Provider = where the API request is sent (for example OpenRouter)
Model    = which AI model HunterX asks the provider to use
API key  = the credential used to authenticate the request
```

- **Provider** — the service that runs the model for you. HunterX sends its
  chat requests to the provider's API.
- **Model** — a model identifier the provider knows, for example
  `deepseek/deepseek-chat`. The model name is **not** a key and is **not**
  secret.
- **API key** — a secret credential issued by the provider. It proves to the
  provider that the request is authorized. The key must belong to the provider
  you selected.

## Quick start

```bash
# 1. Clone the repository (or install HunterX — see the installation guide)
git clone https://github.com/nullc0d30/HunterX.git
cd HunterX

# 2. Create your private .env from the template
cp .env.example .env
```

Edit `.env` and set:

```env
HUNTERX_AI_PROVIDER=openrouter
HUNTERX_AI_MODEL=deepseek/deepseek-chat
HUNTERX_AI_OPENROUTER_KEY=YOUR_API_KEY
```

Then run HunterX normally:

```bash
hunterx config            # confirm the AI settings are resolved
hunterx hunt full_security_assessment https://example.com
```

Replace `YOUR_API_KEY` with a real key you created at the provider — never
share or commit it.

## The `.env` file

- `.env.example` is a **template**. It ships with the repository and contains
  placeholder values only.
- `.env` is your **private, local configuration file**. It contains your real
  API key.
- HunterX already ignores `.env` in Git, so it will not be committed by
  accident. Verify with `git status` after creating it.
- Never paste API keys into source files, GitHub issues, pull requests,
  screenshots, logs or public documentation.
- `.env` is only one way to supply configuration. The same values can be
  provided directly as environment variables — for example with Docker's
  `--env-file`, in CI/CD pipelines or as Kubernetes secrets. HunterX does not
  care where a value came from.

## Configure OpenRouter

OpenRouter is the currently implemented AI provider adapter. To use it:

1. Create an account at <https://openrouter.ai>.
2. Create an API key at <https://openrouter.ai/keys>.
3. Add the key to your `.env` file.

```env
# Where to send the request
HUNTERX_AI_PROVIDER=openrouter

# Which model to use (pick any model slug OpenRouter supports)
HUNTERX_AI_MODEL=deepseek/deepseek-chat

# Your OpenRouter API key (secret — keep it private)
HUNTERX_AI_OPENROUTER_KEY=YOUR_API_KEY
```

Line by line:

| Line | What it does |
|---|---|
| `HUNTERX_AI_PROVIDER=openrouter` | Selects the provider adapter. `openrouter` is the implemented adapter. |
| `HUNTERX_AI_MODEL=deepseek/deepseek-chat` | The model identifier HunterX asks OpenRouter to use. Browse the catalog at <https://openrouter.ai/models>. |
| `HUNTERX_AI_OPENROUTER_KEY=YOUR_API_KEY` | Your OpenRouter API key. The value is secret and never logged. |

If `HUNTERX_AI_MODEL` is left empty, HunterX defaults to
`deepseek/deepseek-chat` on OpenRouter.

## Supported providers

HunterX has a runtime adapter for every provider its configuration layer
recognizes:

```text
HUNTERX_AI_OPENAI_KEY        -> provider=openai       (OpenAI, api.openai.com)
HUNTERX_AI_ANTHROPIC_KEY     -> provider=anthropic    (Anthropic/Claude, api.anthropic.com)
HUNTERX_AI_DEEPSEEK_KEY      -> provider=deepseek     (DeepSeek, api.deepseek.com)
HUNTERX_AI_OPENROUTER_KEY    -> provider=openrouter   (OpenRouter, openrouter.ai)
HUNTERX_AI_GEMINI_KEY        -> provider=gemini       (Google Gemini, generativelanguage.googleapis.com)
HUNTERX_AI_GROK_KEY          -> provider=grok         (xAI/Grok, api.x.ai)
```

- **OpenAI, DeepSeek, OpenRouter and xAI/Grok** share the OpenAI-compatible
  chat-completions transport (each with its own API base URL and bearer key).
- **Anthropic/Claude** uses the Anthropic Messages API (`/v1/messages`, header
  `x-api-key`).
- **Gemini** uses Google's `generateContent` REST API (header `x-goog-api-key`).

Each provider resolves its own endpoint: selecting `provider=openai` sends the
request to `api.openai.com`, `provider=deepseek` to `api.deepseek.com`, and so
on. A request is never silently rerouted to another provider.

### Select provider and model independently

`HUNTERX_AI_PROVIDER` and `HUNTERX_AI_MODEL` are independent:

```env
# OpenAI
HUNTERX_AI_PROVIDER=openai
HUNTERX_AI_MODEL=gpt-4o-mini
HUNTERX_AI_OPENAI_KEY=...

# Anthropic / Claude
HUNTERX_AI_PROVIDER=anthropic
HUNTERX_AI_MODEL=claude-3-5-sonnet-latest
HUNTERX_AI_ANTHROPIC_KEY=...

# DeepSeek
HUNTERX_AI_PROVIDER=deepseek
HUNTERX_AI_MODEL=deepseek-chat
HUNTERX_AI_DEEPSEEK_KEY=...

# OpenRouter (any OpenRouter model slug)
HUNTERX_AI_PROVIDER=openrouter
HUNTERX_AI_MODEL=deepseek/deepseek-chat
HUNTERX_AI_OPENROUTER_KEY=...

# Google Gemini
HUNTERX_AI_PROVIDER=gemini
HUNTERX_AI_MODEL=gemini-1.5-flash
HUNTERX_AI_GEMINI_KEY=...

# xAI / Grok
HUNTERX_AI_PROVIDER=grok
HUNTERX_AI_MODEL=grok-2-latest
HUNTERX_AI_GROK_KEY=...
```

The model value is passed verbatim to the selected provider's API. If the model
is invalid for that provider, the provider returns an error which HunterX reports
truthfully (`invalid model or API endpoint`); it is never silently rewritten to
another model, and HunterX never silently switches providers.

Each provider also accepts an optional custom base URL through its adapter
constructor for proxies/tests; production use relies on the provider's default
endpoint.

## AI configuration variables

| Variable | Purpose | Required |
|---|---|---|
| `HUNTERX_AI_PROVIDER` | AI provider (`openai` \| `anthropic` \| `deepseek` \| `openrouter` \| `gemini` \| `grok`) | No |
| `HUNTERX_AI_MODEL` | Model identifier (provider-specific) | No |
| `HUNTERX_AI_OPENROUTER_KEY` | OpenRouter API key | No |
| `HUNTERX_AI_OPENAI_KEY` | OpenAI API key | No |
| `HUNTERX_AI_ANTHROPIC_KEY` | Anthropic API key | No |
| `HUNTERX_AI_GEMINI_KEY` | Gemini API key | No |
| `HUNTERX_AI_DEEPSEEK_KEY` | DeepSeek API key | No |
| `HUNTERX_AI_GROK_KEY` | Grok/xAI API key | No |

All variables are optional because AI is optional. The provider you select must
have a key configured and a runtime adapter:

- No provider set → AI stays disabled (`NullAIClient`).
- Provider set without its API key → clear configuration error naming the
  provider and the `HUNTERX_AI_<PROVIDER>_KEY` variable.
- Unknown provider → clear configuration error listing the supported providers.
- Invalid key / invalid model / rate limit / provider outage / timeout are each
  reported truthfully; HunterX never silently switches provider or model and
  never reports success when the provider failed.

API keys are masked everywhere (settings dumps, `hunterx config` output,
`repr()` and logs) and are never written back to diagnostics, events or reports.

> **Cost policy:** HunterX does not currently define a `FREE_MODE_ONLY`
> configuration flag. There is therefore no free-mode gate to bypass; the
> selected provider and model are passed through exactly as configured. If you
> need cost control, choose an inexpensive model in `HUNTERX_AI_MODEL`.

## Run HunterX with AI enabled

AI-assisted reasoning activates automatically during normal mission work once a
provider, model and key are configured:

```bash
hunterx config                                   # verify ai.provider / ai.model
hunterx hunt full_security_assessment https://example.com
hunterx mission plan <objective> <target>        # AI-assisted planning
```

Verify the resolved configuration:

```bash
hunterx config
```

You should see `provider: openrouter` and `model: deepseek/deepseek-chat`
(with the API key masked). See the [Quickstart]({{ '/quickstart/' | relative_url }})
and the [CLI Reference]({{ '/cli/' | relative_url }}) for the full command set.

## Docker

HunterX's Docker image reads the same `HUNTERX_AI_*` environment variables. Do
**not** copy `.env` into the image — supply secrets at runtime with
`--env-file`:

```bash
# Inspect the resolved configuration (confirms AI settings loaded)
docker run --rm --env-file .env nullc0d30/hunterx:latest config

# Run a hunt mission with AI enabled
docker run --rm --env-file .env \
  -v hunterx-data:/opt/hunterx/data \
  nullc0d30/hunterx:latest hunt full_security_assessment https://example.com
```

Notes:

- `--env-file .env` reads your local `.env` at container start; the key never
  ends up baked into the image.
- The image runs as a non-root user and persists state under the
  `/opt/hunterx/data` volume. See the [Docker guide]({{ '/DOCKERHUB/' | relative_url }})
  for the full image usage.
- With Docker Compose, pass the same values through the project `.env` file —
  they are already forwarded as `HUNTERX_AI_*` environment variables.

Never build secrets into an image. If you build a custom image, keep your `.env`
out of the build context and out of `Dockerfile` `ENV`/`COPY` lines.

## Troubleshooting

### "No AI provider is configured"

The `NullAIClient` fallback is active. Check:

- `.env` exists in the current directory (or the values are exported).
- `HUNTERX_AI_PROVIDER` is set and not empty.
- The matching `HUNTERX_AI_*_KEY` variable is set.
- HunterX is actually loading the `.env` file — run `hunterx config` and look
  for `ai.provider`. If it is empty, the file is not being read (wrong
  directory, or the variables are not exported in your shell).

### "Invalid API key"

The key does not belong to the selected provider (for example, an OpenRouter
key value that is empty, expired, or mistyped). Re-create the key at the
provider and update `.env`. A key from one provider cannot be used with
another.

### "Model not found"

`HUNTERX_AI_MODEL` must contain a model identifier supported by the selected
provider. For OpenRouter, browse the catalog at
<https://openrouter.ai/models> and use an exact slug such as
`deepseek/deepseek-chat`.

### Docker cannot see the key

Environment variables are supplied at runtime, not baked into the image:

```bash
docker run --rm --env-file .env nullc0d30/hunterx:latest config
```

If the key is missing inside the container, check that `.env` exists and that
`--env-file .env` points at it from the directory you run the command in.

### AI works locally but not in Docker

The container does not inherit your shell environment. Pass the values
explicitly with `--env-file .env` (or set the environment in your orchestration
tooling). Never commit or bake the `.env` file into the image.

### The `ai` extra is missing

The OpenRouter adapter needs the optional `ai` extra (HTTP client). If a
command reports it is missing, install it:

```bash
pip install "hunterxsec[ai]"
```

## Security

> **Security:** Never commit your `.env` file or expose API keys in source
> code, GitHub issues, pull requests, screenshots, logs, or public
> documentation. Use environment variables or runtime secret injection in
> CI/CD and container environments.

HunterX treats API keys as secrets: they are stored as `SecretStr`, masked in
every diagnostic output, and never included in configuration dumps or
exceptions. Keep them out of anything you publish.

## See also

- [Configuration]({{ '/configuration/' | relative_url }}) — all `HUNTERX_*`
  environment variables and profile files
- [Quickstart]({{ '/quickstart/' | relative_url }}) — run your first mission
- [Installation]({{ '/installation/' | relative_url }}) — install HunterX
- [CLI Reference]({{ '/cli/' | relative_url }}) — `hunterx config` and friends
- [Docker guide]({{ '/DOCKERHUB/' | relative_url }}) — running HunterX in a
  container
- [Reasoning Engine]({{ '/reasoning-engine/' | relative_url }}) — how
  AI-assisted reasoning is used in missions
