---
layout: default
title: AI Providers — HunterX v6.0.0
keywords: HunterX AI Providers, LLM, Ollama, OpenAI, AI Configuration
description: >-
  Reference for HunterX AI provider configuration. Learn how to configure and use
  different AI/LLM providers with HunterX.
---
# AI Providers

HunterX supports optional AI/LLM assistance for enhanced vulnerability analysis.
AI integration is disabled by default and can be enabled via configuration.

## Configuration

AI settings are configured under the `ai` section in `hunterx.yaml` or via environment variables.

### Configuration Options

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `ai.enabled` | boolean | `false` | Enable AI/LLM analysis |
| `ai.provider` | string | `ollama` | AI provider to use (`ollama` or `openai`) |
| `ai.model` | string | `llama3.2` | Model name to use with the provider |
| `ai.endpoint` | string | `http://localhost:11434` | API endpoint for the AI provider |

### Provider-Specific Details

#### Ollama

- **Default endpoint**: `http://localhost:11434`
- **Authentication**: None required (assumes local instance)
- **Supported models**: Any model available in your Ollama instance (e.g., `llama3.2`, `codellama`, `mistral`)
- **Setup**: Install and run Ollama from https://ollama.com

#### OpenAI

- **Endpoint**: `https://api.openai.com/v1` (default, but can be overridden via `ai.endpoint`)
- **Authentication**: Requires an API key. The API key must be provided via the `OPENAI_API_KEY` environment variable (not via HunterX configuration).
- **Supported models**: Any model available to your OpenAI account (e.g., `gpt-3.5-turbo`, `gpt-4`, `gpt-4-turbo`)
- **Note**: The `ai.endpoint` can be changed to use a proxy or compatible API.

## Environment Variables

The following environment variables can override AI settings:

| Environment Variable | Maps To | Type | Description |
|----------------------|---------|------|-------------|
| `HX_AI_ENABLED` | `ai.enabled` | boolean | Enable/disable AI |
| `HX_AI_MODEL` | `ai.model` | string | Model name |
| `HX_OOB_URL` | `oob.collaborator_url` | string | (Note: This is for OOB, not AI) |

*Note: There is no specific environment variable for the AI provider or endpoint at this time. These must be set in the configuration file.*

## Example Configuration

### Using Ollama (Default)

```yaml
ai:
  enabled: true
  provider: ollama
  model: llama3.2
  endpoint: http://localhost:11434
```

### Using OpenAI

```yaml
ai:
  enabled: true
  provider: openai
  model: gpt-4
  endpoint: https://api.openai.com/v1
```

Then, set your OpenAI API key as an environment variable:

```bash
export OPENAI_API_KEY="your-api-key-here"
```

## Usage

Once AI is enabled, HunterX will use the following:

- Use the AI reasoning engine to generate attack hypotheses
- Provide explanations for findings
- Assist in prioritizing vulnerabilities
- Generate more accurate reports

## Notes

- AI processing is optional and increases scan time.
- Ensure that your AI provider is accessible and properly configured before enabling.
- For OpenAI, you must have a valid API key and sufficient quota.
- The AI provider and model must be compatible; incompatible combinations will result in errors.
- The `ai.endpoint` should point to the base URL of the provider\'s API (e.g., for Ollama, the default is usually correct; for OpenAI, it is `https://api.openai.com/v1`).
- Some providers may require additional configuration (like API keys) via environment variables specific to the provider.
