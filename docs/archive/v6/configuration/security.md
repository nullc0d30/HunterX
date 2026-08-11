---
layout: default
title: Security Configuration — HunterX v6.0.0
keywords: HunterX Security, Authentication, SSL Verification, API Keys
description: >-
  Reference for HunterX security-related configuration. Learn how to configure
  authentication, SSL/TLS verification, and handle secrets securely.
---
# Security Configuration

HunterX includes several security-related settings to help you conduct assessments
safely and securely.

## Authentication

The `auth` section configures authentication methods for targets that require
credentials.

### Configuration Options

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `auth.type` | string | `none` | Authentication method: `none`, `basic`, `bearer`, `cookie`, `form` |
| `auth.username` | string | `null` | Username for basic or form authentication |
| `auth.password` | string | `null` | Password for basic or form authentication |
| `auth.token` | string | `null` | Bearer token or session token |
| `auth.cookie_file` | string | `null` | Path to a JSON file containing cookies |
| `auth.login_url` | string | `null` | Login URL for form-based authentication |
| `auth.login_data` | object | `{}` | Form fields as key-value pairs for login |

### Authentication Methods

#### none

No authentication is used. This is the default.

#### basic

HTTP Basic Authentication. Provide `username` and `password`.

#### bearer

Bearer Token Authentication. Provide `token`.

#### cookie

Cookie-Based Authentication. Provide a `cookie_file` containing a JSON array of cookie objects.

#### form

Form-Based Authentication. Provide `login_url` and `login_data` (as key-value pairs).

### Example Configuration

```yaml
auth:
  type: bearer
  token: "your-token-here"
```

### Environment Variables

Authentication settings can be overridden via environment variables:

| Environment Variable | Maps To | Description |
|----------------------|---------|-------------|
| `HX_AUTH_TYPE` | `auth.type` | Authentication method |
| `HX_AUTH_TOKEN` | `auth.token` | Bearer or session token |
| `HX_AUTH_USERNAME` | `auth.username` | Username |
| `HX_AUTH_PASSWORD` | `auth.password` | Password |
| `HX_AUTH_COOKIE_FILE` | `auth.cookie_file` | Cookie file path |
| `HX_AUTH_LOGIN_URL` | `auth.login_url` | Login URL |
| `HX_AUTH_LOGIN_DATA` | `auth.login_data` | (Note: Complex objects not supported via env var) |

*Note: Environment variables for complex objects like `login_data` are not supported. Use the configuration file for these.*

## SSL/TLS Verification

The `verify_ssl` setting controls whether HunterX verifies SSL/TLS certificates.

### Configuration Options

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `verify_ssl` | boolean | `true` | Whether to verify SSL certificates |

### Usage

Set to `false` to disable SSL certificate verification (not recommended for production):

```yaml
verify_ssl: false
```

### Environment Variable

```bash
export HX_VERIFY_SSL=false
```

## Out-of-Band (OOB) and AI Services

When using OOB or AI features, HunterX may communicate with external services.
Ensure that you trust these endpoints and that sensitive data is not inadvertently
exposed.

### OOB Configuration

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `oob.enabled` | boolean | `false` | Enable OOB callbacks |
| `oob.collaborator_url` | string | `null` | URL of your OOB collaborator server |

### AI Configuration

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `ai.enabled` | boolean | `false` | Enable AI/LLM analysis |
| `ai.provider` | string | `ollama` | AI provider (`ollama` or `openai`) |
| `ai.model` | string | `llama3.2` | Model name |
| `ai.endpoint` | string | `http://localhost:11434` | API endpoint |

### Security Notes

- **OOB**: Ensure your collaborator server is secure and that you only send
  non-sensitive data via OOB channels.
- **AI**: Be aware that sending data to third-party AI providers (like OpenAI)
  may expose sensitive information. Use self-hosted solutions (like Ollama) for
  maximum confidentiality.
- **API Keys**: For providers that require API keys (e.g., OpenAI), set the
  corresponding environment variable (e.g., `OPENAI_API_KEY`) and **never**
  include it in your configuration file.

## Best Practices

1. **Use least privilege**: Provide only the necessary credentials for testing.
2. **Protect secrets**: Never commit authentication tokens or passwords to version
   control.
3. **Validate HTTPS**: Keep `verify_ssl: true` unless you have a specific reason
   to disable it (e.g., testing self-signed certificates in a lab).
4. **Isolate OOB**: Use a dedicated, secure server for OOB callbacks.
5. **Review AI data flows**: Understand what data is sent to AI providers and
   ensure compliance with your organization\'s data handling policies.

## Related Documentation

- [Configuration Reference](/configuration/) - Full configuration reference
- [Security Overview](/security/) - Security documentation and best practices
- [CLI Reference](/cli/) - Command-line options for authentication and security
