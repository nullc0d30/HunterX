---
layout: default
title: Configuration Reference — HunterX
description: >-
  Complete YAML configuration reference for HunterX vulnerability scanner.
  Scan options, rate limiting, authentication, reporting, plugins, WAF evasion,
  operator profiles, environment variables, and CLI flags.
---

# Configuration Reference

HunterX is configured via `hunterx.yaml` (auto-discovered in working directory), environment variables, and CLI flags (which take precedence).

## File Location

Config file discovery order:
1. `--config <path>` CLI flag
2. `<cwd>/hunterx.yaml`
3. `<cwd>/hunterx.yml`
4. `<project>/hunterx.yaml` (default config bundled with the package)

## Complete YAML Reference

```yaml
# =============================================================================
# HunterX Configuration
# =============================================================================

# --- Scan Targets ---
target:
  url: "http://example.com"              # Single target URL
  endpoints:                             # Additional endpoints to test
    - "/api/v1/login"
    - "/api/v1/search"
  exclude_endpoints:                     # Additional endpoints to skip
    - "/logout"
  scope: "same-origin"                   # same-origin | same-host | wild
  max_depth: 3                           # Max link depth (0 = no crawl)

# --- Request Engine ---
rate_limiting:
  max_rps: 10                            # Max requests per second
  delay: 0.1                             # Fixed delay between requests (s)
  jitter: 0.1                            # Random jitter applied to delay (s)

headers:
  user_agent: "HunterX/4.0.1"            # Custom User-Agent string
  cookies: "session=abc123; token=xyz"   # Raw Cookie header
  custom:                                # Additional custom headers
    X-Correlation-Id: "scan-001"

timeout:
  connect: 10                            # Connection timeout (s)
  read: 30                               # Read timeout (s)
  overall: 300                           # Total scan timeout (s)

proxy:                                   # HTTP proxy (all traffic)
  http: "http://127.0.0.1:8080"
  https: "http://127.0.0.1:8080"

# --- Scanner Core ---
scanner:
  stages:
    - 0                                   # Passive intel
    - 1                                   # Probe
    - 2                                   # Confirm
    - 3                                   # Verify
  skip_stage_0: false                     # Skip passive intel
  skip_waf_detection: false              # Skip WAF detection checks

attack_categories:
  enabled:                                # Categories to test
    - "lfi"
    - "rce"
    - "sqli"
    - "ssti"
    - "ssrf"
    - "xss"
    - "open-redirect"
    - "xxe"
  disabled: []                            # Categories to skip

fingerprint:
  enabled: true                          # Enable target fingerprinting
  technologies:                           # Limit to specific techs
    # - "nginx"
    # - "php"
    # - "express"

# --- Operator Profile ---
profile:
  name: "internal"                       # internal | bounty | gov | custom
  # Internal Profile defaults:
  #   max_requests: 0 (unlimited)
  #   rate_limit: 500 req/s
  #   destructive: true
  #   passive_mode: false
  #
  # Bounty Profile defaults:
  #   max_requests: 500
  #   rate_limit: 10 req/s
  #   destructive: false
  #   passive_mode: false
  #
  # Gov Profile defaults:
  #   max_requests: 100
  #   rate_limit: 5 req/s
  #   destructive: false
  #   passive_mode: true

# --- Authentication ---
auth:
  method: "none"                         # none | basic | bearer | cookie | form
  basic:
    username: "admin"
    password: "password"
  bearer:
    token: "your-bearer-token"
  cookie:
    file: "cookies.json"
  form:
    url: "http://example.com/login"
    username_field: "username"
    password_field: "password"
    username: "user"
    password: "pass"
    extra_fields:
      csrf_token: "..."

# --- Reporting ---
report:
  format: "markdown"                     # markdown | json | sarif | html | zip
  output: "scan-report.md"              # Output file path (auto-extended)
  zip_include_raw: true                  # Include raw HTTP evidence in zip
  sarif_level: "warning"                 # note | warning | error

# --- Plugins ---
plugins:
  detector:                              # Enable/disable detector plugins
    enabled: []
    disabled: []
  reporter:                              # Enable/disable reporter plugins
    enabled: ["html"]
    disabled: []

# --- WAF Evasion ---
waf_evasion:
  enabled: true                          # Enable payload mutation
  mutation_count: 5                      # Number of variants per payload
  mutation_types:                        # Mutation strategies
    - "encoding"
    - "sql"
    - "lfi"

# --- OOB Detection ---
oob:
  enabled: false                         # Enable out-of-band detection
  collaborator_url: "http://oob.example.com"
  callback_token: "secret123"

# --- AI/ML ---
ai:
  llm:
    enabled: false                       # Enable LLM analysis
    provider: "ollama"                   # ollama | openai
    model: "llama3.1"                    # Model name
    url: "http://localhost:11434"        # Provider URL
  ml:
    enabled: false                       # Enable ML anomaly detection
    algorithm: "dbscan"                  # dbscan (default)
    contamination: 0.05                  # Expected outlier fraction

# --- Advanced ---
requests:
  max_redirects: 5
  verify_ssl: true                       # Verify TLS certificates
  follow_redirects: true
  extra_curl_options:
    - "--insecure"
```

## Environment Variables

All YAML keys can be overridden with environment variables using the `HX_` prefix and `_` separator:

| Variable | Example | Overrides |
|----------|---------|-----------|
| `HX_URL` | `http://example.com` | `target.url` |
| `HX_MAX_RPS` | `10` | `rate_limiting.max_rps` |
| `HX_FORMAT` | `json` | `report.format` |
| `HX_OUTPUT` | `report.json` | `report.output` |
| `HX_AUTH_METHOD` | `bearer` | `auth.method` |
| `HX_BEARER_TOKEN` | `tok_xxx` | `auth.bearer.token` |
| `HX_PROXY` | `http://proxy:8080` | `proxy.http` |
| `HX_PROFILE` | `bounty` | `profile.name` |
| `HX_CONFIG` | `/path/to/config.yaml` | Config file path |

## CLI Flags

```
Usage: python hunterx.py [command] [options]

Commands:
  scan          Run a scan (default)
  api           Start REST API server
  version       Print version and exit

Scan Options:
  -u, --url URL              Target URL (required)
  -f, --file FILE            Target URLs file
  -c, --config FILE          Config file path
  -o, --output FILE          Report output path
  --format FORMAT            Report format (markdown|json|sarif|html|zip)
  -p, --profile PROFILE      Operator profile (internal|bounty|gov|custom)
  -a, --auth METHOD          Auth method (basic|bearer|cookie|form)
  --auth-user USER           Auth username
  --auth-pass PASS           Auth password
  --auth-token TOKEN         Bearer token
  --cookie-file FILE         Cookie jar JSON file
  --passive-only             Passive intelligence only
  --max-rps RPS              Max requests per second
  --timeout SECONDS          Request timeout
  --proxy URL                HTTP proxy
  --no-verify-ssl            Disable SSL verification
  --max-depth N              Max crawl depth
  --include-category CAT     Enable attack category
  --exclude-category CAT     Disable attack category
  --llm                      Enable LLM analysis
  --llm-model MODEL          LLM model name
  --llm-provider PROVIDER    LLM provider (ollama|openai)
  --ml                       Enable ML anomaly detection
  --oob URL                  OOB collaborator URL
  --endpoint URL             Additional endpoint
  --exclude-endpoint URL     Exclude endpoint
  -v, --verbose              Verbose output

API Server Options:
  --host HOST                Bind address (default: 0.0.0.0)
  --port PORT                Bind port (default: 8443)
  --reload                   Auto-reload on code changes
```

## Default Configuration

The default configuration (used when no config file is found) applies the **Internal** profile, sets `format: markdown`, disables AI/ML features, and enables all attack categories.

## Configuration Precedence

1. CLI flags (highest)
2. Environment variables
3. Specified config file (`--config`)
4. Auto-discovered `hunterx.yaml`
5. Bundled default config (lowest)
