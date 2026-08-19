# AI Provider / Model Routing Closure — Acceptance

## 1. Root cause

The AI provider abstraction was only **partially** wired. `AISettings`
(config) already exposed all six providers and their keys, and the mission
depended on the generic `AIPort` interface — but the composition factory
(`hunterx.infrastructure.ai.factory`) hardwired exactly one adapter:

```python
_ADAPTERS = {"openrouter": OpenRouterClient}
```

Selecting `openai`, `anthropic`, `deepseek`, `gemini` or `grok` was
"recognized" but raised *"no adapter is implemented yet"*. Provider selection
had no runtime meaning for five of the six documented providers, and every
provider-specific endpoint/credential concept was inert. The docs explicitly
stated only OpenRouter had a runtime adapter.

## 2. Current architecture (before)

```
hunterx hunt / planner
      ↓  AIPort (generic)  ✓ already generic
AIActionSuggester
      ↓  AIPort.complete -> str
build_ai_client(AISettings)
      ↓
{openrouter: OpenRouterClient}   ← the ONLY route
      ↓
null.py  (no provider configured)
```

- `AIPort.complete(prompt, *, model, temperature) -> str` — generic contract ✓
  (mission never branched on provider — verified by grep).
- `AISettings` — provider + model + six `SecretStr` keys ✓.
- Factory — **one** hardwired provider (the gap).
- `OpenRouterClient` — real adapter, OpenAI-compatible chat-completions.

## 3. Final AI routing architecture

```
build_ai_client(AISettings)
      ↓  selects by settings.provider
OpenAICompatibleClient (shared OpenAI-style transport)
      ├── OpenAIClient      provider=openai     https://api.openai.com/v1
      ├── DeepSeekClient    provider=deepseek   https://api.deepseek.com/v1
      ├── OpenRouterClient  provider=openrouter https://openrouter.ai/api/v1
      └── XAIClient         provider=grok       https://api.x.ai/v1
AnthropicClient             provider=anthropic  https://api.anthropic.com/v1  (Messages API)
GeminiClient                provider=gemini     https://generativelanguage.googleapis.com/v1beta (generateContent)
NullAIClient                                          (no provider configured)
```

- One shared transport for the OpenAI-compatible providers; protocol-specific
  adapters only where the wire format differs (Anthropic, Gemini).
- Each adapter resolves its own base URL; auth is provider-specific
  (Bearer, `x-api-key`+`anthropic-version`, `x-goog-api-key`).
- The mission/planner/hypothesis/finding layers depend only on `AIPort` — no
  provider-specific branching (verified: no `openrouter`/provider literals in
  `mission_execution.py`, planners, `ai_suggestion.py`).

## 4. Files changed

- `src/hunterx/infrastructure/ai/providers.py` — new: shared OpenAI-compatible
  transport + `OpenAIClient`, `DeepSeekClient`, `XAIClient`, `AnthropicClient`,
  `GeminiClient`, truthful HTTP-status error mapping.
- `src/hunterx/infrastructure/ai/openrouter.py` — refactored to subclass the
  shared transport (class name, module path, default model preserved).
- `src/hunterx/infrastructure/ai/factory.py` — register all six providers.
- `src/hunterx/infrastructure/ai/__init__.py` — export all adapters.
- `tests/unit/test_ai_providers.py` — new: 41 routing/error/masking tests.
- `tests/unit/test_ai_factory.py` — updated: each provider builds its own
  adapter; model passthrough.
- `tests/unit/test_ai_openrouter.py` — updated fakes to `status_code` + truthful
  error semantics (401 → "authentication failed").
- `docs/configuration/ai.md` — documents all six providers, per-provider
  endpoints/models, independent provider+model selection, credential variables,
  error behavior and the (absent) FREE_MODE_ONLY note.

## 5. Provider matrix

| Provider | Config | Router/Adapter | Model Selection | Auth | Normalized Response | Unit | Live Smoke |
|----------|--------|----------------|-----------------|------|---------------------|------|------------|
| OpenAI | PASS | PASS | PASS | PASS (Bearer) | PASS | PASS | CREDENTIAL UNAVAILABLE |
| Anthropic/Claude | PASS | PASS | PASS | PASS (x-api-key) | PASS | PASS | CREDENTIAL UNAVAILABLE |
| DeepSeek | PASS | PASS | PASS | PASS (Bearer) | PASS | PASS | CREDENTIAL UNAVAILABLE |
| OpenRouter | PASS | PASS | PASS | PASS (Bearer) | PASS | PASS | ROUTE VERIFIED (HTTP 402 credits) |
| Gemini | PASS | PASS | PASS | PASS (x-goog-api-key) | PASS | PASS | CREDENTIAL UNAVAILABLE |
| xAI/Grok | PASS | PASS | PASS | PASS (Bearer) | PASS | PASS | CREDENTIAL UNAVAILABLE |

Live smoke: OpenRouter key present in the repo `.env`; a single bounded request
reached `openrouter.ai` with the correct model/auth and returned a real HTTP
402 (payment required) — routing verified, completion blocked by account
credits. The other five providers have no credentials in the environment →
honestly marked `CREDENTIAL UNAVAILABLE` (NOT converted into PASS).

## 6. Model routing matrix

| Config | Routes to |
|--------|-----------|
| provider=openai, model=gpt-4o-mini | OpenAI /chat/completions, model gpt-4o-mini |
| provider=anthropic, model=claude-3-5-sonnet-latest | Anthropic /v1/messages, model claude-3-5-sonnet-latest |
| provider=deepseek, model=deepseek-chat | DeepSeek /chat/completions, model deepseek-chat |
| provider=openrouter, model=deepseek/deepseek-chat | OpenRouter /chat/completions, model deepseek/deepseek-chat |
| provider=gemini, model=gemini-1.5-flash | Gemini generateContent, model gemini-1.5-flash |
| provider=grok, model=grok-2-latest | xAI /chat/completions, model grok-2-latest |

Model is passed verbatim; a per-call override wins; an invalid model is
reported truthfully by the provider (`invalid model or API endpoint (HTTP 404)`)
and never rewritten. No silent provider fallback: `provider=openai` reaches
`api.openai.com` (unit-tested), `provider=deepseek` reaches
`api.deepseek.com`, `provider=openrouter` reaches `openrouter.ai`.

## 7. Credential configuration

`HUNTERX_AI_OPENAI_KEY`, `HUNTERX_AI_ANTHROPIC_KEY`, `HUNTERX_AI_DEEPSEEK_KEY`,
`HUNTERX_AI_OPENROUTER_KEY`, `HUNTERX_AI_GEMINI_KEY`, `HUNTERX_AI_GROK_KEY`
(from environment or `.env`), stored as `pydantic.SecretStr`. Keys are masked in
`repr()`, settings dumps, `hunterx config` output, logs, exceptions, events and
reports (verified by masking tests + the live mission run where the key did not
appear in `events.jsonl`).

## 8. Error handling

Differentiated and truthful (all without the key): missing key →
`ConfigurationError`; unknown provider → `ConfigurationError`; 401/403 →
`authentication failed`; 402 → `payment required`; 404 → `invalid model or
API endpoint`; 429 → `rate limited`; 5xx → `provider unavailable`; timeout →
`request timed out`; non-JSON/malformed → `malformed provider response` /
`unexpected completion payload`. No retry-forever, no silent provider/model
switch, no success reported on failure.

## 9. FREE_MODE_ONLY behavior

No `FREE_MODE_ONLY` flag exists in the codebase; nothing was invented. There is
therefore no free-mode gate to bypass, and the configured provider/model is
passed through exactly as set. Documented in `docs/configuration/ai.md`.

## 10. Tests added

`tests/unit/test_ai_providers.py` (41 tests, mocked HTTP): provider selection,
model selection, OpenAI/Anthropic/DeepSeek/OpenRouter/Gemini/Grok routing to
their own endpoints, unknown provider, missing credentials, invalid credentials
(401), invalid model (404), timeout, rate-limit, response normalization,
secret masking per provider, no silent provider fallback, no silent model
fallback, truthful embed-unsupported for Anthropic. Plus updated
`test_ai_factory.py` (per-provider adapter construction) and
`test_ai_openrouter.py` (status-code fakes + truthful error mapping).

## 11. Existing regression results

- AI battery: `test_ai_providers` (41), `test_ai_factory` (13),
  `test_ai_openrouter` (14), `test_ai_suggestion` (9) — all pass (plus
  mission/planning domain suites in the same run: 187 passed).
- Mission/integration battery: phase14_2 + phase14_3 + phase15 +
  http_bypass_acceptance + phase13_continuation + authenticated_session +
  mission_orchestration_domain + attack_surface_completion +
  vulnerability_detection + xss_acceptance — **159 passed, 2 skipped**.
- Finding/reporting/toolchain battery: finding_orchestration (service/domain/
  engines) + mission_orchestration_service + mission_planning_checkpoints +
  toolchain_golden + technology_adapters — **109 passed**.
- Real CLI mission with the OpenRouter provider configured (real key) completed
  honestly (0 findings target), key never leaked into events.

## 12. Live smoke-test results

- OpenRouter: initialize → authenticate → one minimal request → the request
  reached `openrouter.ai/api/v1/chat/completions` with the configured model and
  bearer key; the account returned HTTP 402 (payment required) — routing
  verified, completion blocked by credits. **NOT a fabricated PASS.**
- OpenAI / Anthropic / DeepSeek / Gemini / Grok: **CREDENTIAL UNAVAILABLE**
  (no keys in the environment).

## 13. Documentation changes

`docs/configuration/ai.md` now documents: supported providers, independent
provider+model selection with per-provider examples, required key variable per
provider, optional custom base URL, how to verify configuration (`hunterx
config`), what happens with missing credentials (clear error), and the
FREE_MODE_ONLY status.

## 14. Pre-existing failures

- `test_ai_config.py` ×3 (`test_missing_keys_are_handled_safely`,
  `test_missing_provider_is_handled_safely`,
  `test_cli_config_output_is_masked`) — the repo root `.env` contains a real
  `HUNTERX_AI_OPENROUTER_KEY`, so `load_default_settings()` returns a key where
  the tests assume none. Pre-existing (`.env` dated before this phase,
  unrelated to the routing change); these tests pass in a CI/clean environment
  without a `.env`.
- Unchanged from prior phases: `tools/test_cli.py` ×3 (SMB sqlite lock),
  `test_mission_preflight.py` ×4 (stub `profile_tools=`), ARCH-007/003,
  `xss-detection` tool-selection acceptance.

## 15. Remaining limitations

- Live completion smoke tests for OpenAI/Anthropic/DeepSeek/Gemini/Grok are
  not possible without credentials (honestly marked `CREDENTIAL UNAVAILABLE`).
- OpenRouter live completion is blocked by the account's payment state
  (HTTP 402) — routing is verified; completion requires account credits.
- No `FREE_MODE_ONLY` flag exists (documented; not invented).

---

**Verdict: AI ROUTING CLOSURE — PASS**
