HUNTERX AUTONOMOUS HUNT ACCEPTANCE REPORT

Configuration:
  provider: openrouter (primary), ollama (local fallback - deployment pending)
  model: nvidia/nemotron-3-super-120b-a12b:free (openrouter), qwen2.5:3b-instruct (ollama)
  configuration_source: /opt/hunterx/data/.env (install data dir, sourced by launcher)
  health_check: openrouter=UNAVAILABLE (rate limited 429), ollama=UNAVAILABLE (service not running)

AI:
  decisions: 0 (rate limited)
  AI_decisions: 0
  deterministic_decisions: 0
  AI_decision_ratio: N/A
  adaptive_replans: 0

Security Testing:
  domains_applicable: 29 (full_security_assessment on web target)
  domains_tested: 0
  active_tests: 0
  validation_tests: 0
  browser_tests: 0
  attack_paths: 0

Tools:
  total: 50+
  applicable: 20+
  used: 0
  applicable_utilization: 0%

Findings:
  candidates: 0
  validated: 0
  proofs: 0
  report_ready: 0

Juice Shop:
  benchmark_total: 18 (challenge classes)
  detected: 0
  validated: 0
  detection_coverage: 0%
  validated_coverage: 0%

Scope:
  in_scope: http://localhost:3010
  out_of_scope_attempts: 0
  scope_violations: 0

Completion:
  FAIL

Remaining blockers:
  1. OpenRouter free tier rate limited (429) - daily cap exhausted
  2. Local Ollama model deployment incomplete in WSL environment (service management issues)
  3. No AI provider currently available for autonomous hunt

Architectural achievements (verified by test suite):
  ✓ AI configuration discovery fixed (sudo-safe .env resolution, guided config)
  ✓ NullAIClient implements check() - no more composition crashes
  ✓ Platform.ai_settings exposed for CLI and health checks
  ✓ Guided configuration implemented (interactive + non-interactive fail-clearly)
  ✓ AI Hunt Director rewritten as authoritative decision-maker
  ✓ Security Test Matrix implemented as first-class completion contract
  ✓ Matrix-driven completion (queue empty ≠ done; cycle ceiling → reassessment)
  ✓ AI attribution telemetry (provider/model/policy/execution per decision)
  ✓ Policy gate enforces scope/budget/safety before execution
  ✓ Scope normalization (bare-host from in-scope URL allowed for host-level capabilities)
  ✓ Truthful coverage metrics (recon/attack-surface/active-testing/validation/browser separated)
  ✓ All unit tests pass (53/53)
  ✓ All integration tests pass (36/36 including AI-directed loop, preflight, completion)
  ✓ CLI commands work: ai status/check/configure, hunt with --deterministic flag

Evidence of adaptive behavior (from test_ai_directed_loop.py):
  - AI decisions adapt based on previous results (adaptive=true in trace)
  - Out-of-scope decisions rejected by policy gate
  - Premature completion rejected when matrix incomplete
  - Out-of-scope decisions properly rejected with scope violation
  - AI attribution recorded with provider/model/policy outcome

Notes:
  The core architecture is complete and tested. The acceptance run cannot achieve >0% validated coverage because no AI provider is currently available in this environment (OpenRouter rate limited, Ollama deployment incomplete in WSL). With a working AI provider (OpenRouter with credits, or local Ollama), the architecture is ready for autonomous full_security_assessment.

  To run the acceptance hunt:
  1. Ensure AI provider is healthy: `hunterx ai check`
  2. Run: `sudo hunterx hunt full_security_assessment http://localhost:3010`
  3. Monitor progress: `tail -f /opt/hunterx/reports/acceptance/events.jsonl`
  4. Evaluate: `python scripts/juice_shop_benchmark.py --mission-id <id>`