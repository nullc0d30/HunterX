# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Versioned detection rules for JavaScript intelligence.

Detection rules are the unit of intelligence: a named, versioned, human-readable
description of a pattern plus the compiled regular expressions that match it.
Rules are grouped by the artifact they produce (endpoint, route, configuration,
storage, authentication, worker, WebAssembly, security API, dynamic import,
third-party service, secret) and carry a baseline confidence and an evidence
category so downstream analyzers never hard-code patterns.

The registry is pure and deterministic: the same value always yields the same
matches for the same rule set. Rules are intended to run against **token
values** (string literals, template literals, member names) produced by the
tokenizer, not against raw source, so matching is safe and context-aware.
"""

from __future__ import annotations

import contextlib
import re
from dataclasses import dataclass
from enum import StrEnum
from re import Pattern


class RuleCategory(StrEnum):
    """The artifact class a rule produces evidence for."""

    ENDPOINT = "endpoint"
    ROUTE = "route"
    CONFIGURATION = "configuration"
    STORAGE = "storage"
    AUTHENTICATION = "authentication"
    WORKER = "worker"
    WASM = "wasm"
    SECURITY_API = "security-api"
    DYNAMIC_IMPORT = "dynamic-import"
    SERVICE = "service"
    SECRET = "secret"
    TECHNOLOGY = "technology"


@dataclass(frozen=True, slots=True)
class JSRule:
    """A single named detection rule.

    Attributes:
        rule_id: unique rule identifier (e.g. ``js-endpoint-001``).
        category: :class:`RuleCategory` the rule belongs to.
        description: human description of what the rule detects.
        pattern: raw regular expression source.
        version: rule version (bumped when the pattern changes).
        confidence: baseline confidence in ``[0, 1]`` of a match.
        evidence_type: :class:`~hunterx.domain.javascript.models.JSEvidence`
            evidence_type emitted for a match (``string``, ``call``, ...).
        enabled: whether the rule is active.
        tags: free-form tags for selection/filtering.

    """

    rule_id: str
    category: RuleCategory | str
    description: str
    pattern: str
    version: str = "1.0.0"
    confidence: float = 0.7
    evidence_type: str = "string"
    enabled: bool = True
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "category", RuleCategory(self.category))

    @property
    def compiled(self) -> Pattern[str]:
        """Return the compiled pattern (case-insensitive, non-greedy)."""
        return re.compile(self.pattern, re.IGNORECASE)

    @property
    def signature(self) -> str:
        """Return the stable signature ``category:rule_id@version``."""
        return f"{self.category.value}:{self.rule_id}@{self.version}"


@dataclass(frozen=True, slots=True)
class RuleMatch:
    """A single rule match against a value.

    Attributes:
        rule: the rule that matched.
        value: the matched value (masked when sensitive).
        offset: 0-based offset of the match in the scanned text.
        confidence: effective confidence of the match.

    """

    rule: JSRule
    value: str
    offset: int = -1
    confidence: float = 0.7

    @property
    def rule_id(self) -> str:
        """Return the matched rule identifier."""
        return self.rule.rule_id

    @property
    def category(self) -> RuleCategory:
        """Return the matched rule category."""
        return self.rule.category


# ---------------------------------------------------------------------------
# Built-in rule set.
# ---------------------------------------------------------------------------

#: Registry-version constant. Bump when the rule set changes materially.
RULES_VERSION = "1.0.0"


def _rule(
    rule_id: str,
    category: RuleCategory,
    description: str,
    pattern: str,
    *,
    version: str = "1.0.0",
    confidence: float = 0.7,
    evidence_type: str = "string",
    tags: tuple[str, ...] = (),
) -> JSRule:
    return JSRule(
        rule_id=rule_id,
        category=category,
        description=description,
        pattern=pattern,
        version=version,
        confidence=confidence,
        evidence_type=evidence_type,
        tags=tags,
    )


_BUILTIN_RULES: tuple[JSRule, ...] = (
    # -- endpoint references -------------------------------------------------
    _rule(
        "js-endpoint-001",
        RuleCategory.ENDPOINT,
        "absolute http(s) URL string",
        r"https?://[A-Za-z0-9][A-Za-z0-9.\-]*(?::\d{1,5})?(?:/[^\s\"'`<>]*)?",
        confidence=0.85,
        evidence_type="string",
    ),
    _rule(
        "js-endpoint-002",
        RuleCategory.ENDPOINT,
        "protocol-relative URL string",
        r"//[A-Za-z0-9][A-Za-z0-9.\-]*(?::\d{1,5})?(?:/[^\s\"'`<>]*)?",
        confidence=0.5,
        evidence_type="string",
    ),
    _rule(
        "js-endpoint-003",
        RuleCategory.ENDPOINT,
        "fetch() call target",
        r"fetch\s*\(\s*[\"']([^\"']+)[\"']",
        confidence=0.9,
        evidence_type="call",
        tags=("fetch",),
    ),
    _rule(
        "js-endpoint-004",
        RuleCategory.ENDPOINT,
        "XMLHttpRequest open() path",
        r"(?:open|send)\s*\(\s*[\"'](?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)[\"']\s*,\s*[\"']([^\"']+)[\"']",
        confidence=0.85,
        evidence_type="call",
        tags=("xhr",),
    ),
    _rule(
        "js-endpoint-005",
        RuleCategory.ENDPOINT,
        "axios call target",
        r"axios\.(?:get|post|put|patch|delete|head|options|request)\s*\(\s*[\"']([^\"']+)[\"']",
        confidence=0.85,
        evidence_type="call",
        tags=("axios",),
    ),
    _rule(
        "js-endpoint-006",
        RuleCategory.ENDPOINT,
        "WebSocket/EventSource constructor target",
        r"(?:new\s+WebSocket|new\s+EventSource)\s*\(\s*[\"']([^\"']+)[\"']",
        confidence=0.9,
        evidence_type="call",
        tags=("websocket", "eventsource"),
    ),
    _rule(
        "js-endpoint-007",
        RuleCategory.ENDPOINT,
        "API base URL assignment",
        r"(?:API_URL|BASE_URL|apiBaseUrl|baseUrl|API_BASE)\s*[:=]\s*[\"']([^\"']+)[\"']",
        confidence=0.8,
        evidence_type="string",
        tags=("base-url",),
    ),
    # -- client routes --------------------------------------------------------
    _rule(
        "js-route-001",
        RuleCategory.ROUTE,
        "route path definition",
        r"(?:path|route)\s*[:=]\s*[\"'](/[^\"']*)[\"']",
        confidence=0.7,
        evidence_type="string",
    ),
    _rule(
        "js-route-002",
        RuleCategory.ROUTE,
        "history.pushState / location.assign path",
        r"(?:pushState|replaceState)\s*\(\s*[^,]+,\s*[^,]+,\s*[\"']([^\"']+)[\"']",
        confidence=0.7,
        evidence_type="call",
    ),
    # -- configuration --------------------------------------------------------
    _rule(
        "js-config-001",
        RuleCategory.CONFIGURATION,
        "environment variable reference",
        r"(?:process\.env|import\.meta\.env)\.[A-Z0-9_]+",
        confidence=0.9,
        evidence_type="member",
        tags=("environment",),
    ),
    _rule(
        "js-config-002",
        RuleCategory.CONFIGURATION,
        "feature flag assignment",
        r"(?:FEATURE_|featureFlag|flags?)[A-Za-z0-9_]*\s*[:=]\s*[\"']?([^\"',;}\s]+)",
        confidence=0.6,
        evidence_type="string",
        tags=("feature-flag",),
    ),
    _rule(
        "js-config-003",
        RuleCategory.CONFIGURATION,
        "build/release identifier",
        r"(?:BUILD_ID|buildId|RELEASE_ID|releaseId|VERSION)\s*[:=]\s*[\"']([^\"']+)[\"']",
        confidence=0.75,
        evidence_type="string",
        tags=("build-id", "release-id"),
    ),
    _rule(
        "js-config-004",
        RuleCategory.CONFIGURATION,
        "service/application identifier",
        r"(?:APP_ID|appId|CLIENT_ID|clientId|serviceName)\s*[:=]\s*[\"']([^\"']+)[\"']",
        confidence=0.7,
        evidence_type="string",
        tags=("application-id", "client-id"),
    ),
    # -- storage --------------------------------------------------------------
    _rule(
        "js-storage-001",
        RuleCategory.STORAGE,
        "localStorage access",
        r"localStorage\s*\.\s*(?:getItem|setItem|removeItem)\s*\(\s*[\"']([^\"']+)[\"']",
        confidence=0.9,
        evidence_type="call",
    ),
    _rule(
        "js-storage-002",
        RuleCategory.STORAGE,
        "sessionStorage access",
        r"sessionStorage\s*\.\s*(?:getItem|setItem|removeItem)\s*\(\s*[\"']([^\"']+)[\"']",
        confidence=0.9,
        evidence_type="call",
    ),
    _rule(
        "js-storage-003",
        RuleCategory.STORAGE,
        "IndexedDB open()",
        r"(?:indexedDB|webkitIndexedDB)\s*\.\s*open\s*\(\s*[\"']([^\"']+)[\"']",
        confidence=0.9,
        evidence_type="call",
    ),
    _rule(
        "js-storage-004",
        RuleCategory.STORAGE,
        "document.cookie write",
        r"document\s*\.\s*cookie\s*=\s*[\"'][^\"']+[\"']",
        confidence=0.8,
        evidence_type="assignment",
    ),
    _rule(
        "js-storage-005",
        RuleCategory.STORAGE,
        "cache storage open()",
        r"caches\s*\.\s*open\s*\(\s*[\"']([^\"']+)[\"']",
        confidence=0.9,
        evidence_type="call",
    ),
    # -- authentication -------------------------------------------------------
    _rule(
        "js-auth-001",
        RuleCategory.AUTHENTICATION,
        "OAuth authorization endpoint",
        r"(?:authorization_endpoint|authorization_url|authUrl|login_url)\s*[:=]\s*[\"']([^\"']+)[\"']",
        confidence=0.8,
        evidence_type="string",
        tags=("oauth", "authorization-url"),
    ),
    _rule(
        "js-auth-002",
        RuleCategory.AUTHENTICATION,
        "token endpoint",
        r"(?:token_endpoint|tokenUrl|token_url)\s*[:=]\s*[\"']([^\"']+)[\"']",
        confidence=0.8,
        evidence_type="string",
        tags=("token-endpoint",),
    ),
    _rule(
        "js-auth-003",
        RuleCategory.AUTHENTICATION,
        "OIDC issuer",
        r"(?:issuer|iss)\s*[:=]\s*[\"']https?://[^\"']+[\"']",
        confidence=0.6,
        evidence_type="string",
        tags=("oidc",),
    ),
    _rule(
        "js-auth-004",
        RuleCategory.AUTHENTICATION,
        "OAuth grant/scope usage",
        r"(?:grant_type|client_id|redirect_uri|response_type)\s*:\s*[\"']([^\"']+)[\"']",
        confidence=0.75,
        evidence_type="string",
        tags=("oauth",),
    ),
    _rule(
        "js-auth-005",
        RuleCategory.AUTHENTICATION,
        "SAML assertion reference",
        r"(?:SAMLResponse|samlResponse|RelayState)\b",
        confidence=0.6,
        evidence_type="member",
        tags=("saml",),
    ),
    # -- workers --------------------------------------------------------------
    _rule(
        "js-worker-001",
        RuleCategory.WORKER,
        "new Worker() reference",
        r"new\s+Worker\s*\(\s*[\"']([^\"']+)[\"']",
        confidence=0.9,
        evidence_type="call",
    ),
    _rule(
        "js-worker-002",
        RuleCategory.WORKER,
        "new SharedWorker() reference",
        r"new\s+SharedWorker\s*\(\s*[\"']([^\"']+)[\"']",
        confidence=0.9,
        evidence_type="call",
    ),
    _rule(
        "js-worker-003",
        RuleCategory.WORKER,
        "serviceWorker.register() reference",
        r"serviceWorker\s*\.\s*register\s*\(\s*[\"']([^\"']+)[\"']",
        confidence=0.9,
        evidence_type="call",
    ),
    # -- WebAssembly ----------------------------------------------------------
    _rule(
        "js-wasm-001",
        RuleCategory.WASM,
        "WebAssembly.instantiate() reference",
        r"WebAssembly\s*\.\s*instantiate(?:Streaming)?\s*\(",
        confidence=0.9,
        evidence_type="call",
    ),
    _rule(
        "js-wasm-002",
        RuleCategory.WASM,
        "WebAssembly.compile() reference",
        r"WebAssembly\s*\.\s*compile(?:Streaming)?\s*\(",
        confidence=0.9,
        evidence_type="call",
    ),
    _rule(
        "js-wasm-003",
        RuleCategory.WASM,
        ".wasm resource reference",
        r"[\"']([^\"']*\.wasm)[\"']",
        confidence=0.8,
        evidence_type="string",
    ),
    # -- security-relevant APIs ------------------------------------------------
    _rule(
        "js-security-001",
        RuleCategory.SECURITY_API,
        "innerHTML assignment",
        r"(?:\.innerHTML|\.outerHTML)\s*=",
        confidence=0.85,
        evidence_type="assignment",
        tags=("xss-surface",),
    ),
    _rule(
        "js-security-002",
        RuleCategory.SECURITY_API,
        "document.write() usage",
        r"document\s*\.\s*write\s*\(",
        confidence=0.85,
        evidence_type="call",
        tags=("xss-surface",),
    ),
    _rule(
        "js-security-003",
        RuleCategory.SECURITY_API,
        "eval() usage",
        r"(?:eval|Function)\s*\(",
        confidence=0.8,
        evidence_type="call",
        tags=("code-execution",),
    ),
    _rule(
        "js-security-004",
        RuleCategory.SECURITY_API,
        "postMessage() usage",
        r"postMessage\s*\(",
        confidence=0.7,
        evidence_type="call",
        tags=("postmessage",),
    ),
    _rule(
        "js-security-005",
        RuleCategory.SECURITY_API,
        "location redirect assignment",
        r"(?:window\.location|document\.location|location)\s*\.\s*(?:href\s*=|assign\s*\()",
        confidence=0.7,
        evidence_type="call",
        tags=("redirect",),
    ),
    _rule(
        "js-security-006",
        RuleCategory.SECURITY_API,
        "insertAdjacentHTML() usage",
        r"insertAdjacentHTML\s*\(",
        confidence=0.8,
        evidence_type="call",
        tags=("xss-surface",),
    ),
    # -- dynamic imports ------------------------------------------------------
    _rule(
        "js-import-001",
        RuleCategory.DYNAMIC_IMPORT,
        "dynamic import() specifier",
        r"\bimport\s*\(\s*[\"']([^\"']+)[\"']\s*\)",
        confidence=0.9,
        evidence_type="call",
        tags=("chunk",),
    ),
    _rule(
        "js-import-002",
        RuleCategory.DYNAMIC_IMPORT,
        "chunk prefetch/preload URL",
        r"(?:prefetch|preload)\s*\(\s*[\"']([^\"']+)[\"']",
        confidence=0.7,
        evidence_type="call",
        tags=("chunk",),
    ),
    # -- third-party services -------------------------------------------------
    _rule(
        "js-service-001",
        RuleCategory.SERVICE,
        "google tag manager",
        r"(?:googletagmanager\.com/gtm\.js|GTM-[A-Z0-9]+)",
        confidence=0.9,
        evidence_type="string",
        tags=("google", "analytics"),
    ),
    _rule(
        "js-service-002",
        RuleCategory.SERVICE,
        "google analytics",
        r"(?:google-analytics\.com/analytics\.js|gtag\s*\(\s*[\"']config[\"']\s*,\s*[\"']G-[A-Z0-9]+[\"'])",
        confidence=0.9,
        evidence_type="string",
        tags=("google", "analytics"),
    ),
    _rule(
        "js-service-003",
        RuleCategory.SERVICE,
        "sentry error tracking",
        r"(?:browser\.sentry-cdn\.com|@sentry/(?:browser|react|vue|nextjs)|SENTRY_DSN)",
        confidence=0.9,
        evidence_type="string",
        tags=("sentry", "error-tracking"),
    ),
    _rule(
        "js-service-004",
        RuleCategory.SERVICE,
        "stripe payment",
        r"(?:js\.stripe\.com|Stripe\s*\(\s*[\"']pk_[^\"']+[\"'])",
        confidence=0.9,
        evidence_type="string",
        tags=("stripe", "payment"),
    ),
    _rule(
        "js-service-005",
        RuleCategory.SERVICE,
        "google maps",
        r"(?:maps\.googleapis\.com/maps|maps\.google\.com/maps)",
        confidence=0.9,
        evidence_type="string",
        tags=("google", "maps"),
    ),
    _rule(
        "js-service-006",
        RuleCategory.SERVICE,
        "segment analytics",
        r"(?:cdn\.segment\.com|analytics\.segment\.com)",
        confidence=0.9,
        evidence_type="string",
        tags=("segment", "analytics"),
    ),
    _rule(
        "js-service-007",
        RuleCategory.SERVICE,
        "cloudflare insight/bot",
        r"(?:cdnjs\.cloudflare\.com|static\.cloudflareinsights\.com)",
        confidence=0.85,
        evidence_type="string",
        tags=("cloudflare", "cdn"),
    ),
    _rule(
        "js-service-008",
        RuleCategory.SERVICE,
        "intercom chat",
        r"(?:widget\.intercom\.io|intercomSettings)",
        confidence=0.9,
        evidence_type="string",
        tags=("intercom", "chat"),
    ),
    _rule(
        "js-service-009",
        RuleCategory.SERVICE,
        "launchdarkly feature flag",
        r"(?:client\.ldflag|app\.launchdarkly\.com|launchdarkly)",
        confidence=0.85,
        evidence_type="string",
        tags=("launchdarkly", "feature-flag"),
    ),
    _rule(
        "js-service-010",
        RuleCategory.SERVICE,
        "sentry.io error tracking",
        r"(?:sentry\.io|ingest\.sentry\.io)",
        confidence=0.85,
        evidence_type="string",
        tags=("sentry", "error-tracking"),
    ),
    # -- secrets (masking handled by the secrets module) ----------------------
    _rule(
        "js-secret-001",
        RuleCategory.SECRET,
        "AWS access key id",
        r"\bAKIA[0-9A-Z]{16}\b",
        confidence=0.95,
        evidence_type="string",
    ),
    _rule(
        "js-secret-002",
        RuleCategory.SECRET,
        "Google API key",
        r"\bAIza[0-9A-Za-z_-]{35}\b",
        confidence=0.95,
        evidence_type="string",
    ),
    _rule(
        "js-secret-003",
        RuleCategory.SECRET,
        "GitHub personal access token",
        r"\bgh[pousr]_[0-9A-Za-z]{36,255}\b",
        confidence=0.95,
        evidence_type="string",
    ),
    _rule(
        "js-secret-004",
        RuleCategory.SECRET,
        "Slack token",
        r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b",
        confidence=0.9,
        evidence_type="string",
    ),
    _rule(
        "js-secret-005",
        RuleCategory.SECRET,
        "Stripe live secret key",
        r"\bsk_live_[0-9A-Za-z]{16,}\b",
        confidence=0.95,
        evidence_type="string",
    ),
    _rule(
        "js-secret-006",
        RuleCategory.SECRET,
        "Stripe test secret key",
        r"\bsk_test_[0-9A-Za-z]{16,}\b",
        confidence=0.9,
        evidence_type="string",
    ),
    _rule(
        "js-secret-007",
        RuleCategory.SECRET,
        "Stripe live publishable key",
        r"\bpk_live_[0-9A-Za-z]{16,}\b",
        confidence=0.9,
        evidence_type="string",
    ),
    _rule(
        "js-secret-008",
        RuleCategory.SECRET,
        "PEM private key block",
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----",
        confidence=0.95,
        evidence_type="string",
    ),
    _rule(
        "js-secret-009",
        RuleCategory.SECRET,
        "JSON Web Token (JWT)",
        r"\beyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b",
        confidence=0.85,
        evidence_type="string",
    ),
    _rule(
        "js-secret-010",
        RuleCategory.SECRET,
        "generic credential assignment",
        r"(?:password|passwd|secret|token|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|auth[_-]?token)\s*[:=]\s*\\?[\"']([^\"']{8,})?",
        confidence=0.55,
        evidence_type="string",
    ),
)


class JSRuleRegistry:
    """A curated, versioned registry of JavaScript detection rules.

    Attributes:
        rules: the active (enabled) rules in registry order.
        version: the registry version string.

    """

    def __init__(self, rules: tuple[JSRule, ...] = _BUILTIN_RULES) -> None:
        self._rules = tuple(rule for rule in rules if rule.enabled)
        self.version = RULES_VERSION

    @property
    def rules(self) -> tuple[JSRule, ...]:
        """Return the active rules."""
        return self._rules

    def rules_for(self, category: RuleCategory | str) -> tuple[JSRule, ...]:
        """Return the active rules for ``category``."""
        category = RuleCategory(category)
        return tuple(rule for rule in self._rules if rule.category is category)

    def categories(self) -> tuple[RuleCategory, ...]:
        """Return the categories present in the registry (registry order)."""
        seen: list[RuleCategory] = []
        for rule in self._rules:
            if rule.category not in seen:
                seen.append(rule.category)
        return tuple(seen)

    def match(self, value: str, *, categories: set[RuleCategory] | None = None) -> list[RuleMatch]:
        """Match ``value`` against the active rules.

        Args:
            value: the token value to scan.
            categories: optional category filter; ``None`` scans every rule.

        Returns:
            The ordered list of :class:`RuleMatch` hits (registry order).

        """
        matches: list[RuleMatch] = []
        for rule in self._rules:
            if categories is not None and rule.category not in categories:
                continue
            match = rule.compiled.search(value)
            if match:
                matched_text = match.group(0)
                with contextlib.suppress(IndexError):
                    matched_text = match.group(1) or matched_text
                matches.append(
                    RuleMatch(
                        rule=rule,
                        value=matched_text,
                        offset=match.start(),
                        confidence=rule.confidence,
                    )
                )
        return matches

    def match_for_category(
        self, value: str, category: RuleCategory | str
    ) -> list[RuleMatch]:
        """Match ``value`` against the rules of a single ``category``."""
        return self.match(value, categories={RuleCategory(category)})

    def get(self, rule_id: str) -> JSRule | None:
        """Return the rule with ``rule_id`` or ``None``."""
        for rule in self._rules:
            if rule.rule_id == rule_id:
                return rule
        return None

    def signatures(self) -> tuple[str, ...]:
        """Return the stable signature of every active rule."""
        return tuple(rule.signature for rule in self._rules)


#: Module-level default registry (shared, stateless).
DEFAULT_RULES = JSRuleRegistry()
