# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""JavaScript intelligence analyzers.

The analyzers turn token streams (from :mod:`tokenizer`) and rule matches (from
:mod:`rules`) into typed findings — endpoints, routes, configuration, storage,
authentication references, workers, WebAssembly references, security-relevant
API usage, dynamic imports, third-party services and external domains.

Call/pattern rules (``fetch(...)``, ``new Worker(...)``, ``localStorage.set``)
scan the **raw source** with the compiled rule; bare-value rules (absolute URLs,
route paths) additionally scan string/template literal **values**. Every
analyzer is pure and deterministic, and every finding carries masked evidence
with an exact ``file:line:col`` location.

Secrets and technology are intentionally *not* here: they have dedicated
modules (:mod:`secrets`, :mod:`technology`) with their own confidence and
false-positive handling.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.javascript.models import (
    ApiType,
    AuthReferenceKind,
    ConfigurationKind,
    DomainRelation,
    EndpointKind,
    JSAuthenticationReference,
    JSConfigurationIndicator,
    JSDynamicImport,
    JSEndpoint,
    JSEvidence,
    JSExternalDomain,
    JSRoute,
    JSSecurityIndicator,
    JSStorageIndicator,
    JSThirdPartyService,
    JSWasmReference,
    JSWorker,
    RouteFramework,
    SecurityApiKind,
    StorageType,
    ThirdPartyCategory,
    WasmReferenceKind,
    WorkerKind,
)
from hunterx.domain.javascript.rules import JSRuleRegistry, RuleCategory, RuleMatch
from hunterx.domain.javascript.tokenizer import JSToken, JSTokenizer

#: HTTP method keywords accepted by the endpoint analyzer.
_HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "connect", "trace"})

#: Identifier names for HTTP clients (call-context detection).
_HTTP_CLIENT_NAMES = frozenset({"fetch", "axios", "sendbeacon"})

#: File extensions that mark a path as a static asset, not an API/route.
_ASSET_EXTENSIONS = frozenset(
    {
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs",
        ".css",
        ".scss",
        ".less",
        ".map",
        ".wasm",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".webp",
        ".ico",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".mp3",
        ".mp4",
        ".webm",
        ".pdf",
        ".json",
        ".xml",
        ".txt",
        ".html",
        ".htm",
    }
)

#: Identifier names signalling a WebSocket/EventSource construction.
_WEBSOCKET_NAMES = frozenset({"websocket", "eventsource"})

#: Frontend router identifiers mapped to their framework.
_ROUTER_FRAMEWORKS: dict[str, RouteFramework] = {
    "createrouter": RouteFramework.REACT,
    "createbrowserrouter": RouteFramework.REACT,
    "createwebhistory": RouteFramework.REACT,
    "creatememoryhistory": RouteFramework.REACT,
    "router": RouteFramework.REACT,
    "vue-router": RouteFramework.VUE,
    "@angular/router": RouteFramework.ANGULAR,
    "next/router": RouteFramework.NEXT,
}

#: Service category keywords in detected provider/domain names.
_SERVICE_KEYWORDS: dict[str, ThirdPartyCategory] = {
    "google": ThirdPartyCategory.ANALYTICS,
    "analytics": ThirdPartyCategory.ANALYTICS,
    "segment": ThirdPartyCategory.ANALYTICS,
    "sentry": ThirdPartyCategory.ERROR_TRACKING,
    "error": ThirdPartyCategory.ERROR_TRACKING,
    "bugsnag": ThirdPartyCategory.ERROR_TRACKING,
    "stripe": ThirdPartyCategory.PAYMENT,
    "payment": ThirdPartyCategory.PAYMENT,
    "paypal": ThirdPartyCategory.PAYMENT,
    "cloudflare": ThirdPartyCategory.CDN,
    "cdn": ThirdPartyCategory.CDN,
    "auth0": ThirdPartyCategory.AUTHENTICATION,
    "okta": ThirdPartyCategory.AUTHENTICATION,
    "launchdarkly": ThirdPartyCategory.FEATURE_FLAG,
    "flagsmith": ThirdPartyCategory.FEATURE_FLAG,
    "maps": ThirdPartyCategory.MAPS,
    "intercom": ThirdPartyCategory.CHAT,
    "chat": ThirdPartyCategory.CHAT,
    "slack": ThirdPartyCategory.MESSAGING,
    "discord": ThirdPartyCategory.MESSAGING,
    "amazonaws": ThirdPartyCategory.CLOUD,
    "azure": ThirdPartyCategory.CLOUD,
    "firebase": ThirdPartyCategory.CLOUD,
    "doubleclick": ThirdPartyCategory.ADVERTISING,
    "adsystem": ThirdPartyCategory.ADVERTISING,
    "facebook": ThirdPartyCategory.SOCIAL,
    "twitter": ThirdPartyCategory.SOCIAL,
    "storj": ThirdPartyCategory.STORAGE,
    "s3": ThirdPartyCategory.STORAGE,
}


@dataclass(frozen=True, slots=True)
class AnalyzeContext:
    """Provenance envelope shared by every analyzer output.

    Attributes:
        file: asset label used in evidence locations (URL or ``inline``).
        target_key: canonical owning host key.
        correlation_id / mission_id: run provenance.
        tool_id: producing tool.
        source_label: upstream source (``javascript`` for the JS pipeline).

    """

    file: str = ""
    target_key: str = ""
    correlation_id: str = ""
    mission_id: str = ""
    tool_id: str = ""
    source_label: str = "javascript"


def _location(source: str, offset: int) -> tuple[int, int]:
    """Return ``(line, column)`` for a 0-based ``offset`` in ``source``."""
    line = 1
    column = 1
    limit = min(offset, len(source))
    for char in source[:limit]:
        if char == "\n":
            line += 1
            column = 1
        else:
            column += 1
    return line, column


def _evidence(
    source: str,
    offset: int,
    match: RuleMatch | None,
    context: AnalyzeContext,
    *,
    file: str | None = None,
) -> JSEvidence:
    """Build a :class:`JSEvidence` for a rule match at ``offset``."""
    value = match.value if match else ""
    evidence_type = match.rule.evidence_type if match else "string"
    location_file = file if file is not None else context.file
    line, column = _location(source, offset)
    return JSEvidence(
        evidence_type=evidence_type,
        value=value[:120] + ("..." if len(value) > 120 else ""),
        location=f"{location_file}:{line}:{column}" if location_file else f"{line}:{column}",
        offset=offset,
        snippet=value[:60] + ("..." if len(value) > 60 else ""),
        rule_id=match.rule_id if match else "",
        source=context.source_label,
        tool_id=context.tool_id,
        confidence=match.confidence if match else 1.0,
    )


def _token_values(source: str, tokenizer: JSTokenizer, file: str) -> list[tuple[JSToken, str]]:
    """Return ``(token, value)`` pairs for string/template literal tokens."""
    tokens = tokenizer.tokenize(source, file=file)
    return [(token, token.value) for token in tokens if token.is_value()]


class EndpointAnalyzer:
    """Extract client-side endpoint references from a source.

    Covers ``fetch``/XHR/axios/WebSocket/EventSource call contexts, absolute
    and relative URL strings, and API base URL assignments.
    """

    def __init__(
        self,
        *,
        tokenizer: JSTokenizer | None = None,
        rules: JSRuleRegistry | None = None,
    ) -> None:
        self._tokenizer = tokenizer or JSTokenizer()
        self._rules = rules or JSRuleRegistry()

    def analyze(self, source: str, context: AnalyzeContext) -> list[JSEndpoint]:
        """Return the endpoint references found in ``source``."""
        findings: list[JSEndpoint] = []
        seen: set[str] = set()

        for match in self._rules.match_for_category(source, RuleCategory.ENDPOINT):
            value = match.value.strip()
            if not value:
                continue
            key = f"{match.rule_id}:{value}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                JSEndpoint(
                    url=value,
                    method=_method_for_endpoint(source, match),
                    kind=_kind_for_rule(match.rule_id),
                    api_type=_api_type_for(value),
                    evidence=(_evidence(source, match.offset, match, context),),
                    confidence=match.confidence,
                    source=context.source_label,
                    tool_id=context.tool_id,
                    target_key=context.target_key,
                    correlation_id=context.correlation_id,
                    mission_id=context.mission_id,
                )
            )

        # bare relative paths in string literals (e.g. ``"/api/login"``)
        for token, value in _token_values(source, self._tokenizer, context.file):
            if not value.startswith("/") or value.startswith("//"):
                continue
            if not _looks_like_path(value):
                continue
            if _is_asset_path(value) or _has_route_params(value):
                continue
            key = f"path:{value}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                JSEndpoint(
                    url=value,
                    method="GET",
                    kind=EndpointKind.CUSTOM,
                    api_type=ApiType.REST,
                    evidence=(_evidence(source, token.offset, None, context),),
                    confidence=0.5,
                    source=context.source_label,
                    tool_id=context.tool_id,
                    target_key=context.target_key,
                    correlation_id=context.correlation_id,
                    mission_id=context.mission_id,
                )
            )
        return findings


class RouteAnalyzer:
    """Extract frontend route definitions and history navigation paths."""

    def __init__(
        self,
        *,
        tokenizer: JSTokenizer | None = None,
        rules: JSRuleRegistry | None = None,
    ) -> None:
        self._tokenizer = tokenizer or JSTokenizer()
        self._rules = rules or JSRuleRegistry()

    def analyze(self, source: str, context: AnalyzeContext) -> list[JSRoute]:
        """Return the client routes found in ``source``."""
        findings: list[JSRoute] = []
        seen: set[str] = set()

        for match in self._rules.match_for_category(source, RuleCategory.ROUTE):
            value = match.value.strip()
            if not value.startswith("/"):
                value = "/" + value.lstrip("/")
            key = value
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                JSRoute(
                    route=value,
                    pattern=value,
                    parameters=_extract_route_params(value),
                    framework=_framework_for_source(source),
                    evidence=(_evidence(source, match.offset, match, context),),
                    confidence=match.confidence,
                    source=context.source_label,
                    tool_id=context.tool_id,
                    target_key=context.target_key,
                    correlation_id=context.correlation_id,
                    mission_id=context.mission_id,
                )
            )

        # bare "/path" strings in routes arrays
        for token, value in _token_values(source, self._tokenizer, context.file):
            if not value.startswith("/") or value.startswith("//"):
                continue
            if not _looks_like_path(value):
                continue
            if _is_asset_path(value):
                continue
            key = value
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                JSRoute(
                    route=value,
                    pattern=value,
                    parameters=_extract_route_params(value),
                    framework=_framework_for_source(source),
                    evidence=(_evidence(source, token.offset, None, context),),
                    confidence=0.5,
                    source=context.source_label,
                    tool_id=context.tool_id,
                    target_key=context.target_key,
                    correlation_id=context.correlation_id,
                    mission_id=context.mission_id,
                )
            )
        return findings


class ConfigurationAnalyzer:
    """Extract client-side configuration indicators (env, flags, ids)."""

    def __init__(
        self,
        *,
        tokenizer: JSTokenizer | None = None,
        rules: JSRuleRegistry | None = None,
    ) -> None:
        self._tokenizer = tokenizer or JSTokenizer()
        self._rules = rules or JSRuleRegistry()

    def analyze(self, source: str, context: AnalyzeContext) -> list[JSConfigurationIndicator]:
        """Return the configuration indicators found in ``source``."""
        findings: list[JSConfigurationIndicator] = []
        seen: set[str] = set()

        for match in self._rules.match_for_category(source, RuleCategory.CONFIGURATION):
            key = f"{match.rule_id}:{match.value}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                JSConfigurationIndicator(
                    kind=_config_kind_for_rule(match.rule_id),
                    key=_config_key_for_match(match),
                    value="",
                    environment=_environment_for_rule(match.rule_id),
                    evidence=(_evidence(source, match.offset, match, context),),
                    confidence=match.confidence,
                    source=context.source_label,
                    tool_id=context.tool_id,
                    target_key=context.target_key,
                    correlation_id=context.correlation_id,
                    mission_id=context.mission_id,
                )
            )
        return findings


class StorageAnalyzer:
    """Extract client-side storage usage from a source."""

    def __init__(
        self,
        *,
        tokenizer: JSTokenizer | None = None,
        rules: JSRuleRegistry | None = None,
    ) -> None:
        self._tokenizer = tokenizer or JSTokenizer()
        self._rules = rules or JSRuleRegistry()

    def analyze(self, source: str, context: AnalyzeContext) -> list[JSStorageIndicator]:
        """Return the storage indicators found in ``source``."""
        findings: list[JSStorageIndicator] = []
        seen: set[str] = set()

        for match in self._rules.match_for_category(source, RuleCategory.STORAGE):
            key = f"{match.rule_id}:{match.value}"
            if key in seen:
                continue
            seen.add(key)
            storage_type = _storage_type_for_rule(match.rule_id)
            findings.append(
                JSStorageIndicator(
                    storage_type=storage_type,
                    key_pattern=match.value,
                    usage_context=_usage_context_for_rule(match.rule_id),
                    evidence=(_evidence(source, match.offset, match, context),),
                    confidence=match.confidence,
                    source=context.source_label,
                    tool_id=context.tool_id,
                    target_key=context.target_key,
                    correlation_id=context.correlation_id,
                    mission_id=context.mission_id,
                )
            )
        return findings


class AuthenticationAnalyzer:
    """Extract authentication-related references from a source."""

    def __init__(
        self,
        *,
        tokenizer: JSTokenizer | None = None,
        rules: JSRuleRegistry | None = None,
    ) -> None:
        self._tokenizer = tokenizer or JSTokenizer()
        self._rules = rules or JSRuleRegistry()

    def analyze(self, source: str, context: AnalyzeContext) -> list[JSAuthenticationReference]:
        """Return the authentication references found in ``source``."""
        findings: list[JSAuthenticationReference] = []
        seen: set[str] = set()

        for match in self._rules.match_for_category(source, RuleCategory.AUTHENTICATION):
            key = f"{match.rule_id}:{match.value}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                JSAuthenticationReference(
                    kind=_auth_kind_for_rule(match.rule_id),
                    value=match.value,
                    mechanism=_mechanism_for_rule(match.rule_id),
                    evidence=(_evidence(source, match.offset, match, context),),
                    confidence=match.confidence,
                    source=context.source_label,
                    tool_id=context.tool_id,
                    target_key=context.target_key,
                    correlation_id=context.correlation_id,
                    mission_id=context.mission_id,
                )
            )
        return findings


class WorkerAnalyzer:
    """Extract worker and service-worker references from a source."""

    def __init__(
        self,
        *,
        tokenizer: JSTokenizer | None = None,
        rules: JSRuleRegistry | None = None,
    ) -> None:
        self._tokenizer = tokenizer or JSTokenizer()
        self._rules = rules or JSRuleRegistry()

    def analyze(self, source: str, context: AnalyzeContext) -> list[JSWorker]:
        """Return the worker references found in ``source``."""
        findings: list[JSWorker] = []
        seen: set[str] = set()

        for match in self._rules.match_for_category(source, RuleCategory.WORKER):
            key = f"{match.rule_id}:{match.value}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                JSWorker(
                    kind=_worker_kind_for_rule(match.rule_id),
                    url=match.value,
                    registration_context="register" if match.rule_id == "js-worker-003" else "construct",
                    evidence=(_evidence(source, match.offset, match, context),),
                    confidence=match.confidence,
                    source=context.source_label,
                    tool_id=context.tool_id,
                    target_key=context.target_key,
                    correlation_id=context.correlation_id,
                    mission_id=context.mission_id,
                )
            )
        return findings


class WasmAnalyzer:
    """Extract WebAssembly references from a source."""

    def __init__(
        self,
        *,
        tokenizer: JSTokenizer | None = None,
        rules: JSRuleRegistry | None = None,
    ) -> None:
        self._tokenizer = tokenizer or JSTokenizer()
        self._rules = rules or JSRuleRegistry()

    def analyze(self, source: str, context: AnalyzeContext) -> list[JSWasmReference]:
        """Return the WebAssembly references found in ``source``."""
        findings: list[JSWasmReference] = []
        seen: set[str] = set()

        for match in self._rules.match_for_category(source, RuleCategory.WASM):
            key = f"{match.rule_id}:{match.value}"
            if key in seen:
                continue
            seen.add(key)
            url = match.value if ".wasm" in match.value else ""
            findings.append(
                JSWasmReference(
                    kind=_wasm_kind_for_rule(match.rule_id),
                    url=url,
                    evidence=(_evidence(source, match.offset, match, context),),
                    confidence=match.confidence,
                    source=context.source_label,
                    tool_id=context.tool_id,
                    target_key=context.target_key,
                    correlation_id=context.correlation_id,
                    mission_id=context.mission_id,
                )
            )
        return findings


class SecurityAnalyzer:
    """Extract security-relevant browser API usage from a source.

    Intelligence-only: these are surface indicators, never vulnerability
    assertions.
    """

    def __init__(
        self,
        *,
        tokenizer: JSTokenizer | None = None,
        rules: JSRuleRegistry | None = None,
    ) -> None:
        self._tokenizer = tokenizer or JSTokenizer()
        self._rules = rules or JSRuleRegistry()

    def analyze(self, source: str, context: AnalyzeContext) -> list[JSSecurityIndicator]:
        """Return the security-relevant API usages found in ``source``."""
        findings: list[JSSecurityIndicator] = []
        seen: set[str] = set()

        for match in self._rules.match_for_category(source, RuleCategory.SECURITY_API):
            key = f"{match.rule_id}:{match.value}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                JSSecurityIndicator(
                    api=_security_api_for_rule(match.rule_id),
                    context=match.value,
                    evidence=(_evidence(source, match.offset, match, context),),
                    confidence=match.confidence,
                    source=context.source_label,
                    tool_id=context.tool_id,
                    target_key=context.target_key,
                    correlation_id=context.correlation_id,
                    mission_id=context.mission_id,
                )
            )
        return findings


class DynamicImportAnalyzer:
    """Extract dynamic ``import()`` and lazy-chunk references."""

    def __init__(
        self,
        *,
        tokenizer: JSTokenizer | None = None,
        rules: JSRuleRegistry | None = None,
    ) -> None:
        self._tokenizer = tokenizer or JSTokenizer()
        self._rules = rules or JSRuleRegistry()

    def analyze(self, source: str, context: AnalyzeContext) -> list[JSDynamicImport]:
        """Return the dynamic import references found in ``source``."""
        findings: list[JSDynamicImport] = []
        seen: set[str] = set()

        for match in self._rules.match_for_category(source, RuleCategory.DYNAMIC_IMPORT):
            key = f"{match.rule_id}:{match.value}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                JSDynamicImport(
                    specifier=match.value,
                    chunk=bool(match.rule.tags and "chunk" in match.rule.tags),
                    evidence=(_evidence(source, match.offset, match, context),),
                    confidence=match.confidence,
                    source=context.source_label,
                    tool_id=context.tool_id,
                    target_key=context.target_key,
                    correlation_id=context.correlation_id,
                    mission_id=context.mission_id,
                )
            )
        return findings


class ServiceAnalyzer:
    """Extract third-party service references from a source."""

    def __init__(
        self,
        *,
        tokenizer: JSTokenizer | None = None,
        rules: JSRuleRegistry | None = None,
    ) -> None:
        self._tokenizer = tokenizer or JSTokenizer()
        self._rules = rules or JSRuleRegistry()

    def analyze(self, source: str, context: AnalyzeContext) -> list[JSThirdPartyService]:
        """Return the third-party service references found in ``source``."""
        findings: list[JSThirdPartyService] = []
        seen: set[str] = set()

        for match in self._rules.match_for_category(source, RuleCategory.SERVICE):
            key = f"{match.rule_id}:{match.value}"
            if key in seen:
                continue
            seen.add(key)
            provider, service = _provider_service(match.value)
            findings.append(
                JSThirdPartyService(
                    provider=provider,
                    service=service,
                    category=_service_category(match.value),
                    domain=_service_domain(match.value),
                    evidence=(_evidence(source, match.offset, match, context),),
                    confidence=match.confidence,
                    source=context.source_label,
                    tool_id=context.tool_id,
                    target_key=context.target_key,
                    correlation_id=context.correlation_id,
                    mission_id=context.mission_id,
                )
            )
        return findings


class DomainAnalyzer:
    """Extract external domains referenced by a source."""

    def __init__(
        self,
        *,
        tokenizer: JSTokenizer | None = None,
        rules: JSRuleRegistry | None = None,
    ) -> None:
        self._tokenizer = tokenizer or JSTokenizer()
        self._rules = rules or JSRuleRegistry()

    def analyze(self, source: str, context: AnalyzeContext) -> list[JSExternalDomain]:
        """Return the external domains referenced in ``source``."""
        findings: list[JSExternalDomain] = []
        seen: set[str] = set()

        for match in self._rules.match_for_category(source, RuleCategory.ENDPOINT):
            domain = _domain_of_url(match.value)
            if not domain or not _looks_like_domain(domain):
                continue
            key = domain
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                JSExternalDomain(
                    domain=domain,
                    relation=_relation_for_domain(domain, context.target_key),
                    hostname=domain,
                    evidence=(_evidence(source, match.offset, match, context),),
                    confidence=0.7,
                    source=context.source_label,
                    tool_id=context.tool_id,
                    target_key=context.target_key,
                    correlation_id=context.correlation_id,
                    mission_id=context.mission_id,
                )
            )
        return findings


@dataclass(slots=True)
class AnalyzerSet:
    """Composite of the core JavaScript analyzers.

    Attributes:
        endpoint / route / configuration / storage / authentication / worker /
        wasm / security / dynamic_import / service / domain: the sub-analyzers.

    """

    endpoint: EndpointAnalyzer = field(default_factory=EndpointAnalyzer)
    route: RouteAnalyzer = field(default_factory=RouteAnalyzer)
    configuration: ConfigurationAnalyzer = field(default_factory=ConfigurationAnalyzer)
    storage: StorageAnalyzer = field(default_factory=StorageAnalyzer)
    authentication: AuthenticationAnalyzer = field(default_factory=AuthenticationAnalyzer)
    worker: WorkerAnalyzer = field(default_factory=WorkerAnalyzer)
    wasm: WasmAnalyzer = field(default_factory=WasmAnalyzer)
    security: SecurityAnalyzer = field(default_factory=SecurityAnalyzer)
    dynamic_import: DynamicImportAnalyzer = field(default_factory=DynamicImportAnalyzer)
    service: ServiceAnalyzer = field(default_factory=ServiceAnalyzer)
    domain: DomainAnalyzer = field(default_factory=DomainAnalyzer)

    def __post_init__(self) -> None:
        shared_rules = JSRuleRegistry()
        self.endpoint = EndpointAnalyzer(rules=shared_rules)
        self.route = RouteAnalyzer(rules=shared_rules)
        self.configuration = ConfigurationAnalyzer(rules=shared_rules)
        self.storage = StorageAnalyzer(rules=shared_rules)
        self.authentication = AuthenticationAnalyzer(rules=shared_rules)
        self.worker = WorkerAnalyzer(rules=shared_rules)
        self.wasm = WasmAnalyzer(rules=shared_rules)
        self.security = SecurityAnalyzer(rules=shared_rules)
        self.dynamic_import = DynamicImportAnalyzer(rules=shared_rules)
        self.service = ServiceAnalyzer(rules=shared_rules)
        self.domain = DomainAnalyzer(rules=shared_rules)


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------

def _kind_for_rule(rule_id: str) -> EndpointKind:
    if rule_id == "js-endpoint-003":
        return EndpointKind.FETCH
    if rule_id == "js-endpoint-004":
        return EndpointKind.XHR
    if rule_id == "js-endpoint-005":
        return EndpointKind.AXIOS
    if rule_id == "js-endpoint-006":
        return EndpointKind.WEBSOCKET
    if rule_id == "js-endpoint-007":
        return EndpointKind.BASE_URL
    return EndpointKind.CUSTOM


def _method_for_endpoint(source: str, match: RuleMatch) -> str:
    """Infer the HTTP method from the raw call context when available."""
    if match.rule_id == "js-endpoint-006":
        return "GET"
    context = source[max(0, match.offset - 80) : match.offset + 40]
    lowered = context.lower()
    for method in ("get", "post", "put", "patch", "delete", "head", "options"):
        if method in lowered:
            return method.upper()
    return "GET"


def _api_type_for(value: str) -> ApiType:
    lowered = value.lower()
    if "graphql" in lowered:
        return ApiType.GRAPHQL
    if "ws://" in lowered or "wss://" in lowered:
        return ApiType.WEBSOCKET
    if lowered.endswith("/sse") or "sse" in lowered:
        return ApiType.SSE
    if "http://" in lowered or "https://" in lowered or value.startswith("/"):
        return ApiType.REST
    return ApiType.UNKNOWN


def _extract_route_params(pattern: str) -> tuple[str, ...]:
    """Return parameter names embedded in a route pattern."""
    import re

    params: list[str] = []
    for part in pattern.split("/"):
        if part.startswith(":"):
            name = part[1:].split("(")[0]
            if name:
                params.append(name)
    for name in re.findall(r"\{([A-Za-z0-9_]+)\}", pattern):
        params.append(name)
    return tuple(dict.fromkeys(params))


def _framework_for_source(source: str) -> RouteFramework:
    """Infer the routing framework from the whole source (cheap heuristic)."""
    lowered = source.lower()
    if "@angular/router" in lowered:
        return RouteFramework.ANGULAR
    if "vue-router" in lowered:
        return RouteFramework.VUE
    if "next/router" in lowered or "next/link" in lowered:
        return RouteFramework.NEXT
    if "react-router" in lowered or "react-router-dom" in lowered or "createrouter" in lowered:
        return RouteFramework.REACT
    return RouteFramework.OTHER


def _config_kind_for_rule(rule_id: str) -> ConfigurationKind:
    if rule_id == "js-config-001":
        return ConfigurationKind.ENVIRONMENT
    if rule_id == "js-config-002":
        return ConfigurationKind.FEATURE_FLAG
    if rule_id == "js-config-003":
        return ConfigurationKind.BUILD_ID
    if rule_id == "js-config-004":
        return ConfigurationKind.APPLICATION_ID
    return ConfigurationKind.OTHER


def _config_key_for_match(match: RuleMatch) -> str:
    """Derive the configuration key from a matched value."""
    value = match.value or ""
    if match.rule_id == "js-config-001":
        return value.rsplit(".", 1)[-1]
    return value


def _environment_for_rule(rule_id: str) -> str:
    return "runtime" if rule_id == "js-config-001" else ""


def _storage_type_for_rule(rule_id: str) -> StorageType:
    mapping = {
        "js-storage-001": StorageType.LOCAL_STORAGE,
        "js-storage-002": StorageType.SESSION_STORAGE,
        "js-storage-003": StorageType.INDEXED_DB,
        "js-storage-004": StorageType.COOKIE,
        "js-storage-005": StorageType.CACHE_STORAGE,
    }
    return mapping.get(rule_id, StorageType.LOCAL_STORAGE)


def _usage_context_for_rule(rule_id: str) -> str:
    if rule_id == "js-storage-004":
        return "set"
    if rule_id in ("js-storage-003", "js-storage-005"):
        return "open"
    return "access"


def _auth_kind_for_rule(rule_id: str) -> AuthReferenceKind:
    mapping = {
        "js-auth-001": AuthReferenceKind.AUTHORIZATION_URL,
        "js-auth-002": AuthReferenceKind.TOKEN_ENDPOINT,
        "js-auth-003": AuthReferenceKind.OIDC,
        "js-auth-004": AuthReferenceKind.OAUTH,
        "js-auth-005": AuthReferenceKind.SAML,
    }
    return mapping.get(rule_id, AuthReferenceKind.OTHER)


def _mechanism_for_rule(rule_id: str) -> str:
    mapping = {
        "js-auth-001": "oauth2",
        "js-auth-002": "oauth2",
        "js-auth-003": "oidc",
        "js-auth-005": "saml",
    }
    return mapping.get(rule_id, "")


def _worker_kind_for_rule(rule_id: str) -> WorkerKind:
    if rule_id == "js-worker-002":
        return WorkerKind.SHARED_WORKER
    if rule_id == "js-worker-003":
        return WorkerKind.SERVICE_WORKER
    return WorkerKind.WORKER


def _wasm_kind_for_rule(rule_id: str) -> WasmReferenceKind:
    if rule_id == "js-wasm-001":
        return WasmReferenceKind.INSTANTIATE
    if rule_id == "js-wasm-002":
        return WasmReferenceKind.INSTANTIATE_STREAMING
    return WasmReferenceKind.RESOURCE


def _security_api_for_rule(rule_id: str) -> SecurityApiKind:
    mapping = {
        "js-security-001": SecurityApiKind.INNER_HTML,
        "js-security-002": SecurityApiKind.DOCUMENT_WRITE,
        "js-security-003": SecurityApiKind.EVAL,
        "js-security-004": SecurityApiKind.POST_MESSAGE,
        "js-security-005": SecurityApiKind.REDIRECT,
        "js-security-006": SecurityApiKind.DOM_INSERTION,
    }
    return mapping.get(rule_id, SecurityApiKind.INNER_HTML)


def _provider_service(value: str) -> tuple[str, str]:
    lowered = value.lower()
    pairs = (
        ("stripe", "Stripe", "Stripe Payments"),
        ("sentry", "Sentry", "Sentry Error Tracking"),
        ("googletagmanager", "Google", "Google Tag Manager"),
        ("gtm.js", "Google", "Google Tag Manager"),
        ("google-analytics", "Google", "Google Analytics"),
        ("gtag", "Google", "Google Analytics"),
        ("launchdarkly", "LaunchDarkly", "LaunchDarkly Feature Flags"),
        ("segment", "Segment", "Segment Analytics"),
        ("cloudflare", "Cloudflare", "Cloudflare"),
        ("intercom", "Intercom", "Intercom"),
        ("bugsnag", "Bugsnag", "Bugsnag Error Tracking"),
        ("stripe.com", "Stripe", "Stripe Payments"),
        ("paypal", "PayPal", "PayPal"),
        ("auth0", "Auth0", "Auth0"),
        ("okta", "Okta", "Okta"),
        ("facebook", "Facebook", "Facebook"),
        ("discord", "Discord", "Discord"),
        ("slack", "Slack", "Slack"),
        ("firebase", "Firebase", "Firebase"),
        ("azure", "Microsoft Azure", "Azure"),
        ("amazonaws", "Amazon Web Services", "AWS"),
        ("doubleclick", "Google", "DoubleClick Advertising"),
        ("maps.google", "Google", "Google Maps"),
    )
    for needle, provider, service in pairs:
        if needle in lowered:
            return provider, service
    return value, value


def _service_category(value: str) -> ThirdPartyCategory:
    lowered = value.lower()
    for keyword, category in _SERVICE_KEYWORDS.items():
        if keyword in lowered:
            return category
    return ThirdPartyCategory.OTHER


def _service_domain(value: str) -> str:
    """Extract the host from a service URL when present."""
    import urllib.parse

    normalized = value
    if value.startswith("//"):
        normalized = "https:" + value
    if "://" not in normalized:
        return ""
    try:
        return urllib.parse.urlsplit(normalized).hostname or ""
    except ValueError:
        return ""


def _domain_of_url(value: str) -> str:
    """Return the hostname of a URL string, or ``""``."""
    import urllib.parse

    normalized = value
    if value.startswith("//"):
        normalized = "https:" + value
    if "://" not in normalized:
        return ""
    try:
        return urllib.parse.urlsplit(normalized).hostname or ""
    except ValueError:
        return ""


def _looks_like_path(value: str) -> bool:
    """Return ``True`` when ``value`` looks like an API/route path segment."""
    if any(char in value for char in ("\n", "\r", " ")):
        return False
    if not value.startswith("/"):
        return False
    return len(value) > 1


def _is_asset_path(value: str) -> bool:
    """Return ``True`` when ``value`` ends in a static asset extension."""
    lowered = value.lower().split("?", 1)[0].split("#", 1)[0]
    return any(lowered.endswith(ext) for ext in _ASSET_EXTENSIONS)


def _has_route_params(value: str) -> bool:
    """Return ``True`` when ``value`` embeds route parameter markers."""
    return ":" in value or "{" in value or "}" in value


def _looks_like_domain(value: str) -> bool:
    """Return ``True`` when ``value`` is a plausible hostname."""
    import ipaddress

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    if "." not in value:
        return False
    if value in ("localhost",) or value.endswith(".local"):
        return True
    return len(value) <= 253 and all(
        part.isalnum() or "-" in part for part in value.split(".") if part
    )


def _relation_for_domain(domain: str, target_key: str) -> DomainRelation:
    """Classify the relation of ``domain`` to the owning ``target_key``."""
    normalized_target = str(target_key or "").lower().rstrip(".")
    normalized_domain = domain.lower().rstrip(".")
    if not normalized_target:
        return DomainRelation.UNKNOWN
    if normalized_domain == normalized_target or normalized_domain.endswith("." + normalized_target):
        return DomainRelation.SAME_ORIGIN
    target_labels = normalized_target.split(".")
    domain_labels = normalized_domain.split(".")
    if len(target_labels) >= 2 and domain_labels[-2:] == target_labels[-2:]:
        return DomainRelation.SAME_ORGANIZATION
    return DomainRelation.THIRD_PARTY
