# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Canonical event catalog.

The catalog is the single source of truth for every event type the platform
can publish. Each entry is an :class:`~hunterx.domain.events.spec.EventSpec`
with a stable ``event_type``, category, default severity and payload version.
Consumers subscribe by exact type or by category prefix (e.g. ``mission.*``).
"""

from __future__ import annotations

from hunterx.domain.events.enums import EventCategory, EventSeverity
from hunterx.domain.events.spec import EventRegistry, EventSpec

#: Default severity per event category, applied when a producer omits it.
_CATEGORY_SEVERITY: dict[EventCategory, EventSeverity] = {
    EventCategory.MISSION: EventSeverity.INFO,
    EventCategory.EXECUTION: EventSeverity.INFO,
    EventCategory.TOOL: EventSeverity.INFO,
    EventCategory.RECON: EventSeverity.INFO,
    EventCategory.DNS: EventSeverity.INFO,
    EventCategory.HOST: EventSeverity.INFO,
    EventCategory.TOPOLOGY: EventSeverity.INFO,
    EventCategory.TECHNOLOGY: EventSeverity.INFO,
    EventCategory.WEB: EventSeverity.INFO,
    EventCategory.JAVASCRIPT: EventSeverity.INFO,
    EventCategory.API: EventSeverity.INFO,
    EventCategory.AUTH: EventSeverity.INFO,
    EventCategory.AUTHORIZATION: EventSeverity.INFO,
    EventCategory.CLOUD: EventSeverity.INFO,
    EventCategory.VULNERABILITY: EventSeverity.WARNING,
    EventCategory.PLUGIN: EventSeverity.NOTICE,
    EventCategory.DATABASE: EventSeverity.INFO,
    EventCategory.KNOWLEDGE: EventSeverity.INFO,
    EventCategory.AI: EventSeverity.INFO,
    EventCategory.WORKFLOW: EventSeverity.INFO,
    EventCategory.SECURITY: EventSeverity.WARNING,
    EventCategory.REPORTING: EventSeverity.INFO,
    EventCategory.SYSTEM: EventSeverity.INFO,
    EventCategory.CONFIGURATION: EventSeverity.NOTICE,
    EventCategory.USER: EventSeverity.INFO,
    EventCategory.TARGET: EventSeverity.INFO,
    EventCategory.CAMPAIGN: EventSeverity.INFO,
}


def _spec(name: str, category: EventCategory, description: str, *, version: int = 1) -> EventSpec:
    return EventSpec(
        event_type=name,
        category=category,
        severity=_CATEGORY_SEVERITY[category],
        payload_version=version,
        description=description,
    )


def build_catalog() -> list[EventSpec]:
    """Return the canonical event catalog."""
    return [
        # -- mission ---------------------------------------------------------
        _spec("mission.created", EventCategory.MISSION, "A mission record was created"),
        _spec("mission.started", EventCategory.MISSION, "A mission transitioned to RUNNING"),
        _spec("mission.updated", EventCategory.MISSION, "A mission record was updated"),
        _spec("mission.completed", EventCategory.MISSION, "A mission finished successfully"),
        _spec("mission.failed", EventCategory.MISSION, "A mission failed"),
        _spec("mission.cancelled", EventCategory.MISSION, "A mission was cancelled"),
        _spec("mission.deleted", EventCategory.MISSION, "A mission was deleted"),
        # -- offensive orchestration -----------------------------------------
        _spec("mission.scoping.started", EventCategory.MISSION, "Mission scope resolution began"),
        _spec("mission.scoping.completed", EventCategory.MISSION, "Mission scope resolution completed"),
        _spec("mission.planning.started", EventCategory.MISSION, "Mission planning began"),
        _spec("mission.plan.created", EventCategory.MISSION, "An execution plan was created"),
        _spec("mission.phase.started", EventCategory.MISSION, "A mission phase began"),
        _spec("mission.phase.completed", EventCategory.MISSION, "A mission phase completed"),
        _spec("mission.step.started", EventCategory.MISSION, "A mission step began"),
        _spec("mission.step.completed", EventCategory.MISSION, "A mission step completed"),
        _spec("mission.step.failed", EventCategory.MISSION, "A mission step failed"),
        _spec("mission.step.blocked", EventCategory.MISSION, "A mission step was blocked"),
        _spec("mission.tool.selected", EventCategory.MISSION, "A tool was selected for a step"),
        _spec("mission.tool.started", EventCategory.MISSION, "A selected tool began executing"),
        _spec("mission.tool.completed", EventCategory.MISSION, "A selected tool completed executing"),
        _spec("mission.tool.failed", EventCategory.MISSION, "A selected tool failed"),
        _spec("mission.tool.fallback", EventCategory.MISSION, "A step fell back to an alternative tool"),
        _spec("mission.result.created", EventCategory.MISSION, "A canonical step result was produced"),
        _spec("mission.intelligence.updated", EventCategory.MISSION, "Mission intelligence was updated"),
        _spec("mission.replanning.started", EventCategory.MISSION, "Mission replanning began"),
        _spec("mission.replanned", EventCategory.MISSION, "The mission plan was regenerated"),
        _spec("mission.checkpoint.created", EventCategory.MISSION, "A mission checkpoint was persisted"),
        _spec("mission.resumed", EventCategory.MISSION, "A mission resumed from a checkpoint"),
        _spec("mission.blocked", EventCategory.MISSION, "A mission became blocked"),
        _spec("mission.partial", EventCategory.MISSION, "A mission completed partially with gaps"),
        _spec("mission.quality.computed", EventCategory.MISSION, "The mission quality score was computed"),
        _spec("mission.coverage.computed", EventCategory.MISSION, "The mission coverage metrics were computed"),
        # -- adaptive mission & attack-path planning (Sprint 027) ------------
        _spec("mission.plan.revised", EventCategory.MISSION, "A mission plan revision (plan delta) was applied"),
        _spec("mission.action.proposed", EventCategory.MISSION, "A candidate action was proposed by the decision engine"),
        _spec("mission.action.approved", EventCategory.MISSION, "A proposed action was approved and scheduled"),
        _spec("mission.action.started", EventCategory.MISSION, "A scheduled action began executing"),
        _spec("mission.action.completed", EventCategory.MISSION, "A scheduled action completed"),
        _spec("mission.action.failed", EventCategory.MISSION, "A scheduled action failed"),
        _spec("mission.replan.triggered", EventCategory.MISSION, "A replanning trigger was detected"),
        _spec(
            "mission.preflight.completed",
            EventCategory.MISSION,
            "The mission tool-readiness preflight completed with a verdict",
        ),
        _spec(
            "mission.tool.command",
            EventCategory.MISSION,
            "The actual (redacted) command line a mission tool executed",
        ),
        _spec("mission.path.discovered", EventCategory.MISSION, "Attack paths were discovered in the attack-surface graph"),
        _spec("mission.path.validated", EventCategory.MISSION, "An attack path advanced to a validated or proved state"),
        _spec("mission.proof.required", EventCategory.MISSION, "A proof gap was recognised and a proof action planned"),
        _spec("mission.proof.completed", EventCategory.MISSION, "A proof action completed and the finding path closed"),
        # -- execution -------------------------------------------------------
        _spec("execution.started", EventCategory.EXECUTION, "A tool execution began"),
        _spec("execution.completed", EventCategory.EXECUTION, "A tool execution completed"),
        _spec("execution.failed", EventCategory.EXECUTION, "A tool execution failed"),
        _spec("execution.timed_out", EventCategory.EXECUTION, "A tool execution exceeded its deadline"),
        _spec("execution.retried", EventCategory.EXECUTION, "A failed execution was retried"),
        _spec("output.collected", EventCategory.EXECUTION, "Tool output was captured"),
        _spec("normalization.complete", EventCategory.EXECUTION, "Tool output was normalized"),
        # -- tool ------------------------------------------------------------
        _spec("tool.registered", EventCategory.TOOL, "A tool adapter was registered"),
        _spec("tool.executed", EventCategory.TOOL, "A tool completed an execution"),
        _spec("tool.health", EventCategory.TOOL, "Tool health state changed"),
        # -- toolchain intelligence (Sprint 031) ------------------------------
        _spec("tool.execution.started", EventCategory.TOOL, "A tool execution began"),
        _spec("tool.execution.completed", EventCategory.TOOL, "A tool execution completed"),
        _spec("tool.execution.failed", EventCategory.TOOL, "A tool execution failed"),
        _spec("tool.output.received", EventCategory.TOOL, "Raw tool output was captured"),
        _spec("tool.output.parsed", EventCategory.TOOL, "Tool output was parsed into structured records"),
        _spec("tool.output.normalized", EventCategory.TOOL, "Parsed records were normalized into canonical observations"),
        _spec("tool.evidence.extracted", EventCategory.TOOL, "Evidence was extracted from a tool result"),
        _spec("tool.observation.created", EventCategory.TOOL, "A canonical observation was created"),
        _spec("tool.result.contradiction", EventCategory.TOOL, "Tools produced contradictory evidence"),
        _spec("tool.health.failed", EventCategory.TOOL, "A tool health check failed"),
        _spec("tool.version.detected", EventCategory.TOOL, "A tool version was detected"),
        _spec("tool.recommendation.created", EventCategory.TOOL, "A tool recommendation was produced"),
        # -- reconnaissance ---------------------------------------------------
        _spec("recon.started", EventCategory.RECON, "A reconnaissance run began"),
        _spec("recon.tool_completed", EventCategory.RECON, "A recon tool execution finished"),
        _spec("recon.correlated", EventCategory.RECON, "Discovery records were correlated"),
        _spec("recon.persisted", EventCategory.RECON, "Discovery records were persisted"),
        _spec("recon.completed", EventCategory.RECON, "A reconnaissance run finished"),
        _spec("recon.failed", EventCategory.RECON, "A reconnaissance run failed"),
        # -- dns intelligence -------------------------------------------------
        _spec("dns.intelligence.started", EventCategory.DNS, "A DNS intelligence run began"),
        _spec("dns.phase.started", EventCategory.DNS, "A DNS pipeline phase began"),
        _spec("dns.resolution.started", EventCategory.DNS, "A DNS resolution began"),
        _spec("dns.resolution.completed", EventCategory.DNS, "A DNS resolution completed"),
        _spec("dns.resolution.failed", EventCategory.DNS, "A DNS resolution failed"),
        _spec("dns.record.discovered", EventCategory.DNS, "A DNS record was discovered"),
        _spec("dns.conflict.detected", EventCategory.DNS, "A DNS conflict was detected"),
        _spec("dns.change.detected", EventCategory.DNS, "A DNS change was detected"),
        _spec("dns.correlation.completed", EventCategory.DNS, "DNS records were correlated"),
        _spec("dns.intelligence.completed", EventCategory.DNS, "A DNS intelligence run finished"),
        # -- live host & service discovery -----------------------------------
        _spec("host.discovery.started", EventCategory.HOST, "A live host discovery run began"),
        _spec("host.phase.started", EventCategory.HOST, "A live discovery pipeline phase began"),
        _spec("host.host.discovered", EventCategory.HOST, "A live host reachability observation was captured"),
        _spec("host.port.discovered", EventCategory.HOST, "A port state observation was captured"),
        _spec("host.service.discovered", EventCategory.HOST, "A service fingerprint observation was captured"),
        _spec("host.tls.discovered", EventCategory.HOST, "A TLS certificate observation was captured"),
        _spec("host.http.discovered", EventCategory.HOST, "An HTTP service surface observation was captured"),
        _spec("host.conflict.detected", EventCategory.HOST, "A live discovery conflict was detected"),
        _spec("host.change.detected", EventCategory.HOST, "A live state change was detected"),
        _spec("host.correlation.completed", EventCategory.HOST, "Live discovery observations were correlated"),
        _spec("host.discovery.completed", EventCategory.HOST, "A live host discovery run finished"),
        _spec("host.discovery.failed", EventCategory.HOST, "A live host discovery run failed"),
        _spec("host.tool.failed", EventCategory.HOST, "A live discovery tool execution failed"),
        # -- topology --------------------------------------------------------
        _spec("topology.build.started", EventCategory.TOPOLOGY, "A topology build run began"),
        _spec("topology.relationship.discovered", EventCategory.TOPOLOGY, "A new topology relationship was discovered"),
        _spec("topology.relationship.updated", EventCategory.TOPOLOGY, "An existing topology relationship changed"),
        _spec("topology.relationship.removed", EventCategory.TOPOLOGY, "A topology relationship was removed"),
        _spec("topology.entity.correlated", EventCategory.TOPOLOGY, "Topology entities were correlated"),
        _spec("topology.conflict.detected", EventCategory.TOPOLOGY, "A topology relationship conflict was detected"),
        _spec("topology.cluster.created", EventCategory.TOPOLOGY, "A shared-infrastructure cluster was created"),
        _spec("topology.analysis.started", EventCategory.TOPOLOGY, "Topology analysis began"),
        _spec("topology.analysis.completed", EventCategory.TOPOLOGY, "Topology analysis completed"),
        _spec("topology.build.completed", EventCategory.TOPOLOGY, "A topology build run finished"),
        _spec("topology.build.failed", EventCategory.TOPOLOGY, "A topology build run failed"),
        # -- technology fingerprinting ---------------------------------------
        _spec("technology.fingerprinting.started", EventCategory.TECHNOLOGY, "A technology fingerprinting run began"),
        _spec("technology.phase.started", EventCategory.TECHNOLOGY, "A fingerprinting pipeline phase began"),
        _spec("technology.detected", EventCategory.TECHNOLOGY, "A technology was detected on an asset"),
        _spec("technology.updated", EventCategory.TECHNOLOGY, "An existing technology observation was updated"),
        _spec("technology.version.detected", EventCategory.TECHNOLOGY, "An evidence-backed version was detected"),
        _spec("technology.version.changed", EventCategory.TECHNOLOGY, "A technology version changed between missions"),
        _spec("technology.conflict", EventCategory.TECHNOLOGY, "Conflicting technology evidence was detected"),
        _spec("technology.removed", EventCategory.TECHNOLOGY, "A technology is no longer observed on an asset"),
        _spec(
            "technology.fingerprinting.completed", EventCategory.TECHNOLOGY, "A technology fingerprinting run finished"
        ),
        _spec("technology.fingerprinting.failed", EventCategory.TECHNOLOGY, "A technology fingerprinting run failed"),
        # -- web crawling & attack-surface discovery --------------------------
        _spec("crawl.started", EventCategory.WEB, "A web crawl run began"),
        _spec("crawl.phase.started", EventCategory.WEB, "A crawl pipeline phase began"),
        _spec("crawl.url.discovered", EventCategory.WEB, "A URL observation was discovered"),
        _spec("crawl.endpoint.discovered", EventCategory.WEB, "An API endpoint was discovered"),
        _spec("crawl.websocket.discovered", EventCategory.WEB, "A WebSocket endpoint was discovered"),
        _spec("crawl.graphql.discovered", EventCategory.WEB, "A GraphQL endpoint was discovered"),
        _spec("crawl.redirect.discovered", EventCategory.WEB, "An HTTP redirect was discovered"),
        _spec("crawl.auth_boundary.discovered", EventCategory.WEB, "An authentication boundary was discovered"),
        _spec("crawl.change.detected", EventCategory.WEB, "A web-surface change was detected"),
        _spec("crawl.correlation.completed", EventCategory.WEB, "Crawl observations were correlated"),
        _spec("crawl.completed", EventCategory.WEB, "A web crawl run finished"),
        _spec("crawl.failed", EventCategory.WEB, "A web crawl run failed"),
        # -- javascript intelligence ------------------------------------------
        _spec("javascript.analysis.started", EventCategory.JAVASCRIPT, "A JavaScript intelligence run began"),
        _spec("javascript.phase.started", EventCategory.JAVASCRIPT, "A JavaScript analysis pipeline phase began"),
        _spec("javascript.asset.analysed", EventCategory.JAVASCRIPT, "A script asset was analysed"),
        _spec(
            "javascript.secret.discovered",
            EventCategory.JAVASCRIPT,
            "A potential client-side secret indicator was discovered",
        ),
        _spec("javascript.change.detected", EventCategory.JAVASCRIPT, "A client-side surface change was detected"),
        _spec(
            "javascript.correlation.completed",
            EventCategory.JAVASCRIPT,
            "JavaScript intelligence observations were correlated",
        ),
        _spec("javascript.analysis.completed", EventCategory.JAVASCRIPT, "A JavaScript intelligence run finished"),
        _spec("javascript.analysis.failed", EventCategory.JAVASCRIPT, "A JavaScript intelligence run failed"),
        # -- api intelligence --------------------------------------------------
        _spec("api.intelligence.started", EventCategory.API, "An API intelligence run began"),
        _spec("api.phase.started", EventCategory.API, "An API intelligence pipeline phase began"),
        _spec("api.host.discovered", EventCategory.API, "An API host/origin was discovered"),
        _spec("api.spec.discovered", EventCategory.API, "An API specification document was located"),
        _spec("api.api.discovered", EventCategory.API, "A canonical API version was discovered"),
        _spec("api.endpoint.discovered", EventCategory.API, "An API endpoint operation was discovered"),
        _spec("api.version.discovered", EventCategory.API, "An API version was discovered"),
        _spec("api.auth.discovered", EventCategory.API, "An authentication scheme was discovered"),
        _spec("api.authorization.discovered", EventCategory.API, "An authorization model was discovered"),
        _spec("api.rate_limit.discovered", EventCategory.API, "A rate-limit indicator was discovered"),
        _spec("api.pagination.discovered", EventCategory.API, "A pagination style was discovered"),
        _spec("api.filter.discovered", EventCategory.API, "A filter capability was discovered"),
        _spec("api.undocumented.detected", EventCategory.API, "An undocumented API surface was detected"),
        _spec("api.historical.discovered", EventCategory.API, "A historical API surface was discovered"),
        _spec("api.change.detected", EventCategory.API, "An API surface change was detected"),
        _spec("api.conflict.detected", EventCategory.API, "Conflicting API intelligence was detected"),
        _spec("api.correlation.completed", EventCategory.API, "API observations were correlated"),
        _spec("api.intelligence.completed", EventCategory.API, "An API intelligence run finished"),
        _spec("api.intelligence.failed", EventCategory.API, "An API intelligence run failed"),
        # -- authentication intelligence ---------------------------------------
        _spec("auth.discovery.started", EventCategory.AUTH, "An authentication intelligence run began"),
        _spec("auth.phase.started", EventCategory.AUTH, "An authentication intelligence pipeline phase began"),
        _spec("auth.login_surface.discovered", EventCategory.AUTH, "An authentication surface was discovered"),
        _spec("auth.endpoint.discovered", EventCategory.AUTH, "An authentication endpoint was discovered"),
        _spec("auth.identity_provider.discovered", EventCategory.AUTH, "An identity provider was discovered"),
        _spec("auth.oauth.discovered", EventCategory.AUTH, "An OAuth configuration was discovered"),
        _spec("auth.oidc.discovered", EventCategory.AUTH, "An OIDC configuration was discovered"),
        _spec("auth.saml.discovered", EventCategory.AUTH, "A SAML indicator was discovered"),
        _spec("auth.mfa.discovered", EventCategory.AUTH, "An MFA mechanism was discovered"),
        _spec("auth.session_cookie.discovered", EventCategory.AUTH, "A session cookie was discovered"),
        _spec("auth.token_storage.discovered", EventCategory.AUTH, "A token storage indicator was discovered"),
        _spec("auth.csrf.discovered", EventCategory.AUTH, "A CSRF mechanism was discovered"),
        _spec("auth.cors.discovered", EventCategory.AUTH, "A CORS configuration was discovered"),
        _spec("auth.role.discovered", EventCategory.AUTH, "A role indicator was discovered"),
        _spec("auth.permission.discovered", EventCategory.AUTH, "A permission indicator was discovered"),
        _spec("auth.tenant.discovered", EventCategory.AUTH, "A tenant indicator was discovered"),
        _spec("auth.change.detected", EventCategory.AUTH, "An authentication change was detected"),
        _spec("auth.conflict.detected", EventCategory.AUTH, "Conflicting authentication intelligence was detected"),
        _spec("auth.correlation.completed", EventCategory.AUTH, "Authentication observations were correlated"),
        _spec("auth.discovery.completed", EventCategory.AUTH, "An authentication intelligence run finished"),
        _spec("auth.discovery.failed", EventCategory.AUTH, "An authentication intelligence run failed"),
        # -- authorization & access-control intelligence ------------------------
        _spec(
            "authorization.discovery.started", EventCategory.AUTHORIZATION, "An authorization intelligence run began"
        ),
        _spec(
            "authorization.phase.started",
            EventCategory.AUTHORIZATION,
            "An authorization intelligence pipeline phase began",
        ),
        _spec(
            "authorization.subject.discovered", EventCategory.AUTHORIZATION, "An authorization subject was discovered"
        ),
        _spec("authorization.role.discovered", EventCategory.AUTHORIZATION, "A role was discovered"),
        _spec("authorization.permission.discovered", EventCategory.AUTHORIZATION, "A permission was discovered"),
        _spec("authorization.scope.discovered", EventCategory.AUTHORIZATION, "A scope was discovered"),
        _spec("authorization.policy.discovered", EventCategory.AUTHORIZATION, "A policy model was discovered"),
        _spec(
            "authorization.resource.discovered", EventCategory.AUTHORIZATION, "An authorization resource was discovered"
        ),
        _spec("authorization.action.discovered", EventCategory.AUTHORIZATION, "An authorization action was discovered"),
        _spec(
            "authorization.ownership.discovered", EventCategory.AUTHORIZATION, "An ownership indicator was discovered"
        ),
        _spec(
            "authorization.tenant.discovered",
            EventCategory.AUTHORIZATION,
            "A tenant authorization indicator was discovered",
        ),
        _spec(
            "authorization.admin_surface.discovered",
            EventCategory.AUTHORIZATION,
            "An administrative surface was discovered",
        ),
        _spec(
            "authorization.function_level.discovered",
            EventCategory.AUTHORIZATION,
            "A function-level authorization indicator was discovered",
        ),
        _spec(
            "authorization.object_level.discovered",
            EventCategory.AUTHORIZATION,
            "An object-level authorization indicator was discovered",
        ),
        _spec(
            "authorization.field_level.discovered",
            EventCategory.AUTHORIZATION,
            "A field-level authorization indicator was discovered",
        ),
        _spec(
            "authorization.frontend.discovered",
            EventCategory.AUTHORIZATION,
            "A frontend authorization indicator was discovered",
        ),
        _spec(
            "authorization.backend.discovered",
            EventCategory.AUTHORIZATION,
            "A backend authorization indicator was discovered",
        ),
        _spec(
            "authorization.api_correlation.discovered",
            EventCategory.AUTHORIZATION,
            "An API authorization correlation was discovered",
        ),
        _spec(
            "authorization.graphql.discovered",
            EventCategory.AUTHORIZATION,
            "A GraphQL authorization indicator was discovered",
        ),
        _spec(
            "authorization.websocket.discovered",
            EventCategory.AUTHORIZATION,
            "A WebSocket authorization indicator was discovered",
        ),
        _spec(
            "authorization.service.discovered",
            EventCategory.AUTHORIZATION,
            "A service-to-service authorization indicator was discovered",
        ),
        _spec(
            "authorization.decision.discovered",
            EventCategory.AUTHORIZATION,
            "An authorization decision indicator was discovered",
        ),
        _spec("authorization.change.detected", EventCategory.AUTHORIZATION, "An authorization change was detected"),
        _spec(
            "authorization.conflict.detected",
            EventCategory.AUTHORIZATION,
            "Conflicting authorization intelligence was detected",
        ),
        _spec(
            "authorization.correlation.completed",
            EventCategory.AUTHORIZATION,
            "Authorization observations were correlated",
        ),
        _spec(
            "authorization.discovery.completed",
            EventCategory.AUTHORIZATION,
            "An authorization intelligence run finished",
        ),
        _spec(
            "authorization.discovery.failed", EventCategory.AUTHORIZATION, "An authorization intelligence run failed"
        ),
        # -- cloud & saas intelligence ------------------------------------------
        _spec("cloud.intelligence.started", EventCategory.CLOUD, "A cloud intelligence run began"),
        _spec("cloud.phase.started", EventCategory.CLOUD, "A cloud intelligence pipeline phase began"),
        _spec("cloud.provider.discovered", EventCategory.CLOUD, "A cloud provider was discovered"),
        _spec(
            "cloud.account.discovered",
            EventCategory.CLOUD,
            "A cloud account/subscription/project indicator was discovered",
        ),
        _spec("cloud.region.discovered", EventCategory.CLOUD, "A cloud region was discovered"),
        _spec("cloud.resource.discovered", EventCategory.CLOUD, "A cloud resource was discovered"),
        _spec("cloud.service.discovered", EventCategory.CLOUD, "A cloud service was discovered"),
        _spec("cloud.endpoint.discovered", EventCategory.CLOUD, "A cloud endpoint was discovered"),
        _spec("cloud.storage.discovered", EventCategory.CLOUD, "A cloud storage indicator was discovered"),
        _spec("cloud.compute.discovered", EventCategory.CLOUD, "A cloud compute indicator was discovered"),
        _spec("cloud.container.discovered", EventCategory.CLOUD, "A container indicator was discovered"),
        _spec("cloud.kubernetes.discovered", EventCategory.CLOUD, "A Kubernetes indicator was discovered"),
        _spec("cloud.serverless.discovered", EventCategory.CLOUD, "A serverless indicator was discovered"),
        _spec("cloud.database.discovered", EventCategory.CLOUD, "A cloud database indicator was discovered"),
        _spec("cloud.gateway.discovered", EventCategory.CLOUD, "An API gateway was discovered"),
        _spec("cloud.cdn.discovered", EventCategory.CLOUD, "A CDN was discovered"),
        _spec("cloud.load_balancer.discovered", EventCategory.CLOUD, "A load balancer was discovered"),
        _spec("cloud.identity.discovered", EventCategory.CLOUD, "A cloud identity indicator was discovered"),
        _spec("cloud.iam.discovered", EventCategory.CLOUD, "A cloud IAM indicator was discovered"),
        _spec("cloud.environment.discovered", EventCategory.CLOUD, "A cloud environment indicator was discovered"),
        _spec("cloud.saas.discovered", EventCategory.CLOUD, "A SaaS provider was discovered"),
        _spec("cloud.saas_integration.discovered", EventCategory.CLOUD, "A SaaS integration was discovered"),
        _spec("cloud.webhook.discovered", EventCategory.CLOUD, "A webhook was discovered"),
        _spec("cloud.dependency.discovered", EventCategory.CLOUD, "A cloud/third-party dependency was discovered"),
        _spec("cloud.exposure.discovered", EventCategory.CLOUD, "A cloud exposure indicator was discovered"),
        _spec("cloud.change.detected", EventCategory.CLOUD, "A cloud architecture change was detected"),
        _spec("cloud.conflict.detected", EventCategory.CLOUD, "Conflicting cloud intelligence was detected"),
        _spec("cloud.correlation.completed", EventCategory.CLOUD, "Cloud observations were correlated"),
        _spec("cloud.intelligence.completed", EventCategory.CLOUD, "A cloud intelligence run finished"),
        _spec("cloud.intelligence.failed", EventCategory.CLOUD, "A cloud intelligence run failed"),
        # -- vulnerability knowledge & risk correlation --------------------------
        _spec(
            "vulnerability.knowledge.refresh.started",
            EventCategory.VULNERABILITY,
            "A vulnerability knowledge refresh run began",
        ),
        _spec(
            "vulnerability.knowledge.source.updated",
            EventCategory.VULNERABILITY,
            "A vulnerability knowledge source was refreshed",
        ),
        _spec(
            "vulnerability.cve.discovered",
            EventCategory.VULNERABILITY,
            "A canonical CVE was discovered/refreshed",
        ),
        _spec(
            "vulnerability.cwe.discovered",
            EventCategory.VULNERABILITY,
            "A canonical CWE was discovered/refreshed",
        ),
        _spec(
            "vulnerability.cpe.discovered",
            EventCategory.VULNERABILITY,
            "A canonical CPE was discovered",
        ),
        _spec(
            "vulnerability.advisory.discovered",
            EventCategory.VULNERABILITY,
            "A vendor advisory was discovered/refreshed",
        ),
        _spec(
            "vulnerability.match.created",
            EventCategory.VULNERABILITY,
            "A technology→vulnerability match was created",
        ),
        _spec(
            "vulnerability.match.removed",
            EventCategory.VULNERABILITY,
            "A technology→vulnerability match was removed",
        ),
        _spec(
            "vulnerability.version_match.changed",
            EventCategory.VULNERABILITY,
            "A match's version evidence changed between missions",
        ),
        _spec(
            "vulnerability.kev.changed",
            EventCategory.VULNERABILITY,
            "A CVE's KEV membership changed",
        ),
        _spec(
            "vulnerability.epss.changed",
            EventCategory.VULNERABILITY,
            "A CVE's EPSS score changed",
        ),
        _spec(
            "vulnerability.exploitability.changed",
            EventCategory.VULNERABILITY,
            "A CVE's exploitability indicator changed",
        ),
        _spec(
            "vulnerability.risk.created",
            EventCategory.VULNERABILITY,
            "A risk assessment was created",
        ),
        _spec(
            "vulnerability.risk.changed",
            EventCategory.VULNERABILITY,
            "A risk assessment changed",
        ),
        _spec(
            "vulnerability.intelligence.completed",
            EventCategory.VULNERABILITY,
            "A vulnerability intelligence run finished",
        ),
        _spec(
            "vulnerability.intelligence.failed",
            EventCategory.VULNERABILITY,
            "A vulnerability intelligence run failed",
        ),
        # -- safe vulnerability discovery & validation -------------------------
        _spec(
            "vulnerability.hypothesis.created",
            EventCategory.VULNERABILITY,
            "A vulnerability hypothesis was created",
        ),
        _spec(
            "vulnerability.validation.planned",
            EventCategory.VULNERABILITY,
            "A validation plan was created for a hypothesis",
        ),
        _spec(
            "vulnerability.validation.started",
            EventCategory.VULNERABILITY,
            "A validation execution started",
        ),
        _spec(
            "vulnerability.validation.step.started",
            EventCategory.VULNERABILITY,
            "A validation step started",
        ),
        _spec(
            "vulnerability.validation.step.completed",
            EventCategory.VULNERABILITY,
            "A validation step completed",
        ),
        _spec(
            "vulnerability.validation.blocked",
            EventCategory.VULNERABILITY,
            "A validation action was blocked by scope/safety policy",
        ),
        _spec(
            "vulnerability.validation.failed",
            EventCategory.VULNERABILITY,
            "A validation execution failed",
        ),
        _spec(
            "vulnerability.evidence.created",
            EventCategory.VULNERABILITY,
            "Validation evidence was created",
        ),
        _spec(
            "vulnerability.verdict.created",
            EventCategory.VULNERABILITY,
            "A validation verdict was produced",
        ),
        _spec(
            "vulnerability.confirmed",
            EventCategory.VULNERABILITY,
            "A vulnerability hypothesis was confirmed",
        ),
        _spec(
            "vulnerability.false_positive",
            EventCategory.VULNERABILITY,
            "A vulnerability hypothesis was refuted as a false positive",
        ),
        _spec(
            "vulnerability.inconclusive",
            EventCategory.VULNERABILITY,
            "A vulnerability hypothesis was left inconclusive",
        ),
        _spec(
            "vulnerability.resolved",
            EventCategory.VULNERABILITY,
            "A confirmed vulnerability was resolved",
        ),
        _spec(
            "vulnerability.reopened",
            EventCategory.VULNERABILITY,
            "A resolved vulnerability was reopened",
        ),
        _spec(
            "vulnerability.validation.completed",
            EventCategory.VULNERABILITY,
            "A validation execution completed",
        ),
        # -- vulnerability proof & PoC ---------------------------------------
        _spec(
            "proof.created",
            EventCategory.VULNERABILITY,
            "A vulnerability proof candidate was created",
        ),
        _spec(
            "proof.planned",
            EventCategory.VULNERABILITY,
            "A proof plan was created",
        ),
        _spec(
            "proof.started",
            EventCategory.VULNERABILITY,
            "A proof execution started",
        ),
        _spec(
            "proof.step.started",
            EventCategory.VULNERABILITY,
            "A proof step started",
        ),
        _spec(
            "proof.step.completed",
            EventCategory.VULNERABILITY,
            "A proof step completed",
        ),
        _spec(
            "proof.generated",
            EventCategory.VULNERABILITY,
            "A proof PoC was generated",
        ),
        _spec(
            "proof.executed",
            EventCategory.VULNERABILITY,
            "A proof execution completed",
        ),
        _spec(
            "proof.replay.started",
            EventCategory.VULNERABILITY,
            "A proof replay started",
        ),
        _spec(
            "proof.replay.completed",
            EventCategory.VULNERABILITY,
            "A proof replay completed",
        ),
        _spec(
            "proof.validated",
            EventCategory.VULNERABILITY,
            "A proof was validated through replay and evidence evaluation",
        ),
        _spec(
            "proof.failed",
            EventCategory.VULNERABILITY,
            "A proof failed",
        ),
        _spec(
            "proof.blocked",
            EventCategory.VULNERABILITY,
            "A proof action was blocked by scope/safety/proof policy",
        ),
        _spec(
            "proof.inconclusive",
            EventCategory.VULNERABILITY,
            "A proof was left inconclusive",
        ),
        _spec(
            "proof.invalidated",
            EventCategory.VULNERABILITY,
            "A proof was invalidated",
        ),
        _spec(
            "poc.created",
            EventCategory.VULNERABILITY,
            "A PoC artifact was created or versioned",
        ),
        _spec(
            "poc.validated",
            EventCategory.VULNERABILITY,
            "A PoC was validated through replay",
        ),
        _spec(
            "impact.assessed",
            EventCategory.VULNERABILITY,
            "An impact assessment was produced",
        ),
        _spec(
            "confidence.calculated",
            EventCategory.VULNERABILITY,
            "An evidence-driven confidence assessment was calculated",
        ),
        _spec(
            "finding.proven",
            EventCategory.VULNERABILITY,
            "A finding became PROVEN",
        ),
        _spec(
            "finding.confirmed",
            EventCategory.VULNERABILITY,
            "A finding became CONFIRMED",
        ),
        _spec(
            "finding.report_ready",
            EventCategory.VULNERABILITY,
            "A finding became REPORT_READY",
        ),
        # -- finding orchestration (Sprint 028) ------------------------------
        _spec(
            "finding.created",
            EventCategory.VULNERABILITY,
            "An orchestrated finding was created as a candidate",
        ),
        _spec(
            "finding.supported",
            EventCategory.VULNERABILITY,
            "A finding gained hypothesis-supporting evidence",
        ),
        _spec(
            "finding.validation.started",
            EventCategory.VULNERABILITY,
            "Finding validation started",
        ),
        _spec(
            "finding.validation.completed",
            EventCategory.VULNERABILITY,
            "Finding validation completed with a verdict",
        ),
        _spec(
            "finding.evidence.added",
            EventCategory.VULNERABILITY,
            "Evidence was added to a finding",
        ),
        _spec(
            "finding.evidence.conflict",
            EventCategory.VULNERABILITY,
            "Contradictory evidence was detected",
        ),
        _spec(
            "finding.proof.required",
            EventCategory.VULNERABILITY,
            "A validated finding requires proof",
        ),
        _spec(
            "finding.proof.started",
            EventCategory.VULNERABILITY,
            "Finding proof generation started",
        ),
        _spec(
            "finding.proof.replayed",
            EventCategory.VULNERABILITY,
            "A PoC was replayed under controlled conditions",
        ),
        _spec(
            "finding.proof.validated",
            EventCategory.VULNERABILITY,
            "A finding proof was validated",
        ),
        _spec(
            "finding.impact.assessed",
            EventCategory.VULNERABILITY,
            "An evidence-backed impact assessment was produced",
        ),
        _spec(
            "finding.confidence.updated",
            EventCategory.VULNERABILITY,
            "The evidence-driven confidence was updated",
        ),
        _spec(
            "finding.duplicate.detected",
            EventCategory.VULNERABILITY,
            "A finding was correlated as a duplicate",
        ),
        _spec(
            "finding.disproved",
            EventCategory.VULNERABILITY,
            "A finding was disproved by contradictory evidence",
        ),
        # -- proof strategy library & validation ------------------------------
        _spec(
            "proof.strategy.selected",
            EventCategory.VULNERABILITY,
            "A proof strategy was selected for a vulnerability candidate",
        ),
        _spec(
            "proof.strategy.blocked",
            EventCategory.VULNERABILITY,
            "No usable proof strategy could be selected",
        ),
        _spec(
            "proof.strategy.missing_evidence",
            EventCategory.VULNERABILITY,
            "A strategy needs evidence that is not yet available",
        ),
        _spec(
            "proof.validation.started",
            EventCategory.VULNERABILITY,
            "A proof validation began",
        ),
        _spec(
            "proof.validation.completed",
            EventCategory.VULNERABILITY,
            "A proof validation completed with a verdict",
        ),
        _spec(
            "proof.validation.failed",
            EventCategory.VULNERABILITY,
            "A proof validation failed",
        ),
        _spec(
            "proof.validation.inconclusive",
            EventCategory.VULNERABILITY,
            "A proof validation was inconclusive",
        ),
        _spec(
            "proof.validation.contradicted",
            EventCategory.VULNERABILITY,
            "A proof validation found contradictory evidence",
        ),
        _spec(
            "proof.manual_required",
            EventCategory.VULNERABILITY,
            "Automation cannot safely establish proof; manual validation required",
        ),
        _spec(
            "proof.strategy.candidate_created",
            EventCategory.VULNERABILITY,
            "A novel strategy candidate was proposed",
        ),
        _spec(
            "proof.strategy.approved",
            EventCategory.VULNERABILITY,
            "A strategy candidate was approved",
        ),
        _spec(
            "proof.strategy.rejected",
            EventCategory.VULNERABILITY,
            "A strategy candidate was rejected",
        ),
        # -- plugin ----------------------------------------------------------
        _spec("plugin.loaded", EventCategory.PLUGIN, "A plugin was loaded"),
        _spec("plugin.unloaded", EventCategory.PLUGIN, "A plugin was unloaded"),
        _spec("plugin.activated", EventCategory.PLUGIN, "A plugin was activated"),
        _spec("plugin.deactivated", EventCategory.PLUGIN, "A plugin was deactivated"),
        # -- database --------------------------------------------------------
        _spec("database.updated", EventCategory.DATABASE, "A database record changed"),
        _spec("database.connected", EventCategory.DATABASE, "Database connection established"),
        _spec("database.disconnected", EventCategory.DATABASE, "Database connection closed"),
        # -- knowledge -------------------------------------------------------
        _spec("knowledge.recorded", EventCategory.KNOWLEDGE, "A knowledge record was stored"),
        _spec("knowledge.queried", EventCategory.KNOWLEDGE, "A knowledge query completed"),
        _spec("knowledge.linked", EventCategory.KNOWLEDGE, "Knowledge entities were linked"),
        # -- ai --------------------------------------------------------------
        _spec("ai.completed", EventCategory.AI, "An AI completion returned"),
        _spec("ai.embedding", EventCategory.AI, "An embedding was computed"),
        _spec("ai.failed", EventCategory.AI, "An AI call failed"),
        # -- workflow --------------------------------------------------------
        _spec("workflow.started", EventCategory.WORKFLOW, "A workflow execution began"),
        _spec("workflow.step_completed", EventCategory.WORKFLOW, "A workflow step completed"),
        _spec("workflow.completed", EventCategory.WORKFLOW, "A workflow finished"),
        _spec("workflow.failed", EventCategory.WORKFLOW, "A workflow failed"),
        # -- security --------------------------------------------------------
        _spec("security.authenticated", EventCategory.SECURITY, "An authentication succeeded"),
        _spec("security.authorized", EventCategory.SECURITY, "An authorization decision was made"),
        _spec("security.denied", EventCategory.SECURITY, "An access attempt was denied"),
        _spec("security.violation", EventCategory.SECURITY, "A security policy violation occurred"),
        # -- reporting -------------------------------------------------------
        _spec("reporting.generated", EventCategory.REPORTING, "A report was generated"),
        _spec("reporting.rendered", EventCategory.REPORTING, "A report was rendered"),
        _spec("reporting.failed", EventCategory.REPORTING, "Report generation failed"),
        # -- professional reporting (Sprint 029) -----------------------------
        _spec("report.created", EventCategory.REPORTING, "A professional report was created"),
        _spec("report.updated", EventCategory.REPORTING, "A professional report transitioned state"),
        _spec("report.qa.started", EventCategory.REPORTING, "Professional report QA began"),
        _spec("report.qa.passed", EventCategory.REPORTING, "Professional report QA passed"),
        _spec("report.qa.failed", EventCategory.REPORTING, "Professional report QA found blocking defects"),
        _spec("report.generated", EventCategory.REPORTING, "A professional report version was generated"),
        _spec("report.exported", EventCategory.REPORTING, "A professional report was exported"),
        _spec("report.submission_ready", EventCategory.REPORTING, "A professional report became READY_FOR_SUBMISSION"),
        _spec("report.retest.started", EventCategory.REPORTING, "A professional report retest began"),
        _spec("report.retest.completed", EventCategory.REPORTING, "A professional report retest completed"),
        _spec("report.closed", EventCategory.REPORTING, "A professional report was closed"),
        _spec("report.reopened", EventCategory.REPORTING, "A professional report was reopened"),
        # -- target memory & campaign intelligence (Sprint 030) --------------
        _spec("target.memory.updated", EventCategory.TARGET, "Target memory observations were recorded"),
        _spec("target.snapshot.created", EventCategory.TARGET, "A reproducible target snapshot was created"),
        _spec("target.diff.created", EventCategory.TARGET, "A deterministic snapshot diff was created"),
        _spec("target.change.detected", EventCategory.TARGET, "A significant target change was detected"),
        _spec("target.observation.stale", EventCategory.TARGET, "A target observation became stale"),
        _spec("target.revalidation.required", EventCategory.TARGET, "Target observations require revalidation"),
        _spec("coverage.updated", EventCategory.TARGET, "Target coverage memory was updated"),
        _spec("coverage.gap.detected", EventCategory.TARGET, "A coverage gap was detected"),
        _spec("campaign.created", EventCategory.CAMPAIGN, "A campaign was created"),
        _spec("campaign.updated", EventCategory.CAMPAIGN, "A campaign was updated"),
        _spec("campaign.completed", EventCategory.CAMPAIGN, "A campaign was completed"),
        _spec("hypothesis.recorded", EventCategory.VULNERABILITY, "A hypothesis memory record was recorded"),
        _spec("hypothesis.failed", EventCategory.VULNERABILITY, "A hypothesis failed validation"),
        _spec("hypothesis.succeeded", EventCategory.VULNERABILITY, "A hypothesis was validated/proven"),
        _spec("risk.changed", EventCategory.VULNERABILITY, "Target risk changed"),
        _spec("finding.recurred", EventCategory.VULNERABILITY, "A previously remediated finding recurred"),
        # -- system ----------------------------------------------------------
        _spec("system.started", EventCategory.SYSTEM, "A platform component started"),
        _spec("system.stopped", EventCategory.SYSTEM, "A platform component stopped"),
        _spec("system.health", EventCategory.SYSTEM, "A health check result was produced"),
        _spec("system.error", EventCategory.SYSTEM, "An unclassified system error occurred"),
        # -- configuration ---------------------------------------------------
        _spec("configuration.updated", EventCategory.CONFIGURATION, "Configuration changed"),
        _spec("configuration.reloaded", EventCategory.CONFIGURATION, "Configuration was reloaded"),
        _spec("configuration.invalid", EventCategory.CONFIGURATION, "Configuration failed validation"),
        # -- user ------------------------------------------------------------
        _spec("user.login", EventCategory.USER, "A user logged in"),
        _spec("user.logout", EventCategory.USER, "A user logged out"),
        _spec("user.created", EventCategory.USER, "A user account was created"),
        _spec("user.updated", EventCategory.USER, "A user account was updated"),
    ]


def build_registry() -> EventRegistry:
    """Build and populate a canonical :class:`EventRegistry`."""
    registry = EventRegistry()
    registry.register_many(build_catalog())
    return registry
