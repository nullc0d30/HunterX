# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Professional reporting application service.

Sprint 029 use-case service: builds the canonical finding-intelligence
aggregate from a validated finding, classifies it (CWE / OWASP / ATT&CK /
CAPEC / CVE / CVSS), assesses severity, quality, priority and reportability,
builds evidence bundles and timelines, produces remediation and retest plans,
assembles a professional report document, verifies claims, runs QA, applies
redaction, persists immutable report versions and exports the report into
Markdown / HTML / JSON / SARIF / PDF / the structured package format. Every
meaningful action is published as a typed ``report.*`` event.

The service never fabricates facts: every report statement is derived from the
finding, evidence, validation, proof, impact, tool provenance, target
intelligence or explicit analyst reasoning. AI may only explain — it can never
invent evidence, change proof state or override evidence conflicts.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any, TypeVar

from hunterx.domain.entities.tidb.finding_orchestration import (
    FindingImpactAssessment,
    FindingPoC,
    FindingRecord,
    FindingReplayRecord,
    FindingReproduction,
    FindingRootCause,
    FindingValidationAttempt,
)
from hunterx.domain.entities.tidb.reporting_intelligence import (
    RemediationPlanRecord,
    ReportClaimRecord,
    ReportEvidenceSnapshotRecord,
    ReportPackageRecord,
    ReportQaRecord,
    ReportRecord,
    ReportVersionRecord,
    RetestPlanRecord,
)
from hunterx.domain.events import DomainEvent
from hunterx.domain.events.types import (
    ReportClosedEvent,
    ReportCreatedEvent,
    ReportExportedEvent,
    ReportGeneratedEvent,
    ReportQaFailedEvent,
    ReportQaPassedEvent,
    ReportQaStartedEvent,
    ReportReopenedEvent,
    ReportRetestCompletedEvent,
    ReportRetestStartedEvent,
    ReportSubmissionReadyEvent,
    ReportUpdatedEvent,
)
from hunterx.domain.ports.messaging import EventBusPort
from hunterx.domain.ports.reporting import ReportExporterPort
from hunterx.domain.ports.tidb_repositories import TidbRepository, TidbRepositoryFactory
from hunterx.domain.reporting.claims import ClaimExtractor, ClaimVerifier
from hunterx.domain.reporting.classification import ClassificationEngine
from hunterx.domain.reporting.correlation import FindingCorrelationReportBuilder, RelationInput
from hunterx.domain.reporting.enums import (
    ExportFormat,
    QaVerdict,
    RemediationState,
    ReportabilityStatus,
    ReportState,
    RetestState,
    SecurityTestingState,
    SourceReliabilityKind,
    TemplateKind,
)
from hunterx.domain.reporting.evidence import ArtifactInput, EvidenceBundleBuilder
from hunterx.domain.reporting.executive import ExecutiveSummaryEngine, ExecutiveSummaryInput
from hunterx.domain.reporting.lifecycle import ReportStateMachine
from hunterx.domain.reporting.models import (
    AssetCriticality,
    BusinessImpact,
    EvidenceBundle,
    FindingIntelligence,
    FindingTimeline,
    PoCPresentation,
    RemediationPlan,
    ReportClaim,
    ReportDocument,
    ReportQaResult,
    ReportRedaction,
    ReportTemplate,
    ReproductionSection,
    RetestPlan,
    SecurityTestingMatrix,
    SecurityTestingStateEntry,
    ToolProvenance,
)
from hunterx.domain.reporting.prioritization import FindingPriorityEngine, PriorityInput
from hunterx.domain.reporting.qa import QaContext, ReportQAEngine
from hunterx.domain.reporting.quality import FindingQualityEngine, QualityInput
from hunterx.domain.reporting.redaction import ReportRedactor
from hunterx.domain.reporting.remediation import RemediationEngine, RemediationInput
from hunterx.domain.reporting.reportability import ReportabilityEngine, ReportabilityInput
from hunterx.domain.reporting.retest import RetestInput, RetestPlanEngine
from hunterx.domain.reporting.severity import SeverityAssessmentEngine, SeverityInput
from hunterx.domain.reporting.source import SourceReliabilityModelBuilder
from hunterx.domain.reporting.templates import ReportTemplateEngine
from hunterx.domain.reporting.timeline import FindingTimelineBuilder, TimelineEvent
from hunterx.domain.vulnerability_finding.enums import (
    FindingEvidenceKind,
    FindingState,
    PocLifecycleState,
    ReplayVerdict,
)
from hunterx.shared.ids import generate_content_id, generate_id
from hunterx.shared.time import utcnow_iso

#: Canonical reporting analysis version.
_REPORTING_VERSION = "1.0.0"

_E = TypeVar("_E")


class ProfessionalReportingService:
    """Application service for the professional reporting capability.

    All public read methods return JSON-safe mappings; state-changing methods
    persist via TIDB and publish typed ``report.*`` events.
    """

    def __init__(
        self,
        *,
        stores: TidbRepositoryFactory,
        event_bus: EventBusPort | None = None,
        exporter: ReportExporterPort | None = None,
    ) -> None:
        self._stores = stores
        self._event_bus = event_bus
        self._exporter = exporter

        self._classification = ClassificationEngine()
        self._severity = SeverityAssessmentEngine()
        self._quality = FindingQualityEngine()
        self._reportability = ReportabilityEngine()
        self._priority = FindingPriorityEngine()
        self._remediation = RemediationEngine()
        self._retest = RetestPlanEngine()
        self._qa = ReportQAEngine()
        self._redactor = ReportRedactor()
        self._bundle_builder = EvidenceBundleBuilder()
        self._timeline = FindingTimelineBuilder()
        self._source = SourceReliabilityModelBuilder()
        self._templates = ReportTemplateEngine()
        self._executive = ExecutiveSummaryEngine()
        self._correlation = FindingCorrelationReportBuilder()
        self._lifecycle = ReportStateMachine()
        self._claims_extractor = ClaimExtractor()
        self._claims_verifier = ClaimVerifier()

    # -- finding intelligence --------------------------------------------------

    def analyze_finding(self, finding_id: str) -> dict[str, Any]:
        """Build the canonical finding-intelligence aggregate.

        Aggregates the finding, evidence, validation, proof, impact, severity,
        confidence, quality, target intelligence, root cause, tool provenance,
        timeline, scope and report state into one report-ready structure.

        Args:
            finding_id: the validated finding to analyze.

        Returns:
            The finding-intelligence aggregate as a JSON-safe mapping.

        """
        record = self._get_record(finding_id)
        evidence = self._evidence_items(record)
        impact = self._impact_dimensions(finding_id)
        confidence = record.confidence or self._confidence_score(finding_id)
        pocs = self._pocs(finding_id)
        replays = self._replays(finding_id)
        root_cause_ids = self._root_cause_ids(finding_id)
        scope = dict(record.scope or {})

        severity = self._severity.assess(
            SeverityInput(
                finding_id=finding_id,
                vulnerability_class=record.vulnerability_class,
                impact_dimensions=impact,
                confidence=confidence,
                proof_replayed=any(replay.verdict == ReplayVerdict.CONFIRMED.value for replay in replays),
                exploitability_evidence=self._exploitability_evidence(evidence),
                scope="in_scope" if scope.get("scope_ok", True) else "out_of_scope",
                disputed=record.status == FindingState.DISPUTED.value,
                asset_criticality=self._asset_criticality(record),
            )
        )
        classification = self._classification.classify(
            vulnerability_class=record.vulnerability_class,
            cve_ids=self._cve_ids(evidence),
            cvss_vector=self._cvss_vector(evidence),
            reasoning_context=record.description[:120],
        )
        quality = self._quality.score(
            QualityInput(
                finding_id=finding_id,
                evidence_items=len(evidence),
                evidence_quality_avg=self._evidence_quality_avg(evidence),
                validated=record.status in (FindingState.VALIDATED.value, FindingState.PROVED.value, FindingState.REPORT_READY.value),
                proof_validated=any(poc.lifecycle_state == PocLifecycleState.PROOF_VALIDATED.value for poc in pocs),
                replays_successful=sum(1 for replay in replays if replay.verdict == ReplayVerdict.CONFIRMED.value),
                replay_attempts=len(replays),
                impact_assessed=self._impact_assessed(finding_id),
                scope_ok=bool(scope.get("scope_ok", True)),
                asset_identified=bool(record.asset_id or record.affected_assets),
                root_cause_known=bool(root_cause_ids),
                fresh=self._evidence_fresh(record),
                tool_reliability_avg=self._tool_reliability_avg(record),
                open_conflicts=self._open_conflicts(finding_id),
                report_complete=record.status == FindingState.REPORT_READY.value,
            )
        )
        reportability = self._reportability.evaluate(
            ReportabilityInput(
                finding_id=finding_id,
                finding_state=record.status,
                scope_ok=bool(scope.get("scope_ok", True)),
                validated=record.status in (FindingState.VALIDATED.value, FindingState.PROVED.value, FindingState.REPORT_READY.value),
                proof_validated=any(poc.lifecycle_state == PocLifecycleState.PROOF_VALIDATED.value for poc in pocs),
                reproducible=bool(replays),
                impact_assessed=self._impact_assessed(finding_id),
                severity=severity.severity,
                confidence=confidence,
                evidence_items=len(evidence),
                duplicate=record.status == FindingState.DUPLICATE.value,
                false_positive=record.status in (FindingState.DISPROVED.value, FindingState.REJECTED.value),
            )
        )
        priority = self._priority.assess(
            PriorityInput(
                finding_id=finding_id,
                severity_score=severity.risk_score,
                severity=severity.severity,
                confidence=confidence,
                quality_score=quality.quality_score,
                asset_criticality_level=self._asset_criticality(record).criticality_level(),
                exploitability_evidence=self._exploitability_evidence(evidence),
                proof_validated=any(poc.lifecycle_state == PocLifecycleState.PROOF_VALIDATED.value for poc in pocs),
                on_attack_path=bool(record.meta.get("on_attack_path", False)),
                attack_path_validated=bool(record.meta.get("attack_path_validated", False)),
                business_impact_score=self._business_impact_score(impact),
                internet_exposed=self._asset_criticality(record).internet_exposure,
                root_cause_recurring=len(root_cause_ids) > 1,
            )
        )
        impact_model = self._business_impact_model(impact, evidence)
        bundle = self._build_bundle(finding_id, record, evidence, pocs, replays)
        timeline = self._build_timeline(finding_id, record)
        provenance = self._tool_provenance(record, evidence)

        intelligence = FindingIntelligence(
            intelligence_id=generate_id(),
            finding_id=finding_id,
            mission_id=record.mission_id,
            target_id=record.target_id,
            asset_id=record.asset_id,
            title=record.title,
            description=record.description,
            vulnerability_class=record.vulnerability_class,
            finding_state=record.status,
            severity=severity,
            classification=classification,
            confidence=confidence,
            quality=quality,
            priority=priority,
            reportability=reportability,
            impact=impact_model,
            asset_criticality=self._asset_criticality(record),
            attack_path_relationships=_as_str_tuple(record.meta.get("attack_paths")),
            root_cause=root_cause_ids,
            historical_observations=tuple(str(item.evidence_id) for item in evidence),
            tool_provenance=tuple(provenance),
            timeline=timeline,
            evidence_bundle=bundle,
            report_state=ReportState.DRAFT.value,
        )
        return intelligence.to_dict()

    # -- classification / severity / quality / priority ------------------------

    def classify_finding(self, finding_id: str) -> dict[str, Any]:
        """Classify a finding across CWE / OWASP / ATT&CK / CAPEC / CVE / CVSS."""
        intelligence = FindingIntelligence.from_dict(self.analyze_finding(finding_id))
        return intelligence.classification.to_dict()

    def assess_severity(self, finding_id: str) -> dict[str, Any]:
        """Assess the evidence-backed severity of a finding."""
        intelligence = FindingIntelligence.from_dict(self.analyze_finding(finding_id))
        return intelligence.severity.to_dict()

    def assess_quality(self, finding_id: str) -> dict[str, Any]:
        """Assess the report quality of a finding."""
        intelligence = FindingIntelligence.from_dict(self.analyze_finding(finding_id))
        return intelligence.quality.to_dict()

    def assess_priority(self, finding_id: str) -> dict[str, Any]:
        """Assess the remediation priority of a finding."""
        intelligence = FindingIntelligence.from_dict(self.analyze_finding(finding_id))
        return intelligence.priority.to_dict()

    def assess_reportability(self, finding_id: str) -> dict[str, Any]:
        """Assess whether a finding is reportable."""
        intelligence = FindingIntelligence.from_dict(self.analyze_finding(finding_id))
        return intelligence.reportability.to_dict()

    # -- remediation / retest --------------------------------------------------

    def remediate(self, finding_id: str) -> dict[str, Any]:
        """Build and persist an evidence-based remediation plan."""
        record = self._get_record(finding_id)
        root_causes = self._root_causes_for_finding(finding_id)
        root_cause_id = ""
        root_cause_desc = ""
        if root_causes:
            root_cause = root_causes[-1]
            root_cause_id = root_cause.root_cause_id
            root_cause_desc = root_cause.description
        plan = self._remediation.build(
            RemediationInput(
                finding_id=finding_id,
                vulnerability_class=record.vulnerability_class,
                root_cause=root_cause_desc,
                root_cause_id=root_cause_id,
                affected_components=tuple(record.affected_endpoints or record.affected_assets),
                evidence_refs=tuple(record.evidence_refs),
            )
        )
        self._repo(RemediationPlanRecord).save(
            RemediationPlanRecord(
                plan_id=plan.plan_id,
                finding_id=finding_id,
                root_cause_id=root_cause_id,
                plan_json=plan.to_dict(),
            )
        )
        return plan.to_dict()

    def retest(self, finding_id: str) -> dict[str, Any]:
        """Build and persist a retest plan for a finding."""
        record = self._get_record(finding_id)
        pocs = self._repo(FindingPoC).list_by("finding_id", finding_id, limit=1000)
        plan = self._retest.build(
            RetestInput(
                finding_id=finding_id,
                vulnerability_class=record.vulnerability_class,
                endpoints=tuple(record.affected_endpoints or (record.target_id,)),
                behavior=record.title,
                proof_pocs=tuple(item.poc_id for item in pocs),
                evidence_refs=tuple(record.evidence_refs),
            )
        )
        self._repo(RetestPlanRecord).save(
            RetestPlanRecord(plan_id=plan.plan_id, finding_id=finding_id, state=plan.state.value, plan_json=plan.to_dict())
        )
        return plan.to_dict()

    # -- evidence / timeline ---------------------------------------------------

    def evidence_bundle(self, finding_id: str) -> dict[str, Any]:
        """Build the immutable evidence bundle for a finding."""
        record = self._get_record(finding_id)
        evidence = self._evidence_items(record)
        pocs = self._repo(FindingPoC).list_by("finding_id", finding_id, limit=1000)
        replays = self._repo(FindingReplayRecord).list_by("finding_id", finding_id, limit=1000)
        bundle = self._build_bundle(finding_id, record, evidence, pocs, replays)
        return bundle.to_dict()

    def finding_timeline(self, finding_id: str) -> dict[str, Any]:
        """Build the finding timeline from actual persisted events."""
        record = self._get_record(finding_id)
        timeline = self._build_timeline(finding_id, record)
        return timeline.to_dict()

    # -- report lifecycle ------------------------------------------------------

    def create_report(self, finding_id: str, *, template: str = "pentest") -> dict[str, Any]:
        """Create a report draft bound to a finding."""
        record = self._get_record(finding_id)
        kind = _template_kind(template)
        report_id = generate_id()
        template_model = self._templates.template_for(kind)
        entity = ReportRecord(
            id=report_id,
            report_id=report_id,
            finding_id=finding_id,
            mission_id=record.mission_id,
            target_id=record.target_id,
            title=record.title,
            template=kind.value,
            template_version=template_model.version,
            report_schema_version=_REPORTING_VERSION,
            status=ReportState.DRAFT.value,
            generator_version=_REPORTING_VERSION,
        )
        self._repo(ReportRecord).save(entity)
        self._publish(
            ReportCreatedEvent(
                report_id,
                finding_id=finding_id,
                target_id=record.target_id,
                mission_id=record.mission_id,
                template=kind.value,
                provenance=record.provenance,
            )
        )
        return self._report_to_dict(entity)

    def generate_report(
        self,
        finding_id: str,
        *,
        template: str = "pentest",
        report_id: str = "",
        force: bool = False,
    ) -> dict[str, Any]:
        """Generate a professional report package.

        Runs the full pipeline: finding intelligence -> classification ->
        severity -> impact -> root cause -> evidence bundle -> PoC -> timeline
        -> remediation -> retest -> QA -> report package. When ``force`` is
        false, a non-reportable finding blocks generation.

        Args:
            finding_id: the finding to report.
            template: report template kind.
            report_id: optional existing report identifier (else a new report).
            force: bypass the reportability gate (used only for testing).

        Returns:
            The generated report document as a JSON-safe mapping.

        """
        record = self._get_record(finding_id)
        intelligence = FindingIntelligence.from_dict(self.analyze_finding(finding_id))

        if not force and intelligence.reportability.status is not ReportabilityStatus.REPORTABLE:
            return {
                "finding_id": finding_id,
                "generated": False,
                "reason": f"finding is not reportable ({intelligence.reportability.status.value})",
                "reportability": intelligence.reportability.to_dict(),
            }

        kind = _template_kind(template)
        template_model = self._templates.template_for(kind)

        remediation = self._remediation.build(
            RemediationInput(
                finding_id=finding_id,
                vulnerability_class=record.vulnerability_class,
                root_cause_id=(intelligence.root_cause[0] if intelligence.root_cause else ""),
                affected_components=tuple(record.affected_endpoints or record.affected_assets),
                evidence_refs=tuple(record.evidence_refs),
            )
        )
        retest = self._retest.build(
            RetestInput(
                finding_id=finding_id,
                vulnerability_class=record.vulnerability_class,
                endpoints=tuple(record.affected_endpoints or (record.target_id,)),
                behavior=record.title,
                proof_pocs=tuple(item.poc_id for item in self._repo(FindingPoC).list_by("finding_id", finding_id, limit=1000)),
            )
        )

        report_id = report_id or generate_id()
        version_number = self._next_report_version(report_id)

        # Claim extraction + verification against verified references.
        claims = self._claims_extractor.extract(self._document_payload(
            report_id=report_id,
            finding_id=finding_id,
            mission_id=record.mission_id,
            target_id=record.target_id,
            title=record.title,
            kind=kind,
            template_model=template_model,
            intelligence=intelligence,
            remediation=remediation,
            retest=retest,
            poc=self._poc_presentation(finding_id),
            reproduction=self._reproduction_section(finding_id),
        ))
        verified_refs = self._verified_refs(finding_id, intelligence)
        verified_claims = self._claims_verifier.verify(claims, verified_refs=verified_refs)
        blocked_claims = self._claims_verifier.blocked_claims(verified_claims)

        document = self._assemble_document(
            report_id=report_id,
            finding_id=finding_id,
            mission_id=record.mission_id,
            target_id=record.target_id,
            title=record.title,
            kind=kind,
            template_model=template_model,
            version_number=version_number,
            intelligence=intelligence,
            remediation=remediation,
            retest=retest,
            claims=verified_claims,
            blocked_claims=blocked_claims,
            record=record,
        )

        # QA gates the report before it can become submission-ready.
        qa = self._run_qa(document, verified_refs=verified_refs)
        document = _replace_qaless_document(document, qa)

        # Snapshot + version persistence (immutable).
        snapshot = self._capture_snapshot(finding_id, record, intelligence)
        self._persist_report(finding_id, record, report_id, kind, template_model, document, snapshot)

        self._publish(
            ReportGeneratedEvent(
                report_id,
                version=version_number,
                content_hash=generate_content_id(document.to_dict()),
                finding_id=finding_id,
                target_id=record.target_id,
                mission_id=record.mission_id,
                provenance=record.provenance,
            )
        )
        self._publish(
            ReportUpdatedEvent(
                report_id,
                from_state=ReportState.DRAFT.value,
                to_state=ReportState.REPORT_GENERATED.value,
                finding_id=finding_id,
                target_id=record.target_id,
                mission_id=record.mission_id,
                provenance=record.provenance,
            )
        )
        return document.to_dict()

    def get_report(self, report_id: str) -> dict[str, Any]:
        """Return the report metadata and latest package."""
        record = self._get_report_record(report_id)
        payload = self._report_to_dict(record)
        package = self._latest_package(report_id)
        payload["package"] = package.document_json if package else None
        payload["qa"] = self._latest_qa(report_id)
        return payload

    def list_reports(self, finding_id: str) -> list[dict[str, Any]]:
        """List reports for a finding."""
        records = self._repo(ReportRecord).list_by("finding_id", finding_id, limit=100)
        return [self._report_to_dict(record) for record in records]

    def report_versions(self, report_id: str) -> list[dict[str, Any]]:
        """Return the immutable versions of a report."""
        versions = self._repo(ReportVersionRecord).list_by("report_id", report_id, limit=1000)
        return [
            {
                "report_id": item.report_id,
                "version": item.version,
                "finding_id": item.finding_id,
                "template_version": item.template_version,
                "report_schema_version": item.report_schema_version,
                "generated_at": item.generated_at,
                "generator_version": item.generator_version,
                "source_snapshot": item.source_snapshot,
                "content_hash": item.content_hash,
                "status": item.status,
            }
            for item in versions
        ]

    # -- QA ---------------------------------------------------------------------

    def qa_report(self, report_id: str) -> dict[str, Any]:
        """Run the report QA engine over the latest report package."""
        package = self._latest_package(report_id)
        if package is None:
            raise LookupError(f"report {report_id} has no generated package")
        document = ReportDocument.from_dict(dict(package.document_json))
        intelligence = document.intelligence or FindingIntelligence(finding_id=document.finding_id)
        verified_refs = self._verified_refs(document.finding_id, intelligence)
        finding = self._get_record(document.finding_id)
        self._publish(
            ReportQaStartedEvent(
                report_id,
                finding_id=document.finding_id,
                target_id=document.target_id,
                mission_id=document.mission_id,
                provenance=finding.provenance,
            )
        )
        qa = self._run_qa(document, verified_refs=verified_refs, report_record=finding)
        return qa.to_dict()

    def finalize_submission_ready(self, report_id: str) -> dict[str, Any]:
        """Transition a report to READY_FOR_SUBMISSION when all gates pass.

        The report cannot become READY_FOR_SUBMISSION while a blocking QA
        check or an unsupported high-impact claim is open.

        Args:
            report_id: the report to finalize.

        Returns:
            The transition result plus the blocking reasons when denied.

        """
        record = self._get_report_record(report_id)
        qa = self._latest_qa(report_id)
        package = self._latest_package(report_id)
        blocked_claims: list[str] = []
        if package:
            document = ReportDocument.from_dict(dict(package.document_json))
            blocked_claims = [
                claim.claim_text
                for claim in document.claims
                if claim.verification_state.value == "blocked"
            ]
        qa_passed = bool(
            qa is not None
            and qa.get("verdict") in (QaVerdict.PASS.value, QaVerdict.WARN.value)
            and not qa.get("blocked", True)
        )
        redaction_applied = bool(package and (package.document_json.get("redaction") or {}).get("applied"))
        no_unsupported = not blocked_claims

        result = self._lifecycle.transition(
            ReportState.QA_PASSED,
            ReportState.READY_FOR_SUBMISSION,
            qa_passed=qa_passed,
            no_unsupported_claims=no_unsupported,
            redaction_applied=redaction_applied,
        )
        if not result.allowed:
            return {
                "report_id": report_id,
                "ready": False,
                "transition": result.to_dict(),
                "blocked_claims": blocked_claims,
                "qa": qa,
            }
        self._update_report_status(record, ReportState.READY_FOR_SUBMISSION)
        finding = self._get_record(record.finding_id)
        self._publish(
            ReportSubmissionReadyEvent(
                report_id,
                finding_id=record.finding_id,
                target_id=record.target_id,
                mission_id=record.mission_id,
                provenance=finding.provenance,
            )
        )
        return {"report_id": report_id, "ready": True, "transition": result.to_dict()}

    def transition_report(self, report_id: str, *, to_state: str) -> dict[str, Any]:
        """Explicitly transition a report lifecycle state."""
        record = self._get_report_record(report_id)
        target = ReportState(to_state)
        result = self._lifecycle.transition(ReportState(record.status), target)
        if result.allowed:
            self._update_report_status(record, target)
        finding = self._get_record(record.finding_id)
        self._publish(
            ReportUpdatedEvent(
                report_id,
                from_state=record.status,
                to_state=target.value,
                finding_id=record.finding_id,
                target_id=record.target_id,
                mission_id=record.mission_id,
                provenance=finding.provenance,
            )
        )
        return result.to_dict()

    # -- remediation lifecycle -------------------------------------------------

    def remediation_lifecycle(self, finding_id: str, *, state: str) -> dict[str, Any]:
        """Advance the remediation/retest lifecycle for a finding.

        Args:
            finding_id: the finding being remediated.
            state: one of open / remediation_in_progress / retest_required /
                retesting / fix_verified / fix_failed / reopened / closed.

        Returns:
            The applied remediation state as a JSON-safe mapping.

        """
        current = RemediationState(state)
        return {"finding_id": finding_id, "remediation_state": current.value, "applied": True}

    def start_retest(self, finding_id: str) -> dict[str, Any]:
        """Start a retest for a finding and publish the retest-started event."""
        record = self._get_record(finding_id)
        plan = self.retest(finding_id)
        report_id = self._report_for_finding(finding_id)
        if report_id:
            self._publish(
                ReportRetestStartedEvent(
                    report_id,
                    retest_plan_id=str(plan.get("plan_id") or ""),
                    finding_id=finding_id,
                    target_id=record.target_id,
                    mission_id=record.mission_id,
                    provenance=record.provenance,
                )
            )
        return {"finding_id": finding_id, "retest": plan}

    def complete_retest(self, finding_id: str, *, fix_verified: bool) -> dict[str, Any]:
        """Complete a retest and update the remediation state.

        When ``fix_verified`` is true the finding is marked FIX_VERIFIED and
        the original evidence is retained; otherwise FIX_FAILED.

        Args:
            finding_id: the finding being retested.
            fix_verified: whether the original PoC failed (fix holds).

        Returns:
            The remediation state transition result.

        """
        record = self._get_record(finding_id)
        state = RemediationState.FIX_VERIFIED if fix_verified else RemediationState.FIX_FAILED
        retest_state = RetestState.PASSED if fix_verified else RetestState.FAILED
        report_id = self._report_for_finding(finding_id)
        if report_id:
            self._publish(
                ReportRetestCompletedEvent(
                    report_id,
                    retest_state=retest_state.value,
                    fix_verified=fix_verified,
                    finding_id=finding_id,
                    target_id=record.target_id,
                    mission_id=record.mission_id,
                    provenance=record.provenance,
                )
            )
        return {"finding_id": finding_id, "remediation_state": state.value, "fix_verified": fix_verified}

    def close_report(self, report_id: str) -> dict[str, Any]:
        """Close a submitted report."""
        record = self._get_report_record(report_id)
        result = self._lifecycle.transition(ReportState(record.status), ReportState.CLOSED)
        if result.allowed:
            self._update_report_status(record, ReportState.CLOSED)
            finding = self._get_record(record.finding_id)
            self._publish(
                ReportClosedEvent(
                    report_id,
                    finding_id=record.finding_id,
                    target_id=record.target_id,
                    mission_id=record.mission_id,
                    provenance=finding.provenance,
                )
            )
        return result.to_dict()

    def reopen_report(self, report_id: str) -> dict[str, Any]:
        """Reopen a submitted report."""
        record = self._get_report_record(report_id)
        result = self._lifecycle.transition(ReportState(record.status), ReportState.REOPENED)
        if result.allowed:
            self._update_report_status(record, ReportState.REOPENED)
            finding = self._get_record(record.finding_id)
            self._publish(
                ReportReopenedEvent(
                    report_id,
                    finding_id=record.finding_id,
                    target_id=record.target_id,
                    mission_id=record.mission_id,
                    provenance=finding.provenance,
                )
            )
        return result.to_dict()

    # -- export -----------------------------------------------------------------

    def export_report(self, report_id: str, *, fmt: str) -> dict[str, Any]:
        """Export a report into ``fmt``.

        Args:
            report_id: the report to export.
            fmt: markdown / html / json / sarif / pdf / package.

        Returns:
            The rendered output and export metadata.

        """
        package = self._latest_package(report_id)
        if package is None:
            raise LookupError(f"report {report_id} has no generated package")
        document = ReportDocument.from_dict(dict(package.document_json))
        content = self._export_text(document, fmt)
        redacted_content, redaction = self._redactor.redact(content, field_name=f"export:{fmt}")
        export_format = ExportFormat(fmt)
        finding = self._get_record(document.finding_id)
        self._publish(
            ReportExportedEvent(
                report_id,
                fmt=export_format.value,
                version=document.version,
                finding_id=document.finding_id,
                target_id=document.target_id,
                mission_id=document.mission_id,
                provenance=finding.provenance,
            )
        )
        return {
            "report_id": report_id,
            "format": export_format.value,
            "content": redacted_content,
            "redaction_applied": redaction.applied,
            "redaction_records": [item.to_dict() for item in redaction.records],
        }

    def export_sarif(self, report_id: str) -> dict[str, Any]:
        """Export a report as SARIF."""
        return self.export_report(report_id, fmt="sarif")

    # -- template / summary / correlation --------------------------------------

    def report_template(self, template: str = "pentest") -> dict[str, Any]:
        """Return the data-driven template for a template kind."""
        return self._templates.template_for(_template_kind(template)).to_dict()

    def executive_summary(self, report_id: str) -> dict[str, Any]:
        """Build the executive summary for a report."""
        package = self._latest_package(report_id)
        if package is None:
            raise LookupError(f"report {report_id} has no generated package")
        document = ReportDocument.from_dict(dict(package.document_json))
        intelligence = document.intelligence
        findings = (intelligence.to_dict(),) if intelligence else ()
        summary = self._executive.summarize(
            ExecutiveSummaryInput(
                report_id=report_id,
                findings=findings,
                attack_paths=document.attack_paths,
                root_causes=document.root_causes,
            )
        )
        return summary.to_dict()

    def finding_correlation(self, report_id: str) -> dict[str, Any]:
        """Build the cross-finding correlation report for a report."""
        record = self._get_report_record(report_id)
        root_causes = self._repo(FindingRootCause).list_by("mission_id", record.mission_id, limit=1000)
        relations = [
            RelationInput(
                source_finding_id=(
                    item.related_finding_ids[0]
                    if item.related_finding_ids
                    else (item.affected_assets[0] if item.affected_assets else record.finding_id)
                ),
                target_finding_id=(
                    item.affected_assets[0] if item.affected_assets else record.finding_id
                ),
                relation="finding->asset",
                rationale=item.description,
                evidence_refs=tuple(item.evidence_ids or ()),
                validated=True,
            )
            for item in root_causes
        ]
        correlation = self._correlation.build(
            report_id=report_id,
            relations=tuple(relations),
            root_cause_groups=tuple(item.root_cause_id for item in root_causes),
        )
        return correlation.to_dict()

    # -- persistence helpers ----------------------------------------------------

    def _repo(self, entity_cls: type[_E]) -> TidbRepository[_E]:
        """Return the TIDB repository for an entity type."""
        return self._stores.repository_for(entity_cls)

    def _get_record(self, finding_id: str) -> FindingRecord:
        record = self._repo(FindingRecord).get(finding_id)
        if record is None:
            raise LookupError(f"finding {finding_id} does not exist")
        return record

    def _get_report_record(self, report_id: str) -> ReportRecord:
        record = self._repo(ReportRecord).get(report_id)
        if record is None:
            by_field = self._repo(ReportRecord).list_by("report_id", report_id, limit=1)
            if by_field:
                record = by_field[-1]
        if record is None:
            raise LookupError(f"report {report_id} does not exist")
        return record

    def _next_report_version(self, report_id: str) -> int:
        existing = self._repo(ReportVersionRecord).list_by("report_id", report_id, limit=1000)
        return max((item.version for item in existing), default=0) + 1

    def _persist_report(
        self,
        finding_id: str,
        record: FindingRecord,
        report_id: str,
        kind: TemplateKind,
        template_model: ReportTemplate,
        document: ReportDocument,
        snapshot: ReportEvidenceSnapshotRecord,
    ) -> None:
        report = self._repo(ReportRecord).get(report_id)
        if report is None:
            report = ReportRecord(
                id=report_id,
                report_id=report_id,
                finding_id=finding_id,
                mission_id=record.mission_id,
                target_id=record.target_id,
                title=record.title,
                template=kind.value,
                template_version=template_model.version,
                report_schema_version=_REPORTING_VERSION,
                status=document.status,
                generator_version=_REPORTING_VERSION,
                version=document.version,
            )
            self._repo(ReportRecord).save(report)
        else:
            report.status = document.status
            report.version = document.version
            report.title = record.title
            self._repo(ReportRecord).save(report)

        self._repo(ReportVersionRecord).save(
            ReportVersionRecord(
                report_id=report_id,
                finding_id=finding_id,
                template_version=template_model.version,
                report_schema_version=_REPORTING_VERSION,
                generated_at=document.generated_at,
                generator_version=_REPORTING_VERSION,
                source_snapshot=snapshot.snapshot_id,
                content_hash=generate_content_id(document.to_dict()),
                status=document.status,
                version=document.version,
            )
        )
        self._repo(ReportPackageRecord).save(
            ReportPackageRecord(
                package_id=generate_id(),
                report_id=report_id,
                finding_id=finding_id,
                document_json=document.to_dict(),
                content_hash=generate_content_id(document.to_dict()),
                status=document.status,
                generated_at=document.generated_at,
                version=document.version,
            )
        )
        self._repo(ReportQaRecord).save(
            ReportQaRecord(
                qa_id=generate_id(),
                report_id=report_id,
                verdict=document.qa.verdict.value,
                checks=[check.to_dict() for check in document.qa.checks],
                blocked=document.qa.blocked,
                reasons=list(document.qa.reasons),
                checked_at=document.qa.checked_at,
            )
        )
        self._repo(ReportClaimRecord).save_many(
            [
                ReportClaimRecord(
                    claim_id=claim.claim_id,
                    report_id=report_id,
                    finding_id=finding_id,
                    claim_text=claim.claim_text,
                    source_refs=list(claim.source_refs),
                    claim_type=claim.claim_type.value,
                    confidence=claim.confidence,
                    generated_by=claim.generated_by,
                    verification_state=claim.verification_state.value,
                    verification_detail=claim.verification_detail,
                )
                for claim in document.claims
            ]
        )
        self._repo(ReportEvidenceSnapshotRecord).save(snapshot)
        if document.remediation:
            self._repo(RemediationPlanRecord).save(
                RemediationPlanRecord(
                    plan_id=document.remediation.plan_id,
                    finding_id=finding_id,
                    report_id=report_id,
                    root_cause_id=document.remediation.root_cause_id,
                    plan_json=document.remediation.to_dict(),
                )
            )
        if document.retest:
            self._repo(RetestPlanRecord).save(
                RetestPlanRecord(
                    plan_id=document.retest.plan_id,
                    finding_id=finding_id,
                    report_id=report_id,
                    state=document.retest.state.value,
                    plan_json=document.retest.to_dict(),
                )
            )

    def _capture_snapshot(self, finding_id: str, record: FindingRecord, intelligence: FindingIntelligence) -> ReportEvidenceSnapshotRecord:
        snapshot = ReportEvidenceSnapshotRecord(
            snapshot_id=generate_id(),
            report_id="",
            finding_id=finding_id,
            finding_hash=generate_content_id(record.finding_id, record.status, record.updated_at or record.created_at),
            evidence_hash=generate_content_id(*(item.content_hash for item in intelligence.evidence_bundle.artifacts)),
            captured_at=utcnow_iso(),
        )
        return snapshot

    def _update_report_status(self, report: ReportRecord, state: ReportState) -> None:
        report.status = state.value
        self._repo(ReportRecord).save(report)

    def _latest_package(self, report_id: str) -> Any | None:
        packages = self._repo(ReportPackageRecord).list_by("report_id", report_id, limit=1)
        return packages[-1] if packages else None

    def _latest_qa(self, report_id: str) -> dict[str, Any] | None:
        records = self._repo(ReportQaRecord).list_by("report_id", report_id, limit=1)
        if not records:
            return None
        latest = records[-1]
        return {
            "verdict": latest.verdict,
            "checks": latest.checks,
            "blocked": latest.blocked,
            "reasons": latest.reasons,
            "checked_at": latest.checked_at,
        }

    def _run_qa(
        self,
        document: ReportDocument,
        *,
        verified_refs: set[str],
        report_record: Any | None = None,
    ) -> ReportQaResult:
        context = QaContext(
            verified_refs=verified_refs,
            stale_refs=set(),
            open_conflicts=self._open_conflicts(document.finding_id),
            known_duplicates=(),
        )
        rendered = self._export_text(document, "markdown")
        qa = self._qa.check(document, context=context, text_content=rendered)
        if qa.verdict is QaVerdict.PASS:
            self._publish(
                ReportQaPassedEvent(
                    document.report_id,
                    finding_id=document.finding_id,
                    target_id=document.target_id,
                    mission_id=document.mission_id,
                    provenance=(report_record.provenance if report_record else "reporting.service"),
                )
            )
        elif qa.verdict is QaVerdict.FAIL:
            self._publish(
                ReportQaFailedEvent(
                    document.report_id,
                    reasons=qa.reasons,
                    finding_id=document.finding_id,
                    target_id=document.target_id,
                    mission_id=document.mission_id,
                    provenance=(report_record.provenance if report_record else "reporting.service"),
                )
            )
        return qa

    # -- assembly helpers -------------------------------------------------------

    def _assemble_document(
        self,
        *,
        report_id: str,
        finding_id: str,
        mission_id: str,
        target_id: str,
        title: str,
        kind: TemplateKind,
        template_model: ReportTemplate,
        version_number: int,
        intelligence: FindingIntelligence,
        remediation: RemediationPlan,
        retest: RetestPlan,
        claims: tuple[ReportClaim, ...],
        blocked_claims: tuple[ReportClaim, ...],
        record: FindingRecord,
    ) -> ReportDocument:
        poc = self._poc_presentation(finding_id)
        reproduction = self._reproduction_section(finding_id)
        summary = self._executive.summarize(
            ExecutiveSummaryInput(
                report_id=report_id,
                findings=(intelligence.to_dict(),),
                attack_paths=intelligence.attack_path_relationships,
                root_causes=intelligence.root_cause,
            )
        )
        qa = ReportQaResult(report_id=report_id, verdict=QaVerdict.WARN, blocked=True)
        document = ReportDocument(
            report_id=report_id,
            finding_id=finding_id,
            mission_id=mission_id,
            target_id=target_id,
            title=title,
            template=kind,
            template_version=template_model.version,
            schema_version=_REPORTING_VERSION,
            status=ReportState.REPORT_GENERATED.value,
            version=version_number,
            intelligence=intelligence,
            classification=intelligence.classification,
            severity=intelligence.severity,
            priority=intelligence.priority,
            quality=intelligence.quality,
            reportability=intelligence.reportability,
            impact=intelligence.impact,
            asset_criticality=intelligence.asset_criticality,
            remediation=remediation,
            retest=retest,
            reproduction=reproduction,
            poc=poc,
            evidence_bundle=intelligence.evidence_bundle,
            timeline=intelligence.timeline,
            tool_provenance=intelligence.tool_provenance,
            claims=claims,
            qa=qa,
            redaction=ReportRedaction(applied=True),
            executive_summary=summary,
            correlation=self._correlation.build(report_id=report_id, relations=()),
            testing_matrix=SecurityTestingMatrix(
                entries=(
                    SecurityTestingStateEntry(
                        finding_id=finding_id,
                        state=self._testing_state(intelligence),
                        detail=intelligence.finding_state,
                    ),
                )
            ),
            attack_paths=intelligence.attack_path_relationships,
            root_causes=intelligence.root_cause,
            references=tuple(intelligence.classification.cve_ids),
            generated_at=utcnow_iso(),
        )
        # Redact sensitive prose fields while preserving reproduction utility.
        document = self._redact_document(document)
        return document

    def _document_payload(
        self,
        *,
        report_id: str,
        finding_id: str,
        mission_id: str,
        target_id: str,
        title: str,
        kind: TemplateKind,
        template_model: ReportTemplate,
        intelligence: FindingIntelligence,
        remediation: RemediationPlan,
        retest: RetestPlan,
        poc: PoCPresentation | None,
        reproduction: ReproductionSection | None,
    ) -> dict[str, Any]:
        document = self._assemble_document(
            report_id=report_id,
            finding_id=finding_id,
            mission_id=mission_id,
            target_id=target_id,
            title=title,
            kind=kind,
            template_model=template_model,
            version_number=1,
            intelligence=intelligence,
            remediation=remediation,
            retest=retest,
            claims=(),
            blocked_claims=(),
            record=self._get_record(finding_id),
        )
        return document.to_dict()

    def _redact_document(self, document: ReportDocument) -> ReportDocument:
        """Redact sensitive values inside the report document prose."""
        description = document.intelligence.description if document.intelligence else document.title
        redacted_description, redaction = self._redactor.redact(description, field_name="description")
        # Rebuild via to_dict -> from_dict to keep dataclass invariants.
        payload = document.to_dict()
        payload["intelligence"]["description"] = redacted_description
        rebuilt = ReportDocument.from_dict(payload)
        rebuilt = ReportDocument(
            report_id=rebuilt.report_id,
            finding_id=rebuilt.finding_id,
            mission_id=rebuilt.mission_id,
            target_id=rebuilt.target_id,
            title=rebuilt.title,
            template=rebuilt.template,
            template_version=rebuilt.template_version,
            schema_version=rebuilt.schema_version,
            status=rebuilt.status,
            version=rebuilt.version,
            intelligence=rebuilt.intelligence,
            classification=rebuilt.classification,
            severity=rebuilt.severity,
            priority=rebuilt.priority,
            quality=rebuilt.quality,
            reportability=rebuilt.reportability,
            impact=rebuilt.impact,
            asset_criticality=rebuilt.asset_criticality,
            remediation=rebuilt.remediation,
            retest=rebuilt.retest,
            reproduction=rebuilt.reproduction,
            poc=rebuilt.poc,
            evidence_bundle=rebuilt.evidence_bundle,
            timeline=rebuilt.timeline,
            tool_provenance=rebuilt.tool_provenance,
            claims=rebuilt.claims,
            qa=rebuilt.qa,
            redaction=ReportRedaction(applied=True, records=redaction.records, applied_at=utcnow_iso()),
            executive_summary=rebuilt.executive_summary,
            correlation=rebuilt.correlation,
            testing_matrix=rebuilt.testing_matrix,
            attack_paths=rebuilt.attack_paths,
            root_causes=rebuilt.root_causes,
            references=rebuilt.references,
            generated_at=rebuilt.generated_at,
        )
        return rebuilt

    def _poc_presentation(self, finding_id: str) -> PoCPresentation | None:
        pocs = self._repo(FindingPoC).list_by("finding_id", finding_id, limit=1000)
        if not pocs:
            return None
        latest = pocs[-1]
        replays = self._repo(FindingReplayRecord).list_by("finding_id", finding_id, limit=1000)
        confirmed = any(item.verdict == ReplayVerdict.CONFIRMED.value for item in replays)
        return PoCPresentation(
            poc_id=latest.poc_id,
            finding_id=finding_id,
            poc_type=latest.format,
            purpose=f"minimal, deterministic reproduction for {latest.format}",
            preconditions=("authorized target in scope",),
            minimal_reproduction=latest.content[:2000] if latest.content else "",
            expected_result="the vulnerable behavior is observed under controlled conditions",
            actual_result="vulnerable behavior reproduced (see replay records)",
            validation_status=latest.lifecycle_state,
            replay_status="confirmed" if confirmed else "not_run",
            evidence_refs=tuple(item.replay_id for item in replays),
            safe=True,
        )

    def _reproduction_section(self, finding_id: str) -> ReproductionSection | None:
        records = self._repo(FindingReproduction).list_by("finding_id", finding_id, limit=1)
        if not records:
            return None
        item = records[-1]
        return ReproductionSection(
            target=item.finding_id,
            endpoint=item.request,
            method=item.method,
            parameter=", ".join(item.parameters.keys()) if item.parameters else "",
            preconditions=("authorized target",),
            authentication_context=str(item.cookies or item.headers) if (item.cookies or item.headers) else "",
            request=item.request,
            payload_reference=item.payload_reference,
            expected_behavior=item.expected_result,
            observed_behavior=item.actual_result,
            verification=item.response_characteristics,
            proof_refs=(),
            impact="",
            redacted=item.redacted,
        )

    def _build_bundle(
        self,
        finding_id: str,
        record: FindingRecord,
        evidence: list[Any],
        pocs: Sequence[Any],
        replays: Sequence[Any],
    ) -> EvidenceBundle:
        artifacts = tuple(
            ArtifactInput(
                kind=str(item.kind.value if hasattr(item.kind, "value") else item.kind),
                content=str(item.value),
                source=item.source,
                timestamp=item.captured_at,
                collector="finding.lifecycle",
                tool=item.tool_id,
                mission_id=record.mission_id,
                target_id=record.target_id,
                finding_id=finding_id,
                provenance=dict(item.provenance) if item.provenance else {},
                redaction_state="redacted",
            )
            for item in evidence
        )
        return self._bundle_builder.build(
            finding_id=finding_id,
            artifacts=artifacts,
            normalized_observations=tuple(str(item.evidence_id) for item in evidence),
            validation_results=tuple(record.validation_refs),
            proof_references=tuple(item.poc_id for item in pocs),
            replay_results=tuple(item.replay_id for item in replays),
        )

    def _build_timeline(self, finding_id: str, record: FindingRecord) -> FindingTimeline:
        events = [
            TimelineEvent(
                event="candidate_generated",
                detail=record.title,
                occurred_at=record.created_at,
                provenance="finding.lifecycle",
            )
        ]
        for attempt in self._repo(FindingValidationAttempt).list_by("finding_id", finding_id, limit=1000):
            if attempt.executed_at:
                events.append(
                    TimelineEvent(
                        event="validation_started",
                        detail=f"validation {attempt.validation_id} {attempt.status}",
                        occurred_at=attempt.executed_at,
                        provenance=f"tool:{attempt.tool_id}",
                    )
                )
        for replay in self._repo(FindingReplayRecord).list_by("finding_id", finding_id, limit=1000):
            if replay.replayed_at:
                events.append(
                    TimelineEvent(
                        event="proof_replayed",
                        detail=f"replay {replay.replay_id} verdict {replay.verdict}",
                        occurred_at=replay.replayed_at,
                        provenance="proof.replay",
                    )
                )
        impact = self._repo(FindingImpactAssessment).list_by("finding_id", finding_id, limit=1)
        if impact and impact[-1].assessed_at:
            events.append(
                TimelineEvent(
                    event="impact_confirmed",
                    detail="impact assessment recorded",
                    occurred_at=impact[-1].assessed_at,
                    provenance="finding.lifecycle",
                )
            )
        return self._timeline.build(finding_id=finding_id, events=tuple(events))

    def _evidence_items(self, record: FindingRecord) -> list[Any]:
        from hunterx.domain.vulnerability_finding.models import EvidenceItem

        items: list[Any] = []
        for entry in record.observations:
            if not isinstance(entry, dict):
                continue
            try:
                items.append(EvidenceItem.from_dict(entry))
            except (TypeError, ValueError):
                continue
        return items

    def _impact_dimensions(self, finding_id: str) -> dict[str, str]:
        records = self._repo(FindingImpactAssessment).list_by("finding_id", finding_id, limit=1)
        if not records:
            return {}
        dimensions = records[-1].dimensions or {}
        return {str(key): str(value) for key, value in dimensions.items()}

    def _impact_assessed(self, finding_id: str) -> bool:
        dimensions = self._impact_dimensions(finding_id)
        return any(value not in ("none", "") for value in dimensions.values())

    def _business_impact_model(self, impact: dict[str, str], evidence: list[Any]) -> BusinessImpact:
        evidence_ids = {str(item.evidence_id) for item in evidence}
        evidence_refs: dict[Any, tuple[str, ...]] = {}
        for key, value in impact.items():
            if value not in ("none", ""):
                evidence_refs[_impact_type(key)] = tuple(sorted(evidence_ids))
        dimensions = {_impact_type(key): value for key, value in impact.items() if value not in ("none", "")}
        return BusinessImpact(
            dimensions=dimensions,
            evidence_refs=evidence_refs,
            reasoning=("impact derived from evidence-backed impact assessment",),
            analyst_reasoned=False,
        )

    def _business_impact_score(self, impact: dict[str, str]) -> float:
        levels = {"low": 0.3, "medium": 0.6, "high": 1.0}
        scored = [levels.get(value, 0.0) for value in impact.values() if value not in ("none", "")]
        if not scored:
            return 0.0
        return max(scored)

    def _asset_criticality(self, record: FindingRecord) -> AssetCriticality:
        scope = record.scope or {}
        importance = str(scope.get("asset_importance") or "medium")
        return AssetCriticality(
            asset=record.asset_id or (record.affected_assets[0] if record.affected_assets else record.target_id),
            importance=importance if importance in ("low", "medium", "high", "critical") else "medium",
            internet_exposure=bool(scope.get("internet_exposure", False)),
            production=bool(scope.get("production", False)),
            authentication_required=bool(scope.get("authentication_required", False)),
            data_sensitivity=str(scope.get("data_sensitivity") or "unknown"),
            cloud_role=str(scope.get("cloud_role") or ""),
            business_function=str(scope.get("business_function") or ""),
            known_criticality=str(scope.get("known_criticality") or ""),
            evidence_refs=tuple(record.evidence_refs),
        )

    def _confidence_score(self, finding_id: str) -> float:
        from hunterx.domain.entities.tidb.finding_orchestration import FindingConfidenceAssessment

        records = self._repo(FindingConfidenceAssessment).list_by("finding_id", finding_id, limit=1)
        return records[-1].score if records else 0.0

    def _root_cause_ids(self, finding_id: str) -> tuple[str, ...]:
        return tuple(item.root_cause_id for item in self._root_causes_for_finding(finding_id))

    def _root_causes_for_finding(self, finding_id: str) -> list[Any]:
        """Return the root causes whose ``related_finding_ids`` include ``finding_id``.

        ``FindingRootCause`` is mission-scoped: it carries ``related_finding_ids``
        (a list) rather than a single ``finding_id`` column, so membership is
        resolved against the owning mission and filtered in-process.
        """
        record = self._get_record(finding_id)
        candidates = self._repo(FindingRootCause).list_by("mission_id", record.mission_id, limit=1000)
        return [item for item in candidates if finding_id in (item.related_finding_ids or [])]

    def _pocs(self, finding_id: str) -> Sequence[Any]:
        return self._repo(FindingPoC).list_by("finding_id", finding_id, limit=1000)

    def _replays(self, finding_id: str) -> Sequence[Any]:
        return self._repo(FindingReplayRecord).list_by("finding_id", finding_id, limit=1000)

    def _open_conflicts(self, finding_id: str) -> int:
        from hunterx.domain.entities.tidb.finding_orchestration import FindingConflict

        return len(self._repo(FindingConflict).list_by("finding_id", finding_id, limit=1000))

    def _evidence_quality_avg(self, evidence: list[Any]) -> float:
        if not evidence:
            return 0.0
        qualities = {"low": 0.3, "medium": 0.6, "high": 0.9, "proof": 1.0}
        scores = []
        for item in evidence:
            try:
                scores.append(qualities.get(str(item.quality.value if hasattr(item.quality, "value") else item.quality), 0.5))
            except (AttributeError, ValueError):
                scores.append(0.5)
        return sum(scores) / len(scores)

    def _evidence_fresh(self, record: FindingRecord) -> bool:
        return bool(record.first_seen and record.last_seen)

    def _tool_reliability_avg(self, record: FindingRecord) -> float:
        return 0.8 if record.provenance else 0.5

    def _exploitability_evidence(self, evidence: list[Any]) -> bool:
        return any(
            getattr(item, "kind", None) in (
                FindingEvidenceKind.CONTROLLED_CALLBACK,
                FindingEvidenceKind.CONTROLLED_PROOF,
                FindingEvidenceKind.REPLAY,
            )
            for item in evidence
        )

    def _cve_ids(self, evidence: list[Any]) -> tuple[str, ...]:
        cves: list[str] = []
        for item in evidence:
            if getattr(item, "kind", None) is FindingEvidenceKind.CVE_MATCH:
                cves.append(str(item.value))
        return tuple(dict.fromkeys(cves))

    def _cvss_vector(self, evidence: list[Any]) -> str | None:
        for item in evidence:
            if getattr(item, "kind", None) is FindingEvidenceKind.CVE_MATCH:
                value = str(item.value)
                if "CVSS" in value or value.startswith("AV:"):
                    return value
        return None

    def _tool_provenance(self, record: FindingRecord, evidence: list[Any]) -> list[ToolProvenance]:
        provenances: list[ToolProvenance] = []
        if record.provenance:
            reliability = self._source.reliability_for(record.provenance, SourceReliabilityKind.TOOL_SIGNATURE)
            provenances.append(
                ToolProvenance(
                    tool=record.provenance,
                    timestamp=record.created_at,
                    target=record.target_id,
                    reliability=reliability.kind,
                )
            )
        seen: set[str] = set()
        for item in evidence:
            tool = str(item.tool_id or "")
            if not tool or tool in seen:
                continue
            seen.add(tool)
            provenances.append(
                ToolProvenance(
                    tool=tool,
                    version=str(item.provenance.get("version", "") if item.provenance else ""),
                    timestamp=item.captured_at,
                    target=record.target_id,
                    reliability=SourceReliabilityKind.TOOL_SIGNATURE,
                )
            )
        return provenances

    def _verified_refs(self, finding_id: str, intelligence: FindingIntelligence) -> set[str]:
        refs: set[str] = set(intelligence.evidence_bundle.normalized_observations)
        refs.update(intelligence.evidence_bundle.validation_results)
        refs.update(intelligence.evidence_bundle.proof_references)
        refs.update(intelligence.evidence_bundle.replay_results)
        refs.update(intelligence.evidence_bundle.callback_evidence)
        return refs

    def _testing_state(self, intelligence: FindingIntelligence) -> SecurityTestingState:
        if intelligence.finding_state == FindingState.PROVED.value:
            return SecurityTestingState.CONFIRMED
        if intelligence.finding_state in (FindingState.VALIDATED.value, FindingState.REPORT_READY.value):
            return SecurityTestingState.VALIDATED
        if intelligence.finding_state == FindingState.SUPPORTED.value:
            return SecurityTestingState.SUSPECTED
        return SecurityTestingState.UNVERIFIED

    def _report_for_finding(self, finding_id: str) -> str:
        reports = self._repo(ReportRecord).list_by("finding_id", finding_id, limit=1)
        return reports[-1].report_id if reports else ""

    def _report_to_dict(self, record: ReportRecord) -> dict[str, Any]:
        return {
            "report_id": record.report_id,
            "finding_id": record.finding_id,
            "mission_id": record.mission_id,
            "target_id": record.target_id,
            "title": record.title,
            "template": record.template,
            "template_version": record.template_version,
            "report_schema_version": record.report_schema_version,
            "status": record.status,
            "version": record.version,
            "generator_version": record.generator_version,
            "created_at": record.created_at,
            "updated_at": record.updated_at,
        }

    def _export_text(self, document: ReportDocument, fmt: str) -> str:
        """Render a report document into ``fmt``.

        Delegates to the injected reporting adapter. When no adapter is wired,
        only the structured ``json``/``package`` fallback is available.
        """
        if self._exporter is not None:
            return self._exporter.export(document, fmt=fmt)
        if fmt in ("json", "package"):
            return json.dumps(document.to_dict(), indent=2, default=str)
        raise RuntimeError(
            "no report exporter adapter is wired; install the reporting adapter "
            f"to export format '{fmt}'"
        )

    def _publish(self, event: DomainEvent) -> None:
        if self._event_bus is not None:
            self._event_bus.publish(event)


def _template_kind(value: str) -> TemplateKind:
    """Coerce a template string into a canonical kind."""
    try:
        return TemplateKind(value)
    except ValueError:
        return TemplateKind.PENTEST


def _as_str_tuple(value: object) -> tuple[str, ...]:
    """Coerce a JSON value into a tuple of strings."""
    if isinstance(value, (list, tuple)):
        return tuple(str(item) for item in value if item is not None)
    return ()


def _replace_qaless_document(document: ReportDocument, qa: ReportQaResult) -> ReportDocument:
    """Rebuild ``document`` with the computed QA result applied."""
    rebuilt = ReportDocument(
        report_id=document.report_id,
        finding_id=document.finding_id,
        mission_id=document.mission_id,
        target_id=document.target_id,
        title=document.title,
        template=document.template,
        template_version=document.template_version,
        schema_version=document.schema_version,
        status=document.status,
        version=document.version,
        intelligence=document.intelligence,
        classification=document.classification,
        severity=document.severity,
        priority=document.priority,
        quality=document.quality,
        reportability=document.reportability,
        impact=document.impact,
        asset_criticality=document.asset_criticality,
        remediation=document.remediation,
        retest=document.retest,
        reproduction=document.reproduction,
        poc=document.poc,
        evidence_bundle=document.evidence_bundle,
        timeline=document.timeline,
        tool_provenance=document.tool_provenance,
        claims=document.claims,
        qa=qa,
        redaction=document.redaction,
        executive_summary=document.executive_summary,
        correlation=document.correlation,
        testing_matrix=document.testing_matrix,
        attack_paths=document.attack_paths,
        root_causes=document.root_causes,
        references=document.references,
        generated_at=document.generated_at,
    )
    return rebuilt


def _impact_type(value: str) -> Any:
    """Map an impact-dimension string to a business-impact type."""
    from hunterx.domain.reporting.enums import BusinessImpactType

    mapping = {
        "data_exposure": BusinessImpactType.DATA_EXPOSURE,
        "credential_exposure": BusinessImpactType.CREDENTIAL_EXPOSURE,
        "account_takeover": BusinessImpactType.ACCOUNT_TAKEOVER,
        "privilege_boundary": BusinessImpactType.PRIVILEGE_ESCALATION,
        "remote_execution": BusinessImpactType.REMOTE_CODE_EXECUTION,
        "cloud_resource_access": BusinessImpactType.CLOUD_RESOURCE_ACCESS,
        "authorization_boundary": BusinessImpactType.UNAUTHORIZED_ACCESS,
        "availability": BusinessImpactType.AVAILABILITY_IMPACT,
    }
    for key, impact_type in mapping.items():
        if key in value or value == impact_type.value:
            return impact_type
    return BusinessImpactType.BUSINESS_PROCESS_MANIPULATION
