# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""In-memory mission planning repositories.

Test doubles implementing the mission planning repository ports without any
database. Used by unit tests and by embedded/development wiring.
"""

from __future__ import annotations

from collections.abc import Sequence

from hunterx.domain.exceptions import NotFoundError
from hunterx.domain.mission_planning import (
    Checkpoint,
    MissionApprovalLevel,
    MissionPhase,
    MissionPhaseKind,
    MissionPlan,
    MissionProfile,
    MissionTemplate,
    MissionTimelineEntry,
    MissionType,
)
from hunterx.domain.ports.mission_planning import (
    CheckpointRepository,
    MissionPlanRepository,
    MissionProfileRepository,
    MissionTemplateRepository,
    MissionTimelineRepository,
)
from hunterx.engines.mission_planning.api import MissionPlanningAPI


class InMemoryMissionProfileRepository(MissionProfileRepository):
    """In-memory :class:`MissionProfileRepository`."""

    def __init__(self) -> None:
        self._store: dict[str, MissionProfile] = {}

    def save(self, profile: MissionProfile) -> None:
        self._store[profile.profile_id] = profile

    def get(self, profile_id: str) -> MissionProfile | None:
        return self._store.get(profile_id)

    def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[MissionProfile]:
        values = list(self._store.values())
        return values[offset : offset + limit]

    def delete(self, profile_id: str) -> None:
        if profile_id not in self._store:
            raise NotFoundError("MissionProfile", profile_id)
        del self._store[profile_id]


class InMemoryMissionTemplateRepository(MissionTemplateRepository):
    """In-memory :class:`MissionTemplateRepository`."""

    def __init__(self) -> None:
        self._store: dict[str, MissionTemplate] = {}

    def save(self, template: MissionTemplate) -> None:
        self._store[template.template_id] = template

    def get(self, template_id: str) -> MissionTemplate | None:
        return self._store.get(template_id)

    def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[MissionTemplate]:
        values = list(self._store.values())
        return values[offset : offset + limit]

    def delete(self, template_id: str) -> None:
        if template_id not in self._store:
            raise NotFoundError("MissionTemplate", template_id)
        del self._store[template_id]


class InMemoryMissionPlanRepository(MissionPlanRepository):
    """In-memory :class:`MissionPlanRepository`."""

    def __init__(self) -> None:
        self._store: dict[str, MissionPlan] = {}

    def save(self, plan: MissionPlan) -> None:
        self._store[plan.plan_id] = plan

    def get(self, plan_id: str) -> MissionPlan | None:
        return self._store.get(plan_id)

    def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[MissionPlan]:
        values = list(self._store.values())
        return values[offset : offset + limit]

    def list_by_mission(self, mission_id: str, *, limit: int = 100) -> Sequence[MissionPlan]:
        return [p for p in self._store.values() if p.mission_id == mission_id][:limit]

    def list_by_status(self, status: str, *, limit: int = 100) -> Sequence[MissionPlan]:
        return [p for p in self._store.values() if p.status.value == status][:limit]

    def delete(self, plan_id: str) -> None:
        if plan_id not in self._store:
            raise NotFoundError("MissionPlan", plan_id)
        del self._store[plan_id]


class InMemoryCheckpointRepository(CheckpointRepository):
    """In-memory :class:`CheckpointRepository`."""

    def __init__(self) -> None:
        self._store: dict[str, Checkpoint] = {}

    def save(self, checkpoint: Checkpoint) -> None:
        self._store[checkpoint.checkpoint_id] = checkpoint

    def get(self, checkpoint_id: str) -> Checkpoint | None:
        return self._store.get(checkpoint_id)

    def list_by_plan(self, plan_id: str, *, limit: int = 100) -> Sequence[Checkpoint]:
        values = sorted(
            (c for c in self._store.values() if c.plan_id == plan_id),
            key=lambda c: c.created_at,
            reverse=True,
        )
        return values[:limit]

    def delete(self, checkpoint_id: str) -> None:
        if checkpoint_id not in self._store:
            raise NotFoundError("Checkpoint", checkpoint_id)
        del self._store[checkpoint_id]


class InMemoryMissionTimelineRepository(MissionTimelineRepository):
    """In-memory :class:`MissionTimelineRepository`."""

    def __init__(self) -> None:
        self._store: list[MissionTimelineEntry] = []

    def append(self, entry: MissionTimelineEntry) -> None:
        self._store.append(entry)

    def list_by_mission(self, mission_id: str, *, limit: int = 100) -> Sequence[MissionTimelineEntry]:
        entries = [e for e in self._store if e.mission_id == mission_id]
        return entries[-limit:]

    def delete_by_mission(self, mission_id: str) -> None:
        self._store = [e for e in self._store if e.mission_id != mission_id]


def build_in_memory_planning_repositories() -> dict[str, object]:
    """Build all in-memory mission planning repositories keyed by role name."""
    return {
        "mission_profiles": InMemoryMissionProfileRepository(),
        "mission_templates": InMemoryMissionTemplateRepository(),
        "mission_plans": InMemoryMissionPlanRepository(),
        "checkpoints": InMemoryCheckpointRepository(),
        "mission_timeline": InMemoryMissionTimelineRepository(),
    }


def external_pentest_profile() -> MissionProfile:
    """A standard external-pentest profile for tests and examples."""
    return MissionProfile(
        profile_id="external-pentest",
        name="External Penetration Test",
        description="Perimeter-focused pentest of internet-facing assets.",
        version="1.0.0",
        mission_types=(MissionType.EXTERNAL_PENTEST, MissionType.NETWORK_ASSESSMENT),
        phases=(
            MissionPhase(
                phase_id="recon",
                name="Reconnaissance",
                kind=MissionPhaseKind.RECONNAISSANCE,
                estimated_duration_seconds=600,
                actions=("recon.enumerate", "recon.fingerprint"),
                expected_outputs=("assets",),
            ),
            MissionPhase(
                phase_id="enumeration",
                name="Enumeration",
                kind=MissionPhaseKind.ENUMERATION,
                depends_on=("recon",),
                estimated_duration_seconds=900,
                actions=("scan.discover", "scan.fingerprint"),
                parallel=True,
            ),
            MissionPhase(
                phase_id="validation",
                name="Validation",
                kind=MissionPhaseKind.VALIDATION,
                depends_on=("enumeration",),
                optional=True,
                estimated_duration_seconds=300,
                actions=("assess.validate",),
            ),
            MissionPhase(
                phase_id="reporting",
                name="Reporting",
                kind=MissionPhaseKind.REPORTING,
                depends_on=("enumeration", "validation"),
                estimated_duration_seconds=120,
                actions=("report.technical",),
            ),
        ),
        objectives=("Identify internet-facing attack surface", "Find exploitable vulnerabilities"),
        allowed_tools={"include": ["nmap", "nuclei", "httpx"], "exclude": ["hydra"]},
        expected_outputs={"reports": ["technical"], "evidence": "required"},
        approval_level=MissionApprovalLevel.OPERATOR,
        risk_model={"formula": "cvss-v3-base-v2"},
        constraints={"max_scan_duration_h": 24, "max_concurrency": 20},
        compliance_map=("owasp-top10",),
    )


def web_pentest_profile() -> MissionProfile:
    """A lightweight web-application profile for tests."""
    return MissionProfile(
        profile_id="web-pentest",
        name="Web Application Pentest",
        description="Web app security assessment.",
        mission_types=(MissionType.WEB_APPLICATION_PENTEST,),
        phases=(
            MissionPhase(
                phase_id="crawl",
                name="Crawling",
                kind=MissionPhaseKind.CRAWLING,
                estimated_duration_seconds=300,
                actions=("crawl.endpoints",),
            ),
            MissionPhase(
                phase_id="fingerprint",
                name="Fingerprinting",
                kind=MissionPhaseKind.FINGERPRINTING,
                depends_on=("crawl",),
                estimated_duration_seconds=200,
                actions=("fingerprint.stack",),
            ),
            MissionPhase(
                phase_id="assess",
                name="Vulnerability Assessment",
                kind=MissionPhaseKind.VULNERABILITY_ASSESSMENT,
                depends_on=("fingerprint",),
                optional=True,
                estimated_duration_seconds=600,
                actions=("assess.vulnerabilities",),
            ),
            MissionPhase(
                phase_id="report",
                name="Reporting",
                kind=MissionPhaseKind.REPORTING,
                depends_on=("assess",),
                estimated_duration_seconds=60,
                actions=("report.technical",),
            ),
        ),
        approval_level=MissionApprovalLevel.AUTO,
    )


def make_api(*, profile: MissionProfile | None = None, event_bus=None, **kwargs: object) -> MissionPlanningAPI:
    """Build a fully wired :class:`MissionPlanningAPI` over in-memory stores."""
    repos = build_in_memory_planning_repositories()
    api = MissionPlanningAPI(
        plans=repos["mission_plans"],  # type: ignore[arg-type]
        profiles=repos["mission_profiles"],  # type: ignore[arg-type]
        templates=repos["mission_templates"],  # type: ignore[arg-type]
        checkpoints=repos["checkpoints"],  # type: ignore[arg-type]
        timeline=repos["mission_timeline"],  # type: ignore[arg-type]
        event_bus=event_bus,
    )
    if profile is not None:
        api.register_profile(profile)
    return api
