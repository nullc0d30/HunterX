# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Core Target Intelligence Database entities.

Organizations, programs and scope policies form the authorization envelope of
HunterX. Asset groups and tags organise discovered resources across missions.
The ``Target`` entity itself lives in ``hunterx.domain.entities.target`` and is
extended with scope-program linkage there; this module focuses on the entities
that organise and classify targets.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from hunterx.domain.entities.tidb._base import TidbEntity


class ScopeStatus(Enum):
    """Whether a target is authorised for interrogation."""

    IN_SCOPE = "in-scope"
    OUT_OF_SCOPE = "out-of-scope"
    PENDING_REVIEW = "pending-review"


class ProgramStatus(Enum):
    """Lifecycle of an engagement program."""

    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    ARCHIVED = "archived"


@dataclass(slots=True)
class Organization(TidbEntity):
    """An organisation that owns programs and targets.

    Attributes:
        name: organisation name.
        description: optional free-form description.
        website: optional public website.
        industry: optional industry sector.
        external_id: optional identifier in an external CRM/asset system.

    """

    name: str
    description: str = ""
    website: str | None = None
    industry: str | None = None
    external_id: str | None = None


@dataclass(slots=True)
class Program(TidbEntity):
    """A grouping of missions under one engagement, scope and retention policy.

    Attributes:
        organization_id: owning organization.
        name: program name.
        description: optional description.
        status: lifecycle state.
        starts_at: testing window start (UTC ISO-8601).
        ends_at: testing window end (UTC ISO-8601).
        retention_days: optional data-retention override (``None`` = policy default).

    """

    organization_id: str
    name: str
    description: str = ""
    status: ProgramStatus = ProgramStatus.ACTIVE
    starts_at: str | None = None
    ends_at: str | None = None
    retention_days: int | None = None


@dataclass(slots=True)
class ScopePolicy(TidbEntity):
    """Rules governing what a program may and may not touch.

    Attributes:
        program_id: owning program.
        name: policy name.
        rules: list of rule dicts ``{kind, value, action: allow|deny, note}``.
        destructive_allowed: whether destructive actions are permitted.
        approval_required_for: list of actions needing explicit approval.
        windows: list of allowed test windows ``{start, end, timezone}``.

    """

    program_id: str
    name: str = "default"
    rules: list[dict[str, object]] = field(default_factory=list)
    destructive_allowed: bool = False
    approval_required_for: list[str] = field(default_factory=list)
    windows: list[dict[str, object]] = field(default_factory=list)


@dataclass(slots=True)
class AssetGroup(TidbEntity):
    """A named, hierarchical group of assets.

    Attributes:
        name: group name.
        program_id: optional owning program.
        parent_id: identifier of the parent group (self-referencing hierarchy).
        description: optional description.

    """

    name: str
    program_id: str | None = None
    parent_id: str | None = None
    description: str = ""


@dataclass(slots=True)
class Tag(TidbEntity):
    """A classification label attachable to any entity.

    Attributes:
        name: tag name.
        color: optional UI hint (hex).
        category: optional tag taxonomy bucket.

    """

    name: str
    color: str | None = None
    category: str | None = None
