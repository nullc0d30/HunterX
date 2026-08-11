# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Database error recovery tests (Sprint 034.3 §20).

Injects connection failures, constraint violations and transaction rollbacks
and verifies error classification, safe rollback, mission-state preservation and
the absence of evidence corruption.
"""

from __future__ import annotations

import pytest

from hunterx.config.settings import DatabaseSettings
from hunterx.domain.entities.tidb import (
    URL,
    FindingRecord,
    IntelligenceTargetRecord,
)
from hunterx.domain.exceptions import DomainValidationError, NotFoundError
from hunterx.infrastructure.db.sql.crud import SqlCrudRepository
from hunterx.infrastructure.db.sql.factory import SessionFactory

pytest.importorskip("sqlalchemy")


def _is_connection_error(exc: Exception) -> bool:
    from sqlalchemy.exc import OperationalError

    return isinstance(exc, OperationalError)


def test_connection_failure_is_classified_and_safe(session_factory) -> None:
    """A dead database URL must raise a connection-class error and leave the
    repository usable for later operations."""
    broken = SqlCrudRepository(
        SessionFactory(DatabaseSettings(url="sqlite:///C:/__hunterx_does_not_exist__/no.db")),
        IntelligenceTargetRecord,
    )
    with pytest.raises(Exception) as excinfo:
        broken.save(IntelligenceTargetRecord(target_id="tgt-conn", value="x.example.com"))
    assert _is_connection_error(excinfo.value)

    # The healthy repository still works.
    repo = SqlCrudRepository(session_factory, IntelligenceTargetRecord)
    repo.save(IntelligenceTargetRecord(target_id="tgt-ok", value="ok.example.com"))
    assert repo.count() == 1


def test_constraint_violation_classified_and_rolled_back(sql_factory) -> None:
    """A duplicate canonical URL must raise an integrity-class error and roll
    back so no duplicate is persisted."""
    from sqlalchemy.exc import IntegrityError

    url_repo = sql_factory.repository_for(URL)
    url_repo.save(URL(url="https://c.example.com/", host="c.example.com"))
    with pytest.raises(IntegrityError):
        url_repo.save(URL(url="https://c.example.com/", host="other.example.com"))
    assert url_repo.count() == 1


def test_validation_error_classification(sql_factory) -> None:
    repo = sql_factory.repository_for(IntelligenceTargetRecord)
    with pytest.raises(DomainValidationError):
        repo.save(IntelligenceTargetRecord(id="not-a-valid-ulid", target_id="x", value="y"))


def test_not_found_classification(sql_factory) -> None:
    repo = sql_factory.repository_for(IntelligenceTargetRecord)
    with pytest.raises(NotFoundError):
        repo.get_or_raise("does-not-exist")


def test_mission_state_preserved_after_failure(sql_factory) -> None:
    """A failed write must not corrupt previously persisted mission state."""
    target_repo = sql_factory.repository_for(IntelligenceTargetRecord)
    target = IntelligenceTargetRecord(
        target_id="tgt-mission", value="mission.example.com", status="active", phase="recon"
    )
    target_repo.save(target)

    # Trigger a failure on an unrelated write.
    url_repo = sql_factory.repository_for(URL)
    url_repo.save(URL(url="https://d.example.com/", host="d.example.com"))
    with pytest.raises(Exception):
        url_repo.save(URL(url="https://d.example.com/", host="other.example.com"))

    loaded = target_repo.get(target.id)
    assert loaded is not None
    assert loaded.status == "active"
    assert loaded.phase == "recon"


def test_no_evidence_corruption_after_failure(sql_factory) -> None:
    """A failed write must not corrupt persisted evidence rows."""
    finding_repo = sql_factory.repository_for(FindingRecord)
    finding = FindingRecord(finding_id="F-safe", target_id="tgt-1", title="safe", evidence_refs=["ev-1"])
    finding_repo.save(finding)

    with pytest.raises(DomainValidationError):
        finding_repo.save(
            FindingRecord(id="not-a-valid-ulid", finding_id="F-bad", target_id="tgt-1", title="bad")
        )

    loaded = finding_repo.get(finding.id)
    assert loaded is not None
    assert loaded.evidence_refs == ["ev-1"]
    assert loaded.title == "safe"
