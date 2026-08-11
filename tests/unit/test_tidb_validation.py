# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the TIDB validation services."""

from __future__ import annotations

from dataclasses import replace

import pytest

from hunterx.domain.entities.tidb import (
    DNSRecord,
    DnsRecordType,
    Organization,
    Port,
    PortState,
    Program,
    ProgramStatus,
)
from hunterx.domain.exceptions import DomainValidationError
from hunterx.domain.services.validation import (
    EntityTidbValidator,
    EnvelopeTidbValidator,
    TidbValidationResult,
)

sqlalchemy = pytest.importorskip("sqlalchemy")


def test_valid_entity_passes() -> None:
    org = Organization(name="Acme")
    result = EnvelopeTidbValidator().validate(org)
    assert result.valid
    assert result.issues == []


def test_invalid_id_fails() -> None:
    org = Organization(name="Acme")
    bad = replace(org, id="not-a-ulid")
    result = EnvelopeTidbValidator().validate(bad)
    assert not result.valid
    assert any(issue.field == "id" for issue in result.issues)


def test_invalid_timestamp_fails() -> None:
    org = Organization(name="Acme")
    bad = replace(org, created_at="yesterday")
    result = EnvelopeTidbValidator().validate(bad)
    assert not result.valid
    assert any(issue.field == "created_at" for issue in result.issues)


def test_non_positive_version_fails() -> None:
    org = Organization(name="Acme")
    bad = replace(org, version=0)
    result = EnvelopeTidbValidator().validate(bad)
    assert not result.valid
    assert any(issue.field == "version" for issue in result.issues)


def test_deleted_at_timestamp_validated() -> None:
    org = Organization(name="Acme")
    bad = replace(org, deleted_at="nope")
    result = EnvelopeTidbValidator().validate(bad)
    assert not result.valid
    assert any(issue.field == "deleted_at" for issue in result.issues)


def test_entity_validator_rejects_bad_enum() -> None:
    validator = EntityTidbValidator()
    port = Port(ip_address_id="ip", number=80, state=PortState.OPEN)
    assert validator.validate(port).valid

    bad = replace(port, state="bogus")  # type: ignore[arg-type]
    result = validator.validate(bad)
    assert not result.valid
    assert any(issue.field == "state" for issue in result.issues)


def test_entity_validator_accepts_enum_values() -> None:
    validator = EntityTidbValidator()
    prog = Program(organization_id="o", name="p", status=ProgramStatus.ACTIVE)
    dns = DNSRecord(name="a.example.com", record_type=DnsRecordType.A, value="1.2.3.4")
    assert validator.validate(prog).valid
    assert validator.validate(dns).valid


def test_raise_if_invalid_raises() -> None:
    result = TidbValidationResult(valid=False)
    with pytest.raises(DomainValidationError):
        result.raise_if_invalid()


def test_raise_if_invalid_silent_when_valid() -> None:
    TidbValidationResult(valid=True).raise_if_invalid()  # should not raise
