# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Duplicate control tests (Sprint 034.3 §12).

Canonical uniqueness: assets, URLs, services, observations, findings,
evidence fingerprints and tool executions. The same observation from Nmap,
Naabu and Masscan must remain separately attributable while resolving into
canonical target intelligence.
"""

from __future__ import annotations

import pytest

from hunterx.domain.entities.tidb import (
    URL,
    Domain,
    FindingRecord,
    IntelligenceAssetRecord,
    IPAddress,
    ObservationRecord,
    Port,
    Service,
)

pytest.importorskip("sqlalchemy")


def test_canonical_url_cannot_duplicate(sql_factory) -> None:
    repo = sql_factory.repository_for(URL)
    repo.save(URL(url="https://example.com/", host="example.com"))
    with pytest.raises(Exception):
        repo.save(URL(url="https://example.com/", host="other.example.com"))
    assert repo.count() == 1


def test_canonical_domain_cannot_duplicate(sql_factory) -> None:
    repo = sql_factory.repository_for(Domain)
    repo.save(Domain(name="example.com", target_id="tgt-1"))
    with pytest.raises(Exception):
        repo.save(Domain(name="example.com", target_id="tgt-2"))
    assert repo.count() == 1


def test_canonical_ip_cannot_duplicate(sql_factory) -> None:
    repo = sql_factory.repository_for(IPAddress)
    repo.save(IPAddress(address="192.0.2.10", hostname_id="h-1"))
    with pytest.raises(Exception):
        repo.save(IPAddress(address="192.0.2.10", hostname_id="h-2"))
    assert repo.count() == 1


def test_canonical_port_is_unique_per_ip(sql_factory) -> None:
    repo = sql_factory.repository_for(Port)
    repo.save(Port(ip_address_id="ip-1", number=443, protocol="tcp"))
    with pytest.raises(Exception):
        repo.save(Port(ip_address_id="ip-1", number=443, protocol="tcp"))
    # A different ip may carry the same port number.
    repo.save(Port(ip_address_id="ip-2", number=443, protocol="tcp"))
    assert repo.count() == 2


def test_finding_identity_is_protected_by_primary_key(sql_factory) -> None:
    """The finding service sets ``id=finding_id``; a duplicate finding_id is
    therefore an upsert, never a second row."""
    from hunterx.shared.ids import generate_id

    repo = sql_factory.repository_for(FindingRecord)
    fid = generate_id()
    first = FindingRecord(id=fid, finding_id=fid, target_id="tgt-1", title="SQLi")
    repo.save(first)
    second = FindingRecord(id=fid, finding_id=fid, target_id="tgt-1", title="SQLi again")
    repo.save(second)
    assert repo.count() == 1
    loaded = repo.get(fid)
    assert loaded is not None and loaded.title == "SQLi again"


def test_same_observation_from_multiple_tools_stays_attributable(backend_factory) -> None:
    """Nmap, Naabu and Masscan can each report the same port; the records stay
    distinct and attributable while carrying the same canonical dedup_key."""
    repo = backend_factory.repository_for(ObservationRecord)
    repo.save_many(
        [
            ObservationRecord(
                observation_id=f"obs-{tool}",
                target_id="tgt-1",
                mission_id="mis-1",
                tool=tool,
                value="443/tcp open",
                normalized_value="tcp/443",
                dedup_key="port|tgt-1|443/tcp",
            )
            for tool in ("nmap", "naabu", "masscan")
        ]
    )
    records = list(repo.list_by("target_id", "tgt-1", limit=10))
    assert {r.tool for r in records} == {"nmap", "naabu", "masscan"}
    # All resolve to the same canonical normalized observation.
    assert {r.normalized_value for r in records} == {"tcp/443"}
    assert {r.dedup_key for r in records} == {"port|tgt-1|443/tcp"}


def test_service_canonical_uniqueness_via_composite_key(sql_factory) -> None:
    """Distinct services on the same port coexist; there is no duplicate-
    suppression conflict between them."""
    repo = sql_factory.repository_for(Service)
    repo.save(Service(port_id="p-1", name="https"))
    repo.save(Service(port_id="p-1", name="https-alt"))
    assert repo.count() == 2


def test_asset_canonical_key_is_application_deduped(memory_factory) -> None:
    """Intelligence assets use the canonical ``asset_key`` (kind:name) for
    application-layer dedup; re-saving the same asset (same envelope id)
    overwrites rather than duplicates."""
    from hunterx.shared.ids import generate_id

    repo = memory_factory.repository_for(IntelligenceAssetRecord)
    aid = generate_id()
    repo.save(IntelligenceAssetRecord(id=aid, asset_id="a-1", target_id="tgt-1", asset_key="domain:example.com", name="example.com"))
    repo.save(IntelligenceAssetRecord(id=aid, asset_id="a-1", target_id="tgt-1", asset_key="domain:example.com", name="example.com"))
    assert repo.count() == 1
