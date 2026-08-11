# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the reconnaissance domain: models, confidence and correlation."""

from __future__ import annotations

from hunterx.domain.recon.confidence import ConfidenceEngine
from hunterx.domain.recon.correlator import ReconCorrelator
from hunterx.domain.recon.models import (
    DiscoveryKind,
    DiscoveryRecord,
    ReconBatch,
    ReconExecutionSummary,
    ReconMode,
    ReconTarget,
    infer_ip_version,
)


def _record(kind: DiscoveryKind, name: str, tool: str, *, source: str = "", confidence: float = 1.0) -> DiscoveryRecord:
    return DiscoveryRecord(kind=kind, name=name, tool_id=tool, source=source, confidence=confidence)


class TestDiscoveryRecord:
    def test_name_is_normalised(self) -> None:
        record = DiscoveryRecord(kind=DiscoveryKind.SUBDOMAIN, name="  WwW.Example.COM ", tool_id="subfinder")
        assert record.name == "www.example.com"

    def test_empty_name_rejected(self) -> None:
        import pytest

        with pytest.raises(ValueError):
            DiscoveryRecord(kind=DiscoveryKind.DOMAIN, name="   ", tool_id="subfinder")

    def test_keys_are_kind_specific(self) -> None:
        sub = _record(DiscoveryKind.SUBDOMAIN, "www.example.com", "subfinder")
        domain = _record(DiscoveryKind.DOMAIN, "www.example.com", "amass")
        assert sub.key() != domain.key()
        assert sub.key() == "subdomain:www.example.com"

    def test_asn_key_uses_number(self) -> None:
        a = _record(DiscoveryKind.ASN, "AS13335", "amass", confidence=1.0)
        b = _record(DiscoveryKind.ASN, "13335", "bbot", confidence=1.0)
        assert a.key() == b.key() == "asn:13335"

    def test_dns_key_combines_fields(self) -> None:
        a = _record(
            DiscoveryKind.DNS_RECORD,
            "example.com",
            "subfinder",
            confidence=1.0,
        )
        assert a.key() == "dns:example.com||"
        with_records = DiscoveryRecord(
            kind=DiscoveryKind.DNS_RECORD,
            name="example.com",
            tool_id="subfinder",
            details={"record_type": "A", "value": "1.2.3.4"},
        )
        assert with_records.key() == "dns:example.com|A|1.2.3.4"

    def test_certificate_key_uses_fingerprint(self) -> None:
        a = DiscoveryRecord(kind=DiscoveryKind.CERTIFICATE, name="sha256:abc", tool_id="amass")
        b = DiscoveryRecord(
            kind=DiscoveryKind.CERTIFICATE,
            name="sha256:abc",
            tool_id="subfinder",
            details={"sha256": "abc"},
        )
        assert a.key() == b.key()

    def test_round_trip_dict(self) -> None:
        original = _record(DiscoveryKind.IP_ADDRESS, "1.2.3.4", "bbot", source="passive", confidence=0.7)
        restored = DiscoveryRecord.from_dict(original.to_dict())
        assert restored == original
        assert restored.key() == original.key()


class TestReconBatch:
    def test_aggregation_helpers(self) -> None:
        batch = ReconBatch(
            mission_id="m1",
            correlation_id="c1",
            target=ReconTarget(value="example.com"),
            mode=ReconMode.PASSIVE,
        )
        batch.add_record(_record(DiscoveryKind.SUBDOMAIN, "a.example.com", "subfinder"))
        batch.add_records([_record(DiscoveryKind.SUBDOMAIN, "b.example.com", "amass")])
        batch.add_execution(ReconExecutionSummary(tool_id="subfinder", status="completed", records=1))
        assert batch.count() == 2
        assert batch.distinct() == 2
        assert len(batch.by_kind(DiscoveryKind.SUBDOMAIN)) == 2
        assert len(batch.executions) == 1

    def test_duplicate_assets_count_once(self) -> None:
        batch = ReconBatch(mission_id="m", correlation_id="c", target=ReconTarget(value="example.com"))
        batch.add_records(
            [
                _record(DiscoveryKind.SUBDOMAIN, "a.example.com", "subfinder"),
                _record(DiscoveryKind.SUBDOMAIN, "a.example.com", "amass"),
            ]
        )
        assert batch.count() == 2
        assert batch.distinct() == 1


class TestConfidenceEngine:
    def test_source_confidence_respects_tool_and_kind(self) -> None:
        engine = ConfidenceEngine()
        assert engine.source_confidence("subfinder", DiscoveryKind.SUBDOMAIN) > engine.source_confidence(
            "theharvester", DiscoveryKind.SUBDOMAIN
        )

    def test_unknown_tool_scores_low(self) -> None:
        engine = ConfidenceEngine()
        assert engine.source_confidence("mystery-tool", DiscoveryKind.SUBDOMAIN) <= 0.2

    def test_corroboration_boosts_confidence(self) -> None:
        engine = ConfidenceEngine()
        alone = engine.merged_confidence([_record(DiscoveryKind.SUBDOMAIN, "a.example.com", "subfinder")])
        corroborated = engine.merged_confidence(
            [
                _record(DiscoveryKind.SUBDOMAIN, "a.example.com", "subfinder"),
                _record(DiscoveryKind.SUBDOMAIN, "a.example.com", "amass"),
            ]
        )
        assert corroborated > alone
        assert corroborated <= 1.0

    def test_merged_confidence_is_clamped(self) -> None:
        engine = ConfidenceEngine()
        many = engine.merged_confidence(
            [
                _record(DiscoveryKind.SUBDOMAIN, "a.example.com", "subfinder", confidence=1.0),
                _record(DiscoveryKind.SUBDOMAIN, "a.example.com", "amass", confidence=1.0),
                _record(DiscoveryKind.SUBDOMAIN, "a.example.com", "bbot", confidence=1.0),
                _record(DiscoveryKind.SUBDOMAIN, "a.example.com", "findomain", confidence=1.0),
            ]
        )
        assert many == 1.0


class TestReconCorrelator:
    def test_deduplicates_across_tools(self) -> None:
        correlator = ReconCorrelator()
        merged = correlator.correlate(
            [
                _record(DiscoveryKind.SUBDOMAIN, "a.example.com", "subfinder", source="crt.sh"),
                _record(DiscoveryKind.SUBDOMAIN, "a.example.com", "amass", source="passive"),
                _record(DiscoveryKind.SUBDOMAIN, "b.example.com", "assetfinder"),
            ]
        )
        assert len(merged) == 2
        a = next(record for record in merged if record.name == "a.example.com")
        assert set(a.details["tools"]) == {"subfinder", "amass"}
        assert a.confidence > 0.8

    def test_scope_filters_hostname_like_records(self) -> None:
        correlator = ReconCorrelator()
        merged = correlator.correlate(
            [
                _record(DiscoveryKind.SUBDOMAIN, "a.example.com", "subfinder"),
                _record(DiscoveryKind.SUBDOMAIN, "evil.org", "subfinder"),
                _record(DiscoveryKind.IP_ADDRESS, "10.0.0.1", "bbot"),
                _record(DiscoveryKind.CIDR, "10.0.0.0/24", "bbot"),
            ],
            scope="example.com",
        )
        names = {record.name for record in merged}
        assert "a.example.com" in names
        assert "evil.org" not in names
        assert "10.0.0.1" in names  # address-space records always kept

    def test_scope_matches_bare_domain(self) -> None:
        correlator = ReconCorrelator()
        merged = correlator.correlate(
            [_record(DiscoveryKind.DOMAIN, "example.com", "amass")],
            scope="example.com",
        )
        assert len(merged) == 1

    def test_merge_preserves_strongest_tool_and_target(self) -> None:
        correlator = ReconCorrelator()
        weak = _record(DiscoveryKind.SUBDOMAIN, "a.example.com", "assetfinder", confidence=0.4)
        strong = _record(DiscoveryKind.SUBDOMAIN, "a.example.com", "subfinder", confidence=1.0)
        strong = DiscoveryRecord(
            kind=strong.kind,
            name=strong.name,
            tool_id=strong.tool_id,
            confidence=strong.confidence,
            target_id="target-123",
        )
        merged = correlator.correlate([weak, strong], scope="")
        assert len(merged) == 1
        record = merged[0]
        assert record.tool_id == "subfinder"
        assert record.target_id == "target-123"

    def test_correlate_sorts_by_kind_then_name(self) -> None:
        correlator = ReconCorrelator()
        merged = correlator.correlate(
            [
                _record(DiscoveryKind.SUBDOMAIN, "z.example.com", "subfinder"),
                _record(DiscoveryKind.DOMAIN, "example.com", "subfinder"),
            ]
        )
        assert [record.kind for record in merged] == [DiscoveryKind.DOMAIN, DiscoveryKind.SUBDOMAIN]


def test_infer_ip_version() -> None:
    assert infer_ip_version("1.2.3.4") == 4
    assert infer_ip_version("::1") == 6
    assert infer_ip_version("not-an-ip") == 4
