# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the DNS intelligence domain: models, normalization, validation,
confidence, wildcard/DNSSEC/mail analysis, correlation, conflicts, scope,
strategy and history."""

from __future__ import annotations

import pytest

from hunterx.domain.dns.confidence import DnsConfidenceEngine, DnsConfidencePolicy
from hunterx.domain.dns.conflicts import DnsConflictResolver
from hunterx.domain.dns.correlator import DnsCorrelator, correlate_records
from hunterx.domain.dns.dnssec import DnssecAnalyzer, algorithm_names
from hunterx.domain.dns.history import DnsHistory
from hunterx.domain.dns.mail import MailAnalyzer
from hunterx.domain.dns.models import (
    DnsRecord,
    DnsRecordType,
    DnsTarget,
    make_record,
    normalize_hostname,
    records_from_payload,
)
from hunterx.domain.dns.normalizer import DnsNormalizer
from hunterx.domain.dns.scope import ScopeEnforcer, ScopePolicy
from hunterx.domain.dns.strategy import DnsStrategyBuilder
from hunterx.domain.dns.validator import DnsValidator
from hunterx.domain.dns.wildcard import WildcardDetector
from hunterx.domain.recon.models import ReconMode


def _record(name: str, record_type: DnsRecordType | str, value: str, **kwargs: object) -> DnsRecord:
    return make_record(name, record_type, value, **kwargs)


class TestDnsRecordModel:
    def test_name_is_normalized(self) -> None:
        record = _record("  WwW.Example.COM. ", DnsRecordType.A, "1.2.3.4")
        assert record.name == "www.example.com"

    def test_empty_name_rejected(self) -> None:
        with pytest.raises(ValueError):
            _record("   ", DnsRecordType.A, "1.2.3.4")

    def test_key_is_name_type_value(self) -> None:
        a = _record("example.com", DnsRecordType.A, "1.2.3.4")
        b = _record("example.com", DnsRecordType.A, "1.2.3.4", tool_id="dnsx")
        assert a.key() == b.key()

    def test_dict_round_trip(self) -> None:
        original = _record("example.com", DnsRecordType.MX, "10 mail.example.com", ttl=3600, priority=10)
        restored = DnsRecord.from_dict(original.to_dict())
        assert restored == original

    def test_records_from_payload(self) -> None:
        record = _record("example.com", DnsRecordType.A, "1.2.3.4")
        payload = {"dns_records": [record.to_dict()]}
        assert records_from_payload(payload) == [record]
        assert records_from_payload(None) == []
        assert records_from_payload({"dns_records": "nope"}) == []

    def test_unknown_type_coerced_to_other(self) -> None:
        record = _record("example.com", "BOGUS", "x")
        assert record.record_type is DnsRecordType.OTHER


class TestDnsTarget:
    def test_defaults(self) -> None:
        target = DnsTarget(value="example.com")
        assert target.target_type == "domain"


class TestDnsNormalizer:
    def test_normalizes_addresses(self) -> None:
        normalizer = DnsNormalizer()
        record = normalizer.normalize(_record("Example.COM", DnsRecordType.A, "1.2.3.4"))
        assert record.name == "example.com"
        assert record.value == "1.2.3.4"

    def test_compresses_ipv6(self) -> None:
        normalizer = DnsNormalizer()
        record = normalizer.normalize(_record("example.com", DnsRecordType.AAAA, "2001:0db8:0000:0000:0000:0000:0000:0001"))
        assert record.value == "2001:db8::1"

    def test_splits_mx_priority(self) -> None:
        normalizer = DnsNormalizer()
        record = normalizer.normalize(_record("example.com", DnsRecordType.MX, "10 mail.example.com"))
        assert record.value == "mail.example.com"
        assert record.priority == 10

    def test_joins_txt_fragments(self) -> None:
        normalizer = DnsNormalizer()
        record = normalizer.normalize(_record("example.com", DnsRecordType.TXT, '"v=spf1" " -all"'))
        assert record.value == "v=spf1 -all"

    def test_normalization_is_idempotent_and_preserves_raw(self) -> None:
        normalizer = DnsNormalizer()
        record = _record("Example.COM", DnsRecordType.A, "1.2.3.4", raw_value="1.2.3.4")
        once = normalizer.normalize(record)
        twice = normalizer.normalize(once)
        assert once == twice
        assert once.raw_value == "1.2.3.4"


class TestDnsValidator:
    def test_valid_a_record(self) -> None:
        validator = DnsValidator()
        result = validator.validate_record(_record("example.com", DnsRecordType.A, "1.2.3.4"))
        assert result.valid
        assert result.status == "valid"

    def test_ipv4_record_holding_ipv6_rejected(self) -> None:
        validator = DnsValidator()
        result = validator.validate_record(_record("example.com", DnsRecordType.A, "::1"))
        assert not result.valid

    def test_invalid_address_rejected(self) -> None:
        validator = DnsValidator()
        result = validator.validate_record(_record("example.com", DnsRecordType.A, "not-an-ip"))
        assert not result.valid

    def test_invalid_hostname_rejected(self) -> None:
        validator = DnsValidator()
        result = validator.validate_record(_record("example.com", DnsRecordType.CNAME, "bad host!!"))
        assert not result.valid

    def test_mx_priority_bounds(self) -> None:
        validator = DnsValidator()
        result = validator.validate_record(_record("example.com", DnsRecordType.MX, "mail.example.com", priority=70000))
        assert not result.valid

    def test_ttl_bounds(self) -> None:
        validator = DnsValidator()
        result = validator.validate_record(_record("example.com", DnsRecordType.A, "1.2.3.4", ttl=2**40))
        assert not result.valid

    def test_srv_shape(self) -> None:
        validator = DnsValidator()
        assert validator.validate_record(_record("sip.example.com", DnsRecordType.SRV, "host 5060 5")).valid
        assert not validator.validate_record(_record("sip.example.com", DnsRecordType.SRV, "garbage")).valid

    def test_caa_shape(self) -> None:
        validator = DnsValidator()
        assert validator.validate_record(_record("example.com", DnsRecordType.CAA, "0 issue letsencrypt.org")).valid
        assert not validator.validate_record(_record("example.com", DnsRecordType.CAA, "notcaa")).valid

    def test_resolution_rcode_consistency(self) -> None:
        from hunterx.domain.dns.models import DNSResolution

        validator = DnsValidator()
        assert validator.validate_resolution(DNSResolution(name="example.com", status="resolved", rcode="NOERROR")).valid
        assert not validator.validate_resolution(DNSResolution(name="example.com", status="resolved", rcode="SERVFAIL")).valid


class TestDnsConfidenceEngine:
    def test_known_tool_scores_higher_than_unknown(self) -> None:
        engine = DnsConfidenceEngine()
        dnsx = engine.record_confidence(_record("example.com", DnsRecordType.A, "1.2.3.4", tool_id="dnsx"))
        unknown = engine.record_confidence(_record("example.com", DnsRecordType.A, "1.2.3.4", tool_id="mystery"))
        assert dnsx > unknown

    def test_invalid_status_reduces_confidence(self) -> None:
        engine = DnsConfidenceEngine()
        valid = engine.record_confidence(_record("example.com", DnsRecordType.A, "1.2.3.4", tool_id="dnsx"))
        invalid = engine.record_confidence(
            DnsRecord(
                name="example.com",
                record_type=DnsRecordType.A,
                value="1.2.3.4",
                tool_id="dnsx",
                validation_status="invalid",
            )
        )
        assert invalid < valid

    def test_resolver_agreement_boosts(self) -> None:
        engine = DnsConfidenceEngine()
        single = engine.record_confidence(_record("example.com", DnsRecordType.A, "1.2.3.4", tool_id="dnsx"))
        dual = engine.record_confidence(
            _record("example.com", DnsRecordType.A, "1.2.3.4", tool_id="dnsx", resolver="1.1.1.1,8.8.8.8")
        )
        assert dual > single

    def test_merged_confidence_corroboration(self) -> None:
        engine = DnsConfidenceEngine()
        alone = engine.merged_confidence([_record("example.com", DnsRecordType.A, "1.2.3.4", tool_id="dnsx")])
        corroborated = engine.merged_confidence(
            [
                _record("example.com", DnsRecordType.A, "1.2.3.4", tool_id="dnsx"),
                _record("example.com", DnsRecordType.A, "1.2.3.4", tool_id="dnspython"),
            ]
        )
        assert corroborated > alone
        assert corroborated <= 1.0

    def test_empty_group_scores_zero(self) -> None:
        engine = DnsConfidenceEngine()
        assert engine.merged_confidence([]) == 0.0

    def test_historical_stability(self) -> None:
        engine = DnsConfidenceEngine()
        unstable = engine.historical_confidence(0.9, observations=1, stable=False)
        stable = engine.historical_confidence(0.9, observations=10, stable=True)
        assert stable >= unstable

    def test_freshness_decay(self) -> None:
        engine = DnsConfidenceEngine()
        fresh = engine.freshness_confidence(0.9, age_hours=0)
        stale = engine.freshness_confidence(0.9, age_hours=48)
        assert fresh == 0.9
        assert stale < fresh
        assert stale >= 0.45


class TestWildcardDetector:
    def _zone_resolver(self, address: str):
        """Resolver that answers random probes but not the apex (catch-all)."""

        def resolve(name: str) -> list[DnsRecord]:
            if name == "example.com":
                return []
            return [_record(name, DnsRecordType.A, address)]

        return resolve

    def test_detects_wildcard(self) -> None:
        detector = WildcardDetector(resolve=self._zone_resolver("192.0.2.10"), probes=4)
        finding = detector.probe("example.com")
        assert finding.wildcard
        assert finding.confidence > 0.5
        assert finding.matching_records()

    def test_no_wildcard_when_answers_differ(self) -> None:
        counts = {"x1": 0, "x2": 0, "x3": 0, "x4": 0}

        def resolve(name: str) -> list[DnsRecord]:
            label = name.split(".")[0]
            counts[label] = counts.get(label, 0) + 1
            return [_record(name, DnsRecordType.A, f"192.0.2.{1 + counts[label]}")]

        detector = WildcardDetector(resolve=resolve, probes=4)
        finding = detector.probe("example.com")
        assert not finding.wildcard

    def test_no_wildcard_when_signature_matches_apex(self) -> None:
        detector = WildcardDetector(
            resolve=lambda name: [_record(name, DnsRecordType.A, "192.0.2.1")],
            probes=4,
        )
        finding = detector.probe("example.com")
        assert not finding.wildcard

    def test_special_names_never_probed(self) -> None:
        detector = WildcardDetector(resolve=lambda name: [_record(name, DnsRecordType.A, "1.1.1.1")])
        finding = detector.probe("foo.localhost")
        assert not finding.wildcard
        assert not finding.probed_names


class TestDnssecAnalyzer:
    def test_secured_zone(self) -> None:
        analyzer = DnssecAnalyzer()
        records = [
            _record("example.com", DnsRecordType.DS, "12345 8 2 abc"),
            _record("example.com", DnsRecordType.DNSKEY, "257 3 8 base64key"),
            _record("example.com", DnsRecordType.RRSIG, "A 8 2 3600 sig"),
        ]
        finding = analyzer.analyze(records)
        assert finding.status == "secured"
        assert finding.secured
        assert finding.confidence == 0.95

    def test_unsecured_zone(self) -> None:
        analyzer = DnssecAnalyzer()
        finding = analyzer.analyze([_record("example.com", DnsRecordType.A, "1.2.3.4")])
        assert finding.status == "unsecured"
        assert not finding.secured

    def test_broken_delegation(self) -> None:
        analyzer = DnssecAnalyzer()
        finding = analyzer.analyze([_record("example.com", DnsRecordType.DS, "12345 8 2 abc")])
        assert finding.status == "broken"

    def test_algorithm_names(self) -> None:
        records = [
            _record("example.com", DnsRecordType.DNSKEY, "257 3 13 base64key"),
            _record("example.com", DnsRecordType.DNSKEY, "257 3 8 base64key2"),
        ]
        assert algorithm_names(records) == ["ECDSAP256SHA256", "RSASHA256"]


class TestMailAnalyzer:
    def test_full_authentication_posture(self) -> None:
        analyzer = MailAnalyzer()
        records = [
            _record("example.com", DnsRecordType.MX, "10 mail.example.com", priority=10),
            _record("example.com", DnsRecordType.TXT, "v=spf1 ip4:192.0.2.0/24 -all"),
            _record("_dmarc.example.com", DnsRecordType.TXT, "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"),
            _record("google._domainkey.example.com", DnsRecordType.TXT, "v=DKIM1; k=rsa; p=abc"),
        ]
        finding = analyzer.analyze(records)
        assert finding.spf_hardfail
        assert finding.spf_valid
        assert finding.dmarc_policy == "reject"
        assert finding.dmarc_rua == ("mailto:dmarc@example.com",)
        assert finding.dkim_selectors == ("google",)
        assert finding.has_mx
        assert finding.has_dkim
        assert finding.authenticated

    def test_softfail_not_authenticated(self) -> None:
        analyzer = MailAnalyzer()
        records = [
            _record("example.com", DnsRecordType.TXT, "v=spf1 ~all"),
            _record("_dmarc.example.com", DnsRecordType.TXT, "v=DMARC1; p=none"),
        ]
        finding = analyzer.analyze(records)
        assert not finding.authenticated
        assert finding.dmarc_policy == "none"

    def test_no_records(self) -> None:
        analyzer = MailAnalyzer()
        finding = analyzer.analyze([])
        assert not finding.has_mx
        assert not finding.spf_valid
        assert finding.confidence >= 0.5


class TestCorrelator:
    def test_merges_corroborating_observations(self) -> None:
        result = correlate_records(
            [
                _record("example.com", DnsRecordType.A, "1.2.3.4", tool_id="dnsx", resolver="1.1.1.1"),
                _record("example.com", DnsRecordType.A, "1.2.3.4", tool_id="dnspython", resolver="8.8.8.8"),
                _record("example.com", DnsRecordType.MX, "10 mail.example.com", priority=10),
            ]
        )
        assert len(result.records) == 2
        a = next(record for record in result.records if record.record_type is DnsRecordType.A)
        assert set(a.resolver.split(",")) == {"1.1.1.1", "8.8.8.8"}
        assert a.confidence > 0.7
        assert result.merged == 1

    def test_detects_value_conflict(self) -> None:
        result = correlate_records(
            [
                _record("example.com", DnsRecordType.A, "1.2.3.4", tool_id="dnsx"),
                _record("example.com", DnsRecordType.A, "5.6.7.8", tool_id="dnspython"),
            ]
        )
        assert len(result.conflicts) == 1
        conflict = result.conflicts[0]
        assert conflict.values == ("1.2.3.4", "5.6.7.8")
        assert conflict.selected in conflict.values

    def test_scope_filters_out_of_scope(self) -> None:
        policy = ScopePolicy(roots=frozenset({"example.com"}))
        result = correlate_records(
            [
                _record("example.com", DnsRecordType.A, "1.2.3.4"),
                _record("evil.org", DnsRecordType.A, "6.7.8.9"),
            ],
            scope=policy,
        )
        assert [record.name for record in result.records] == ["example.com"]
        assert result.scoped_out == 1

    def test_object_correlator(self) -> None:
        correlator = DnsCorrelator()
        result = correlator.correlate([_record("example.com", DnsRecordType.A, "1.2.3.4")])
        assert len(result.records) == 1


class TestConflictResolver:
    def test_most_confident_wins(self) -> None:
        resolver = DnsConflictResolver(strategy="most-confident")
        weak = _record("example.com", DnsRecordType.A, "1.2.3.4", tool_id="mystery")
        strong = _record("example.com", DnsRecordType.A, "5.6.7.8", tool_id="dnsx")
        result = correlate_records([weak, strong])
        conflict = result.conflicts[0]
        selected = resolver.select(conflict, [weak, strong])
        assert selected.value == "5.6.7.8"

    def test_most_recent_wins(self) -> None:
        resolver = DnsConflictResolver(strategy="most-recent")
        old = _record("example.com", DnsRecordType.A, "1.2.3.4", observed_at="2026-01-01T00:00:00+00:00")
        new = _record("example.com", DnsRecordType.A, "5.6.7.8", observed_at="2026-02-01T00:00:00+00:00")
        result = correlate_records([old, new])
        conflict = result.conflicts[0]
        assert resolver.select(conflict, [old, new]).value == "5.6.7.8"

    def test_all_values_joins(self) -> None:
        resolver = DnsConflictResolver(strategy="all-values")
        a = _record("example.com", DnsRecordType.A, "1.2.3.4")
        b = _record("example.com", DnsRecordType.A, "5.6.7.8")
        result = correlate_records([a, b])
        conflict = result.conflicts[0]
        assert resolver.select(conflict, [a, b]).value == "1.2.3.4,5.6.7.8"

    def test_unknown_strategy_rejected(self) -> None:
        with pytest.raises(ValueError):
            DnsConflictResolver(strategy="random")


class TestScopeEnforcer:
    def test_name_within_root(self) -> None:
        policy = ScopePolicy(roots=frozenset({"example.com"}))
        enforcer = ScopeEnforcer(policy)
        assert enforcer.allows_name("www.example.com").allowed
        assert not enforcer.allows_name("example.org").allowed

    def test_excluded_name(self) -> None:
        policy = ScopePolicy(roots=frozenset({"example.com"}), excludes=frozenset({"secret.example.com"}))
        enforcer = ScopeEnforcer(policy)
        assert not enforcer.allows_name("secret.example.com").allowed
        assert enforcer.allows_name("www.example.com").allowed

    def test_address_cidr_restriction(self) -> None:
        policy = ScopePolicy(root_cidrs=frozenset({"192.0.2.0/24"}))
        enforcer = ScopeEnforcer(policy)
        assert enforcer.allows_address("192.0.2.5").allowed
        assert not enforcer.allows_address("203.0.113.5").allowed

    def test_excluded_cidr(self) -> None:
        policy = ScopePolicy(root_cidrs=frozenset({"0.0.0.0/0"}), excluded_cidrs=frozenset({"10.0.0.0/8"}))
        enforcer = ScopeEnforcer(policy)
        assert enforcer.allows_address("8.8.8.8").allowed
        assert not enforcer.allows_address("10.1.2.3").allowed

    def test_record_scope_combines_name_and_value(self) -> None:
        policy = ScopePolicy(
            roots=frozenset({"example.com"}),
            root_cidrs=frozenset({"192.0.2.0/24"}),
        )
        enforcer = ScopeEnforcer(policy)
        assert enforcer.allows_record(_record("www.example.com", DnsRecordType.A, "192.0.2.10")).allowed
        assert not enforcer.allows_record(_record("www.example.com", DnsRecordType.A, "203.0.113.10")).allowed

    def test_filter_records(self) -> None:
        policy = ScopePolicy(roots=frozenset({"example.com"}))
        enforcer = ScopeEnforcer(policy)
        kept = enforcer.filter_records(
            [
                _record("www.example.com", DnsRecordType.A, "1.2.3.4"),
                _record("evil.org", DnsRecordType.A, "6.7.8.9"),
            ]
        )
        assert len(kept) == 1
        assert kept[0].name == "www.example.com"


class TestDnsStrategyBuilder:
    def test_active_domain_plan(self) -> None:
        builder = DnsStrategyBuilder()
        strategy = builder.build("example.com", mode=ReconMode.ACTIVE, target_kind="domain")
        assert DnsRecordType.DNSKEY in strategy.record_types
        assert strategy.with_dnssec
        assert strategy.with_mail
        assert strategy.active_resolvers == ("8.8.8.8", "1.1.1.1")

    def test_host_plan_is_limited(self) -> None:
        builder = DnsStrategyBuilder()
        strategy = builder.build("1.2.3.4", mode=ReconMode.ACTIVE, target_kind="ip")
        assert DnsRecordType.A in strategy.record_types
        assert DnsRecordType.MX not in strategy.record_types

    def test_ip_target_fails_closed_on_resolvers(self) -> None:
        builder = DnsStrategyBuilder()
        strategy = builder.build("192.168.1.1", target_kind="ip")
        assert strategy.active_resolvers == ()

    def test_passive_mode_plan(self) -> None:
        builder = DnsStrategyBuilder()
        types = builder.record_types_for(ReconMode.PASSIVE, "domain")
        assert DnsRecordType.TXT in types
        assert DnsRecordType.DS not in types

    def test_mode_for_coerces(self) -> None:
        builder = DnsStrategyBuilder()
        assert builder.mode_for("active") is ReconMode.ACTIVE
        assert builder.mode_for("garbage") is ReconMode.HYBRID


class TestDnsHistory:
    def test_detects_added_removed_changed(self) -> None:
        history = DnsHistory()
        historical = [
            _record("example.com", DnsRecordType.A, "1.2.3.4", observed_at="2026-01-01T00:00:00+00:00"),
            _record("www.example.com", DnsRecordType.A, "5.6.7.8", observed_at="2026-01-01T00:00:00+00:00"),
        ]
        current = [
            _record("example.com", DnsRecordType.A, "9.9.9.9", observed_at="2026-02-01T00:00:00+00:00"),
            _record("mail.example.com", DnsRecordType.A, "3.3.3.3", observed_at="2026-02-01T00:00:00+00:00"),
        ]
        comparison = history.compare(historical, current)
        kinds = {change.change for change in comparison.changes}
        assert kinds == {"added", "removed", "changed"}
        assert comparison.unchanged == 0
        assert comparison.historical == 2
        assert comparison.current == 2

    def test_unchanged_records_counted(self) -> None:
        history = DnsHistory()
        same = [_record("example.com", DnsRecordType.A, "1.2.3.4")]
        comparison = history.compare(same, same)
        assert comparison.changes == []
        assert comparison.unchanged == 1

    def test_summarize_and_by_name(self) -> None:
        history = DnsHistory()
        comparison = history.compare(
            [_record("example.com", DnsRecordType.A, "1.2.3.4")],
            [_record("example.com", DnsRecordType.A, "9.9.9.9")],
        )
        assert history.summarize(comparison) == {"added": 0, "removed": 0, "changed": 1}
        assert len(history.by_name(comparison, "example.com")) == 1


def test_normalize_hostname() -> None:
    assert normalize_hostname("WwW.Example.COM.") == "www.example.com"


def test_dns_confidence_policy_defaults() -> None:
    policy = DnsConfidencePolicy()
    assert policy.base_for("dnsx") == 0.92
    assert policy.base_for("unknown") == 0.2
