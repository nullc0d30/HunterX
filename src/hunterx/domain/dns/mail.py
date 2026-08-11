# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mail infrastructure intelligence (SPF, DMARC, DKIM).

Analyzes TXT records to determine a domain's mail authentication posture.
Deterministic, explainable checks over raw TXT content.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from hunterx.domain.dns.models import DnsRecord, DnsRecordType, normalize_hostname

#: SPF mechanisms known to be unsafe (soft-fail/permissive).
_SOFTFAIL_MECHANISMS = frozenset({"+all", "~all"})

#: DMARC policies.
_DMARC_POLICIES = frozenset({"none", "quarantine", "reject"})


@dataclass(frozen=True, slots=True)
class MailInfrastructureFinding:
    """The mail authentication posture of a domain.

    Attributes:
        domain: the domain analyzed.
        spf: raw SPF record when present.
        spf_valid: whether the SPF record is syntactically plausible.
        spf_mechanisms: the SPF mechanisms found.
        spf_hardfail: whether ``-all`` terminates the SPF record.
        dmarc_policy: the DMARC policy found (``none``/``quarantine``/``reject``)
            or empty when absent.
        dmarc_rua: the DMARC aggregate reporting address(es) found.
        dkim_selectors: the DKIM selector names observed.
        has_mx: whether an MX record was observed.
        has_dkim: whether any DKIM record was observed.
        confidence: confidence in the finding in ``[0, 1]``.
        details: extra evidence.

    """

    domain: str
    spf: str = ""
    spf_valid: bool = False
    spf_mechanisms: tuple[str, ...] = ()
    spf_hardfail: bool = False
    dmarc_policy: str = ""
    dmarc_rua: tuple[str, ...] = ()
    dkim_selectors: tuple[str, ...] = ()
    has_mx: bool = False
    has_dkim: bool = False
    confidence: float = 0.0
    details: dict[str, object] = field(default_factory=dict)

    @property
    def authenticated(self) -> bool:
        """Return whether the domain is fully mail-authenticated.

        Requires a valid SPF with hard-fail, a DMARC policy (reject or
        quarantine) and a DKIM selector.
        """
        return self.spf_hardfail and self.dmarc_policy in ("reject", "quarantine") and self.has_dkim


class MailAnalyzer:
    """Analyze SPF, DMARC and DKIM records for a domain."""

    def analyze(self, records: list[DnsRecord], *, domain: str = "") -> MailInfrastructureFinding:
        """Analyze ``records`` (TXT/MX/DKIM) for a domain.

        When ``domain`` is omitted the domain is inferred from the MX owner or
        the TXT owner names.
        """
        domain = normalize_hostname(domain or _domain_of(records))
        txt_records = [record for record in records if record.record_type is DnsRecordType.TXT]
        has_mx = any(record.record_type is DnsRecordType.MX for record in records)

        spf, spf_valid, spf_mechanisms, spf_hardfail = self._analyze_spf(txt_records)
        dmarc_policy, dmarc_rua = self._analyze_dmarc(txt_records, domain)
        dkim_selectors = self._analyze_dkim(txt_records, domain)

        checks: list[bool] = [spf_valid]
        if dmarc_policy:
            checks.append(dmarc_policy in _DMARC_POLICIES)
        if dkim_selectors:
            checks.append(True)
        passed = sum(checks)
        total = max(1, len(checks))
        confidence = 0.5 + 0.15 * passed / total if checks else 0.5

        return MailInfrastructureFinding(
            domain=domain,
            spf=spf,
            spf_valid=spf_valid,
            spf_mechanisms=tuple(spf_mechanisms),
            spf_hardfail=spf_hardfail,
            dmarc_policy=dmarc_policy,
            dmarc_rua=tuple(dmarc_rua),
            dkim_selectors=tuple(dkim_selectors),
            has_mx=has_mx,
            has_dkim=bool(dkim_selectors),
            confidence=confidence,
            details={"txt_count": len(txt_records)},
        )

    def _analyze_spf(self, txt_records: list[DnsRecord]) -> tuple[str, bool, list[str], bool]:
        """Extract and validate an SPF record from TXT records."""
        for record in txt_records:
            value = record.value
            if _is_spf(value):
                mechanisms = _extract_spf_mechanisms(value)
                hardfail = _ends_hardfail(mechanisms)
                valid = _validate_spf(value, mechanisms)
                return value, valid, mechanisms, hardfail
        return "", False, [], False

    def _analyze_dmarc(self, txt_records: list[DnsRecord], domain: str) -> tuple[str, tuple[str, ...]]:
        """Extract a DMARC record (owner ``_dmarc.<domain>``)."""
        dmarc_records = [r for r in txt_records if normalize_hostname(r.name).startswith("_dmarc.")]
        for record in dmarc_records:
            value = record.value
            if not value.strip().lower().startswith("v=dmarc1"):
                continue
            policy = _extract_dmarc_policy(value)
            rua = _extract_dmarc_rua(value)
            return policy, tuple(rua)
        return "", ()

    def _analyze_dkim(self, txt_records: list[DnsRecord], domain: str) -> list[str]:
        """Extract DKIM selectors from TXT records under ``*._domainkey``."""
        selectors = []
        for record in txt_records:
            name = normalize_hostname(record.name)
            if name.endswith(f"._domainkey.{domain}") or name.endswith("._domainkey"):
                selector = name.split("._domainkey")[0].rstrip(".")
                if selector and selector not in selectors:
                    selectors.append(selector)
        return selectors


def _is_spf(value: str) -> bool:
    """Return whether a TXT value is an SPF record."""
    return value.strip().lower().startswith("v=spf1")


def _extract_spf_mechanisms(value: str) -> list[str]:
    """Split an SPF record into its mechanisms."""
    parts = value.split()
    return [part for part in parts[1:] if _is_mechanism(part)]


def _is_mechanism(part: str) -> bool:
    """Return whether an SPF token looks like a mechanism (not a modifier)."""
    if "=" in part:
        return False
    return part.startswith(("+", "-", "~", "?")) or part in ("all", "mx", "a", "ptr", "ip4", "ip6")


def _ends_hardfail(mechanisms: list[str]) -> bool:
    """Return whether the SPF record ends in ``-all``."""
    return bool(mechanisms and mechanisms[-1] == "-all")


def _validate_spf(value: str, mechanisms: list[str]) -> bool:
    """Plausibility check: version, at least one mechanism, sane terminator."""
    if not value.strip().lower().startswith("v=spf1"):
        return False
    if not mechanisms:
        return False
    last = mechanisms[-1]
    return last in ("-all", "~all", "?all", "+all") or any(m == "all" for m in mechanisms)


def _extract_dmarc_policy(value: str) -> str:
    """Extract the DMARC ``p=`` policy tag value."""
    match = re.search(r"(?i)(?:^|\s)p\s*=\s*([^;\s]+)", value)
    if match:
        return match.group(1).lower().rstrip(";")
    return ""


def _extract_dmarc_rua(value: str) -> list[str]:
    """Extract the DMARC ``rua=`` reporting addresses."""
    match = re.search(r"(?i)(?:^|\s)rua\s*=\s*([^;\s]+)", value)
    if not match:
        return []
    addresses = match.group(1).split(",")
    return [address.strip() for address in addresses if address.strip()]


def _domain_of(records: list[DnsRecord]) -> str:
    """Infer the domain from the first MX/TXT owner name."""
    for record in records:
        name = record.name
        if name and name != ".":
            return name
    return ""
