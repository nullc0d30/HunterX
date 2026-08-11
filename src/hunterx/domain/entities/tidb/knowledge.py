# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Knowledge-base Target Intelligence Database entities.

Mirrored global reference data (CVE/CWE/CAPEC/EPSS/MITRE) and exploit
references. These tables are read-mostly and synced by the knowledge mirror
syncers; they must never be written by capability logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.entities.tidb._base import TidbEntity


@dataclass(slots=True)
class CVE(TidbEntity):
    """A mirrored CVE record.

    Attributes:
        cve_id: canonical CVE identifier (e.g. ``CVE-2024-1234``).
        description: vulnerability description.
        cvss_v2: CVSS v2 base score.
        cvss_v3: CVSS v3.x base score.
        cvss_v4: CVSS v4 base score.
        published: publication timestamp (ISO).
        last_modified: last-modification timestamp (ISO).
        vendor: affected vendor.
        product: affected product.
        known_exploited: whether CISA KEV marks it exploited.
        poc_available: whether a public PoC exists.

    """

    cve_id: str
    description: str = ""
    cvss_v2: float | None = None
    cvss_v3: float | None = None
    cvss_v4: float | None = None
    published: str | None = None
    last_modified: str | None = None
    vendor: str | None = None
    product: str | None = None
    known_exploited: bool = False
    poc_available: bool = False


@dataclass(slots=True)
class CWE(TidbEntity):
    """A mirrored CWE record.

    Attributes:
        cwe_id: canonical CWE identifier (e.g. ``CWE-79``).
        name: weakness name.
        description: weakness description.
        mitigations: list of mitigation strings.
        related_cwes: list of related CWE ids.
        taxonomy: map of taxonomy references (OWASP, etc.).

    """

    cwe_id: str
    name: str = ""
    description: str = ""
    mitigations: list[str] = field(default_factory=list)
    related_cwes: list[str] = field(default_factory=list)
    taxonomy: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class CAPEC(TidbEntity):
    """A mirrored CAPEC attack pattern.

    Attributes:
        capec_id: canonical CAPEC identifier (e.g. ``CAPEC-242``).
        name: pattern name.
        description: pattern description.
        prerequisites: list of prerequisites.
        steps: list of attack steps.
        related_weaknesses: list of related CWE ids.
        severity_hint: severity hint.

    """

    capec_id: str
    name: str = ""
    description: str = ""
    prerequisites: list[str] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)
    related_weaknesses: list[str] = field(default_factory=list)
    severity_hint: str | None = None


@dataclass(slots=True)
class EPSS(TidbEntity):
    """A mirrored EPSS score for a CVE.

    Attributes:
        cve_id: referenced CVE.
        score: EPSS score in ``[0, 1]``.
        percentile: EPSS percentile in ``[0, 1]``.
        score_date: score publication date.
        source: data source name.

    """

    cve_id: str
    score: float = 0.0
    percentile: float = 0.0
    score_date: str | None = None
    source: str = "first.org"


@dataclass(slots=True)
class MITRETechnique(TidbEntity):
    """A mirrored MITRE ATT&CK technique.

    Attributes:
        technique_id: ATT&CK technique id (e.g. ``T1059``).
        name: technique name.
        description: technique description.
        tactics: list of tactic ids.
        subtechniques: list of subtechnique ids.
        detection: detection guidance.
        mitigations: list of mitigations.
        platforms: list of platforms.

    """

    technique_id: str
    name: str = ""
    description: str = ""
    tactics: list[str] = field(default_factory=list)
    subtechniques: list[str] = field(default_factory=list)
    detection: str = ""
    mitigations: list[str] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)


@dataclass(slots=True)
class MITRETactic(TidbEntity):
    """A mirrored MITRE ATT&CK tactic.

    Attributes:
        tactic_id: tactic id (e.g. ``TA0001``).
        name: tactic name.
        description: tactic description.
        techniques: list of technique ids under this tactic.

    """

    tactic_id: str
    name: str = ""
    description: str = ""
    techniques: list[str] = field(default_factory=list)


@dataclass(slots=True)
class MITREGroup(TidbEntity):
    """A mirrored MITRE ATT&CK threat group.

    Attributes:
        group_id: group id (e.g. ``G0007``).
        name: group name.
        aliases: list of group aliases.
        description: group description.
        techniques: list of technique ids attributed to the group.
        software: list of software ids attributed to the group.

    """

    group_id: str
    name: str = ""
    aliases: list[str] = field(default_factory=list)
    description: str = ""
    techniques: list[str] = field(default_factory=list)
    software: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ExploitReference(TidbEntity):
    """A reference to a public exploit for a CVE.

    Attributes:
        cve_id: referenced CVE.
        source: source name (exploit-db, metasploit, github, ...).
        url: exploit URL.
        kind: poc|module|writeup|... .
        published: publication timestamp (ISO).
        verified: whether the exploit has been verified.

    """

    cve_id: str
    source: str = ""
    url: str | None = None
    kind: str = "poc"
    published: str | None = None
    verified: bool = False
