# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool integration completeness gate (CI).

Every tool HunterX publicly claims to integrate must have machine-actionable
knowledge — a registry that is "just a list of names" is a CI failure.

The gate enforces:

1. Every claimed tool has at least identity + capability + discovery knowledge
   (it is discoverable, not merely named).
2. The audit is internally consistent: a tool's derived maturity level always
   matches its actual dimensions (no false ``FULLY_INTEGRATED`` claims) and a
   ``FULLY_INTEGRATED`` tool has every dimension present.
3. A quality floor: most claimed tools reach ``FULLY_INTEGRATED`` (command,
   argument, invocation, output, parser, platform and safety knowledge all
   present). Tools that honestly cannot (e.g. no reliable version probe) are
   classified at a lower level with the missing dimensions reported — never
   silently upgraded.
"""

from __future__ import annotations

from hunterx.platform import build_platform
from hunterx.tools.readiness.audit import IntegrationLevel, _derive_level
from hunterx.tools.readiness.manifest import CLAIMED_EXTERNAL_TOOLS

_ALL_DIMENSIONS = {
    "identity", "capability", "discovery", "installation", "verification",
    "version", "commands", "arguments", "invocation", "output", "parser",
    "platform", "safety",
}

#: Claimed tools that honestly cannot reach FULLY_INTEGRATED because they lack
#: a reliable version probe or a trusted install method. Kept explicit so the
#: audit never silently reclassifies them.
_KNOWN_HONEST_LIMITATIONS = {
    "kiterunner": ("installation", "verification"),
    "massdns": ("verification",),
    "waybackurls": ("verification",),
    "xssstrike": ("verification",),
}


def _audit():
    platform = build_platform()
    return platform.tool_readiness_service.audit(
        list(CLAIMED_EXTERNAL_TOOLS), refresh_availability=False
    )


class TestClaimedToolMinimumKnowledge:
    def test_every_claimed_tool_is_discoverable(self) -> None:
        report = _audit()
        below = [a for a in report.audits if a.level.value == IntegrationLevel.UNKNOWN.value]
        assert not below, f"claimed tools with no identity/capability/discovery: {below}"

        for audit in report.audits:
            assert audit.dimensions["identity"], audit.tool_id
            assert audit.dimensions["capability"], audit.tool_id
            assert audit.dimensions["discovery"], audit.tool_id

    def test_claimed_tools_have_declared_installation(self) -> None:
        report = _audit()
        # Every claimed tool either declares install methods or is honestly
        # classified lower with the reason reported.
        for audit in report.audits:
            if audit.dimensions["installation"]:
                continue
            assert audit.tool_id in _KNOWN_HONEST_LIMITATIONS, audit.tool_id
            assert "installation" in audit.missing, audit.tool_id


class TestAuditConsistency:
    def test_derived_level_matches_dimensions(self) -> None:
        report = _audit()
        for audit in report.audits:
            expected = _derive_level(audit.dimensions)
            assert expected is audit.level, (
                f"{audit.tool_id}: dimensions imply {expected.value}, audit reported {audit.level.value}"
            )

    def test_fully_integrated_requires_every_dimension(self) -> None:
        report = _audit()
        for audit in report.audits:
            if audit.level is not IntegrationLevel.FULLY_INTEGRATED:
                continue
            missing = [d for d in _ALL_DIMENSIONS if not audit.dimensions.get(d)]
            assert not missing, f"{audit.tool_id} claimed fully integrated but missing {missing}"

    def test_level_ladder_is_respected(self) -> None:
        report = _audit()
        for audit in report.audits:
            if audit.level is IntegrationLevel.FULLY_INTEGRATED:
                continue
            # A lower level must have a concrete, reported reason.
            assert audit.missing, f"{audit.tool_id} is {audit.level.value} without any missing dimension"


class TestQualityFloor:
    def test_majority_of_claimed_tools_are_fully_integrated(self) -> None:
        report = _audit()
        fully = sum(1 for a in report.audits if a.level is IntegrationLevel.FULLY_INTEGRATED)
        assert fully >= 30, f"only {fully}/{len(report.audits)} claimed tools fully integrated"

    def test_honest_limitations_are_reported(self) -> None:
        report = _audit()
        by_id = {a.tool_id: a for a in report.audits}
        for tool_id, missing in _KNOWN_HONEST_LIMITATIONS.items():
            audit = by_id[tool_id]
            assert audit.level is not IntegrationLevel.FULLY_INTEGRATED, tool_id
            for dimension in missing:
                assert not audit.dimensions[dimension], f"{tool_id}: {dimension} should be absent"
