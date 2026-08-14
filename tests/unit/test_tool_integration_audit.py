# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the tool integration audit (maturity model).

Verifies the progressive maturity ladder, the knowledge-vs-runtime distinction
and that no tool is ever classified fully integrated without every dimension.
"""

from __future__ import annotations

from hunterx.domain.tool_intelligence import (
    ToolArgument,
    ToolInputContract,
    ToolKnowledge,
    ToolOutputContract,
    ToolSafetyProfile,
)
from hunterx.tools.readiness.audit import (
    IntegrationLevel,
    ToolIntegrationAuditor,
    _derive_level,
)
from hunterx.tools.readiness.definitions import ToolDefinitionBuilder
from tests.framework.readiness import linux_platform, tip_with


def _register_knowledge(tip, tool_id: str) -> None:  # noqa: ANN001
    """Register minimal machine-actionable knowledge for ``tool_id``."""
    tip.register_knowledge(
        ToolKnowledge(
            tool_id=tool_id,
            capabilities=("port-scanning",),
            inputs=ToolInputContract(accepts=("host",), required=("host",)),
            outputs=ToolOutputContract(formats=("xml",), parser="live-observations", normalizer="x"),
            cli_binary=tool_id,
            arguments=(ToolArgument("host", "", "string", required=True, description="Target host."),),
            safe_mode="passive",
            safety_profile=ToolSafetyProfile(safety_class="passive", destructive=False, requires_authorization=False),
        )
    )


class TestMaturityLadder:
    def test_level_ladder_is_progressive(self) -> None:
        # A tool with only identity+capability is KNOWN.
        base = {
            "identity": True,
            "capability": True,
            "discovery": False,
            "installation": False,
            "verification": False,
            "version": False,
            "commands": False,
            "arguments": False,
            "invocation": False,
            "output": False,
            "parser": False,
            "platform": False,
            "safety": False,
        }
        assert _derive_level(base) is IntegrationLevel.KNOWN

        discoverable = dict(base, discovery=True)
        assert _derive_level(discoverable) is IntegrationLevel.DISCOVERABLE

        installable = dict(discoverable, installation=True)
        assert _derive_level(installable) is IntegrationLevel.INSTALLABLE

        verified = dict(installable, verification=True, version=True)
        assert _derive_level(verified) is IntegrationLevel.VERIFIED

        invokable = dict(
            verified,
            commands=True,
            arguments=True,
            invocation=True,
        )
        assert _derive_level(invokable) is IntegrationLevel.INVOKABLE

        parsable = dict(invokable, output=True, parser=True)
        assert _derive_level(parsable) is IntegrationLevel.PARSABLE

        fully = dict(parsable, platform=True, safety=True)
        assert _derive_level(fully) is IntegrationLevel.FULLY_INTEGRATED

    def test_unknown_without_identity(self) -> None:
        dimensions = {"identity": False, "capability": True}
        assert _derive_level(dimensions) is IntegrationLevel.UNKNOWN


class TestAuditor:
    def test_knowledge_without_runtime_is_not_invokable_claim(self) -> None:
        # A tool with complete knowledge but no registered adapter still reports
        # the knowledge dimensions; the runtime flag stays False.
        tip = tip_with(["nmap"])
        _register_knowledge(tip, "nmap")
        auditor = ToolIntegrationAuditor(tip, ToolDefinitionBuilder(tip, linux_platform()))
        audit = auditor.audit_tool("nmap")

        assert audit.dimensions["commands"]
        assert audit.dimensions["parser"]
        assert not audit.runtime

    def test_audit_distinguishes_knowledge_from_runtime(self) -> None:
        tip = tip_with(["nmap"])
        _register_knowledge(tip, "nmap")
        auditor = ToolIntegrationAuditor(tip, ToolDefinitionBuilder(tip, linux_platform()))
        audit = auditor.audit_tool("nmap")

        assert audit.level is not IntegrationLevel.UNKNOWN
        # Knowledge is present even though nothing is installed.
        assert audit.dimensions["identity"] and audit.dimensions["discovery"]
        assert audit.available is False

    def test_report_summary_counts_levels(self) -> None:
        tip = tip_with(["nmap", "ghosttool"])
        auditor = ToolIntegrationAuditor(tip, ToolDefinitionBuilder(tip, linux_platform()))
        report = auditor.audit()

        assert report.summary[IntegrationLevel.UNKNOWN.value] >= 0
        assert sum(report.summary.values()) == len(report.audits)

    def test_missing_dimensions_are_reported(self) -> None:
        tip = tip_with(["ghosttool"])
        auditor = ToolIntegrationAuditor(tip, ToolDefinitionBuilder(tip, linux_platform()))
        audit = auditor.audit_tool("ghosttool")

        assert "installation" in audit.missing
        assert "commands" in audit.missing
        assert audit.level is IntegrationLevel.UNKNOWN or audit.level is IntegrationLevel.KNOWN
