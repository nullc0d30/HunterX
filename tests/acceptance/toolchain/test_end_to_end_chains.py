# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""End-to-end toolchain chains (Sprint 034.5).

Runs representative chains through the ChainExecutor with a fixture-driven
engine wired into the composed platform, proving the required flows:

- recon:   subfinder/amass → dnsx → httpx → katana → ffuf → nuclei
- api:     graphql discovery → inql → nuclei
- secrets: gitleaks → trufflehog → semgrep
- web:     nuclei → dalfox → sqlmap → verification
- cloud:   cloud-analysis (in-process)
"""

from __future__ import annotations

import pytest

from hunterx.domain.execution import (
    ExecutionOutput,
    ExecutionResult,
    ExecutionStatus,
)
from hunterx.platform import build_platform
from hunterx.tools.sdk.engine import ExecutionEngine
from hunterx.tools.sdk.pipeline import PipelineResult
from hunterx.tools.sdk.session import ExecutionSession

#: tool_id → fixture JSON payload (canonical records per family).
_FIXTURE_OUTPUTS: dict[str, dict] = {
    "subfinder": {"discoveries": [{"kind": "subdomain", "name": "api.example.com"}, {"kind": "subdomain", "name": "www.example.com"}]},
    "amass": {"discoveries": [{"kind": "subdomain", "name": "api.example.com"}]},
    "dnsx": {"dns_records": [{"name": "api.example.com", "record_type": "A", "response": "1.2.3.4"}]},
    "httpx": {"requests": [{"url": "https://api.example.com"}, {"url": "https://www.example.com"}]},
    "nikto": {"requests": [{"url": "https://api.example.com"}]},
    "katana": {"urls": [{"url": "https://api.example.com/admin"}, {"url": "https://api.example.com/api/users"}]},
    "gospider": {"urls": [{"url": "https://api.example.com/contact"}]},
    "ffuf": {"content": {"requests": [{"url": "https://api.example.com/admin", "status": 200}]}},
    "gobuster": {"content": {"requests": [{"url": "https://api.example.com/admin", "status": 200}]}},
    "arjun": {"parameters": {"findings": [{"name": "id", "endpoint": "https://api.example.com/search"}]}},
    "paramspider": {"parameters": {"findings": [{"name": "q", "endpoint": "https://api.example.com/search"}]}},
    "kiterunner": {"parameters": {"findings": [{"name": "", "endpoint": "https://api.example.com/api"}]}},
    "nuclei": {"candidates": [{"template_id": "cve-2021-0001", "severity": "high", "requires_validation": True, "confidence": 0.6}]},
    "dalfox": {"candidates": [{"vulnerability_class": "xss", "requires_validation": True, "confidence": 0.6, "detail": "XSS"}]},
    "sqlmap": {"candidates": [{"vulnerability_class": "sql-injection", "requires_validation": True, "confidence": 0.6, "detail": "SQLi"}]},
    "gitleaks": {"secrets": {"findings": [{"secret_type": "aws-access-token", "fingerprint": "abc", "masked_value": "AKIA***"}]}},
    "trufflehog": {"secrets": {"findings": [{"secret_type": "AWS", "fingerprint": "def", "masked_value": "AKIA***"}]}},
    "semgrep": {"candidates": [{"vulnerability_class": "sast", "check_id": "python.eval", "requires_validation": True, "confidence": 0.7}]},
    "api-graphql": {"apis": [{"type": "api-host", "url": "https://api.example.com"}]},
    "inql": {"apis": [{"type": "graphql-introspection", "endpoint": "https://api.example.com/graphql"}]},
    "graphqlmap": {"apis": [{"type": "graphql-introspection", "endpoint": "https://api.example.com/graphql"}]},
    "cloud-analysis": {"observations": [{"kind": "cloud-resource", "value": "arn:aws:s3:::bucket"}]},
    "prowler": {"observations": [{"kind": "cloud-resource", "value": "arn:aws:s3:::bucket", "finding": "publicly-accessible"}]},
    "scoutsuite": {"observations": [{"kind": "cloud-resource", "value": "arn:aws:iam::123:role/app"}]},
    "passive-probe": {"observations": [{"kind": "probe", "value": "reachable"}]},
    "proof-replay": {"observations": [{"kind": "proof", "value": "replayed"}]},
}

#: Chains to certify: (name, capabilities, target, target_type, expected_status)
_CHAINS = [
    pytest.param(
        "recon-to-vulnerability",
        [
            "subdomain-discovery",
            "dns-records",
            "http-probing",
            "web-crawling",
            "historical-url-discovery",
            "parameter-discovery",
            "directory-discovery",
            "vulnerability-scan",
        ],
        "example.com",
        "domain",
        "completed",
        id="recon-dns-probe-crawl-url-param-content-vuln",
    ),
    pytest.param(
        "api-chain",
        ["graphql-testing", "graphql-introspection", "vulnerability-scan"],
        "https://api.example.com/graphql",
        "url",
        "completed",
        id="api-graphql-vuln",
    ),
    pytest.param(
        "secrets-chain",
        ["secrets-scan", "static-analysis"],
        "/repo",
        "path",
        "completed",
        id="repo-secrets-sast",
    ),
    pytest.param(
        "web-vuln-chain",
        ["vulnerability-scan", "xss-detection", "sqli-detection"],
        "https://api.example.com",
        "url",
        "completed",
        id="web-vuln-verification",
    ),
    pytest.param(
        "cloud-chain",
        ["cloud-assessment"],
        "arn:aws:iam::123:role/app",
        "cloud-resource",
        "completed",
        id="cloud-saas",
    ),
]


def _fixture_engine(planned_tools: list[str], failures: dict[str, str] | None = None) -> ExecutionEngine:
    """Build an engine returning canned fixture output per planned tool.

    Adapters are registered for the planned tools plus every fixture provider
    so capability-equivalent fallbacks can be exercised at runtime.
    """

    class FakeEngine(ExecutionEngine):
        def __init__(self, *a, **k):
            self._adapters = {tool: object() for tool in sorted(set(planned_tools) | set(_FIXTURE_OUTPUTS))}

        def adapter_for(self, tool_id):
            return self._adapters.get(tool_id)

        def execute(self, context):
            out = ExecutionOutput()
            failure = failures.get(context.tool_id) if failures else None
            if failure:
                out.exit_code = 1
                out.stderr = failure
                result = ExecutionResult(
                    execution_id=context.execution_id, tool_id=context.tool_id,
                    status=ExecutionStatus.FAILED, output=out, error=failure,
                )
            else:
                out.exit_code = 0
                out.json = _FIXTURE_OUTPUTS.get(context.tool_id, {})
                result = ExecutionResult(
                    execution_id=context.execution_id, tool_id=context.tool_id,
                    status=ExecutionStatus.COMPLETED, output=out,
                )
            return PipelineResult(result=result, session=ExecutionSession(context), attempts=1)

    return FakeEngine()


@pytest.mark.parametrize(("name", "capabilities", "target", "target_type", "expected"), _CHAINS)
def test_end_to_end_chain(name, capabilities, target, target_type, expected):
    platform = build_platform()
    service = platform.toolchain_service
    plan = service.chain(name, list(capabilities), scope="scoped")
    planned_tools = {step["tool_id"] for step in plan["steps"]}
    # Every planned tool must be a registered tool with a defined contract.
    for tool in planned_tools:
        contract = service.contract(tool)
        assert contract["support_level"] in ("fully-supported", "execution-only", "partial-support")
    service._engine = _fixture_engine(sorted(planned_tools))
    report = service.execute_chain(name, list(capabilities), target, target_type=target_type, scope="scoped")
    assert report["status"] == expected
    assert report["observation_count"] >= 1
    for step in report["steps"]:
        for observation in step["observations"]:
            assert observation["provenance"]["source"] == step["tool_id"]
            assert observation["raw_artifact_reference"].startswith("exec://")


def test_intelligence_reuse_across_chains():
    """Observations from one chain feed a later chain without losing provenance."""
    platform = build_platform()
    service = platform.toolchain_service
    plan = service.chain("recon", ["subdomain-discovery", "http-probing"])
    planned_tools = {step["tool_id"] for step in plan["steps"]}
    service._engine = _fixture_engine(sorted(planned_tools))
    first = service.execute_chain("recon", ["subdomain-discovery", "http-probing"], "example.com", target_type="domain")
    assert first["observation_count"] >= 1
    # The discovered subdomain became reusable target intelligence.
    domain_observations = [
        obs["normalized_value"]
        for step in first["steps"]
        for obs in step["observations"]
        if obs["observation_kind"] == "domain"
    ]
    assert "api.example.com" in domain_observations


def test_chain_failure_falls_back_to_equivalent_tool():
    platform = build_platform()
    service = platform.toolchain_service
    plan = service.chain("recon", ["subdomain-discovery"])
    primary = plan["steps"][0]["tool_id"]
    # Force the primary tool to fail; the executor should fall back to a
    # capability-equivalent tool and still complete.
    service._engine = _fixture_engine([primary], failures={primary: "crashed"})
    report = service.execute_chain("recon", ["subdomain-discovery"], "example.com", target_type="domain")
    assert report["status"] == "completed"
