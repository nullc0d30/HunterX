# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Base adapter for JavaScript intelligence tools.

Every JavaScript tool adapter implements the SDK :class:`ToolAdapter` lifecycle
and shares this base. JavaScript analysis is an in-process capability: the
adapter receives already-acquired script content through the execution
parameters (no binary, no subprocess), runs the domain analyzers and secret/
technology/dependency detectors, and serialises the per-asset analysis into the
pipeline's JSON payload under the ``javascript`` key exactly as
:func:`~hunterx.domain.javascript.models.findings_from_payload` expects.

Adapters stay content-free in unit tests: tests inject source text and assert
on the JSON payload without touching the network.
"""

from __future__ import annotations

import abc
import time

from hunterx.domain.execution import ExecutionContext, ExecutionOutput
from hunterx.domain.javascript.analyzers import AnalyzeContext
from hunterx.domain.javascript.models import JSAcquisition, JSAssetAnalysis, JSAssetKind, findings_from_payload
from hunterx.domain.tools import ToolDescriptor
from hunterx.domain.vulnerability_capability.probe_executor import is_loopback_target
from hunterx.plugins.sdk.results import EvidenceResult, FindingResult
from hunterx.tools.adapter import ToolOutput
from hunterx.tools.sdk.adapter import ToolAdapter
from hunterx.tools.sdk.output import OutputCollector
from hunterx.tools.web.httpclient import HttpPageFetcher


class JavaScriptToolAdapter(ToolAdapter, abc.ABC):
    """Shared base for in-process JavaScript intelligence adapters.

    Subclasses must declare a ``descriptor`` and implement :meth:`analyze`,
    which runs the domain analyzers over one script source and returns the
    resulting :class:`JSAssetAnalysis`. The default :meth:`run` builds the
    acquisition + analysis context from the execution parameters, records the
    analysis and writes the normalized JSON payload.
    """

    #: Static descriptor; subclasses must set this.
    descriptor: ToolDescriptor

    def prepare(self, context: ExecutionContext) -> None:
        """No setup required for in-process analyzers; hook kept for parity."""

    def cleanup(self, context: ExecutionContext) -> None:
        """Nothing to release; hook kept for parity."""

    # -- adapter contract ----------------------------------------------------

    @abc.abstractmethod
    def analyze(self, source: str, context: AnalyzeContext) -> JSAssetAnalysis:
        """Analyze one script source and return the per-asset analysis."""

    def run(self, context: ExecutionContext, collector: OutputCollector) -> None:
        """Analyze the supplied script content and emit the JS payload."""
        params = context.parameters or {}
        source = _param_str(params.get("content"))
        url = _param_str(params.get("url")) or (context.target or "")
        if not source and not url:
            collector.set_exit_code(1)
            collector.attach_stderr("no script content or URL provided")
            collector.set_json({"javascript": {"analyses": []}})
            return
        if not source and url:
            # The mission schedules JS analysis against a discovered script
            # asset; acquire the script content in-process (loopback-only).
            source, ok = _fetch_script(url)
            if not ok:
                collector.set_exit_code(1)
                collector.attach_stderr(f"failed to acquire script content from {url}")
                collector.set_json({"javascript": {"analyses": []}})
                return
        acquisition = self._acquisition(context, url)
        analyze_context = AnalyzeContext(
            file=url or "inline",
            target_key=context.target,
            correlation_id=context.correlation_id,
            mission_id=context.mission_id,
            tool_id=context.tool_id,
            source_label="javascript",
        )
        analysis = self.analyze(source, analyze_context)
        analysis.asset = acquisition
        collector.set_exit_code(0)
        collector.set_json({"javascript": {"analyses": [analysis.to_dict()]}})

    def validate_output(self, context: ExecutionContext, output: ExecutionOutput) -> tuple[bool, list[str]]:
        """Validate collected output; empty analysis sets are valid results."""
        errors: list[str] = []
        if output.exit_code != 0:
            errors.append(f"exit code {output.exit_code}")
        return (not errors, errors)

    def normalize(self, context: ExecutionContext, output: ExecutionOutput) -> ToolOutput:
        """Project JavaScript analyses into the canonical tool output."""
        tool_output = ToolOutput()
        if output.stdout:
            tool_output.raw = output.stdout
        analyses = findings_from_payload(output.json)
        for analysis in analyses:
            tool_output.assets.append(analysis.asset.to_dict())
            for finding in _iter_findings(analysis):
                tool_output.findings.append(_finding_result(finding, context))
            for evidence in analysis.evidence:
                tool_output.evidence.append(_evidence_result(evidence))
        if output.stderr:
            tool_output.error = output.stderr
        return tool_output

    # -- helpers -------------------------------------------------------------

    def _acquisition(self, context: ExecutionContext, url: str) -> JSAcquisition:
        """Build the acquisition record from execution context and parameters."""
        params = context.parameters or {}
        kind_value = _param_str(params.get("asset_kind"), "external")
        try:
            asset_kind = JSAssetKind(kind_value)
        except ValueError:
            asset_kind = JSAssetKind.EXTERNAL
        return JSAcquisition(
            url=url,
            origin=_origin_of(url),
            parent_url=_param_str(params.get("parent_url")),
            asset_kind=asset_kind,
            status_code=_param_int(params.get("status_code")),
            content_type=_param_str(params.get("content_type")) or None,
            content_length=_param_int(params.get("content_length")),
            etag=_param_str(params.get("etag")) or None,
            last_modified=_param_str(params.get("last_modified")) or None,
            sha256=_param_str(params.get("sha256")),
            content_hash=_param_str(params.get("content_hash")),
            size=_param_int(params.get("size")) or 0,
            source=_param_str(params.get("source"), "crawl"),
            tool_id=context.tool_id,
            target_key=context.target,
            mission_id=context.mission_id,
            execution_id=context.execution_id,
            correlation_id=context.correlation_id,
        )


def _iter_findings(analysis: JSAssetAnalysis) -> list[object]:
    """Return every finding of an analysis as its domain object."""
    findings: list[object] = []
    for field_name in (
        "endpoints",
        "routes",
        "auth",
        "domains",
        "services",
        "storage",
        "secrets",
        "technology",
        "dependencies",
        "configuration",
        "workers",
        "wasm",
        "security",
        "dynamic_imports",
    ):
        findings.extend(getattr(analysis, field_name) or ())
    return findings


def _finding_result(finding: object, context: ExecutionContext) -> FindingResult:
    """Project a finding into the canonical :class:`FindingResult` shape."""
    data = getattr(finding, "to_dict", None)
    payload = data() if callable(data) else {}
    metadata = dict(payload)
    value = metadata.pop("url", None) or metadata.pop("route", None) or metadata.pop("domain", None) or metadata.pop("location", None) or context.target
    confidence = metadata.pop("confidence", None)
    if confidence is not None:
        metadata["confidence"] = confidence
    return FindingResult(
        title=metadata.pop("kind", None) or metadata.pop("classification", None) or type(finding).__name__,
        severity=_severity(finding),
        target=str(value),
        description="",
        risk_score=None,
        metadata=metadata,
    )


def _evidence_result(evidence: object) -> EvidenceResult:
    """Project a domain evidence record into :class:`EvidenceResult`."""
    content = getattr(evidence, "content", None) or getattr(evidence, "to_dict", None)
    if callable(content):
        content = content()
    return EvidenceResult(content=str(content) if content is not None else "")


def _severity(finding: object) -> str:
    """Derive a severity name for a finding."""
    tier = getattr(finding, "tier", None)
    if tier is not None:
        value = str(tier.value if hasattr(tier, "value") else tier).lower()
        if value in ("critical", "high", "medium", "low", "info"):
            return "high" if value == "critical" else value if value != "info" else "low"
    confidence = getattr(finding, "confidence", 0) or 0
    return "medium" if confidence >= 0.9 else "low"


def _fetch_script(url: str) -> tuple[str, bool]:
    """Acquire script content for ``url`` (loopback-only) or return empty.

    A bounded retry absorbs transient connection resets from busy local
    servers (dev/test targets close idle or loaded connections aggressively),
    so script acquisition is robust inside a mission run.
    The retry window must be wider than the reset storm: after a heavy
    toolchain burst a busy server keeps resetting new
    connections for several seconds, and a 3-attempt flat retry exhausts its
    budget inside that window, permanently losing the asset. Five attempts
    with linear backoff (0.5-2.5s sleeps) ride out the storm while staying
    strictly bounded — no unbounded retry is possible.
    """
    if not is_loopback_target(url):
        return "", False
    for attempt in range(5):
        try:
            page = HttpPageFetcher().fetch(url)
        except Exception:  # noqa: BLE001 - acquisition failures must never escape
            time.sleep(0.5 * (attempt + 1))
            continue
        if page.status_code == 200 and page.content:
            return page.content, True
        if page.status_code == 200:
            return "", False
        # status 0 = connection/transport failure; retry against the busy server.
        time.sleep(0.5 * (attempt + 1))
    return "", False


def _origin_of(url: str) -> str:
    """Return ``scheme://host[:port]`` of ``url`` or ``""``."""
    import urllib.parse

    if "://" not in url:
        return ""
    try:
        parsed = urllib.parse.urlsplit(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    except ValueError:
        return ""


def _param_str(value: object, default: str = "") -> str:
    if isinstance(value, str):
        return value
    return str(value) if value is not None else default


def _param_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None
