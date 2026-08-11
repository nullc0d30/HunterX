# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""In-process JavaScript intelligence analyzer adapter.

The binary-free analysis path for the JavaScript Intelligence & Client-Side
Attack-Surface Discovery capability. The adapter runs the versioned detection
rules through the domain :class:`AnalyzerSet`, the secret scanner with strict
masking, and the technology/dependency detectors over one script source, and
emits a normalized per-asset :class:`JSAssetAnalysis`.

``run`` needs no network: content is passed through the execution parameters
(``content``/``url``), so unit tests stay hermetic:
``JavaScriptAnalyzerAdapter().run(context, collector)``.
"""

from __future__ import annotations

from hunterx.domain.javascript.analyzers import AnalyzeContext
from hunterx.domain.javascript.models import JSAssetAnalysis, JSEvidence
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.javascript.base import JavaScriptToolAdapter

_VERSION = "1.0.0"


class JavaScriptAnalyzerAdapter(JavaScriptToolAdapter):
    """SDK adapter running the full in-process JavaScript analysis pipeline.

    The adapter exposes a ``descriptor`` for registration and an execution
    lifecycle so it participates in the standard pipeline, but ``run`` analyses
    supplied script content in-process rather than invoking an external tool.
    """

    descriptor = ToolDescriptor(
        name="javascript",
        version=_VERSION,
        description=(
            "In-process JavaScript intelligence: tokenizer, versioned detection "
            "rules, endpoints/routes/configuration/storage/auth/workers/wasm/"
            "security/dynamic-import/service/domain analyzers, secret scanning "
            "with strict masking and technology/dependency detection."
        ),
        entrypoint="hunterx.tools.javascript.analyzer:JavaScriptAnalyzerAdapter",
        targets=("host", "domain", "url", "script"),
        capabilities=("javascript-analysis", "client-side-discovery", "secret-scanning"),
        permissions=("none",),
        parameters={
            "content": {"type": "string", "description": "JavaScript source to analyse."},
            "url": {"type": "string", "description": "Absolute URL of the asset."},
            "asset_kind": {"type": "string", "description": "Asset kind (external/inline/bundle/...)."},
            "content_hash": {"type": "string", "description": "Stable content hash for deduplication."},
            "parent_url": {"type": "string", "description": "Page URL that referenced the script."},
        },
    )

    def __init__(self) -> None:
        from hunterx.domain.javascript.analyzers import AnalyzerSet
        from hunterx.domain.javascript.secrets import JSSecretScanner
        from hunterx.domain.javascript.technology import JSDependencyDetector, JSTechnologyDetector

        self._analyzers = AnalyzerSet()
        self._secrets = JSSecretScanner()
        self._technology = JSTechnologyDetector()
        self._dependencies = JSDependencyDetector()

    def analyze(self, source: str, context: AnalyzeContext) -> JSAssetAnalysis:
        """Run the full analysis pipeline over ``source``."""
        analyzers = self._analyzers
        analysis = JSAssetAnalysis(asset=None)  # type: ignore[arg-type]  # asset set by base.run
        analysis.endpoints = analyzers.endpoint.analyze(source, context)
        analysis.routes = analyzers.route.analyze(source, context)
        analysis.configuration = analyzers.configuration.analyze(source, context)
        analysis.storage = analyzers.storage.analyze(source, context)
        analysis.auth = analyzers.authentication.analyze(source, context)
        analysis.workers = analyzers.worker.analyze(source, context)
        analysis.wasm = analyzers.wasm.analyze(source, context)
        analysis.security = analyzers.security.analyze(source, context)
        analysis.dynamic_imports = analyzers.dynamic_import.analyze(source, context)
        analysis.services = analyzers.service.analyze(source, context)
        analysis.domains = analyzers.domain.analyze(source, context)
        analysis.secrets = self._secrets.scan(source, context)
        analysis.technology = [detection.evidence for detection in self._technology.detect(source, context)]
        analysis.dependencies = self._dependencies.detect(source, context)
        analysis.evidence = self._collect_evidence(analysis)
        return analysis

    def _collect_evidence(self, analysis: JSAssetAnalysis) -> list[JSEvidence]:
        """Merge evidence fragments from every finding, deduplicated."""
        seen: set[str] = set()
        merged: list[JSEvidence] = []
        for finding in self._findings(analysis):
            for item in getattr(finding, "evidence", None) or ():
                if not isinstance(item, JSEvidence):
                    continue
                digest = getattr(item, "integrity", "") or f"{item.location}:{item.value}"
                if digest in seen:
                    continue
                seen.add(digest)
                merged.append(item)
        return merged

    def _findings(self, analysis: JSAssetAnalysis) -> list[object]:
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
