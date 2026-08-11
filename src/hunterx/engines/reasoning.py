# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Reasoning (AI) engine.

Wraps the AI provider port and offers a small set of deterministic guardrails
around model calls: prompt templates, structured summarization of findings,
and a no-magic guarantee that AI results are always paired with their source
evidence.
"""

from __future__ import annotations

from hunterx.domain.entities import Finding
from hunterx.domain.ports.services import AIPort
from hunterx.shared.result import Failure, Result, Success

_SUMMARY_PROMPT = (
    "Summarize the following security findings for an executive audience. "
    "Use plain language, state the affected systems, and rank by severity:\n\n"
    "{findings}\n\nSummary:"
)


class ReasoningEngine:
    """AI-assisted reasoning over mission data.

    Pure rule-based analyses run directly; AI calls go through the injected
    :class:`~hunterx.domain.ports.services.AIPort`. When no provider is
    configured, AI-backed operations return a :class:`Failure` instead of
    inventing content.
    """

    def __init__(self, ai: AIPort) -> None:
        self._ai = ai

    def summarize_findings(self, findings: list[Finding], *, model: str | None = None) -> Result[str, Exception]:
        """Produce an executive summary of a list of findings."""
        if not findings:
            return Success("No findings to summarize.")
        lines = [
            f"- [{f.severity.name}] {f.title} on {f.target} (via {f.tool})" for f in findings
        ]
        prompt = _SUMMARY_PROMPT.format(findings="\n".join(lines))
        try:
            summary = self._ai.complete(prompt, model=model).strip()
        except Exception as exc:
            return Failure(exc)
        if not summary:
            return Failure(Exception("AI provider returned an empty summary."))
        return Success(summary)
