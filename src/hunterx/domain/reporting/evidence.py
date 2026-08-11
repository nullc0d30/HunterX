# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Evidence bundle & integrity builder.

Assembles an immutable evidence bundle referencing raw observations, requests,
responses, tool output, validation results, PoCs and replay results, with
SHA-256 content hashes and full provenance. Full raw evidence stays in the
evidence store; the bundle carries references and hashes, never duplicate
payloads.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.reporting.models import EvidenceArtifact, EvidenceBundle
from hunterx.shared.ids import generate_content_id, generate_id
from hunterx.shared.time import utcnow_iso


@dataclass(frozen=True, slots=True)
class ArtifactInput:
    """One evidence artifact input.

    Attributes:
        kind: artifact kind.
        content: artifact content used for the integrity hash.
        source: producing source.
        timestamp: capture timestamp.
        collector: collecting component.
        tool: producing tool.
        mission_id / target_id / finding_id: ownership identifiers.
        provenance: free-form provenance map.
        redaction_state: redaction state.

    """

    kind: str = "observation"
    content: str = ""
    source: str = ""
    timestamp: str = ""
    collector: str = ""
    tool: str = ""
    mission_id: str = ""
    target_id: str = ""
    finding_id: str = ""
    provenance: dict[str, object] = field(default_factory=dict)
    redaction_state: str = "redacted"


class EvidenceBundleBuilder:
    """Builds immutable, integrity-checked evidence bundles."""

    def build(
        self,
        *,
        finding_id: str,
        artifacts: tuple[ArtifactInput, ...],
        normalized_observations: tuple[str, ...] = (),
        requests: tuple[str, ...] = (),
        response_metadata: tuple[str, ...] = (),
        headers: dict[str, str] | None = None,
        callback_evidence: tuple[str, ...] = (),
        tool_outputs: tuple[str, ...] = (),
        validation_results: tuple[str, ...] = (),
        proof_references: tuple[str, ...] = (),
        replay_results: tuple[str, ...] = (),
    ) -> EvidenceBundle:
        """Build an evidence bundle with integrity hashes.

        Args:
            finding_id: owning finding.
            artifacts: artifact inputs (hashed into the bundle).
            normalized_observations: observation references.
            requests: request references.
            response_metadata: response metadata references.
            headers: safe headers map.
            callback_evidence: controlled callback references.
            tool_outputs: tool output references.
            validation_results: validation result references.
            proof_references: proof/PoC references.
            replay_results: replay result references.

        Returns:
            An immutable :class:`EvidenceBundle`.

        """
        timestamp = utcnow_iso()
        created: list[EvidenceArtifact] = []
        for item in artifacts:
            created.append(
                EvidenceArtifact(
                    artifact_id=generate_id(),
                    kind=item.kind,
                    content_hash=generate_content_id(item.kind, item.content, item.source, item.timestamp),
                    source=item.source,
                    timestamp=item.timestamp or timestamp,
                    collector=item.collector,
                    tool=item.tool,
                    mission_id=item.mission_id,
                    target_id=item.target_id,
                    finding_id=item.finding_id,
                    provenance=item.provenance,
                    redaction_state=item.redaction_state,
                )
            )
        bundle_hash = generate_content_id(
            finding_id,
            *(item.content_hash for item in created),
            tuple(normalized_observations),
            tuple(requests),
            tuple(response_metadata),
            tuple(callback_evidence),
            tuple(tool_outputs),
            tuple(validation_results),
            tuple(proof_references),
            tuple(replay_results),
        )
        return EvidenceBundle(
            bundle_id=generate_id(),
            finding_id=finding_id,
            artifacts=tuple(created),
            normalized_observations=tuple(normalized_observations),
            requests=tuple(requests),
            response_metadata=tuple(response_metadata),
            headers=dict(headers or {}),
            callback_evidence=tuple(callback_evidence),
            tool_outputs=tuple(tool_outputs),
            validation_results=tuple(validation_results),
            proof_references=tuple(proof_references),
            replay_results=tuple(replay_results),
            timestamps=(timestamp,),
            bundle_hash=bundle_hash,
            immutable=True,
            created_at=timestamp,
        )

    @staticmethod
    def verify_integrity(bundle: EvidenceBundle) -> bool:
        """Return ``True`` when the bundle hash matches its artifacts.

        Recomputes the bundle hash from the artifact hashes and compares it to
        the stored ``bundle_hash``; altered evidence therefore fails the check.
        """
        recomputed = generate_content_id(
            bundle.finding_id,
            *(item.content_hash for item in bundle.artifacts),
            tuple(bundle.normalized_observations),
            tuple(bundle.requests),
            tuple(bundle.response_metadata),
            tuple(bundle.callback_evidence),
            tuple(bundle.tool_outputs),
            tuple(bundle.validation_results),
            tuple(bundle.proof_references),
            tuple(bundle.replay_results),
        )
        return recomputed == bundle.bundle_hash


__all__ = ["ArtifactInput", "EvidenceBundleBuilder"]
