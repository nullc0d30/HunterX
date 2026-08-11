# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Built-in parsers and canonical normalizers for the Tool Intelligence Layer.

These reference implementations show how raw tool output becomes structured
records (parsers) and then canonical observations (normalizers). Integrated
tools ship their own parser/normalizer pair in their integration pack; these
built-ins cover the common JSON/JSONL/text shapes and the core observation
kinds (domain, url, ip, port, technology).
"""

from __future__ import annotations

import json
from typing import Any

from hunterx.domain.tool_intelligence import CanonicalObservation


def _parse_records(raw: Any, metadata: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse ``raw`` into a list of record mappings.

    Accepts a JSON string, a list of mappings, a single mapping, or newline
    separated JSON (JSONL). Returns an empty list when nothing parseable is
    present — the caller decides whether empty output is an error.
    """
    if raw is None:
        return []
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    if isinstance(raw, dict):
        return [raw]
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return []
        records: list[dict[str, Any]] = []
        try:
            parsed = json.loads(text)
        except (ValueError, TypeError):
            parsed = None
        if isinstance(parsed, dict):
            return [parsed]
        if isinstance(parsed, list):
            return [item for item in parsed if isinstance(item, dict)]
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except (ValueError, TypeError):
                continue
            if isinstance(item, dict):
                records.append(item)
        return records
    return []


def _kind(record: dict[str, Any]) -> str:
    return str(record.get("observation_kind") or record.get("kind") or "other")


def _common(
    record: dict[str, Any],
    metadata: dict[str, Any],
    kind: str,
    value: str = "",
    normalized: str = "",
) -> CanonicalObservation:
    tool_id = str(metadata.get("tool_id", ""))
    target_id = str(record.get("target_id") or metadata.get("target_id", ""))
    value = value or str(record.get("value") or record.get("name") or "")
    normalized = normalized or value
    correlation_key = str(record.get("correlation_key") or "")
    if not correlation_key and kind and target_id and normalized:
        correlation_key = f"{kind}:{target_id}:{normalized}"
    observation_id = str(record.get("observation_id") or "")
    if not observation_id and tool_id and correlation_key:
        observation_id = f"{tool_id}-{correlation_key}"
    return CanonicalObservation(
        observation_id=observation_id,
        target_id=target_id,
        tool_id=tool_id,
        observation_kind=kind,
        value=value,
        normalized_value=normalized,
        asset_id=str(record.get("asset_id", "")),
        tool_version=str(metadata.get("tool_version", "")),
        confidence=float(record.get("confidence", 1.0)),
        timestamp=str(record.get("timestamp", "")),
        source=str(record.get("source", tool_id)),
        raw_artifact_reference=str(record.get("raw_artifact_reference", "")),
        correlation_key=correlation_key,
        provenance=dict(record.get("provenance") or {}),
    )


def _normalize_default(record: dict[str, Any], metadata: dict[str, Any]) -> CanonicalObservation:
    """Normalize a generic record without a specialised normalizer."""
    return _common(record, metadata, _kind(record))


def _normalize_domain(record: dict[str, Any], metadata: dict[str, Any]) -> CanonicalObservation:
    """Normalize a domain observation."""
    domain = str(
        record.get("domain")
        or record.get("name")
        or record.get("value")
        or ""
    ).strip().lower()
    return _common(
        record,
        metadata,
        "domain",
        value=domain,
        normalized=domain,
    )


def _normalize_url(record: dict[str, Any], metadata: dict[str, Any]) -> CanonicalObservation:
    """Normalize a URL observation."""
    url = str(record.get("url") or record.get("value") or "").strip()
    return _common(record, metadata, "url", value=url, normalized=url)


def _normalize_ip(record: dict[str, Any], metadata: dict[str, Any]) -> CanonicalObservation:
    """Normalize an IP observation."""
    ip = str(record.get("ip") or record.get("address") or record.get("value") or "").strip()
    return _common(record, metadata, "ip", value=ip, normalized=ip)


def _normalize_port(record: dict[str, Any], metadata: dict[str, Any]) -> CanonicalObservation:
    """Normalize a port observation."""
    port = str(record.get("port") or record.get("value") or "").strip()
    return _common(record, metadata, "port", value=port, normalized=port)


def _normalize_technology(record: dict[str, Any], metadata: dict[str, Any]) -> CanonicalObservation:
    """Normalize a technology observation."""
    tech = str(record.get("name") or record.get("technology") or record.get("value") or "").strip()
    return _common(record, metadata, "technology", value=tech, normalized=tech)
