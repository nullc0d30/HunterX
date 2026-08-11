# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""WSDL / SOAP parser.

In-process parser that models a WSDL 1.1/2.0 document into canonical SOAP API
intelligence operations: services, ports, port types and operations with
parameter style. Parsing is bounded to the WSDL structure (no deep XSD schema
traversal) and never issues network traffic.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from xml.etree.ElementTree import Element  # nosec B405 - type-only annotation; parsing uses defusedxml

from defusedxml.common import DefusedXmlException
from defusedxml.ElementTree import ParseError
from defusedxml.ElementTree import fromstring as xml_fromstring

from hunterx.domain.api.models import (
    ApiEvidence,
    ApiKind,
    ApiOperationObservation,
    APISpecObservation,
    ApiSurfaceForm,
    EvidenceStrength,
    EvidenceType,
    normalize_path,
    operation_hash,
)

_WSDL20_NS = "http://www.w3.org/ns/wsdl"


@dataclass(frozen=True, slots=True)
class SoapParseResult:
    """The parsed contents of one WSDL document.

    Attributes:
        spec: the located spec observation.
        operations: SOAP operations parsed from the document.
        services: detected service names.

    """

    spec: APISpecObservation
    operations: tuple[ApiOperationObservation, ...] = ()
    services: tuple[str, ...] = ()

    def __len__(self) -> int:
        """Return the number of operations."""
        return len(self.operations)


class SoapParser:
    """Parse WSDL documents into canonical SOAP operations.

    Usage::

        parser = SoapParser()
        result = parser.parse(wsdl_text, source_url="https://.../service.wsdl")
    """

    def __init__(self, *, max_operations: int = 2000, max_spec_size_bytes: int = 5 * 1024 * 1024) -> None:
        self._max_operations = max_operations
        self._max_spec_size_bytes = max_spec_size_bytes

    def parse(self, document: str | bytes, *, source_url: str = "") -> SoapParseResult:
        """Parse a WSDL XML document."""
        raw = _as_text(document)
        if len(raw.encode("utf-8")) > self._max_spec_size_bytes:
            raise ValueError(f"WSDL document exceeds size cap of {self._max_spec_size_bytes} bytes")
        try:
            root = xml_fromstring(raw)
        except (ParseError, DefusedXmlException) as exc:
            raise ValueError(f"invalid WSDL document: {exc}") from exc

        services = _services(root)
        operations = _operations(root, services, source_url)
        origin = _origin(source_url)
        spec = APISpecObservation(
            source_url=source_url,
            spec_type="wsdl",
            format="xml",
            spec_version=_version(root),
            title=_title(root) or (services[0] if services else ""),
            operation_count=len(operations),
            schema_count=0,
            integrity=hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32],
            size_bytes=len(raw.encode("utf-8")),
            origin_key=origin,
            confidence=0.95,
            evidence=(
                ApiEvidence(
                    evidence_type=EvidenceType.SPEC_DOCUMENT,
                    value="wsdl document",
                    source=source_url or "soap",
                    strength=EvidenceStrength.STRONG,
                    tool_id="api-soap",
                ),
            ),
            source="api-soap",
            tool_id="api-soap",
        )
        return SoapParseResult(
            spec=spec,
            operations=tuple(operations[: self._max_operations]),
            services=tuple(services),
        )


def _services(root: Element) -> list[str]:
    """Extract service names from a WSDL document."""
    services: list[str] = []
    for element in _iter_elements(root, ("service",)):
        name = element.get("name")
        if name and name not in services:
            services.append(str(name))
    return services


def _operations(
    root: Element,
    services: Sequence[str],
    source_url: str,
) -> list[ApiOperationObservation]:
    """Extract portType operations as canonical SOAP operations."""
    operations: list[ApiOperationObservation] = []
    seen: set[tuple[str, str]] = set()
    origin = _origin(source_url)
    for port_type in _iter_elements(root, ("portType",)):
        port_name = str(port_type.get("name") or "")
        for element in port_type:
            operation_name = str(element.get("name") or "")
            if not operation_name:
                continue
            key = (port_name, operation_name)
            if key in seen:
                continue
            seen.add(key)
            path = f"/{port_name}/{operation_name}" if port_name else f"/{operation_name}"
            normalized = normalize_path(path)
            operations.append(
                ApiOperationObservation(
                    origin_key=origin,
                    method="POST",
                    path=path,
                    normalized_path=normalized,
                    path_hash=operation_hash("POST", normalized),
                    operation_id=operation_name,
                    api_kind=ApiKind.SOAP,
                    surface_form=ApiSurfaceForm.WSDL,
                    documented=True,
                    tags=tuple(services) or (port_name,),
                    content_type="text/xml",
                    response_content_type="text/xml",
                    confidence=0.95,
                    sources=(source_url or "api-soap",),
                    evidence=(
                        ApiEvidence(
                            evidence_type=EvidenceType.SPEC_DOCUMENT,
                            value=f"soap operation {operation_name}",
                            source=source_url or "soap",
                            strength=EvidenceStrength.STRONG,
                            tool_id="api-soap",
                        ),
                    ),
                    source="api-soap",
                    tool_id="api-soap",
                )
            )
    return operations


def _iter_elements(root: Element, names: tuple[str, ...]) -> list[Element]:
    """Return matching child elements ignoring namespace prefixes."""
    result: list[Element] = []
    for element in root.iter():
        local = element.tag.rsplit("}", 1)[-1]
        if local in names:
            result.append(element)
    return result


def _version(root: Element) -> str:
    """Detect WSDL 1.1 vs 2.0 from the root tag."""
    if _WSDL20_NS in root.tag:
        return "2.0"
    return "1.1"


def _title(root: Element) -> str:
    """Extract the WSDL document title if present."""
    for element in _iter_elements(root, ("documentation",)):
        text = (element.text or "").strip()
        if text:
            return text[:255]
    return ""


def _origin(source_url: str) -> str:
    """Derive the origin of a WSDL document from its URL."""
    from hunterx.domain.api.models import origin_of

    return origin_of(source_url) if source_url else "unknown"


def _as_text(document: str | bytes) -> str:
    """Decode bytes safely."""
    if isinstance(document, bytes):
        return document.decode("utf-8", errors="replace")
    return str(document)
