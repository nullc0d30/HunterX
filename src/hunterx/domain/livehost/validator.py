# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Live Host & Service Discovery observation validator.

Validates raw discovery output before it is trusted: canonical addresses, port
ranges, protocol/state spellings, service fingerprints, TLS certificate
metadata and HTTP service surfaces. Validation is pure and non-destructive —
invalid observations are marked with a status, never discarded, so the
capability keeps provenance for every result even when it cannot trust it.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime

from hunterx.domain.livehost.models import (
    HttpFinding,
    LiveHost,
    PortFinding,
    ServiceFinding,
    TlsFinding,
    infer_ip_version,
)

#: A service fingerprint is only useful when at least one of these names it.
_SERVICE_IDENTITY_FIELDS = ("service", "product")

#: Fingerprint methods the capability understands.
_KNOWN_FINGERPRINT_METHODS = frozenset({"probed", "matched", "syn-ack", "unknown"})

#: Valid HTTP status code range (RFC 9110).
_MAX_STATUS = 599

#: A single SHA-256 certificate fingerprint in lowercase hex.
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

#: A hostname (allowing a trailing dot) or bare label.
_HOSTNAME = re.compile(r"(?i)^[a-z0-9](?:[a-z0-9-_]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-_]{0,61}[a-z0-9])?)*\.?$")


@dataclass(frozen=True, slots=True)
class LiveValidationResult:
    """Outcome of validating a live discovery observation.

    Attributes:
        valid: whether every check passed.
        issues: human-readable validation messages.
        kind: the observation kind validated (``host``/``port``/...).

    """

    valid: bool
    issues: tuple[str, ...]
    kind: str = ""

    @property
    def status(self) -> str:
        """Return ``valid`` or ``invalid`` as a string for persistence."""
        return "valid" if self.valid else "invalid"


class LiveValidator:
    """Validate live host & service observations."""

    def validate_observation(self, observation: object) -> LiveValidationResult:
        """Validate a single observation by its runtime type."""
        if isinstance(observation, LiveHost):
            return self.validate_host(observation)
        if isinstance(observation, PortFinding):
            return self.validate_port(observation)
        if isinstance(observation, ServiceFinding):
            return self.validate_service(observation)
        if isinstance(observation, TlsFinding):
            return self.validate_tls(observation)
        if isinstance(observation, HttpFinding):
            return self.validate_http(observation)
        return LiveValidationResult(False, ("unknown observation kind",), kind="unknown")

    def validate_host(self, host: LiveHost) -> LiveValidationResult:
        """Validate a canonical host reachability observation."""
        issues: list[str] = []
        if not _is_address(host.address):
            issues.append(f"host address '{host.address}' is not a valid IP address")
        elif host.ip_version != infer_ip_version(host.address):
            issues.append(f"host ip_version {host.ip_version} does not match its address")
        if host.hostname and not _HOSTNAME.fullmatch(host.hostname):
            issues.append(f"host hostname '{host.hostname}' is not a valid hostname")
        if host.rtt_ms < 0:
            issues.append(f"host rtt_ms {host.rtt_ms} is negative")
        if not _in_unit(host.confidence):
            issues.append(f"host confidence {host.confidence} is out of range [0, 1]")
        if host.reachable is True and host.state.value == "unreachable":
            issues.append("host claims reachable=True but state is unreachable")
        if host.reachable is False and host.state.value == "reachable":
            issues.append("host claims reachable=False but state is reachable")
        return LiveValidationResult(valid=not issues, issues=tuple(issues), kind="host")

    def validate_port(self, port: PortFinding) -> LiveValidationResult:
        """Validate a canonical port state observation."""
        issues: list[str] = []
        if not _is_address(port.address):
            issues.append(f"port address '{port.address}' is not a valid IP address")
        if not 1 <= port.port <= 65535:
            issues.append(f"port {port.port} is out of range [1, 65535]")
        if not _in_unit(port.confidence):
            issues.append(f"port confidence {port.confidence} is out of range [0, 1]")
        return LiveValidationResult(valid=not issues, issues=tuple(issues), kind="port")

    def validate_service(self, service: ServiceFinding) -> LiveValidationResult:
        """Validate a canonical service fingerprint observation."""
        issues: list[str] = []
        if not _is_address(service.address):
            issues.append(f"service address '{service.address}' is not a valid IP address")
        if not 1 <= service.port <= 65535:
            issues.append(f"service port {service.port} is out of range [1, 65535]")
        if not any(getattr(service, field) for field in _SERVICE_IDENTITY_FIELDS):
            issues.append("service has neither a service name nor a product")
        if service.fingerprint_method not in _KNOWN_FINGERPRINT_METHODS:
            issues.append(f"service fingerprint method '{service.fingerprint_method}' is unknown")
        if not _in_unit(service.confidence):
            issues.append(f"service confidence {service.confidence} is out of range [0, 1]")
        return LiveValidationResult(valid=not issues, issues=tuple(issues), kind="service")

    def validate_tls(self, tls: TlsFinding) -> LiveValidationResult:
        """Validate a canonical TLS metadata observation."""
        issues: list[str] = []
        if not _is_address(tls.address):
            issues.append(f"tls address '{tls.address}' is not a valid IP address")
        if not 1 <= tls.port <= 65535:
            issues.append(f"tls port {tls.port} is out of range [1, 65535]")
        if tls.sha256 and not _SHA256.fullmatch(tls.sha256):
            issues.append(f"tls sha256 '{tls.sha256}' is not a 64-hex fingerprint")
        for label, value in (("not_before", tls.not_before), ("not_after", tls.not_after)):
            if value and not _is_iso(value):
                issues.append(f"tls {label} '{value}' is not an ISO-8601 timestamp")
        if not _in_unit(tls.confidence):
            issues.append(f"tls confidence {tls.confidence} is out of range [0, 1]")
        return LiveValidationResult(valid=not issues, issues=tuple(issues), kind="tls")

    def validate_http(self, http: HttpFinding) -> LiveValidationResult:
        """Validate a canonical HTTP service surface observation."""
        issues: list[str] = []
        if not _is_address(http.address):
            issues.append(f"http address '{http.address}' is not a valid IP address")
        if not 1 <= http.port <= 65535:
            issues.append(f"http port {http.port} is out of range [1, 65535]")
        if http.scheme not in ("http", "https"):
            issues.append(f"http scheme '{http.scheme}' is not http/https")
        if http.status_code is not None and not 100 <= http.status_code <= _MAX_STATUS:
            issues.append(f"http status_code {http.status_code} is out of range [100, {_MAX_STATUS}]")
        if not _in_unit(http.confidence):
            issues.append(f"http confidence {http.confidence} is out of range [0, 1]")
        return LiveValidationResult(valid=not issues, issues=tuple(issues), kind="http")


def _is_address(value: str) -> bool:
    """Return whether ``value`` parses as an IP address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_iso(value: str) -> bool:
    """Return whether ``value`` parses as an ISO-8601 timestamp."""
    try:
        datetime.fromisoformat(value)
        return True
    except ValueError:
        return False


def _in_unit(value: float) -> bool:
    """Return whether ``value`` is within the unit interval."""
    return 0.0 <= value <= 1.0
