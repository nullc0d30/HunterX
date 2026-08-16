# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Scheme-aware target normalization.

Security tools take the mission target in one of two shapes:

- web-facing tools (``httpx``, ``whatweb``, ...) need a full URL;
- host/domain/network tools (``nmap``, ``subfinder``, ``dnsx``, ...) need a
  bare hostname, IP or domain.

Passing a full URL (``http://localhost:3010``) to a host tool silently yields
empty results — the tool runs, finds nothing and reports success. This module
normalizes the raw mission target into a structured :class:`TargetSpec` so the
execution runner can hand every adapter the shape its descriptor declares,
instead of stripping the scheme globally or passing the URL verbatim.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

#: Default port per URL scheme (only for well-known web schemes).
_DEFAULT_PORT_BY_SCHEME = {"http": 80, "https": 443}
#: Implicit scheme used when the target carries no scheme.
_DEFAULT_SCHEME = "http"

_IPV6_RE = re.compile(r"^\[[0-9a-fA-F:]+\]$")
_WILDCARD_DOMAIN_RE = re.compile(r"^\*(\.[^*]+)+$")


@dataclass(frozen=True)
class TargetSpec:
    """A parsed, scheme-aware view of the mission target.

    Attributes:
        raw: the target exactly as the operator provided it.
        scheme: URL scheme (``http``/``https``) or ``""`` when absent.
        hostname: the host part (never includes the scheme, port or path).
        host_or_ip: the hostname with brackets stripped (IPv6 addresses are
            returned without ``[...]`` for CLI consumption).
        port: the explicit port, or the scheme default when none was given
            (``0`` when the target carried no scheme and no port).
        url: a full URL for web-facing tools (implicit ``http://`` is added
            when the target carried no scheme).
        path: the request path (``""`` when the target carried none).

    """

    raw: str
    scheme: str
    hostname: str
    host_or_ip: str
    port: int
    url: str
    path: str

    @property
    def is_ip(self) -> bool:
        """Return ``True`` when the host part is an IP address."""
        return _is_ip(self.host_or_ip)

    @property
    def is_domain(self) -> bool:
        """Return ``True`` when the host part looks like a domain name."""
        return bool(self.host_or_ip) and not self.is_ip and ("." in self.host_or_ip or _WILDCARD_DOMAIN_RE.match(self.host_or_ip))

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe mapping of this target spec."""
        return {
            "raw": self.raw,
            "scheme": self.scheme,
            "hostname": self.hostname,
            "host_or_ip": self.host_or_ip,
            "port": self.port,
            "url": self.url,
            "path": self.path,
        }


def normalize_target(raw: str) -> TargetSpec:
    """Parse ``raw`` into a scheme-aware :class:`TargetSpec`.

    Accepts full URLs (``https://host:8443/path``), bare host:port pairs
    (``host:8443``), bare hostnames, IPs and bracketed IPv6 literals. A target
    that cannot be parsed yields an empty spec instead of raising, so the
    mission runner can still record a structured failure.
    """
    raw = (raw or "").strip()
    if not raw:
        return TargetSpec(raw="", scheme="", hostname="", host_or_ip="", port=0, url="", path="")
    scheme = ""
    if "://" in raw:
        split = urlsplit(raw)
        scheme = (split.scheme or "").lower()
        host = split.hostname or ""
        path = split.path or ""
    else:
        host, path = _split_bare_target(raw)
    if _IPV6_RE.match(host):
        host = host.strip("[]")
    port = _explicit_port(raw, scheme, host)
    url = raw if "://" in raw else f"{scheme or _DEFAULT_SCHEME}://{host}" + (f":{port}" if _explicit_port_raw(raw) else "")
    return TargetSpec(
        raw=raw,
        scheme=scheme,
        hostname=host,
        host_or_ip=host,
        port=port,
        url=url,
        path=path,
    )


def _split_bare_target(raw: str) -> tuple[str, str]:
    """Split a bare host[:port][/path] into ``(host, path)``."""
    head, _, path = raw.partition("/")
    head = head.strip("[]")
    host = head
    if head.startswith("[") and "]" in head:
        host = head
    elif ":" in head:
        candidate, tail = head.rsplit(":", 1)
        if tail.isdigit():
            host = candidate
    return host, f"/{path}" if path else ""


def target_for_adapter(spec: TargetSpec, declared_targets: tuple[str, ...]) -> str:
    """Return the target string an adapter with ``declared_targets`` expects.

    Web-facing tools (``url`` declared) receive the full URL; host/domain/
    network tools receive the bare host (never the scheme, port or path).
    Unknown declarations fall back to the raw target so no adapter is ever
    handed an empty string by accident.
    """
    if not spec.raw:
        return spec.raw
    if "url" in declared_targets:
        return spec.url
    if not spec.host_or_ip:
        return spec.raw
    return spec.host_or_ip


def target_type_for(spec: TargetSpec, declared_targets: tuple[str, ...]) -> str:
    """Return the canonical ``target_type`` for an adapter's declarations."""
    if "url" in declared_targets:
        return "url"
    if spec.is_ip:
        return "ip" if "ip" in declared_targets else "host"
    if spec.is_domain:
        return "domain" if "domain" in declared_targets else "host"
    return "host"


def has_meaningful_content(content: object) -> bool:
    """Return ``True`` when a normalized observation content carries evidence.

    A dict whose values are all empty (empty strings, ``None``, empty lists,
    empty dicts, ``0``) carries no meaningful evidence — an empty-but-successful
    execution must never be treated as an assessment of the target.
    """
    if isinstance(content, dict):
        return any(_meaningful_value(value) for value in content.values())
    return _meaningful_value(content)


def _meaningful_value(value: object) -> bool:
    if isinstance(value, dict):
        return any(_meaningful_value(item) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(_meaningful_value(item) for item in value)
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    text = str(value).strip()
    if not text:
        return False
    return text not in {"0", "0.0", "[]", "{}", "null", "none", "false"}


def _explicit_port(raw: str, scheme: str, host: str) -> int:
    """Return the explicit port or the scheme default (``0`` when unknown)."""
    port = _explicit_port_raw(raw)
    if port:
        return port
    if scheme in _DEFAULT_PORT_BY_SCHEME:
        return _DEFAULT_PORT_BY_SCHEME[scheme]
    return 0


def _explicit_port_raw(raw: str) -> int:
    """Return the explicit port from ``raw`` or ``0`` when absent."""
    head = raw.split("://")[-1]
    head = head.split("/")[0].strip("[]")
    if ":" in head:
        tail = head.rsplit(":", 1)[1]
        if tail.isdigit():
            return int(tail)
    return 0


def _is_ip(value: str) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


__all__ = [
    "TargetSpec",
    "has_meaningful_content",
    "normalize_target",
    "target_for_adapter",
    "target_type_for",
]
