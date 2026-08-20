# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Canonicalization and deduplication for discovered assets.

Providers report the same host, URL or port under many equivalent spellings
(``Example.COM``, ``example.com.``, ``https://example.com:443/``, ...). This
module collapses those spellings onto one canonical identity so the pipeline can
deduplicate assets with full provenance merging (best-evidence confidence,
union of sources, earliest first-seen).
"""

from __future__ import annotations

import ipaddress
from typing import Iterable
from urllib.parse import urlsplit

from hunterx.domain.discovery.models import DiscoveredAsset, DiscoveryEvidence


def canonical_host(host: str) -> str:
    """Lowercase a host, strip a trailing dot and any surrounding whitespace.

    Example:
        ``"  Example.COM. " -> "example.com"``
    """
    value = host.strip().rstrip(".").lower()
    if value.endswith("."):
        value = value[:-1]
    return value


def canonical_ip(ip: str) -> str:
    """Compress an IP address (IPv4/IPv6) to its canonical spelling.

    Raises:
        ValueError: when the value is not a valid IP literal (the caller decides
            whether an unrecognized value is a hostname instead).
    """
    return str(ipaddress.ip_address(ip.strip()))


def canonical_port(port: int | str) -> int:
    """Normalize a port to a positive integer."""
    value = int(str(port).strip())
    if value < 1 or value > 65535:
        raise ValueError(f"invalid port {value!r}")
    return value


def canonical_url(url: str) -> str:
    """Normalize a URL for deduplication.

    The scheme and host are lowercased, a default port matching the scheme is
    dropped, any fragment and trailing slash (for root paths) are removed.

    A malformed URL (for example an invalid port coming from a third-party
    provider) cannot be canonicalized; it is returned verbatim (stripped) so
    the pipeline records the asset honestly instead of crashing.
    """
    value = url.strip()
    try:
        parts = urlsplit(value)
        scheme = parts.scheme.lower()
        host = canonical_host(parts.hostname or "")
        if not host:
            return value
        port = parts.port
    except ValueError:
        return value
    if port is not None and ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        port = None
    netloc = host
    if port is not None:
        netloc = f"{host}:{port}"
    path = parts.path.rstrip("/") if parts.path else ""
    if parts.path == "/" or path == "":
        path = ""
    query = f"?{parts.query}" if parts.query else ""
    return f"{scheme}://{netloc}{path}{query}"


def canonical_host_port(host: str, port: int | str) -> str:
    """Return a canonical ``host:port`` identity."""
    return f"{canonical_host(host)}:{canonical_port(port)}"


def asset_key(kind: str, name: str) -> str:
    """Return the canonical deduplication key for a (kind, name) pair."""
    return f"{kind}:{name}".lower()


def is_ip(value: str) -> bool:
    """Return True when the value is a valid IP literal."""
    try:
        canonical_ip(value)
    except ValueError:
        return False
    return True


def is_hostname(value: str) -> bool:
    """Return True when the value looks like a DNS hostname.

    Empty values, whitespace, URL forms and IP literals are not hostnames.
    """
    value = value.strip().rstrip(".").lower()
    if not value or any(char.isspace() for char in value):
        return False
    if "/" in value or ":" in value:
        return False
    if is_ip(value):
        return False
    return True


def host_from_url(url: str) -> str:
    """Extract the canonical host from a URL (or the URL itself if not a URL)."""
    parts = urlsplit(url.strip())
    if parts.scheme and parts.hostname:
        return canonical_host(parts.hostname)
    return canonical_host(url)


class DiscoveryDeduper:
    """Merge equivalent assets under one canonical identity with provenance.

    The deduper is deliberately a plain in-memory registry: it does not know
    about the target, the engine or the persistence layer, so it can be reused
    by unit tests and the application service alike.
    """

    def __init__(self) -> None:
        self._assets: dict[str, DiscoveredAsset] = {}
        self._raw_count = 0
        self._merged_count = 0

    def add(self, asset: DiscoveredAsset) -> DiscoveredAsset:
        """Register an asset, merging it with any existing equivalent.

        Returns:
            The merged asset (the existing one when an equivalent already
            existed, otherwise the newly inserted one).
        """
        self._raw_count += 1
        key = asset_key(asset.kind, _canonical_name(asset.kind, asset.name))
        existing = self._assets.get(key)
        if existing is None:
            object.__setattr__(asset, "canonical_key", key)
            self._assets[key] = asset
            return asset
        self._merged_count += 1
        existing.merge(asset)
        return existing

    def add_many(self, assets: Iterable[DiscoveredAsset]) -> None:
        """Register many assets."""
        for asset in assets:
            self.add(asset)

    def get(self, kind: str, name: str) -> DiscoveredAsset | None:
        """Return the deduplicated asset for a (kind, name) pair."""
        return self._assets.get(asset_key(kind, name))

    def has(self, kind: str, name: str) -> bool:
        """Return True when a canonical asset exists."""
        return asset_key(kind, name) in self._assets

    def __contains__(self, key: str) -> bool:
        return key in self._assets

    def all(self) -> list[DiscoveredAsset]:
        """Return every deduplicated asset."""
        return list(self._assets.values())

    def by_kind(self, kind: str) -> list[DiscoveredAsset]:
        """Return every deduplicated asset of ``kind``."""
        return [asset for asset in self._assets.values() if asset.kind == kind]

    def stats(self) -> dict[str, int]:
        """Return deduplication statistics (raw vs merged assets)."""
        return {
            "raw": self._raw_count,
            "merged": self._merged_count,
            "unique": len(self._assets),
        }

    def evidence_for(self, kind: str, name: str) -> list[DiscoveryEvidence]:
        """Return provenance for a canonical asset (empty when absent)."""
        asset = self.get(kind, name)
        return list(asset.evidence) if asset else []


def _canonical_name(kind: str, name: str) -> str:
    """Return the canonical identity used for deduplication keys.

    Host-like kinds collapse equivalent spellings (case, trailing dots);
    IP kinds compress literals; everything else is stripped verbatim.
    """
    value = str(name).strip()
    if kind in ("host", "subdomain", "domain", "dns_record"):
        return canonical_host(value)
    if kind in ("ip", "cidr"):
        try:
            return canonical_ip(value)
        except ValueError:
            return value
    return value


__all__ = [
    "DiscoveryDeduper",
    "asset_key",
    "canonical_host",
    "canonical_host_port",
    "canonical_ip",
    "canonical_port",
    "canonical_url",
    "host_from_url",
    "is_hostname",
    "is_ip",
]