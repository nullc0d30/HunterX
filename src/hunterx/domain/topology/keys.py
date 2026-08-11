# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Canonical key helpers for topology entities.

Every topology node is addressed by a stable, deterministic canonical key of the
form ``kind:name``. Normalization collapses equivalent spellings (lowercasing,
trailing-dot removal, canonical IP/CIDR notation) so correlation never
duplicates an entity.
"""

from __future__ import annotations

import ipaddress


def normalize_hostname(name: str) -> str:
    """Normalize a host/domain name: lowercase, strip the trailing dot."""
    value = (name or "").strip().lower()
    while value.endswith(".") and len(value) > 1:
        value = value[:-1]
    return value


def normalize_domain(name: str) -> str:
    """Normalize a domain name (same rules as :func:`normalize_hostname`)."""
    return normalize_hostname(name)


def normalize_ip(address: str) -> str:
    """Return the canonical string form of an IP address."""
    return str(ipaddress.ip_address((address or "").strip()))


def normalize_cidr(network: str) -> str:
    """Return the canonical string form of a CIDR network."""
    return str(ipaddress.ip_network((network or "").strip(), strict=False))


def normalize_nameserver(name: str) -> str:
    """Normalize a nameserver host (lowercase, trailing dot removed)."""
    return normalize_hostname(name)


def normalize_mx(name: str) -> str:
    """Normalize an MX exchange host."""
    return normalize_hostname(name)


def normalize_cert_fingerprint(value: str) -> str:
    """Normalize a certificate fingerprint: lowercase, remove separators."""
    return "".join((value or "").lower().split(":")).strip()


def is_ip(value: str) -> bool:
    """Return ``True`` when ``value`` parses as an IP address."""
    try:
        ipaddress.ip_address((value or "").strip())
    except ValueError:
        return False
    return True


def is_cidr(value: str) -> bool:
    """Return ``True`` when ``value`` parses as a CIDR network."""
    try:
        ipaddress.ip_network((value or "").strip(), strict=False)
    except ValueError:
        return False
    return True


def entity_key(kind: str, name: str) -> str:
    """Build a canonical node key ``kind:name``."""
    return f"{kind}:{name}"


def relationship_key(rel_type: str, source_key: str, target_key: str) -> str:
    """Build the stable dedup key for a directed relationship."""
    return f"{rel_type}:{source_key}|{target_key}"


def domain_of_hostname(hostname: str) -> str | None:
    """Return the parent domain label of ``hostname`` or ``None`` for apex hosts.

    ``www.example.co.uk`` → ``example.co.uk``; ``example.com`` → ``None`` (the
    name is already a registrable-looking apex). This is a best-effort public
    suffix heuristic used only for intra-graph PART_OF edges.
    """
    labels = normalize_hostname(hostname).split(".")
    if len(labels) < 3:
        return None
    return ".".join(labels[1:])
