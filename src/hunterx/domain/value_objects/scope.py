# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Scope-related value objects: addresses, hosts, URLs, ports and services."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum

from hunterx.domain.exceptions import InvalidTargetError


@dataclass(frozen=True, slots=True)
class IPAddress:
    """A validated IPv4 or IPv6 address."""

    address: str

    def __post_init__(self) -> None:
        try:
            ipaddress.ip_address(self.address)
        except ValueError:
            raise InvalidTargetError(f"Invalid IP address '{self.address}'.") from None

    @property
    def version(self) -> int:
        """Return the IP protocol version (4 or 6)."""
        return ipaddress.ip_address(self.address).version


@dataclass(frozen=True, slots=True)
class DomainName:
    """A validated DNS domain name (lowercased, no trailing dot)."""

    name: str
    _PATTERN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")

    def __post_init__(self) -> None:
        normalized = self.name.lower().rstrip(".")
        if not self._PATTERN.fullmatch(normalized):
            raise InvalidTargetError(f"Invalid domain name '{self.name}'.")
        object.__setattr__(self, "name", normalized)


@dataclass(frozen=True, slots=True)
class Hostname:
    """A hostname: either an IP address or a domain name."""

    value: str

    def __post_init__(self) -> None:
        try:
            ipaddress.ip_address(self.value)
            return
        except ValueError:
            pass
        DomainName(self.value)


@dataclass(frozen=True, slots=True)
class URL:
    """A validated absolute URL with scheme and host."""

    url: str

    def __post_init__(self) -> None:
        import urllib.parse

        parsed = urllib.parse.urlsplit(self.url)
        if parsed.scheme not in ("http", "https", "ftp", "ws", "wss"):
            raise InvalidTargetError(f"Unsupported URL scheme in '{self.url}'.")
        if not parsed.netloc:
            raise InvalidTargetError(f"URL '{self.url}' has no host.")

    @property
    def scheme(self) -> str:
        """Return the URL scheme (e.g. ``https``)."""
        import urllib.parse

        return urllib.parse.urlsplit(self.url).scheme

    @property
    def host(self) -> str:
        """Return the URL host, or an empty string when absent."""
        import urllib.parse

        return urllib.parse.urlsplit(self.url).hostname or ""


class Protocol(Enum):
    """Transport-layer protocols used by services."""

    TCP = "tcp"
    UDP = "udp"


@dataclass(frozen=True, slots=True)
class Port:
    """A validated network port number."""

    number: int

    def __post_init__(self) -> None:
        if not 0 <= self.number <= 65535:
            raise InvalidTargetError(f"Port {self.number} is out of range [0, 65535].")


@dataclass(frozen=True, slots=True)
class Service:
    """A service bound to a port/protocol on a host."""

    name: str
    port: Port
    protocol: Protocol = Protocol.TCP


@dataclass(frozen=True, slots=True)
class AssetIdentifier:
    """A stable identifier for an asset within a mission.

    Combines a scheme (e.g. ``ip``, ``dns``, ``url``, ``host``) with the raw
    value so identifiers are unambiguous across asset kinds.
    """

    scheme: str
    value: str

    def __str__(self) -> str:
        return f"{self.scheme}:{self.value}"


@dataclass(frozen=True, slots=True)
class Scope:
    """The authorized scope of a mission: the targets it may touch.

    Attributes:
        roots: the entry target identifiers (CIDR/domain/URL).
        includes: additional identifiers explicitly authorized.
        excludes: identifiers that are off-limits.

    """

    roots: tuple[str, ...] = ()
    includes: tuple[str, ...] = ()
    excludes: tuple[str, ...] = field(default=())

    def allows(self, identifier: str) -> bool:
        """Return ``True`` when ``identifier`` is in scope (not excluded)."""
        if identifier in self.excludes:
            return False
        return identifier in self.roots or identifier in self.includes
