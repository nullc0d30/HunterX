# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""DNS tool adapters.

Integrates the DNS tooling (ProjectDiscovery ``dnsx`` binary and the
``dnspython`` active resolver) into the Tool Integration SDK. Every adapter
emits canonical :class:`~hunterx.domain.dns.models.DnsRecord` instances into
the pipeline payload under ``dns_records``; the active resolver client provides
pooling, retries, deduplication and caching for in-process resolution.
"""

from hunterx.tools.dns.base import DnsToolAdapter
from hunterx.tools.dns.dnspython import DnspythonAdapter
from hunterx.tools.dns.dnsx import DnsxAdapter
from hunterx.tools.dns.massdns import MassdnsAdapter
from hunterx.tools.dns.registry import (
    DNS_TOOL_IDS,
    DnsAdapterFactory,
    dns_adapters,
    register_dns_adapters,
)
from hunterx.tools.dns.resolver import ResolverClient
from hunterx.tools.dns.shuffledns import ShufflednsAdapter
from hunterx.tools.dns.tip import register_dns_tools

__all__ = [
    "DNS_TOOL_IDS",
    "DnsAdapterFactory",
    "DnsToolAdapter",
    "DnsxAdapter",
    "DnspythonAdapter",
    "MassdnsAdapter",
    "ResolverClient",
    "ShufflednsAdapter",
    "dns_adapters",
    "register_dns_adapters",
    "register_dns_tools",
]
