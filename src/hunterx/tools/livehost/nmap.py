# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Nmap tool adapter.

Integrates ``nmap`` — the de-facto network discovery and port scanner — into
the Tool Integration SDK. The adapter builds the CLI command from the execution
context (target, ports, protocol, service detection, TLS metadata), parses the
XML output (``-oX -``) into canonical discovery observations and publishes them
on the execution output.

XML contract (verified against Nmap ``-oX`` output):
    ``<host>`` carries ``<status state=...>``, ``<address addrtype=...>``,
    ``<hostnames>``, ``<ports>`` (each ``<port>`` with ``<state>`` and optional
    ``<service>``/``<cpe>``) and an optional ``<hostscript>`` block whose
    ``ssl-cert`` script yields the certificate metadata used for
    :class:`TlsFinding` records.
"""

from __future__ import annotations

from xml.etree.ElementTree import Element  # nosec B405 - type-only annotation; parsing uses defusedxml

from defusedxml.common import DefusedXmlException
from defusedxml.ElementTree import ParseError
from defusedxml.ElementTree import fromstring as xml_fromstring

from hunterx.domain.execution import ExecutionContext
from hunterx.domain.livehost.models import (
    DEFAULT_TOP_PORTS,
    HostState,
    PortState,
    ReachabilityMethod,
    TransportProtocol,
    make_host,
    make_http,
    make_port,
    make_service,
    make_tls,
)
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.livehost.base import LiveToolAdapter
from hunterx.tools.recon.runner import CommandResult, guard_positional_target

_VERSION = "7.95"


class NmapAdapter(LiveToolAdapter):
    """SDK adapter for the ``nmap`` network discovery tool."""

    descriptor = ToolDescriptor(
        name="nmap",
        version=_VERSION,
        description="Flexible network discovery, port scanning and service/version detection.",
        entrypoint="hunterx.tools.livehost.nmap:NmapAdapter",
        targets=("ip", "cidr", "host", "domain"),
        capabilities=("host-discovery", "port-scanning", "service-fingerprint"),
        permissions=("network",),
        parameters={
            "ports": {
                "type": "array",
                "items": {"type": "integer"},
                "description": "Ports to probe (default: top well-known ports).",
            },
            "protocol": {
                "type": "string",
                "enum": ["tcp", "udp", "both"],
                "description": "Transport protocol(s) to scan.",
            },
            "service_detection": {
                "type": "boolean",
                "description": "Enable service/version detection (-sV).",
            },
            "with_tls": {
                "type": "boolean",
                "description": "Collect TLS certificate metadata via the ssl-cert script.",
            },
            "host_discovery_only": {
                "type": "boolean",
                "description": "Run host discovery only (-sn), emitting no port results.",
            },
            "rate_limit": {
                "type": "integer",
                "description": "Maximum packets per second.",
            },
            "min_hostgroup": {
                "type": "integer",
                "description": "Minimum parallel host group size.",
            },
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build the ``nmap`` command line for ``context``."""
        argv = ["nmap", "-oX", "-"]
        if bool(context.parameters.get("host_discovery_only")):
            argv += ["-sn"]
        else:
            protocol = str(context.parameters.get("protocol") or "tcp").lower()
            ports = self._param_ports(context, DEFAULT_TOP_PORTS)
            argv += self._port_args(protocol, ports)
            if bool(context.parameters.get("service_detection")) or _is_tls_requested(context):
                argv.append("-sV")
            if _is_tls_requested(context):
                argv += ["--script", "ssl-cert"]
        rate_limit = self._param_int(context, "rate_limit", 0)
        if rate_limit > 0:
            argv += ["--max-rate", str(rate_limit)]
        min_hostgroup = self._param_int(context, "min_hostgroup", 0)
        if min_hostgroup > 0:
            argv += ["--min-hostgroup", str(min_hostgroup)]
        argv.append(guard_positional_target(context.target, label="nmap target"))
        return argv

    @staticmethod
    def _port_args(protocol: str, ports: tuple[int, ...]) -> list[str]:
        """Return nmap protocol/port flags for ``protocol`` and ``ports``."""
        argv: list[str] = []
        if protocol == "udp":
            argv.append("-sU")
        elif protocol == "both":
            argv += ["-sT", "-sU"]
        else:
            argv.append("-sT")
        argv += ["-p", ",".join(str(port) for port in ports)]
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[object]:
        """Parse Nmap XML output into canonical discovery observations."""
        root = _parse_xml(result.stdout)
        if root is None or root.tag != "nmaprun":
            return []
        observations: list[object] = []
        for host_element in root.iter("host"):
            observations.extend(_parse_host(host_element, context))
        return observations


def _parse_xml(text: str) -> Element | None:
    """Parse ``text`` as XML, returning the root element or ``None``.

    Malicious documents (external entities, entity-expansion bombs) raise
    ``defusedxml`` protection errors that are treated as unparseable, so a
    hostile tool output can never resolve entities or expand a bomb.
    """
    try:
        return xml_fromstring(text)
    except (ParseError, DefusedXmlException):
        return None


def _parse_host(element: Element, context: ExecutionContext) -> list[object]:
    """Convert one Nmap ``<host>`` element into observations."""
    observations: list[object] = []
    address, ip_version = _host_address(element)
    if not address:
        return []
    status = element.find("status")
    state = _host_state(status)
    methods = _reachability_methods(status)
    hostname = _hostname(element)
    target_id = context.parameters.get("target_id") if isinstance(context.parameters.get("target_id"), str) else None
    host = make_host(
        address,
        ip_version=ip_version,
        hostname=hostname,
        state=state,
        reachable=None if state is HostState.UNKNOWN else state is HostState.REACHABLE,
        methods=methods,
        tool_id="nmap",
        source="nmap",
        target_id=target_id,
        execution_id=context.execution_id,
        correlation_id=context.correlation_id,
    )
    observations.append(host)
    if bool(context.parameters.get("host_discovery_only")):
        return observations
    for port_element in element.findall("./ports/port"):
        observations.extend(_parse_port(port_element, address, hostname, target_id, context))
    observations.extend(_parse_host_scripts(element, address, target_id, context))
    return observations


def _parse_port(
    port_element: Element,
    address: str,
    hostname: str,
    target_id: str | None,
    context: ExecutionContext,
) -> list[object]:
    """Convert one ``<port>`` element into port/service/http observations."""
    observations: list[object] = []
    protocol = _parse_protocol(port_element.get("protocol"))
    port = _optional_int(port_element.get("portid"))
    if port is None:
        return []
    state_element = port_element.find("state")
    state = _parse_port_state(state_element.get("state") if state_element is not None else None)
    reason = state_element.get("reason", "") if state_element is not None else ""
    observations.append(
        make_port(
            address,
            port,
            protocol=protocol,
            state=state,
            reason=reason,
            tool_id="nmap",
            source="nmap",
            target_id=target_id,
            execution_id=context.execution_id,
            correlation_id=context.correlation_id,
        )
    )
    service_element = port_element.find("service")
    if service_element is not None and state is PortState.OPEN:
        observations.extend(_parse_service(service_element, port_element, address, port, protocol, target_id, context))
    return observations


def _parse_service(
    service_element: Element,
    port_element: Element,
    address: str,
    port: int,
    protocol: TransportProtocol,
    target_id: str | None,
    context: ExecutionContext,
) -> list[object]:
    """Convert one ``<service>`` element into service (+HTTP) observations."""
    observations: list[object] = []
    service_name = str(service_element.get("name") or "").strip().lower()
    if not service_name:
        return observations
    evidence = tuple(str(cpe.text).strip() for cpe in port_element.findall("cpe") if cpe.text and cpe.text.strip())
    fingerprint_method = _fingerprint_method(service_element.get("method"))
    observations.append(
        make_service(
            address,
            port,
            service_name,
            protocol=protocol,
            product=str(service_element.get("product") or ""),
            version=str(service_element.get("version") or ""),
            extrainfo=str(service_element.get("extrainfo") or ""),
            banner=str(service_element.get("banner") or ""),
            fingerprint_method=fingerprint_method,
            evidence=evidence,
            tool_id="nmap",
            source="nmap",
            target_id=target_id,
            execution_id=context.execution_id,
            correlation_id=context.correlation_id,
        )
    )
    if service_name in ("http", "https"):
        scheme = "https" if service_name == "https" else "http"
        observations.append(
            make_http(
                address,
                port,
                scheme=scheme,
                host="",
                server=str(service_element.get("product") or ""),
                tech_hints=tuple(hint for hint in (*evidence, str(service_element.get("extrainfo") or "")) if hint),
                tool_id="nmap",
                source="nmap",
                target_id=target_id,
                execution_id=context.execution_id,
                correlation_id=context.correlation_id,
            )
        )
    return observations


def _parse_host_scripts(
    host_element: Element,
    address: str,
    target_id: str | None,
    context: ExecutionContext,
) -> list[object]:
    """Extract TLS certificate metadata from the ``ssl-cert`` host script."""
    observations: list[object] = []
    script = next(
        (node for node in host_element.iter("script") if node.get("id") == "ssl-cert"),
        None,
    )
    if script is None:
        return []
    x509 = next((node for node in script.iter("table") if node.get("key") == "x509"), None)
    if x509 is None:
        return []
    subject = _table_elem(script, "subject", "commonName")
    issuer = _table_elem(script, "issuer", "commonName")
    serial = _elem(x509, "serialNumber")
    sha256 = _elem(x509, "SHA-256") or _elem(x509, "SHA256")
    not_before = _table_elem(x509, "validity", "notBefore")
    not_after = _table_elem(x509, "validity", "notAfter")
    san = _subject_alt_names(x509)
    if not (sha256 or subject):
        return []
    observations.append(
        make_tls(
            address,
            _script_port(script) or 443,
            subject=subject,
            issuer=issuer,
            serial=serial,
            sha256=sha256,
            san=san,
            not_before=not_before,
            not_after=not_after,
            tool_id="nmap",
            source="nmap",
            target_id=target_id,
            execution_id=context.execution_id,
            correlation_id=context.correlation_id,
        )
    )
    return observations


# -- parsing helpers ----------------------------------------------------------


def _host_address(host_element: Element) -> tuple[str, int]:
    """Return the canonical (address, ip_version) of a host element."""
    for address in host_element.iter("address"):
        addr = str(address.get("addr") or "").strip()
        addr_type = str(address.get("addrtype") or "").lower()
        if addr and addr_type in ("ipv4", "ipv6"):
            return addr, 6 if addr_type == "ipv6" else 4
    return "", 4


def _host_state(status: Element | None) -> HostState:
    value = status.get("state") if status is not None else ""
    if value == "up":
        return HostState.REACHABLE
    if value == "down":
        return HostState.UNREACHABLE
    return HostState.UNKNOWN


def _reachability_methods(status: Element | None) -> tuple[ReachabilityMethod, ...]:
    reason = (status.get("reason") or "") if status is not None else ""
    lowered = reason.lower()
    if "syn-ack" in lowered or "syn" in lowered:
        return (ReachabilityMethod.TCP_SYN,)
    if "connect" in lowered:
        return (ReachabilityMethod.TCP_CONNECT,)
    if "icmp" in lowered:
        return (ReachabilityMethod.ICMP,)
    if "dns" in lowered:
        return (ReachabilityMethod.DNS,)
    if "app" in lowered or "response" in lowered:
        return (ReachabilityMethod.APPLICATION,)
    return (ReachabilityMethod.TCP_SYN,)


def _hostname(host_element: Element) -> str:
    for hostname in host_element.iter("hostname"):
        name = str(hostname.get("name") or "").strip()
        if name:
            return name
    return ""


def _parse_protocol(value: str | None) -> TransportProtocol:
    try:
        return TransportProtocol(str(value or "tcp").lower())
    except ValueError:
        return TransportProtocol.TCP


def _parse_port_state(value: str | None) -> PortState:
    try:
        return PortState(str(value or "unknown").lower())
    except ValueError:
        return PortState.UNKNOWN


def _fingerprint_method(value: str | None) -> str:
    method = str(value or "unknown").strip().lower()
    if method in ("probed", "matched", "syn-ack"):
        return method
    if method == "table":
        return "matched"
    return "unknown"


def _optional_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _elem(table: Element, key: str) -> str:
    """Return the text of a direct ``<elem key=...>`` child of ``table``."""
    for elem in table.findall("elem"):
        if elem.get("key") == key:
            return str(elem.text or "").strip()
    return ""


def _table_elem(root: Element, table_key: str, elem_key: str) -> str:
    """Return the text of an elem nested under ``table key=table_key``."""
    for table in root.iter("table"):
        if table.get("key") == table_key:
            value = _elem(table, elem_key)
            if value:
                return value
    return ""


def _subject_alt_names(x509: Element) -> tuple[str, ...]:
    """Extract DNS SANs from the x509 extensions table."""
    for table in x509.iter("table"):
        if table.get("key") != "extensions":
            continue
        value = _elem(table, "subjectAltName")
        if not value:
            continue
        names = []
        for part in value.split(","):
            part = part.strip()
            if part.lower().startswith("dns:"):
                name = part[4:].strip().strip("*.")
                if name:
                    names.append(name)
        return tuple(dict.fromkeys(names))
    return ()


def _script_port(script: Element) -> int | None:
    """Return the port the ssl-cert script ran against (from its port id)."""
    value = _table_elem(script, "port", "portid")
    return _optional_int(value) if value else None


def _is_tls_requested(context: ExecutionContext) -> bool:
    """Return whether TLS metadata collection was requested."""
    return bool(context.parameters.get("with_tls"))
