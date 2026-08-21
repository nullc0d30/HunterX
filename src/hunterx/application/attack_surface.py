# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Attack-surface application service.

Bridges the target-agnostic attack-surface domain model into mission execution:
observation intake → surface classification → graph update → capability mapping
→ assessment-queue scheduling → exhaustion evaluation.

The capability list is sourced from the live HunterX catalog (the
vulnerability-capability registry plus the coverage vocabulary) — this module
never hardcodes a capability set, so it stays aligned with the platform even as
the catalog grows.
"""

from __future__ import annotations

import contextlib
from typing import Any
from urllib.parse import urlsplit

from hunterx.domain.attack_surface.capability_map import CapabilityMapper
from hunterx.domain.attack_surface.completion import CompletionGate
from hunterx.domain.attack_surface.enums import (
    AssessmentStatus,
    AuthContextState,
    SurfaceKind,
    SurfaceLayer,
)
from hunterx.domain.attack_surface.graph import SurfaceGraph
from hunterx.domain.attack_surface.models import (
    DynamicObject,
    SurfaceContext,
    surface_key,
)
from hunterx.domain.attack_surface.queue import AssessmentQueue, schedule_assignments
from hunterx.domain.attack_surface.registry import SurfaceKindRegistry
from hunterx.domain.target_intelligence.enums import CoverageCapability
from hunterx.shared.time import utcnow_iso

#: Surface kinds whose node name is a URL. Any classified observation kind in
#: this set is preserved verbatim on the URL node — a ``javascript``/``sink``/
#: ``source``/``upload``/``client_route``/``workflow`` observation never
#: silently degrades to a generic ``endpoint`` (the discovery information is
#: preserved for capability mapping and surface-kind coverage).
_URL_BEARING_KINDS: frozenset[str] = frozenset(
    {
        SurfaceKind.API_ENDPOINT.value,
        SurfaceKind.AUTH_SURFACE.value,
        SurfaceKind.AUTHORIZATION_CONTEXT.value,
        SurfaceKind.CLIENT_ROUTE.value,
        SurfaceKind.CLOUD_RESOURCE.value,
        SurfaceKind.DOWNLOAD.value,
        SurfaceKind.FILE.value,
        SurfaceKind.GRAPHQL_OPERATION.value,
        SurfaceKind.JAVASCRIPT_ENDPOINT.value,
        SurfaceKind.REDIRECT.value,
        SurfaceKind.ROUTE.value,
        SurfaceKind.SINK.value,
        SurfaceKind.SOURCE.value,
        SurfaceKind.UPLOAD.value,
        SurfaceKind.WEBSOCKET.value,
        SurfaceKind.WORKFLOW.value,
    }
)

#: Parameter-name hints that indicate a surface fetches remote URLs (SSRF
#: surface) or exposes object identifiers (IDOR/BOLA surface). Applied to
#: input attributes generically — never to a hardcoded target endpoint.
_FETCH_HINT_NAMES = {"url", "uri", "fetch", "next", "redirect", "callback", "destination", "return"}
_OBJECT_HINT_NAMES = {"id", "uid", "userid", "user_id", "object", "resource", "item", "account", "key"}


class CapabilityCatalog:
    """Sources the live capability id list from the HunterX catalog."""

    @staticmethod
    def from_platform() -> list[str]:
        """Return the platform capability ids (registry + coverage vocabulary).

        The probeable capability classes come from the vulnerability-capability
        registry; the discovery/coverage capabilities come from the target
        intelligence coverage vocabulary. The union is the authoritative
        capability catalog for surface mapping.
        """
        from hunterx.domain.vulnerability_capability.registry import registered_classes

        ids: set[str] = set(registered_classes())
        ids.update(capability.value for capability in CoverageCapability)
        return sorted(ids)


def _as_list(value: Any) -> list[Any]:
    """Return ``value`` as a list (single values are wrapped)."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _host_of(url: str) -> str:
    """Return the host part of a URL (or the value itself when not a URL)."""
    value = str(url or "").strip()
    if not value:
        return ""
    try:
        parts = urlsplit(value if "://" in value else f"//{value}")
    except (ValueError, TypeError):
        return value
    host = parts.hostname or ""
    if not host and parts.path:
        host = parts.path.split("/", 1)[0]
    return host or value


def _url_path(value: str) -> str:
    """Return the path portion of a URL-like string (``""`` for non-URLs)."""
    try:
        parts = urlsplit(str(value))
        if parts.scheme and parts.netloc:
            return parts.path or "/"
    except (ValueError, TypeError):
        pass
    return ""


def _fetch_hint(name: str) -> bool:
    """Return ``True`` when an input name implies remote-URL fetching."""
    return str(name or "").lower().lstrip("-") in _FETCH_HINT_NAMES


def _object_hint(name: str) -> bool:
    """Return ``True`` when an input name implies an object identifier."""
    return str(name or "").lower().lstrip("-") in _OBJECT_HINT_NAMES


class AttackSurfaceService:
    """Per-mission attack-surface model, mapping, queue and completion gate.

    Args:
        mission_id: owning mission id.
        target_key: root target key.
        catalog: capability ids; ``None`` sources the live platform catalog.
        registry: surface-kind registry; ``None`` uses the built-ins.
        mapper: capability mapper; ``None`` builds one from ``catalog``.
        graph: surface graph; ``None`` builds a fresh one.
        queue: assessment queue; ``None`` builds a fresh one.
        gate: completion gate; ``None`` builds one with defaults.
        event_bus: optional messaging port for surface events.

    """

    def __init__(
        self,
        *,
        mission_id: str = "",
        target_key: str = "",
        catalog: list[str] | None = None,
        registry: SurfaceKindRegistry | None = None,
        mapper: CapabilityMapper | None = None,
        graph: SurfaceGraph | None = None,
        queue: AssessmentQueue | None = None,
        gate: CompletionGate | None = None,
        event_bus: Any | None = None,
    ) -> None:
        self.mission_id = mission_id
        self.target_key = target_key
        self.catalog = catalog if catalog is not None else CapabilityCatalog.from_platform()
        self.registry = registry if registry is not None else SurfaceKindRegistry()
        self.mapper = mapper if mapper is not None else CapabilityMapper(self.catalog, registry=self.registry)
        self.graph = graph if graph is not None else SurfaceGraph(registry=self.registry, target_key=target_key)
        self.queue = queue if queue is not None else AssessmentQueue()
        self.gate = gate if gate is not None else CompletionGate()
        self._event_bus = event_bus
        self._target_established = False

    # -- intake -------------------------------------------------------------

    def establish_target(self) -> str:
        """Ensure the root target node exists and return its key."""
        if not self._target_established:
            self.graph.set_target(mission_id=self.mission_id, target_key=self.target_key)
            self._target_established = True
        return self.target_key

    def on_observation(
        self,
        *,
        observation_type: str = "",
        content: Any = None,
        asset_key: str = "",
        capability: str = "",
        source: str = "",
        session_state: str = "",
    ) -> dict[str, Any]:
        """Ingest a discovery observation into the surface model.

        Classifies the observation, upserts surface nodes, maps applicable
        capabilities, schedules assessment tasks and updates the completion
        gate's discovery bookkeeping. Returns a summary of new surfaces.
        """
        surfaces_before = self.graph.node_count()
        self.establish_target()
        host = _host_of(asset_key)
        host_key = surface_key(SurfaceKind.HOST, host) if host and host != self.target_key else self.target_key
        if host and host != self.target_key and self.graph.node(host_key) is None:
            self.graph.upsert(
                self.target_key,
                kind=SurfaceKind.HOST,
                name=host,
                mission_id=self.mission_id,
                source=source,
            )

        context = self._context_for(content=content, session_state=session_state)
        base_kind = self.registry.classify(observation_type)
        base_parent = host_key if host_key != self.target_key else self.target_key

        new_surfaces = 0
        entries: list[dict[str, Any]] = []
        if observation_type in ("asset", "subdomain", "host", "hostname", "domain", "dns_record"):
            if asset_key:
                entries.append(self._entry(base_kind, asset_key, base_parent, context, content))
        else:
            entries.extend(self._url_entries(content, asset_key, base_parent, context, default_kind=base_kind))
            if not any(entry["name"] == asset_key for entry in entries) and asset_key:
                entries.append(self._entry(base_kind, asset_key, base_parent, context, content))
        existing_names: dict[str, str] = {node.name: node.kind_value() for node in self.graph.nodes()}
        for entry in entries:
            # A URL already registered as a *specific* URL-bearing surface kind
            # is never re-registered as a generic ``endpoint``/``url`` — the
            # same endpoint must not be represented by two graph nodes under
            # different kinds. Nodes of non-URL kinds (target/host/technology)
            # never suppress a URL surface.
            existing_kind = existing_names.get(entry["name"])
            if (
                entry["kind"] in (SurfaceKind.ENDPOINT.value, SurfaceKind.URL.value)
                and existing_kind in _URL_BEARING_KINDS
            ):
                continue
            node, is_new = self.graph.upsert(
                entry["parent_key"],
                kind=entry["kind"],
                name=entry["name"],
                mission_id=self.mission_id,
                dynamic_type=entry.get("dynamic_type", ""),
                attributes=entry.get("attributes", {}),
                context=context,
                confidence=entry.get("confidence", 0.8),
                source=source,
            )
            if is_new:
                existing_names[entry["name"]] = entry["kind"]
                new_surfaces += 1
        # Child inputs/objects/workflows attach to the base surface the asset
        # observation named (the endpoint/URL node), not the raw kind string.
        base_surface_key = self.target_key
        if asset_key:
            matched = [node for node in self.graph.nodes() if node.name == asset_key]
            base_surface_key = matched[0].key if matched else surface_key(base_kind, asset_key)
        if observation_type not in ("asset", "subdomain", "host", "hostname", "domain", "dns_record"):
            child_entries = self._input_entries(content, base_surface_key, context)
            child_entries.extend(self._technology_entries(content, self.target_key, context))
            child_entries.extend(self._object_entries(content, base_surface_key, context))
            child_entries.extend(self._workflow_entries(content, base_surface_key, context))
            for entry in child_entries:
                node, is_new = self.graph.upsert(
                    entry["parent_key"],
                    kind=entry["kind"],
                    name=entry["name"],
                    mission_id=self.mission_id,
                    dynamic_type=entry.get("dynamic_type", ""),
                    attributes=entry.get("attributes", {}),
                    context=context,
                    confidence=entry.get("confidence", 0.8),
                    source=source,
                )
                if is_new:
                    new_surfaces += 1
                if entry["kind"] == SurfaceKind.OBJECT.value:
                    self._record_dynamic_object(entry, node, source)

        # Capability × Surface × Context mapping + queue scheduling.
        for node in self.graph.nodes():
            if node.layer in (SurfaceLayer.INPUT, SurfaceLayer.OBJECT, SurfaceLayer.SURFACE, SurfaceLayer.WORKFLOW):
                self._map_and_schedule(node, capability=capability)

        self.gate.record_observation(surfaces_before=surfaces_before, surfaces_after=self.graph.node_count())
        summary = self.snapshot()
        self._publish("mission.surface.updated", summary)
        return {"new_surfaces": new_surfaces, **summary}

    # -- mapping / scheduling -----------------------------------------------

    def _map_and_schedule(self, node: Any, *, capability: str = "") -> int:
        """Map capabilities for ``node`` and schedule their assessment tasks."""
        assignments = self.mapper.map_for(node)
        for assignment in assignments:
            self.graph.attach_assignment(assignment)
        tasks = schedule_assignments(
            self.queue,
            assignments,
            mission_id=self.mission_id,
            strategy="differential",
        )
        for task in tasks:
            if capability and task.capability_id == capability:
                task.mark(AssessmentStatus.SCHEDULED)
        return len(tasks)

    # -- completion ---------------------------------------------------------

    def record_attack_paths(self, count: int) -> None:
        """Feed the attack-path count into the completion gate."""
        self.gate.record_attack_paths(count)

    def mark_unavailable(self, reason: str) -> None:
        """Mark the target unavailable (never converted into completion)."""
        self.gate.mark_unavailable(reason)

    def mark_blocked(self, reason: str) -> None:
        """Mark the assessment blocked (never converted into completion)."""
        self.gate.mark_blocked(reason)

    def exhaustion(self) -> Any:
        """Return the current attack-surface exhaustion report."""
        return self.gate.evaluate(self.graph, self.queue)

    def snapshot(self) -> dict[str, Any]:
        """Serialize a compact surface-model summary."""
        assignments = self.graph.assignments()
        return {
            "mission_id": self.mission_id,
            "target_key": self.target_key,
            "surfaces": self.graph.node_count(),
            "inputs": len(self.graph.surfaces_for(layer=SurfaceLayer.INPUT)),
            "objects": self.graph.object_count(),
            "workflows": len(self.graph.surfaces_for(layer=SurfaceLayer.WORKFLOW)),
            "capability_assignments": len(assignments),
            "applicable_assignments": sum(1 for a in assignments if a.applicable),
            "queue_total": self.queue.total(),
            "queue_remaining": self.queue.remaining(),
            "kinds": sorted({node.kind_value() for node in self.graph.nodes()}),
            "updated_at": utcnow_iso(),
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize the full service state to a JSON-safe mapping."""
        return {
            "catalog": list(self.catalog),
            "registry": self.registry.to_dict(),
            "mapper": self.mapper.to_dict(),
            "graph": self.graph.to_dict(),
            "queue": self.queue.to_dict(),
            "gate": self.gate.to_dict(),
            "snapshot": self.snapshot(),
        }

    # -- extraction helpers -------------------------------------------------

    def _entry(
        self,
        kind: str,
        name: str,
        parent_key: str,
        context: SurfaceContext,
        content: Any,
    ) -> dict[str, Any]:
        """Build a surface entry from primitives."""
        attributes: dict[str, Any] = {}
        if isinstance(content, dict):
            for key in ("method", "status_code", "content_type", "redirect", "dynamic_type", "resource_kind"):
                if content.get(key) is not None:
                    attributes[key] = content[key]
        return {
            "kind": kind,
            "name": str(name).strip(),
            "parent_key": parent_key,
            "attributes": attributes,
            "context": context,
            "dynamic_type": str((content or {}).get("dynamic_type", "")) if isinstance(content, dict) else "",
        }

    def _url_entries(
        self,
        content: Any,
        asset_key: str,
        base_parent: str,
        context: SurfaceContext,
        *,
        default_kind: str = "",
    ) -> list[dict[str, Any]]:
        """Extract URL/endpoint surface entries from discovery payload shapes.

        ``default_kind`` lets a classified observation type (e.g. ``api`` →
        ``api_endpoint``, ``graphql`` → ``graphql_operation``) shape the node
        kind instead of defaulting every URL to ``endpoint``/``url``.
        """
        urls: list[str] = []
        if isinstance(content, list):
            urls = [str(entry) for entry in content if entry]
        elif isinstance(content, dict):
            for key in ("urls", "endpoints", "routes"):
                for entry in _as_list(content.get(key)):
                    if isinstance(entry, dict):
                        url = entry.get("url") or entry.get("endpoint") or entry.get("route")
                    else:
                        url = entry
                    if url:
                        urls.append(str(url))
            crawl = content.get("crawl")
            if isinstance(crawl, dict):
                for entry in _as_list(crawl.get("urls")):
                    url = entry.get("url") if isinstance(entry, dict) else entry
                    if url:
                        urls.append(str(url))
        if asset_key and _url_path(asset_key):
            urls.append(str(asset_key))
        entries: list[dict[str, Any]] = []
        for url in dict.fromkeys(urls):
            host = _host_of(url)
            parent = self.target_key
            if host and host != self.target_key:
                parent = surface_key(SurfaceKind.HOST, host)
                if self.graph.node(parent) is None:
                    self.graph.upsert(
                        self.target_key,
                        kind=SurfaceKind.HOST,
                        name=host,
                        mission_id=self.mission_id,
                        source="discovery",
                    )
            attributes = {"fetch_hint": _fetch_hint(url)} if _fetch_hint(url) else {}
            if default_kind and default_kind in _URL_BEARING_KINDS:
                kind = default_kind
            else:
                kind = SurfaceKind.ENDPOINT.value if _url_path(url) else SurfaceKind.URL.value
            entries.append(
                {
                    "kind": kind,
                    "name": str(url).strip(),
                    "parent_key": parent,
                    "attributes": attributes,
                    "context": context,
                }
            )
        return entries

    def _input_entries(
        self,
        content: Any,
        base_parent: str,
        context: SurfaceContext,
    ) -> list[dict[str, Any]]:
        """Extract input-layer surfaces (parameters, form fields, JSON fields)."""
        parameters: list[tuple[str, dict[str, Any]]] = []
        if isinstance(content, dict):
            raw = content.get("parameters")
            if raw is None:
                raw = content.get("parameter")
            for parameter in _as_list(raw):
                if isinstance(parameter, dict):
                    name = str(parameter.get("name") or parameter.get("parameter") or "").strip()
                    if name:
                        parameters.append((name, dict(parameter)))
                elif parameter is not None:
                    parameters.append((str(parameter).strip(), {}))
        entries: list[dict[str, Any]] = []
        for name, attributes in parameters:
            if not name:
                continue
            if not attributes.get("fetch_hint") and _fetch_hint(name):
                attributes["fetch_hint"] = True
            if not attributes.get("object_hint") and _object_hint(name):
                attributes["object_hint"] = True
            entries.append(
                {
                    "kind": SurfaceKind.PARAMETER.value,
                    "name": name,
                    "parent_key": base_parent,
                    "attributes": attributes,
                    "context": context,
                }
            )
        return entries

    def _technology_entries(
        self,
        content: Any,
        parent_key: str,
        context: SurfaceContext,
    ) -> list[dict[str, Any]]:
        """Extract technology surfaces from a technology observation."""
        technologies: list[str] = []
        if isinstance(content, dict):
            for key in ("technologies", "technology"):
                technologies.extend(_as_list(content.get(key)))
            if content.get("name"):
                technologies.append(str(content["name"]))
        entries: list[dict[str, Any]] = []
        for technology in technologies:
            if technology:
                entries.append(
                    {
                        "kind": SurfaceKind.TECHNOLOGY.value,
                        "name": str(technology),
                        "parent_key": parent_key,
                        "attributes": {},
                        "context": context,
                    }
                )
        return entries

    def _object_entries(
        self,
        content: Any,
        base_parent: str,
        context: SurfaceContext,
    ) -> list[dict[str, Any]]:
        """Extract dynamic object surfaces from an observation payload.

        A business object is represented dynamically: its discovered type and
        identifiers are arbitrary strings (``user``, ``order``, ``product``,
        ...) — never hardcoded classes.
        """
        entries: list[dict[str, Any]] = []
        objects: list[Any] = []
        if isinstance(content, dict):
            raw = content.get("objects") or content.get("resources")
            if raw is not None:
                objects = _as_list(raw)
            elif content.get("object_type") or content.get("resource_kind"):
                objects = [content]
        for obj in objects:
            if not isinstance(obj, dict):
                continue
            object_type = str(obj.get("object_type") or obj.get("resource_kind") or obj.get("resource") or "").strip()
            name = str(obj.get("name") or obj.get("identifier") or obj.get("id") or "").strip()
            if not object_type and not name:
                continue
            entries.append(
                {
                    "kind": SurfaceKind.OBJECT.value,
                    "name": name or object_type or obj.get("object_id", ""),
                    "parent_key": base_parent,
                    "attributes": dict(obj),
                    "context": context,
                    "dynamic_type": object_type,
                }
            )
            identifiers = _as_list(obj.get("identifiers") or (obj.get("identifier") if obj.get("identifier") else ()))
            if identifiers:
                entries.append(
                    {
                        "kind": SurfaceKind.OBJECT_IDENTIFIER.value,
                        "name": str(obj.get("identifier") or (identifiers[0] if identifiers else "")),
                        "parent_key": base_parent,
                        "attributes": {"object_type": object_type, "identifiers": identifiers},
                        "context": context,
                    }
                )
        return entries

    def _workflow_entries(
        self,
        content: Any,
        base_parent: str,
        context: SurfaceContext,
    ) -> list[dict[str, Any]]:
        """Extract workflow / state-transition surfaces from an observation."""
        entries: list[dict[str, Any]] = []
        workflows: list[Any] = []
        if isinstance(content, dict):
            raw = content.get("workflows")
            if raw is not None:
                workflows = _as_list(raw)
            elif content.get("workflow"):
                workflows = _as_list(content["workflow"])
        for workflow in workflows:
            if isinstance(workflow, dict):
                name = str(workflow.get("name") or workflow.get("workflow") or "").strip()
                attributes = dict(workflow)
            else:
                name = str(workflow or "").strip()
                attributes = {}
            if name:
                entries.append(
                    {
                        "kind": SurfaceKind.WORKFLOW.value,
                        "name": name,
                        "parent_key": base_parent,
                        "attributes": attributes,
                        "context": context,
                    }
                )
        return entries

    def _record_dynamic_object(self, entry: dict[str, Any], node: Any, source: str) -> None:
        """Persist a :class:`DynamicObject` for an object surface entry."""
        attributes = entry.get("attributes") or {}
        identifiers = attributes.get("identifiers")
        if isinstance(identifiers, list):
            identifier_list = tuple(str(item) for item in identifiers)
        elif attributes.get("identifier"):
            identifier_list = (str(attributes["identifier"]),)
        else:
            identifier_list = (str(entry["name"]),) if entry["name"] else ()
        obj = DynamicObject(
            mission_id=self.mission_id,
            target_key=self.target_key,
            object_type=entry.get("dynamic_type", ""),
            name=entry["name"],
            key=node.key,
            identifiers=identifier_list,
            identifier_kinds=("path",) if identifiers else (),
            attributes=attributes,
            parent_key=entry["parent_key"],
            source=source,
        )
        self.graph.add_object(obj)

    def _context_for(self, *, content: Any, session_state: str) -> SurfaceContext:
        """Build the surface context from an observation payload."""
        attributes: dict[str, Any] = {}
        if isinstance(content, dict):
            attributes = content
        auth_state = self._auth_state(session_state)
        method = str(attributes.get("method") or "")
        content_type = str(attributes.get("content_type") or "")
        fetch_hint = bool(attributes.get("fetch_hint") or _fetch_hint(str(attributes.get("name") or "")))
        object_hint = bool(attributes.get("object_hint") or _object_hint(str(attributes.get("name") or "")))
        technologies = tuple(str(tech) for tech in _as_list(attributes.get("technologies")))
        return SurfaceContext(
            auth_state=auth_state,
            authorization_state=tuple(str(label) for label in _as_list(attributes.get("authorization_state"))),
            technologies=technologies,
            method=method,
            content_type=content_type,
            fetch_hint=fetch_hint,
            object_hint=object_hint,
            multi_tenant=bool(attributes.get("multi_tenant")),
            session_label=str(attributes.get("session_label") or ""),
        )

    def _auth_state(self, session_state: str) -> AuthContextState:
        """Map a raw session-state string to an :class:`AuthContextState`."""
        normalized = (session_state or "").lower()
        if "multi" in normalized or "tenant" in normalized:
            return AuthContextState.MULTI_USER
        if "auth" in normalized and "expired" in normalized:
            return AuthContextState.SESSION_EXPIRED
        if "auth" in normalized:
            return AuthContextState.AUTHENTICATED
        return AuthContextState.ANONYMOUS

    def _publish(self, event_type: str, payload: dict[str, Any]) -> None:
        """Publish a surface event on the wired bus (best-effort)."""
        if self._event_bus is None:
            return
        with contextlib.suppress(Exception):
            from hunterx.domain.events import DomainEvent

            self._event_bus.publish(
                DomainEvent(
                    event_type=event_type,
                    payload=payload,
                    source="application.attack_surface",
                    mission_id=self.mission_id,
                )
            )


__all__ = ["AttackSurfaceService", "CapabilityCatalog"]
