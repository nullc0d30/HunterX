# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Canonical JSON-safe serialization boundary.

Every value that enters a JSON-backed persistence structure (SQLAlchemy
``JSON``/``JSONB`` columns, audit snapshots, JSON-text columns, event payloads)
MUST already be JSON-compatible. This module is the single canonical helper
that enforces that invariant: :func:`to_json_safe` recursively transforms any
Python value into a JSON-native structure while preserving as much semantic
information as possible.

Contract:

* JSON-native scalars (``None``, ``bool``, ``int``, ``float``, ``str``) are
  preserved exactly.
* Mappings, sequences and sets are recursed; set/frozenset elements are sorted
  so the output is deterministic.
* Non-string mapping keys are stringified deterministically; collisions are
  disambiguated with a numeric suffix so no key is silently dropped.
* Well-known standard-library values get faithful typed representations:
  enums keep their semantic value, datetimes become ISO-8601, UUIDs and paths
  become strings, bytes become a bounded typed preview.
* Dataclasses and project objects exposing ``to_json_safe_dict``/``to_dict``/
  ``model_dump`` are expanded structurally (never reduced to ``str()``), so
  domain objects such as the JavaScript tokenizer's ``JSToken`` survive
  persistence with their fields intact.
* Arbitrary objects without a structured representation fall back to a typed
  marker with a memory-address-free ``repr`` — never ``<X object at 0x...>``.
* Circular references terminate deterministically with a ``__circular__``
  marker; pathological depth terminates with ``__truncated__``.
* Non-finite floats (NaN/Infinity) become their canonical string forms so the
  emitted document is always valid strict JSON.
* Credential-looking mapping keys (passwords, tokens, authorization headers,
  cookies, API keys) are masked through :mod:`hunterx.shared.masking`, so
  fallback serialization can never leak secrets into durable storage.

The function never raises on unsupported input, never mutates its arguments,
and returns fresh containers.
"""

from __future__ import annotations

import dataclasses
import datetime as _datetime
import json
import re
import uuid as _uuid
from collections.abc import Mapping
from enum import Enum
from pathlib import Path
from typing import Any

from hunterx.shared.masking import mask_value

__all__ = ["register_json_safe", "safe_repr", "to_json_safe"]

#: Maximum recursion depth before a subtree is replaced with a truncation
#: marker. Far above any legitimate payload depth; purely a runaway guard.
_MAX_DEPTH = 64

_INF = float("inf")

#: Mapping-key names whose values must never be persisted verbatim.
_SECRET_KEY_FRAGMENTS = (
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "authorization",
    "auth_header",
    "cookie",
    "set-cookie",
    "bearer",
    "credential",
    "private_key",
    "access_token",
    "refresh_token",
    "session_id",
    "proxy_auth",
)

_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]+")

#: Deterministic placeholder substituted for memory addresses in fallback
#: representations (``<X object at 0x7f...>`` -> ``<X object at …>``).
_ADDRESS_PLACEHOLDER = "…"

#: Project-approved per-class serializers registered at import time via
#: :func:`register_json_safe`. Explicit serializers take priority over the
#: generic dataclass/object policies.
_EXPLICIT_SERIALIZERS: dict[type, Any] = {}


def register_json_safe(cls: type, serializer: Any) -> None:
    """Register an explicit serializer ``(obj) -> JSON-safe value`` for ``cls``."""
    _EXPLICIT_SERIALIZERS[cls] = serializer


def safe_repr(value: Any) -> str:
    """Return a deterministic repr of ``value`` without memory addresses."""
    try:
        text = repr(value)
    except Exception:  # noqa: BLE001 - repr must never raise outward
        text = f"<{type(value).__name__}>"
    return _ADDRESS_RE.sub(_ADDRESS_PLACEHOLDER, text)


def _is_secret_key(key: str) -> bool:
    lowered = key.lower()
    return any(fragment in lowered for fragment in _SECRET_KEY_FRAGMENTS)


def _stringify_key(key: Any, seen_keys: set[str]) -> str:
    """Convert a mapping key to a unique string deterministically."""
    if isinstance(key, str):
        base = key
    elif isinstance(key, Enum):
        base = str(key.value)
    elif isinstance(key, bool):
        base = "true" if key else "false"
    elif key is None:
        base = "null"
    elif isinstance(key, int):
        base = str(key)
    else:
        base = safe_repr(key)
    candidate = base
    counter = 1
    while candidate in seen_keys:
        candidate = f"{base}#{counter}"
        counter += 1
    return candidate


def _explicit_serializer(obj: Any) -> Any | None:
    for cls, serializer in _EXPLICIT_SERIALIZERS.items():
        if isinstance(obj, cls):
            return serializer
    return None


def _sanitize_entry(key: str, item: Any) -> Any:
    """Mask ``item`` when its key/field name looks credential-bearing.

    Applied uniformly to mappings, dataclass fields, structured payloads and
    generic object attributes so fallback serialization can never persist a
    secret verbatim.
    """
    if not _is_secret_key(key):
        return item
    if isinstance(item, str):
        return mask_value(item, reveal_head=1, reveal_tail=1)
    return "[masked]"


def _structured_payload(obj: Any) -> dict[str, Any] | None:
    """Return a structured dict for ``obj`` from its approved accessors."""
    for name in ("to_json_safe_dict", "to_dict", "model_dump"):
        method = getattr(obj, name, None)
        if callable(method):
            try:
                payload = method()
            except Exception:  # noqa: BLE001 - accessor failures fall through
                continue
            if isinstance(payload, Mapping):
                return dict(payload)
    return None


def to_json_safe(
    value: Any,
    *,
    _depth: int = 0,
    _active: frozenset[int] | None = None,
) -> Any:
    """Recursively convert ``value`` into a JSON-compatible structure.

    See the module docstring for the full contract. The function is pure: it
    never mutates ``value`` and always returns fresh containers for composite
    inputs.
    """
    if _active is None:
        _active = frozenset()
    if _depth > _MAX_DEPTH:
        return {"__type__": type(value).__name__, "__truncated__": True}

    # -- JSON-native passthrough -------------------------------------------
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if value != value:  # NaN (nan != nan is the defining property)
            return "NaN"
        if value == _INF:
            return "Infinity"
        if value == -_INF:
            return "-Infinity"
        return value

    # -- explicit project-approved serializers ------------------------------
    serializer = _explicit_serializer(value)
    if serializer is not None:
        return to_json_safe(serializer(value), _depth=_depth + 1, _active=_active)

    # -- mappings ------------------------------------------------------------
    if isinstance(value, Mapping):
        obj_id = id(value)
        if obj_id in _active:
            return {"__circular__": True}
        active = _active | {obj_id}
        result: dict[str, Any] = {}
        for key, item in value.items():
            safe_key = _stringify_key(key, set(result))
            safe_item = to_json_safe(item, _depth=_depth + 1, _active=active)
            result[safe_key] = _sanitize_entry(safe_key, safe_item)
        return result

    # -- sequences and sets ---------------------------------------------------
    if isinstance(value, (list, tuple)):
        obj_id = id(value)
        if obj_id in _active:
            return {"__circular__": True}
        active = _active | {obj_id}
        return [to_json_safe(item, _depth=_depth + 1, _active=active) for item in value]
    if isinstance(value, (set, frozenset)):
        items = [to_json_safe(item, _depth=_depth + 1, _active=_active) for item in value]
        items.sort(key=lambda item: json.dumps(item, sort_keys=True, default=str))
        return {"__type__": "set", "items": items}

    # -- well-known standard-library values ------------------------------------
    if isinstance(value, Enum):
        return to_json_safe(value.value, _depth=_depth + 1, _active=_active)
    if isinstance(value, (_datetime.datetime, _datetime.date, _datetime.time)):
        return value.isoformat()
    if isinstance(value, _uuid.UUID):
        return str(value)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        preview = value[:256]
        try:
            decoded = preview.decode("utf-8")
        except UnicodeDecodeError:
            decoded = preview.decode("latin-1")
        return {
            "__type__": "bytes",
            "size": len(value),
            "preview": decoded,
            "truncated": len(value) > len(preview),
        }

    # -- dataclasses -------------------------------------------------------------
    if dataclasses.is_dataclass(value) and not isinstance(value, dataclasses.Field):
        obj_id = id(value)
        if obj_id in _active:
            return {"__type__": type(value).__name__, "__circular__": True}
        active = _active | {obj_id}
        payload: dict[str, Any] = {"__type__": type(value).__name__}
        for field_info in dataclasses.fields(value):  # type: ignore[arg-type]
            field_value = getattr(value, field_info.name, None)
            safe_field = to_json_safe(field_value, _depth=_depth + 1, _active=active)
            payload[field_info.name] = _sanitize_entry(field_info.name, safe_field)
        return payload

    # -- objects with approved structured accessors ------------------------------
    structured = _structured_payload(value)
    if structured is not None:
        obj_id = id(value)
        if obj_id in _active:
            return {"__type__": type(value).__name__, "__circular__": True}
        active = _active | {obj_id}
        payload = {"__type__": type(value).__name__}
        for key, item in structured.items():
            safe_key = _stringify_key(key, set(payload))
            safe_item = to_json_safe(item, _depth=_depth + 1, _active=active)
            payload[safe_key] = _sanitize_entry(safe_key, safe_item)
        return payload

    # -- generic objects: public, non-callable attributes --------------------------
    obj_id = id(value)
    if obj_id in _active:
        return {"__type__": type(value).__name__, "__circular__": True}
    active = _active | {obj_id}
    attributes: dict[str, Any] = {}
    slots = getattr(type(value), "__slots__", None)
    names: list[str]
    if slots is not None:
        names = [
            slot
            for slot in slots
            if isinstance(slot, str) and not slot.startswith("_") and hasattr(value, slot)
        ]
    else:
        names = [
            name
            for name in vars(value)
            if not name.startswith("_") and not callable(getattr(value, name, None))
        ] if hasattr(value, "__dict__") else []
    for name in sorted(names)[:64]:
        try:
            attributes[name] = getattr(value, name)
        except Exception:  # noqa: BLE001 - attribute read failures degrade to skip
            continue
    if attributes:
        payload = {"__type__": type(value).__name__}
        for name in attributes:
            safe_attr = to_json_safe(attributes[name], _depth=_depth + 1, _active=active)
            payload[name] = _sanitize_entry(name, safe_attr)
        return payload
    return {"__type__": type(value).__name__, "repr": safe_repr(value)}
