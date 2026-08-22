# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Resource governance — mission memory instrumentation.

The real-runtime memory probe answers the question *where did the memory go*.
It records, at the same instant:

- the process RSS / VmRSS / VmHWM / VmPeak (``/proc/<pid>/status`` on Linux),
- the process-tree RSS/CPU (the governor's own sampler),
- the Python heap (``tracemalloc`` current/top, opt-in),
- the mission aggregate: per-collection item counts AND approximate serialized
  bytes (observations, hypotheses, decisions, findings, endpoints, parameters,
  attack paths, trace, history, tool executions, negative evidence, coverage,
  branches, baselines, runs),
- the model attacker context (hypotheses, plans, learning context items/bytes,
  prompt size, response size),
- the assessment-queue depth,
- and the :class:`ResourceGovernor`'s own measurement taken at the same time.

The probe is designed to be cheap: per-item serialized-size measurement is
capped per item, and the whole snapshot is produced only when requested (the
mission runner requests it at a throttled interval). Output is appended as
JSON-lines to a file configured via ``HUNTERX_RESOURCE_TELEMETRY_FILE``.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass
from typing import Any

from hunterx.resource.sampler import ProcessTreeSampler

#: Cap for a single item's serialized-size measurement (keeps the probe cheap).
_ITEM_JSON_CAP = 262144

#: Cap for a single collection's total measured bytes (keeps the probe cheap).
_COLLECTION_JSON_CAP = 8 * 1024 * 1024


@dataclass(slots=True)
class CollectionMetrics:
    """Item count and approximate serialized bytes of one collection."""

    name: str = ""
    count: int = 0
    approx_bytes: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {"name": self.name, "count": self.count, "approx_bytes": self.approx_bytes}


def _json_len(value: Any) -> int:
    """Return the JSON-serialized length of ``value`` (capped per item)."""
    try:
        return len(json.dumps(value, default=str, separators=(",", ":"))[:_ITEM_JSON_CAP])
    except (TypeError, ValueError, RecursionError):
        try:
            return len(str(value)[:_ITEM_JSON_CAP])
        except Exception:  # noqa: BLE001 - measurement is best-effort
            return 0


def _item_bytes(item: Any) -> int:
    """Approximate the serialized bytes of one aggregate item (capped)."""
    to_dict = getattr(item, "to_dict", None)
    if callable(to_dict):
        try:
            return _json_len(to_dict())
        except Exception:  # noqa: BLE001 - best-effort
            return _json_len(item)
    if isinstance(item, dict):
        return _json_len(item)
    if hasattr(item, "__dict__"):
        return _json_len(item.__dict__)
    return _json_len(item)


def collection_metrics(name: str, items: list[Any]) -> CollectionMetrics:
    """Measure one list-backed collection (count + capped approximate bytes)."""
    count = len(items)
    total = 0
    for item in items:
        total += _item_bytes(item)
        if total >= _COLLECTION_JSON_CAP:
            total = _COLLECTION_JSON_CAP
            break
    return CollectionMetrics(name=name, count=count, approx_bytes=total)


def mapping_metrics(name: str, mapping: dict[str, Any]) -> CollectionMetrics:
    """Measure one dict-backed collection (count + capped approximate bytes)."""
    count = len(mapping)
    total = 0
    for value in mapping.values():
        total += _item_bytes(value)
        if total >= _COLLECTION_JSON_CAP:
            total = _COLLECTION_JSON_CAP
            break
    return CollectionMetrics(name=name, count=count, approx_bytes=total)


def process_status_mb() -> dict[str, float]:
    """Return ``{vmrss_mb, vmhwm_mb, vmpeak_mb}`` from ``/proc/self/status``.

    Falls back to ``psutil`` and then to ``0`` on platforms without ``/proc``.
    """
    if os.name == "posix":
        try:

            status = _read("/proc/self/status")
            vmrss = _status_kb(status, "VmRSS")
            vmhwm = _status_kb(status, "VmHWM")
            vmpeak = _status_kb(status, "VmPeak")
            if vmrss:
                return {
                    "vmrss_mb": vmrss / 1024.0,
                    "vmhwm_mb": (vmhwm or vmrss) / 1024.0,
                    "vmpeak_mb": (vmpeak or vmrss) / 1024.0,
                }
        except Exception:  # noqa: BLE001 - measurement is best-effort
            pass
    try:
        import psutil  # type: ignore[import-not-found]

        process = psutil.Process(os.getpid())
        memory = process.memory_info()
        return {"vmrss_mb": memory.rss / 1048576.0, "vmhwm_mb": memory.rss / 1048576.0, "vmpeak_mb": memory.rss / 1048576.0}
    except Exception:  # noqa: BLE001
        return {"vmrss_mb": 0.0, "vmhwm_mb": 0.0, "vmpeak_mb": 0.0}


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def _status_kb(status: str, key: str) -> float:
    import re

    match = re.search(rf"{key}:\s+(\d+)\s*kB", status)
    return float(match.group(1)) if match else 0.0


class HeapStats:
    """Python-heap statistics via ``tracemalloc`` (opt-in)."""

    def __init__(self, enabled: bool = False) -> None:
        self._enabled = enabled
        self._lock = threading.Lock()
        if enabled:
            try:
                import tracemalloc

                tracemalloc.start()
            except Exception:  # noqa: BLE001 - tracemalloc is optional
                self._enabled = False

    @property
    def enabled(self) -> bool:
        """Return ``True`` when heap tracing is active."""
        return self._enabled

    def snapshot_mb(self) -> dict[str, float]:
        """Return ``{heap_current_mb, heap_peak_mb}`` (``0`` when disabled)."""
        if not self._enabled:
            return {"heap_current_mb": 0.0, "heap_peak_mb": 0.0}
        try:
            import tracemalloc

            current, peak = tracemalloc.get_traced_memory()
            return {"heap_current_mb": current / 1048576.0, "heap_peak_mb": peak / 1048576.0}
        except Exception:  # noqa: BLE001
            return {"heap_current_mb": 0.0, "heap_peak_mb": 0.0}


class MissionMemoryProbe:
    """Record a cross-sectional memory snapshot of a running mission."""

    def __init__(
        self,
        *,
        sampler: ProcessTreeSampler | None = None,
        heap_enabled: bool = False,
    ) -> None:
        self._sampler = sampler if sampler is not None else ProcessTreeSampler()
        self._heap = HeapStats(enabled=heap_enabled)

    # -- process --------------------------------------------------------------

    def process_tree_mb(self) -> dict[str, float]:
        """Return the process-tree RSS/CPU (the governor's own sampler)."""
        snapshot = self._sampler.snapshot()
        return {
            "process_tree_rss_mb": snapshot.rss_mb,
            "process_tree_cpu_percent": snapshot.cpu_percent,
            "process_count": float(snapshot.process_count),
        }

    # -- mission aggregate -------------------------------------------------------

    def measure_mission(self, mission: Any) -> list[dict[str, Any]]:
        """Measure the mission aggregate collections (counts + approx bytes)."""
        if mission is None:
            return []
        metrics: list[CollectionMetrics] = []
        metrics.append(collection_metrics("observations", _as_list(getattr(mission, "observations", ()))))
        metrics.append(collection_metrics("hypotheses", _as_list(getattr(mission, "hypotheses", ()))))
        metrics.append(collection_metrics("decisions", _as_list(getattr(mission, "decisions", ()))))
        metrics.append(collection_metrics("branches", _as_list(getattr(mission, "branches", ()))))
        metrics.append(collection_metrics("runs", _as_list(getattr(mission, "runs", ()))))
        metrics.append(collection_metrics("trace", _as_list(getattr(mission, "trace", ()))))
        metrics.append(collection_metrics("negative_evidence", _as_list(getattr(mission, "negative_evidence", ()))))
        metrics.append(collection_metrics("baselines", _as_list(getattr(mission, "baselines", ()))))
        metrics.append(collection_metrics("differential_results", _as_list(getattr(mission, "differential_results", ()))))
        metrics.append(collection_metrics("impact_analyses", _as_list(getattr(mission, "impact_analyses", ()))))
        metrics.append(collection_metrics("novel_behaviors", _as_list(getattr(mission, "novel_behaviors", ()))))
        metrics.append(collection_metrics("telemetry_snapshots", _as_list(getattr(mission, "telemetry_snapshots", ()))))
        metrics.append(collection_metrics("checkpoints", _as_list(getattr(mission, "checkpoints", ()))))
        coverage = getattr(mission, "coverage", None) or {}
        metrics.append(
            CollectionMetrics(
                name="coverage",
                count=sum(len(cells) for cells in coverage.values()),
                approx_bytes=min(_COLLECTION_JSON_CAP, _json_len(coverage)),
            )
        )
        context = getattr(mission, "context", None)
        if context is not None:
            metrics.append(collection_metrics("context.observations", _as_list(getattr(context, "observations", ()))))
            metrics.append(collection_metrics("context.findings", _as_list(getattr(context, "findings", ()))))
            metrics.append(collection_metrics("context.tool_executions", _as_list(getattr(context, "tool_executions", ()))))
            metrics.append(collection_metrics("context.attack_paths", _as_list(getattr(context, "attack_paths", ()))))
            metrics.append(collection_metrics("context.surface_relationships", _as_list(getattr(context, "surface_relationships", ()))))
            metrics.append(collection_metrics("context.history", _as_list(getattr(context, "history", ()))))
            metrics.append(mapping_metrics("context.endpoints", getattr(context, "endpoints", None) or {}))
            metrics.append(mapping_metrics("context.parameters", getattr(context, "parameters", None) or {}))
            metrics.append(mapping_metrics("context.assets", getattr(context, "assets", None) or {}))
            metrics.append(mapping_metrics("context.technologies", getattr(context, "technologies", None) or {}))
            metrics.append(mapping_metrics("context.services", getattr(context, "services", None) or {}))
            metrics.append(mapping_metrics("context.evidence", getattr(context, "evidence", None) or {}))
            metrics.append(mapping_metrics("context.proofs", getattr(context, "proofs", None) or {}))
        return [metric.to_dict() for metric in metrics]

    def aggregate_bytes(self, metrics: list[dict[str, Any]] | None = None) -> int:
        """Return the total approximate aggregate bytes of the mission."""
        if metrics is None:
            return 0
        return int(sum(metric.get("approx_bytes", 0) for metric in metrics))

    # -- model attacker -----------------------------------------------------------

    def measure_model(self, attacker: Any) -> dict[str, Any]:
        """Measure the model attacker's in-memory context (counts + bytes)."""
        if attacker is None:
            return {"enabled": False}
        learning = getattr(attacker, "_learning", None)
        hypotheses = _as_list(getattr(attacker, "_hypotheses", None))
        plans = _as_list(getattr(attacker, "_plans", None))
        result: dict[str, Any] = {"enabled": True}
        if isinstance(hypotheses, dict):
            hypotheses = list(hypotheses.values())
        result["hypotheses_count"] = len(hypotheses)
        result["hypotheses_bytes"] = min(_COLLECTION_JSON_CAP, sum(_item_bytes(h) for h in hypotheses[:512]))
        result["plans_count"] = len(plans)
        result["plans_bytes"] = min(_COLLECTION_JSON_CAP, sum(_item_bytes(p) for p in plans[:512]))
        if learning is not None:
            result["learning_observations"] = len(_as_list(getattr(learning, "observations", ())))
            result["learning_findings"] = len(_as_list(getattr(learning, "validated_findings", ())))
            result["learning_paths"] = len(_as_list(getattr(learning, "adjacent_paths", ())))
            result["learning_disproven"] = len(getattr(learning, "disproven_fingerprints", set()))
            result["learning_bytes"] = min(_COLLECTION_JSON_CAP, _json_len(getattr(learning, "summary", lambda: {})()))
        surface = getattr(attacker, "_surface", None)
        if surface is not None:
            try:
                queue = getattr(surface, "queue", None)
                result["queue_remaining"] = queue.remaining() if queue is not None else -1
                graph = getattr(surface, "graph", None)
                result["surface_nodes"] = len(graph.nodes()) if graph is not None else -1
            except Exception:  # noqa: BLE001 - measurement is best-effort
                result["queue_remaining"] = -1
                result["surface_nodes"] = -1
        return result

    # -- combined snapshot -----------------------------------------------------------

    def snapshot(
        self,
        *,
        mission_id: str = "",
        mission: Any = None,
        governor: Any = None,
        model_attacker: Any = None,
        prompt_size: int = 0,
        response_size: int = 0,
    ) -> dict[str, Any]:
        """Record one cross-sectional memory snapshot (JSON-safe)."""
        record: dict[str, Any] = {"mission_id": mission_id}
        record.update(process_status_mb())
        record.update(self.process_tree_mb())
        record.update(self._heap.snapshot_mb())
        collections = self.measure_mission(mission)
        record["mission_collections"] = collections
        record["mission_aggregate_approx_bytes"] = self.aggregate_bytes(collections)
        record["model"] = self.measure_model(model_attacker)
        record["prompt_bytes"] = int(prompt_size)
        record["response_bytes"] = int(response_size)
        if governor is not None:
            record["governor"] = governor.report()
        return record


class TelemetryLog:
    """Append JSON-lines telemetry to a file (best-effort, never raises)."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = threading.Lock()

    def append(self, record: dict[str, Any]) -> None:
        """Append one JSON-lines record (best-effort, never raises)."""
        if not self._path:
            return
        try:
            line = json.dumps(record, default=str)
        except (TypeError, ValueError, RecursionError):
            line = json.dumps({"record": str(record)[:4000]}, default=str)
        with self._lock:
            try:
                with open(self._path, "a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
            except OSError:
                pass


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, dict):
        return list(value.values())
    return [value]


__all__ = [
    "CollectionMetrics",
    "HeapStats",
    "MissionMemoryProbe",
    "TelemetryLog",
    "collection_metrics",
    "mapping_metrics",
    "process_status_mb",
]
