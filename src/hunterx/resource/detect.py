# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Resource governance — environment-aware resource detection.

Detects the *effective* resources available to HunterX rather than merely the
physical host resources: bare-metal Linux, VM, WSL and container/cgroup
environments are all recognized, and cgroup memory limits, cgroup memory usage,
cgroup CPU quotas, CPU affinity/cpuset and host memory are read where available.

The guiding invariant: ``physical RAM != RAM available to HunterX``. For
containers the effective limit is the cgroup limit; for WSL/VM the effective
limit is whatever the runtime exposes.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

#: 1 MiB in bytes.
_MEBIBYTE = 1024 * 1024


class EnvironmentKind(StrEnum):
    """Runtime environment class of the HunterX host."""

    BARE_METAL = "bare_metal"
    VM = "vm"
    WSL = "wsl"
    CONTAINER = "container"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class EnvironmentInfo:
    """Effective environment resources of the HunterX process.

    Attributes:
        kind: detected environment class.
        total_memory_mb: physical (host-visible) RAM.
        effective_memory_limit_mb: RAM effectively available to HunterX
            (min of cgroup limit and host RAM).
        memory_limit_source: where the effective limit came from
            (``cgroup_v2``, ``cgroup_v1``, ``meminfo``, ``default``).
        cpu_count: effective CPU count available to the process.
        cpu_quota: effective CPU quota (fractional cores; ``0.0`` = unlimited).
        cgroup_memory_current_mb: current cgroup memory usage (``0.0`` = n/a).
        cgroup_memory_max_mb: configured cgroup memory limit (``0.0`` = none).

    """

    kind: EnvironmentKind = EnvironmentKind.UNKNOWN
    total_memory_mb: float = 0.0
    effective_memory_limit_mb: float = 0.0
    memory_limit_source: str = "default"
    cpu_count: int = 0
    cpu_quota: float = 0.0
    cgroup_memory_current_mb: float = 0.0
    cgroup_memory_max_mb: float = 0.0


def _read(path: str | Path) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip()
    except (OSError, ValueError):
        return ""


def _detect_kind() -> EnvironmentKind:
    version = _read("/proc/version").lower()
    if "microsoft" in version or "wsl" in version:
        return EnvironmentKind.WSL
    cgroup_v2_max = _read("/sys/fs/cgroup/memory.max")
    if cgroup_v2_max and cgroup_v2_max not in ("max", ""):
        return EnvironmentKind.CONTAINER
    cgroup_v1_limit = _read("/sys/fs/cgroup/memory/memory.limit_in_bytes")
    if cgroup_v1_limit and cgroup_v1_limit.isdigit() and int(cgroup_v1_limit) < (1 << 62):
        return EnvironmentKind.CONTAINER
    dmi = _read("/sys/class/dmi/id/product_name").lower()
    if dmi and re.search(r"vmware|virtualbox|qemu|kvm|virtual machine|bochs|xen|hyper-v", dmi):
        return EnvironmentKind.VM
    return EnvironmentKind.BARE_METAL


def _host_total_memory_mb() -> float:
    meminfo = _read("/proc/meminfo")
    match = re.search(r"MemTotal:\s+(\d+)\s*kB", meminfo)
    if match:
        return int(match.group(1)) / 1024.0
    try:
        import resource  # type: ignore[import-not-found]

        if hasattr(resource, "getpagesize"):
            return 0.0
    except Exception:  # noqa: BLE001 - best-effort detection
        pass
    return 0.0


def _cgroup_v2_memory() -> tuple[float, float]:
    """Return ``(max_mb, current_mb)`` for cgroup v2 (``0.0`` when unset)."""
    max_value = _read("/sys/fs/cgroup/memory.max")
    current = _read("/sys/fs/cgroup/memory.current")
    max_mb = 0.0
    current_mb = 0.0
    if max_value and max_value != "max":
        try:
            max_mb = int(max_value) / _MEBIBYTE
        except ValueError:
            max_mb = 0.0
    if current:
        try:
            current_mb = int(current) / _MEBIBYTE
        except ValueError:
            current_mb = 0.0
    return max_mb, current_mb


def _cgroup_v1_memory() -> tuple[float, float]:
    """Return ``(max_mb, current_mb)`` for cgroup v1 (``0.0`` when unset)."""
    limit = _read("/sys/fs/cgroup/memory/memory.limit_in_bytes")
    usage = _read("/sys/fs/cgroup/memory/memory.usage_in_bytes")
    max_mb = 0.0
    current_mb = 0.0
    if limit and limit.isdigit():
        value = int(limit)
        # The v1 "no limit" sentinel is a huge number; treat it as unset.
        if value < (1 << 62):
            max_mb = value / _MEBIBYTE
    if usage and usage.isdigit():
        current_mb = int(usage) / _MEBIBYTE
    return max_mb, current_mb


def _cgroup_v2_cpu_quota() -> float:
    """Return the cgroup v2 fractional CPU quota (``0.0`` = no limit)."""
    value = _read("/sys/fs/cgroup/cpu.max")
    if not value:
        return 0.0
    parts = value.split()
    if len(parts) != 2:
        return 0.0
    quota, period = parts
    try:
        quota_value = int(quota)
        period_value = int(period)
    except ValueError:
        return 0.0
    if quota_value <= 0 or period_value <= 0:
        return 0.0
    return quota_value / period_value


def _cgroup_v1_cpu_quota() -> float:
    """Return the cgroup v1 fractional CPU quota (``0.0`` = no limit)."""
    quota = _read("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
    period = _read("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
    try:
        quota_value = int(quota)
        period_value = int(period)
    except ValueError:
        return 0.0
    if quota_value <= 0 or period_value <= 0:
        return 0.0
    return quota_value / period_value


def detect_cgroup_memory() -> tuple[float, float, str]:
    """Return ``(max_mb, current_mb, source)`` from the active cgroup (``0`` = none)."""
    max_v2, current_v2 = _cgroup_v2_memory()
    if max_v2 or current_v2:
        return max_v2, current_v2, "cgroup_v2"
    max_v1, current_v1 = _cgroup_v1_memory()
    if max_v1 or current_v1:
        return max_v1, current_v1, "cgroup_v1"
    return 0.0, 0.0, ""


def detect_cpu_quota() -> float:
    """Return the effective fractional CPU quota (``0.0`` = no quota configured)."""
    quota_v2 = _cgroup_v2_cpu_quota()
    if quota_v2:
        return quota_v2
    return _cgroup_v1_cpu_quota()


def detect_effective_cpu_count() -> int:
    """Return the CPU count the process may actually use (quota-aware)."""
    cpu_count = os.cpu_count() or 1
    quota = detect_cpu_quota()
    if quota and quota < cpu_count:
        return max(1, int(round(quota)))
    # cpuset (affinity) aware: report the number of allowed CPUs when possible.
    allowed = _read("/sys/fs/cgroup/cpuset.cpus.effective")
    if allowed and allowed not in ("", "\n"):
        try:
            count = _count_cpu_list(allowed)
            if count and count < cpu_count:
                return count
        except ValueError:
            pass
    return cpu_count


def _count_cpu_list(value: str) -> int:
    """Count CPUs from a cpuset list expression (``0,2-4`` -> 4)."""
    total = 0
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            low, high = part.split("-", 1)
            total += int(high) - int(low) + 1
        else:
            total += 1
    return total


def detect_environment() -> EnvironmentInfo:
    """Detect the effective environment resources of the HunterX process."""
    kind = _detect_kind()
    total_mb = _host_total_memory_mb()
    cgroup_max, cgroup_current, cgroup_source = detect_cgroup_memory()
    effective_limit = total_mb
    limit_source = "meminfo"
    if cgroup_max and (total_mb == 0.0 or cgroup_max < total_mb):
        effective_limit = cgroup_max
        limit_source = cgroup_source
    cpu_count = detect_effective_cpu_count()
    cpu_quota = detect_cpu_quota()
    return EnvironmentInfo(
        kind=kind,
        total_memory_mb=total_mb,
        effective_memory_limit_mb=effective_limit,
        memory_limit_source=limit_source,
        cpu_count=cpu_count,
        cpu_quota=cpu_quota,
        cgroup_memory_current_mb=cgroup_current,
        cgroup_memory_max_mb=cgroup_max,
    )


def describe_environment(info: EnvironmentInfo | None = None) -> str:
    """Return a compact human description of the detected environment."""
    info = info if info is not None else detect_environment()
    return (
        f"{info.kind.value} "
        f"memory_limit={info.effective_memory_limit_mb:.0f}MB "
        f"({info.memory_limit_source}) "
        f"cpus={info.cpu_count} "
        f"cpu_quota={info.cpu_quota:.2f}"
    )


__all__ = [
    "EnvironmentInfo",
    "EnvironmentKind",
    "describe_environment",
    "detect_cgroup_memory",
    "detect_cpu_quota",
    "detect_effective_cpu_count",
    "detect_environment",
]
