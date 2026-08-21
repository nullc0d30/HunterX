# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Resource governance — process-tree sampler.

Samples the resident memory and CPU of the *entire HunterX process tree*
(parent + children + grandchildren) plus the host memory pressure. On Linux the
``/proc`` filesystem is walked to compute the exact process-tree RSS and CPU
time; on platforms without ``/proc`` (e.g. a Windows developer machine) the
sampler degrades to ``psutil`` when available and otherwise to a best-effort
self-process reading. The governor never blocks on sampling: every read is
guarded and bounded.
"""

from __future__ import annotations

import os
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

_MEBIBYTE = 1024 * 1024


@dataclass(frozen=True, slots=True)
class ProcessSnapshot:
    """A sampled resource snapshot of the HunterX process tree and host.

    Attributes:
        rss_bytes: resident set size of the whole process tree.
        rss_mb: resident set size in MiB.
        process_count: number of processes accounted for.
        cpu_percent: process-tree CPU utilization since the previous sample.
        cpu_cores: effective CPU count of the host.
        host_total_mb: physical host RAM.
        host_available_mb: host RAM currently available.
        host_used_mb: host RAM currently in use.

    """

    rss_bytes: int = 0
    rss_mb: float = 0.0
    process_count: int = 0
    cpu_percent: float = 0.0
    cpu_cores: int = 0
    host_total_mb: float = 0.0
    host_available_mb: float = 0.0
    host_used_mb: float = 0.0


class ProcessTreeSampler:
    """Sample process-tree RSS/CPU and host memory for the governor.

    Args:
        pid: root process id (defaults to the current process).
        interval_s: smoothing window used for CPU-percent computation.

    """

    def __init__(self, *, pid: int | None = None, interval_s: float = 3.0) -> None:
        self._pid = pid if pid is not None else os.getpid()
        self._interval = max(0.1, interval_s)
        self._lock = threading.Lock()
        self._prev_cpu_ticks: float | None = None
        self._prev_wall: float = 0.0

    def snapshot(self) -> ProcessSnapshot:
        """Return a fresh resource snapshot (never raises)."""
        if os.name == "nt":
            return self._snapshot_windows()
        return self._snapshot_posix()

    # -- POSIX (Linux / WSL) ---------------------------------------------------

    def _snapshot_posix(self) -> ProcessSnapshot:
        rss, cpu_ticks, count = self._collect_posix()
        cpu_percent = self._cpu_percent(cpu_ticks)
        host_total, host_available = self._host_memory()
        return ProcessSnapshot(
            rss_bytes=rss,
            rss_mb=rss / _MEBIBYTE,
            process_count=count,
            cpu_percent=cpu_percent,
            cpu_cores=os.cpu_count() or 1,
            host_total_mb=host_total,
            host_available_mb=host_available,
            host_used_mb=max(0.0, host_total - host_available),
        )

    def _collect_posix(self) -> tuple[int, float, int]:
        """Sum RSS and CPU ticks over the process tree rooted at ``self._pid``.

        A single pass over ``/proc`` builds the PPID children map and per-process
        stats; the tree walk then sums only the processes that belong to HunterX.
        """
        proc = Path("/proc")
        children: dict[int, list[int]] = defaultdict(list)
        stats: dict[int, tuple[int, float]] = {}
        try:
            pids = [int(entry.name) for entry in proc.iterdir() if entry.name.isdigit()]
        except OSError:
            pids = []
        page_size = _page_size()
        for pid in pids:
            stat = _read(f"/proc/{pid}/stat")
            statm = _read(f"/proc/{pid}/statm")
            if not stat or not statm:
                continue
            try:
                rparen = stat.rfind(")")
                after = stat[rparen + 1 :].split()
                ppid = int(after[1])
                utime = int(after[10])
                stime = int(after[11])
                rss_pages = int(statm.split()[1])
            except (ValueError, IndexError):
                continue
            children[ppid].append(pid)
            stats[pid] = (rss_pages * page_size, utime + stime)
        included = self._descendants(children, pid=self._pid)
        included.add(self._pid)
        if not included:
            included = {self._pid}
        rss = 0
        cpu = 0.0
        for pid in included:
            entry = stats.get(pid)
            if entry is None:
                continue
            rss += entry[0]
            cpu += entry[1]
        return rss, cpu, len(included)

    @staticmethod
    def _descendants(children: dict[int, list[int]], pid: int | None = None, root: int | None = None) -> set[int]:
        """Walk the child map from ``pid`` (defaults to the sampler root)."""
        if pid is None:
            pid = root
        if pid is None:
            return set()
        result: set[int] = set()
        stack = list(children.get(pid, ()))
        while stack:
            child = stack.pop()
            if child in result:
                continue
            result.add(child)
            stack.extend(children.get(child, ()))
        return result

    # -- Windows (development) -------------------------------------------------

    def _snapshot_windows(self) -> ProcessSnapshot:
        rss_bytes, cpu_ticks, count = self._collect_windows()
        host_total, host_available = self._host_memory()
        return ProcessSnapshot(
            rss_bytes=rss_bytes,
            rss_mb=rss_bytes / _MEBIBYTE,
            process_count=count,
            cpu_percent=self._cpu_percent(cpu_ticks),
            cpu_cores=os.cpu_count() or 1,
            host_total_mb=host_total,
            host_available_mb=host_available,
            host_used_mb=max(0.0, host_total - host_available),
        )

    def _collect_windows(self) -> tuple[int, float, int]:
        try:
            import psutil  # type: ignore[import-not-found]
        except ImportError:  # pragma: no cover - optional on the dev platform
            return self._windows_ctypes_rss(), 0.0, 1
        try:
            root = psutil.Process(self._pid)
            processes = [root, *root.children(recursive=True)]
            rss = sum(int(p.memory_info().rss) for p in processes if p.is_running())
            cpu = sum(p.cpu_times().user + p.cpu_times().system for p in processes if p.is_running())
            return rss, cpu, len(processes)
        except Exception:  # noqa: BLE001 - best-effort sampling
            return self._windows_ctypes_rss(), 0.0, 1

    def _windows_ctypes_rss(self) -> int:  # pragma: no cover - dev-only fallback
        """Return the current working set of this process via ctypes (best-effort)."""
        try:
            import ctypes
            from ctypes import wintypes

            class ProcessMemoryCounters(ctypes.Structure):  # noqa: N801  # ctypes ABI struct name
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            psapi = ctypes.WinDLL("psapi.dll")
            counters = ProcessMemoryCounters()
            counters.cb = ctypes.sizeof(ProcessMemoryCounters)
            handle = ctypes.windll.kernel32.GetCurrentProcess()
            ok = psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb)
            if ok:
                return int(counters.WorkingSetSize)
        except Exception:  # noqa: BLE001 - sampling must never raise
            pass
        return 0

    # -- shared helpers ---------------------------------------------------------

    def _cpu_percent(self, cpu_ticks: float) -> float:
        """Return the CPU percent since the previous sample (0 on the first)."""
        now = time.monotonic()
        elapsed = now - self._prev_wall
        with self._lock:
            previous = self._prev_cpu_ticks
            self._prev_cpu_ticks = cpu_ticks
            self._prev_wall = now
        if previous is None or elapsed <= 0:
            return 0.0
        delta_ticks = max(0.0, cpu_ticks - previous)
        hz = _clock_ticks_per_second()
        if hz <= 0:
            return 0.0
        cores = max(1, os.cpu_count() or 1)
        return min(100.0 * cores, (delta_ticks / hz) / elapsed * 100.0)

    @staticmethod
    def _host_memory() -> tuple[float, float]:
        """Return ``(total_mb, available_mb)`` of host RAM (best-effort)."""
        if os.name == "posix":

            meminfo = _read("/proc/meminfo")
            total = _meminfo_kb(meminfo, "MemTotal")
            available = _meminfo_kb(meminfo, "MemAvailable")
            if total:
                available_mb = available if available else total
                return total / 1024.0, available_mb / 1024.0
        try:
            import psutil  # type: ignore[import-not-found]

            vm = psutil.virtual_memory()
            return vm.total / _MEBIBYTE, vm.available / _MEBIBYTE
        except Exception:  # noqa: BLE001 - best-effort
            return 0.0, 0.0

    def child_pids(self) -> list[int]:
        """Return the direct child PIDs of the rooted process (best-effort)."""
        if os.name == "nt":
            try:
                import psutil  # type: ignore[import-not-found]

                root = psutil.Process(self._pid)
                return [p.pid for p in root.children()]
            except Exception:  # noqa: BLE001
                return []
        try:
            return [int(p) for p in (Path("/proc") / str(self._pid) / "task" / str(self._pid) / "children").read_text().split()]
        except OSError:
            return []


def _read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def _meminfo_kb(meminfo: str, key: str) -> float:
    import re

    match = re.search(rf"{key}:\s+(\d+)\s*kB", meminfo)
    return float(match.group(1)) if match else 0.0


def _page_size() -> int:
    try:
        return os.sysconf("SC_PAGE_SIZE")
    except (AttributeError, ValueError, OSError):
        return 4096


def _clock_ticks_per_second() -> float:
    try:
        return float(os.sysconf("SC_CLK_TCK"))
    except (AttributeError, ValueError, OSError):
        return 100.0


__all__ = ["ProcessSnapshot", "ProcessTreeSampler"]
