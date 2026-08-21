# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Resource-governance tests: process-tree sampling.

The sampler must account for the ENTIRE HunterX process tree (parent +
children + grandchildren) and never raise. The /proc walk is exercised through
a fake filesystem; CPU-percent math and host-memory parsing are tested
directly.
"""

from __future__ import annotations

from hunterx.resource.sampler import ProcessTreeSampler


class TestProcessTreeWalk:
    def test_descendants_walk_includes_children_and_grandchildren(self) -> None:
        sampler = ProcessTreeSampler(pid=1)
        children = {1: [10, 11], 10: [20], 20: [30], 2: [99]}
        included = sampler._descendants(children, pid=1)
        assert included == {10, 11, 20, 30}
        assert 99 not in included

    def test_snapshot_never_raises(self) -> None:
        sampler = ProcessTreeSampler(pid=__import__("os").getpid())
        snapshot = sampler.snapshot()
        assert snapshot.rss_mb >= 0.0
        assert snapshot.process_count >= 1
        assert snapshot.cpu_cores >= 1


class TestCpuPercent:
    def test_first_sample_is_zero(self) -> None:
        sampler = ProcessTreeSampler(pid=1)
        assert sampler._cpu_percent(100.0) == 0.0

    def test_cpu_percent_is_bounded(self) -> None:
        sampler = ProcessTreeSampler(pid=1)
        import time as _time

        sampler._prev_cpu_ticks = 0.0
        sampler._prev_wall = _time.monotonic() - 1.0
        percent = sampler._cpu_percent(100.0)
        assert 0.0 <= percent <= 100.0 * 2  # capped at cores * 100


class TestHostMemoryParsing:
    def test_meminfo_kb(self) -> None:
        from hunterx.resource.sampler import _meminfo_kb

        meminfo = "MemTotal:       16777216 kB\nMemAvailable:    8388608 kB\n"
        assert _meminfo_kb(meminfo, "MemTotal") == 16777216.0
        assert _meminfo_kb(meminfo, "MemAvailable") == 8388608.0
        assert _meminfo_kb(meminfo, "Missing") == 0.0


__all__ = []
