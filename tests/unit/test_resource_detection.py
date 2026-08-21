# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Resource-governance tests: environment-aware resource detection.

Verifies the effective-resource detection used by the mission resource
governor: cgroup v1/v2 memory limits, CPU quota detection, cpuset-aware CPU
count, host memory and environment classification (bare-metal / VM / WSL /
container). The guiding invariant under test: ``physical RAM != RAM available
to HunterX`` — a container cgroup limit is the effective limit even when the
physical host has far more RAM.
"""

from __future__ import annotations

import pytest

from hunterx.resource.detect import (
    EnvironmentKind,
    _count_cpu_list,
    detect_cgroup_memory,
    detect_cpu_quota,
    detect_effective_cpu_count,
    detect_environment,
)


@pytest.fixture(autouse=True)
def _isolated_proc(monkeypatch: pytest.MonkeyPatch) -> None:
    """Redirect every /sys/fs/cgroup read through a monkeypatchable helper.

    The detection helpers read fixed paths; we monkeypatch the module-level
    ``_read`` function so tests never touch the real host cgroup files.
    """
    import hunterx.resource.detect as detect

    real_read = detect._read

    def fake_read(path: str) -> str:
        overrides = getattr(detect, "_TEST_OVERRIDES", None)
        if overrides is not None and path in overrides:
            return overrides[path]
        return real_read(path)

    monkeypatch.setattr(detect, "_read", fake_read)


def _set(monkeypatch: pytest.MonkeyPatch, values: dict[str, str]) -> None:
    import hunterx.resource.detect as detect

    monkeypatch.setattr(detect, "_TEST_OVERRIDES", dict(values), raising=False)


class TestCgroupMemoryDetection:
    def test_cgroup_v2_memory_limit_is_detected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # A 2 GiB container cgroup limit.
        _set(
            monkeypatch,
            {
                "/sys/fs/cgroup/memory.max": str(2 * 1024 * 1024 * 1024),
                "/sys/fs/cgroup/memory.current": str(512 * 1024 * 1024),
            },
        )
        max_mb, current_mb, source = detect_cgroup_memory()
        assert source == "cgroup_v2"
        assert max_mb == pytest.approx(2048.0)
        assert current_mb == pytest.approx(512.0)

    def test_cgroup_v2_unlimited_is_ignored(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set(monkeypatch, {"/sys/fs/cgroup/memory.max": "max"})
        max_mb, current_mb, source = detect_cgroup_memory()
        assert max_mb == 0.0
        assert current_mb == 0.0
        assert source == ""

    def test_cgroup_v1_memory_limit_is_detected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set(
            monkeypatch,
            {
                "/sys/fs/cgroup/memory/memory.limit_in_bytes": str(4 * 1024 * 1024 * 1024),
                "/sys/fs/cgroup/memory/memory.usage_in_bytes": str(1024 * 1024 * 1024),
            },
        )
        max_mb, current_mb, source = detect_cgroup_memory()
        assert source == "cgroup_v1"
        assert max_mb == pytest.approx(4096.0)
        assert current_mb == pytest.approx(1024.0)

    def test_cgroup_v1_huge_sentinel_is_unlimited(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # The v1 "no limit" sentinel is a huge number and must be treated as unset.
        _set(monkeypatch, {"/sys/fs/cgroup/memory/memory.limit_in_bytes": str(1 << 63)})
        max_mb, _current_mb, source = detect_cgroup_memory()
        assert max_mb == 0.0
        assert source == ""


class TestCpuQuotaDetection:
    def test_cgroup_v2_cpu_quota(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set(monkeypatch, {"/sys/fs/cgroup/cpu.max": "200000 100000"})
        assert detect_cpu_quota() == pytest.approx(2.0)

    def test_cgroup_v2_unlimited_quota(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set(monkeypatch, {"/sys/fs/cgroup/cpu.max": "max 100000"})
        assert detect_cpu_quota() == 0.0

    def test_cgroup_v1_cpu_quota(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set(
            monkeypatch,
            {
                "/sys/fs/cgroup/cpu/cpu.cfs_quota_us": "50000",
                "/sys/fs/cgroup/cpu/cpu.cfs_period_us": "100000",
            },
        )
        assert detect_cpu_quota() == pytest.approx(0.5)

    def test_cpuset_list_count(self) -> None:
        assert _count_cpu_list("0,2-4") == 4
        assert _count_cpu_list("0-3") == 4
        assert _count_cpu_list("7") == 1


class TestEffectiveCpuCount:
    def test_quota_reduces_cpu_count(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Host reports 8 CPUs; the cgroup quota allows 2.
        monkeypatch.setattr("hunterx.resource.detect.os.cpu_count", lambda: 8)
        _set(monkeypatch, {"/sys/fs/cgroup/cpu.max": "200000 100000"})
        assert detect_effective_cpu_count() == 2

    def test_cpuset_reduces_cpu_count(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("hunterx.resource.detect.os.cpu_count", lambda: 8)
        _set(monkeypatch, {"/sys/fs/cgroup/cpuset.cpus.effective": "0-1"})
        assert detect_effective_cpu_count() == 2


class TestEnvironmentDetection:
    def test_container_cgroup_limit_beats_host_ram(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Physical host: 16 GiB. Container cgroup: 4 GiB. Effective limit = 4 GiB.
        _set(
            monkeypatch,
            {
                "/proc/meminfo": "MemTotal:       16777216 kB\n",
                "/proc/version": "Linux version 6.8.0 (gcc)",
                "/sys/fs/cgroup/memory.max": str(4 * 1024 * 1024 * 1024),
                "/sys/fs/cgroup/memory.current": "0",
            },
        )
        info = detect_environment()
        assert info.kind is EnvironmentKind.CONTAINER
        assert info.total_memory_mb == pytest.approx(16384.0)
        assert info.effective_memory_limit_mb == pytest.approx(4096.0)
        assert info.memory_limit_source == "cgroup_v2"

    def test_wsl_is_detected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set(
            monkeypatch,
            {
                "/proc/version": "Linux version 5.15.90.1-microsoft-standard-WSL2 (gcc)",
                "/proc/meminfo": "MemTotal:        4194304 kB\n",
            },
        )
        info = detect_environment()
        assert info.kind is EnvironmentKind.WSL
        assert info.effective_memory_limit_mb == pytest.approx(4096.0)

    def test_bare_metal_uses_host_memory(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set(
            monkeypatch,
            {
                "/proc/meminfo": "MemTotal:       8388608 kB\n",
                "/proc/version": "Linux version 6.8.0 (gcc)",
            },
        )
        info = detect_environment()
        assert info.kind is EnvironmentKind.BARE_METAL
        assert info.effective_memory_limit_mb == pytest.approx(8192.0)
        assert info.memory_limit_source == "meminfo"


__all__ = []
