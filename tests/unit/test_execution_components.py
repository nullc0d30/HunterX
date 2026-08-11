# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for execution SDK components: sandbox, resources, timeout, retry,
locks, cache and queue."""

from __future__ import annotations

import os
import time

import pytest

from hunterx.domain.exceptions import SandboxError, ToolLockError, ToolTimeoutError
from hunterx.domain.execution import ExecutionOutput, FailureKind, RetryPolicy
from hunterx.plugins.manifest import PermissionFlag
from hunterx.tools.sdk.cache import ExecutionCache
from hunterx.tools.sdk.context import ExecutionContextBuilder
from hunterx.tools.sdk.locks import ToolLockManager
from hunterx.tools.sdk.queue import ToolQueue
from hunterx.tools.sdk.resources import ResourceManager
from hunterx.tools.sdk.retry import RetryManager
from hunterx.tools.sdk.sandbox import ExecutionSandbox
from hunterx.tools.sdk.timeout import TimeoutManager
from tests.framework.execution import make_context


class TestExecutionSandbox:
    def test_permission_enforcement(self) -> None:
        sandbox = ExecutionSandbox()
        context = make_context(permissions=("network",))
        sandbox.enforce_permission(context, PermissionFlag.NETWORK)
        with pytest.raises(SandboxError):
            sandbox.enforce_permission(context, PermissionFlag.FILESYSTEM)

    def test_grants(self) -> None:
        sandbox = ExecutionSandbox()
        context = make_context(permissions=("network",))
        assert sandbox.grants(context, PermissionFlag.NETWORK)
        assert not sandbox.grants(context, PermissionFlag.FILESYSTEM)

    def test_temp_directory_is_isolated(self, tmp_path) -> None:  # noqa: ANN001 - pytest fixture
        sandbox = ExecutionSandbox()
        context = make_context()
        context = ExecutionContextBuilder.from_context(context).with_directories(temp_directory=str(tmp_path)).build()
        path = sandbox.create_temp_directory(context)
        assert os.path.isdir(path)
        assert context.execution_id in path

    def test_prepare_environment_isolates_secrets(self) -> None:
        sandbox = ExecutionSandbox()
        context = make_context(permissions=("secrets",))
        env = sandbox.prepare_environment(context, secrets={"TOKEN": "abc123"})
        assert env["HUNTERX_SECRET_TOKEN"] == "abc123"
        assert env["HUNTERX_EXECUTION_ID"] == context.execution_id
        sanitized = sandbox.sanitized_environment(context, secrets={"TOKEN": "abc123"})
        assert "HUNTERX_SECRET_TOKEN" not in sanitized

    def test_secrets_not_injected_without_permission(self) -> None:
        sandbox = ExecutionSandbox()
        env = sandbox.prepare_environment(make_context(), secrets={"TOKEN": "abc123"})
        assert "HUNTERX_SECRET_TOKEN" not in env

    def test_mask_secrets_redacts_values(self) -> None:
        sandbox = ExecutionSandbox()
        output = ExecutionOutput(stdout="token abc123 leaked", exit_code=0)
        masked = sandbox.mask_secrets(output, {"TOKEN": "abc123"})
        assert "abc123" not in masked.stdout
        assert "[REDACTED]" in masked.stdout
        assert output.stdout == "token abc123 leaked"


class TestResourceManager:
    def test_acquire_and_release(self) -> None:
        manager = ResourceManager(max_parallel_jobs=1)
        lease = manager.acquire(make_context())
        assert manager.usage().active_executions == 1
        lease.release()
        assert manager.usage().active_executions == 0

    def test_parallel_cap_blocks(self) -> None:
        manager = ResourceManager(max_parallel_jobs=1)
        first = manager.try_acquire(make_context())
        assert first is not None
        assert manager.try_acquire(make_context()) is None
        first.release()
        assert manager.try_acquire(make_context()) is not None

    def test_lease_is_reentrant_safe(self) -> None:
        manager = ResourceManager(max_parallel_jobs=2)
        with manager.acquire(make_context()):
            assert manager.usage().active_executions == 1
        assert manager.usage().active_executions == 0

    def test_queue_accounting(self) -> None:
        manager = ResourceManager(max_queue_size=1)
        manager.reserve_queue()
        with pytest.raises(RuntimeError):
            manager.reserve_queue()
        manager.release_queue()
        manager.reserve_queue()

    def test_limits_for_merges_execution_and_defaults(self) -> None:
        manager = ResourceManager(max_parallel_jobs=3, max_queue_size=5)
        limits = manager.limits_for(make_context())
        assert limits.max_parallel_jobs == 3
        assert limits.max_queue_size == 5


class TestTimeoutManager:
    def test_expired_raises(self) -> None:
        manager = TimeoutManager()
        context = make_context(timeout_seconds=0.01)
        manager.arm(context)
        time.sleep(0.05)
        assert manager.expired(context)
        with pytest.raises(ToolTimeoutError):
            manager.check(context)

    def test_unlimited_never_expires(self) -> None:
        manager = TimeoutManager()
        context = make_context()
        manager.arm(context)
        assert not manager.expired(context)
        assert manager.remaining_ms(context) == 0

    def test_disarm(self) -> None:
        manager = TimeoutManager()
        context = make_context(timeout_seconds=0.01)
        manager.arm(context)
        manager.disarm(context.execution_id)
        assert not manager.expired(context)


class TestRetryManager:
    def test_eligible_only_for_retryable_kinds(self) -> None:
        manager = RetryManager()
        policy = RetryPolicy(max_attempts=3)
        assert manager.eligible(policy, FailureKind.RETRYABLE, attempt=0)
        assert manager.eligible(policy, FailureKind.RETRYABLE, attempt=1)
        assert not manager.eligible(policy, FailureKind.RETRYABLE, attempt=2)
        assert not manager.eligible(policy, FailureKind.NOT_RETRYABLE, attempt=0)

    def test_delay_grows_with_backoff(self) -> None:
        manager = RetryManager()
        policy = RetryPolicy(base_delay_s=1.0, backoff_factor=2.0, jitter=False)
        assert manager.delay_for(policy, attempt=0) == 1.0
        assert manager.delay_for(policy, attempt=1) == 2.0
        assert manager.delay_for(policy, attempt=2) == 4.0


class TestToolLockManager:
    def test_exclusive_lock_blocks_other_thread(self) -> None:
        import threading

        locks = ToolLockManager()
        outcome: dict[str, bool] = {}
        acquired = threading.Event()

        def other() -> None:
            try:
                locks.acquire("nmap", "10.0.0.5", blocking=False)
                outcome["ok"] = True
            except ToolLockError:
                outcome["ok"] = False
            finally:
                acquired.set()

        with locks.locked("nmap", "10.0.0.5"):
            worker = threading.Thread(target=other)
            worker.start()
            assert acquired.wait(2)
            worker.join()
            assert outcome["ok"] is False

    def test_lock_is_reentrant_on_same_thread(self) -> None:
        locks = ToolLockManager()
        with locks.locked("nmap", "10.0.0.5"):
            locks.acquire("nmap", "10.0.0.5", blocking=False)
            locks.release("nmap", "10.0.0.5")

    def test_lock_released_on_exit(self) -> None:
        locks = ToolLockManager()
        with locks.locked("nmap", "10.0.0.5"):
            pass
        locks.acquire("nmap", "10.0.0.5", blocking=False)
        locks.release("nmap", "10.0.0.5")

    def test_different_targets_do_not_conflict(self) -> None:
        locks = ToolLockManager()
        with locks.locked("nmap", "10.0.0.5"):
            locks.acquire("nmap", "10.0.0.6", blocking=False)
            locks.release("nmap", "10.0.0.6")


class TestExecutionCache:
    def test_set_and_get(self) -> None:
        cache = ExecutionCache(ttl_s=60)
        context = make_context(target="10.0.0.5", parameters={"ports": "80"})
        key = cache.key_for(context)
        cache.set(key, object())  # type: ignore[arg-type]
        assert cache.get(key) is not None

    def test_key_is_deterministic(self) -> None:
        cache = ExecutionCache()
        a = make_context(target="10.0.0.5")
        b = make_context(target="10.0.0.5")
        assert cache.key_for(a) == cache.key_for(b)

    def test_missing_and_expired(self) -> None:
        cache = ExecutionCache(ttl_s=0)
        assert cache.get("nope") is None
        assert cache.purge_expired() == 0

    def test_invalidate(self) -> None:
        cache = ExecutionCache(ttl_s=60)
        context = make_context()
        key = cache.key_for(context)
        cache.set(key, object())  # type: ignore[arg-type]
        cache.invalidate(key)
        assert cache.get(key) is None


class TestToolQueue:
    def test_fifo_order(self) -> None:
        queue = ToolQueue()
        queue.enqueue(make_context(target="10.0.0.1"))
        queue.enqueue(make_context(target="10.0.0.2"))
        assert queue.dequeue().context.target == "10.0.0.1"
        assert queue.dequeue().context.target == "10.0.0.2"
        assert queue.dequeue() is None

    def test_capacity_bound(self) -> None:
        queue = ToolQueue(capacity=1)
        queue.enqueue(make_context())
        with pytest.raises(RuntimeError):
            queue.enqueue(make_context())

    def test_deduplicate(self) -> None:
        queue = ToolQueue(deduplicate=True)
        queue.enqueue(make_context(target="10.0.0.5"))
        with pytest.raises(RuntimeError):
            queue.enqueue(make_context(target="10.0.0.5"))
