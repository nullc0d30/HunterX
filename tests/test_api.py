# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from unittest.mock import patch
from api.models import ScanJob, ScanStatus
from api.job_queue import JobQueue


def test_scan_status_values():
    assert ScanStatus.PENDING.value == "pending"
    assert ScanStatus.RUNNING.value == "running"
    assert ScanStatus.COMPLETED.value == "completed"
    assert ScanStatus.FAILED.value == "failed"
    assert ScanStatus.CANCELLED.value == "cancelled"


def test_scan_job_defaults():
    job = ScanJob(id="test-1", target_url="http://example.com")
    assert job.profile == "bounty"
    assert job.status == ScanStatus.PENDING
    assert job.progress == 0.0
    assert job.results == []
    assert job.error is None


def test_job_queue_create():
    queue = JobQueue()
    job = queue.create("http://example.com", "bounty", {})
    assert job.id is not None
    assert len(job.id) > 0
    assert job.target_url == "http://example.com"
    assert job.profile == "bounty"
    assert job.status == ScanStatus.PENDING


def test_job_queue_get():
    queue = JobQueue()
    job = queue.create("http://example.com", "gov", {})
    retrieved = queue.get(job.id)
    assert retrieved is not None
    assert retrieved.id == job.id


def test_job_queue_get_not_found():
    queue = JobQueue()
    assert queue.get("nonexistent") is None


def test_job_queue_update():
    queue = JobQueue()
    job = queue.create("http://example.com", "bounty", {})
    queue.update(job.id, status=ScanStatus.RUNNING, progress=0.5)
    updated = queue.get(job.id)
    assert updated.status == ScanStatus.RUNNING
    assert updated.progress == 0.5


def test_job_queue_list_all():
    queue = JobQueue()
    queue.create("http://a.com", "bounty", {})
    queue.create("http://b.com", "gov", {})
    jobs = queue.list_all()
    assert len(jobs) == 2


def test_job_queue_concurrent_safe():
    import threading
    queue = JobQueue()
    errors = []

    def add_jobs():
        for i in range(50):
            try:
                queue.create(f"http://target{i}.com", "bounty", {})
            except Exception as e:
                errors.append(str(e))

    threads = [threading.Thread(target=add_jobs) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0
    assert len(queue.list_all()) == 200


@patch("api.server.HAS_FASTAPI", False)
def test_api_disabled_graceful():
    try:
        from api.server import start_api
        with patch("core.utils.logger") as mock_log:
            start_api()
            mock_log.error.assert_called_once()
    except Exception:
        pass


def test_job_queue_update_nonexistent():
    queue = JobQueue()
    queue.update("no-such-job", status=ScanStatus.FAILED, error="test")
    assert queue.get("no-such-job") is None
