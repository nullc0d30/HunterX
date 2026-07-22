import threading
import uuid
from datetime import datetime
from typing import Dict, Optional, List

from api.models import ScanJob, ScanStatus


class JobQueue:
    """In-memory job queue for async scan execution."""

    def __init__(self):
        self._jobs: Dict[str, ScanJob] = {}
        self._lock = threading.Lock()

    def create(self, target_url: str, profile: str = "bounty", options: dict = None) -> ScanJob:
        job = ScanJob(
            id=str(uuid.uuid4())[:8],
            target_url=target_url,
            profile=profile,
            options=options or {},
        )
        with self._lock:
            self._jobs[job.id] = job
        return job

    def get(self, job_id: str) -> Optional[ScanJob]:
        with self._lock:
            return self._jobs.get(job_id)

    def update(self, job_id: str, **kwargs):
        with self._lock:
            job = self._jobs.get(job_id)
            if job:
                for k, v in kwargs.items():
                    setattr(job, k, v)

    def list_all(self) -> List[ScanJob]:
        with self._lock:
            return list(self._jobs.values())

    def delete(self, job_id: str):
        with self._lock:
            self._jobs.pop(job_id, None)


queue = JobQueue()
