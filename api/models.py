from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional
from enum import Enum


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ScanJob:
    id: str
    target_url: str
    profile: str = "bounty"
    status: ScanStatus = ScanStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    progress: float = 0.0
    results: List[Dict] = field(default_factory=list)
    error: Optional[str] = None
    options: Dict = field(default_factory=dict)
