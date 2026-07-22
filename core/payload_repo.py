import json
import os
import tempfile
import urllib.request
from typing import Optional


class RemotePayloadRepo:
    """Fetches latest payloads from remote repositories."""

    REMOTE_SOURCES = {
        "payloadsallthethings": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/{category}/Intruder/{file}",
        "fuzzdb": "https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/attack/{category}/{file}",
        "seclists": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/{file}",
    }

    def __init__(self, cache_dir: Optional[str] = None):
        self.cache_dir = cache_dir or os.path.join(tempfile.gettempdir(), "hunterx_payloads")
        os.makedirs(self.cache_dir, exist_ok=True)

    def fetch(self, source: str, category: str, filename: str) -> Optional[str]:
        """Fetch a payload file from remote and cache it locally."""
        cache_path = os.path.join(self.cache_dir, f"{source}_{category}_{filename}")
        if os.path.exists(cache_path):
            with open(cache_path) as f:
                return f.read()

        template = self.REMOTE_SOURCES.get(source)
        if not template:
            return None

        url = template.format(category=category, file=filename)
        try:
            resp = urllib.request.urlopen(url, timeout=10)
            content = resp.read().decode("utf-8", errors="ignore")
            with open(cache_path, "w") as f:
                f.write(content)
            return content
        except Exception:
            return None

    def list_cache(self) -> list:
        return os.listdir(self.cache_dir) if os.path.isdir(self.cache_dir) else []

    def clear_cache(self):
        if os.path.isdir(self.cache_dir):
            for f in os.listdir(self.cache_dir):
                os.remove(os.path.join(self.cache_dir, f))
