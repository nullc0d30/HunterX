# SPDX-License-Identifier: Proprietary
# Copyright NullC0d3 — HunterX v3.1
import re
from typing import List

class PayloadClassifier:
    """
    Classifies payloads based on filename patterns and content heuristics.
    """
    
    # GUARDRAILS: Patterns that are NEVER allowed
    DESTRUCTIVE_PATTERNS = [
        r"rm\s+-rf", r"mkfs", r"dd\s+if=", r":\(\)\{ :\|:& \};:", # Fork bombs / Wipe
        r"wget\s+http", r"curl\s+http", r"nc\s+-e", r"bash\s+-i", # Reverse shells / Exfil
        r"into\s+outfile", r"dumpfile", r"load_file", # SQL Write/Read (Sensitive)
        r"shutdown", r"reboot", r"init\s+0",
        r"chmod\s+777", r"chown\s+root"
    ]

    # Mapping filename patterns/regex to categories
    PATTERNS = {
        r"rce|exec|command": "RCE",
        r"lfi|traversal|etc_passwd": "LFI",
        r"ssti|template": "SSTI",
        r"open_redirect|redirect": "OPEN_REDIRECT",
        r"xss|cross_site": "XSS",
        r"sqli|sql|injection": "SQLI",
        r"ssrf": "SSRF",
        r"xxe": "XXE",
        r"crlf": "CRLF",
        r"leak|disclosure": "INFO_LEAK",
        r"bypass|403": "WAF_BYPASS",
        r"common|files|sensitive": "FILE_DISCLOSURE"
    }

    def classify_file(self, filename: str) -> List[str]:
        """
        Return a list of categories for a given filename.
        """
        categories = set()
        filename_lower = filename.lower()
        
        for pattern, category in self.PATTERNS.items():
            if re.search(pattern, filename_lower):
                categories.add(category)
        
        if not categories:
            categories.add("GENERIC")
            
        return list(categories)

    def classify_payload_content(self, payload: str) -> List[str]:
        """
        Heuristic content analysis for unclassified payloads.
        """
        cats = set()
        p = payload.lower()
        
        if any(x in p for x in ["<script", "javascript:", "onload=", "onerror="]):
            cats.add("XSS")
        if any(x in p for x in ["union select", "waitfor delay", "sleep(", "benchmark("]):
            cats.add("SQLI")
        if any(x in p for x in ["../../", "/etc/passwd", "win.ini"]):
            cats.add("LFI")
        if any(x in p for x in ["{{", "${", "<%="]):
            cats.add("SSTI")
        if any(x in p for x in ["|", ";", "`", "$("]):
            cats.add("RCE")
            
        return list(cats) if cats else ["GENERIC"]

    def detect_stage(self, payload: str, category: str) -> int:
        """
        Guess the stage (1=Probe, 2=Confirm, 3=Exploit) based on heuristics.
        """
        p = payload.lower()
        length = len(p)
        
        # Stage 1: Probes (Simple, standard checks)
        if category in ("LFI",) and (p == "/etc/passwd" or p == "../../../../etc/passwd" or p == "c:\\boot.ini"):
            return 1
        if category in ("RCE",) and (p == ";id" or p == "`id`" or p == "$(id)"):
            return 1
        if category in ("SSTI",) and (p == "{{7*7}}" or p == "${7*7}"):
            return 1
        if category == "OPEN_REDIRECT" and "google.com" in p and length < 30:
            return 1
            
        # Stage 3: Exploits (Complex, obfuscated, or data exfil)
        if length > 50:
            return 3
        if any(x in p for x in ["wget", "curl", "netcat", "bash -i"]):
            return 3
            
        # Default to Stage 2 (Confirmation / Standard)
        return 2

    def is_destructive(self, payload: str) -> bool:
        """
        Check if payload matches any destructive patterns.
        """
        for pattern in self.DESTRUCTIVE_PATTERNS:
            if re.search(pattern, payload, re.IGNORECASE):
                return True
        return False
