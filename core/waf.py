# -----------------------------------------------------------------------------
# HunterX - The Al-Assisted Vulnerability Hunter
# Developed by: NullC0d3
#
# This software is protected by copyright and intellectual property laws.
# Unauthorized reproduction, distribution, or reverse engineering is strictly prohibited.
# For authorized use only.
# -----------------------------------------------------------------------------
from .utils import logger
import urllib.parse
import random

class WAFDetect:
    """
    Detects and attempts to evade WAFs.
    """
    def __init__(self):
        self.detected_waf = None
        self.blocking_signatures = [
            # Known WAF block pages/headers
            "cf-ray", "cloudflare", "imperva", "incapsula",
            "x-iinfo", "x-cdn", "akamai",
            "waf", "firewall", "blocked", "forbidden"
        ]

    def check_blocking(self, response) -> bool:
        """
        Check if a response indicates WAF blocking (403/406 with specific hints).
        """
        if not response:
            return False
            
        if response.status_code in [403, 406, 501]:
            # Basic status check check
            # Look for headers
            for h in response.headers:
                for sig in self.blocking_signatures:
                    if sig in h.lower() or sig in response.headers[h].lower():
                        logger.warning(f"Likely WAF detected via Header: {sig}")
                        self.detected_waf = sig
                        return True
            
            # Look for body content
            text_lower = response.text.lower()
            if "captcha" in text_lower or "security" in text_lower or "denied" in text_lower:
                return True

        return False

    def evade(self, payload: str, evasion_level: str = "medium") -> str:
        """
        Apply evasion techniques to payload.
        """
        if evasion_level == "low":
            return payload # No evasion
            
        # Medium: Basic encoding
        if evasion_level == "medium":
            # Randomly choose URL encoding
            if random.random() > 0.5:
                return urllib.parse.quote(payload)
            # Or URL double encoding for special chars
            return payload
            
        # High: Aggressive techniques
        if evasion_level == "high":
            # 1. Double URL Encode
            # 2. Path Traversal tricks for LFI/Redirect
            if "/" in payload:
                # Replace / with // or /./
                if random.random() > 0.5:
                    return payload.replace("/", "//")
                else:
                    return payload.replace("/", "/./")
                    
            # 3. SQLi comments
            if "UNION" in payload.upper():
                return payload.replace(" ", "/**/")
                
        return payload
