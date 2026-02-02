# -----------------------------------------------------------------------------
# HunterX - The Al-Assisted Vulnerability Hunter
# Developed by: NullC0d3
#
# This software is protected by copyright and intellectual property laws.
# Unauthorized reproduction, distribution, or reverse engineering is strictly prohibited.
# For authorized use only.
# -----------------------------------------------------------------------------
from dataclasses import dataclass, field
from typing import Dict, List

@dataclass
class TargetContext:
    # Probabilistic scores (0.0 to 1.0)
    os: Dict[str, float] = field(default_factory=lambda: {"linux": 0.5, "windows": 0.5})
    tech: Dict[str, float] = field(default_factory=dict)
    database: Dict[str, float] = field(default_factory=dict)
    waf_detected: bool = False
    
    def get_likely_os(self) -> str:
        """Return the OS with highest probability."""
        return max(self.os.items(), key=lambda k: k[1])[0]

class ContextEngine:
    """
    Probabilistic analysis of target environment.
    """
    def __init__(self):
        pass

    def analyze(self, baseline) -> TargetContext:
        ctx = TargetContext()
        
        # Analyze Headers
        headers = {k.lower(): v.lower() for k, v in baseline.headers.items()}
        server = headers.get("server", "")
        powered_by = headers.get("x-powered-by", "")
        
        # OS Heuristics
        if any(x in server for x in ["ubuntu", "debian", "centos", "redhat"]):
            ctx.os["linux"] += 0.4
            ctx.os["windows"] -= 0.2
        elif any(x in server for x in ["iis", "windows", "microsoft"]):
            ctx.os["windows"] += 0.4
            ctx.os["linux"] -= 0.2
            
        if "asp.net" in powered_by:
            ctx.os["windows"] += 0.3
            ctx.tech["aspnet"] = 0.9

        if "php" in powered_by:
            ctx.tech["php"] = 0.9
            ctx.os["linux"] += 0.1 # Slight bias

        self._normalize(ctx.os)
        return ctx

    def update_with_probe(self, ctx: TargetContext, payload: str, response_text: str):
        """
        Update probabilities based on probe responses.
        """
        lower_text = response_text.lower()
        
        # OS Confirmation
        if "root:x:0:0" in lower_text:
            ctx.os["linux"] = 0.99
            ctx.os["windows"] = 0.01
        
        if "bit app support" in lower_text and "fonts" in lower_text: # win.ini
            ctx.os["windows"] = 0.99
            ctx.os["linux"] = 0.01
            
        # DB Errors
        if "sql syntax" in lower_text or "mysql" in lower_text:
            ctx.database["mysql"] = ctx.database.get("mysql", 0) + 0.3
            
        self._normalize(ctx.os)

    def _normalize(self, scores: Dict[str, float]):
        """Ensure scores sum to 1.0 (roughly) or cap at 1.0."""
        # For OS, they are mutually exclusive, so we normalize.
        total = sum(scores.values())
        if total > 0:
            for k in scores:
                scores[k] = scores[k] / total
