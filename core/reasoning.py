# -----------------------------------------------------------------------------
# HunterX - The Al-Assisted Vulnerability Hunter
# Developed by: NullC0d3
#
# This software is protected by copyright and intellectual property laws.
# Unauthorized reproduction, distribution, or reverse engineering is strictly prohibited.
# For authorized use only.
# -----------------------------------------------------------------------------
from typing import List, Dict, Any
from .utils import logger

class ReasoningEngine:
    """
    Infers potential attack chains based on confirmed findings and context.
    Does NOT execute them. Only maps possibilities.
    """
    def __init__(self):
        self.chains = []

    def reason(self, findings: List[Dict], context: Any) -> List[Dict]:
        """
        Analyze findings to suggest next-step attack chains.
        """
        self.chains = []
        
        # Aggregate finding types
        vuln_types = set()
        for f in findings:
            if f.get("findings") or f.get("diff_score", 0) > 80:
                vuln_types.add(f.get("payload_category", "GENERIC"))
                
        # 1. LFI Chains
        if "LFI" in vuln_types:
            if context.get_likely_os() == "linux":
                self.chains.append({
                    "chain": "LFI -> Log Poisoning -> RCE",
                    "likelihood": "High",
                    "reason": "LFI detected on Linux. Check access methods (Apache/SSH logs) for poisoning."
                })
                self.chains.append({
                    "chain": "LFI -> /proc/self/environ -> RCE",
                    "likelihood": "Medium",
                    "reason": "LFI on Linux could allow environ poisoning."
                })
            elif context.get_likely_os() == "windows":
                self.chains.append({
                    "chain": "LFI -> SAM Hive Extraction -> Hash Cracking",
                    "likelihood": "High",
                    "reason": "Windows LFI allows exfiltration of SAM/SYSTEM hives."
                })

        # 2. XSS Chains
        if "XSS" in vuln_types:
            self.chains.append({
                "chain": "Reflected XSS -> CSRF Bypass",
                "likelihood": "Medium",
                "reason": "XSS can be used to extract Anti-CSRF tokens."
            })
            
        # 3. SSTI Chains
        if "SSTI" in vuln_types:
            self.chains.append({
                "chain": "SSTI -> RCE",
                "likelihood": "Critical",
                "reason": "SSTI almost always leads to full RCE via template sandbox escape."
            })
            
        # 4. Open Redirect
        if "Open Redirect" in vuln_types:
             self.chains.append({
                "chain": "Open Redirect -> OAuth Token Theft",
                "likelihood": "Low",
                "reason": "If used in OAuth flow, can steal tokens."
            })

        logger.info(f"Reasoning Engine inferred {len(self.chains)} potential attack chains.")
        return self.chains
