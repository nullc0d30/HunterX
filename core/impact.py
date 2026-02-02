# -----------------------------------------------------------------------------
# HunterX - The Al-Assisted Vulnerability Hunter
# Developed by: NullC0d3
#
# This software is protected by copyright and intellectual property laws.
# Unauthorized reproduction, distribution, or reverse engineering is strictly prohibited.
# For authorized use only.
# -----------------------------------------------------------------------------
from typing import Dict, Any

class ImpactAnalyzer:
    """
    Analyzes verified findings to determine real-world impact and exploitability.
    Conservative assessment: Impact is Low unless proven otherwise.
    """
    
    def analyze(self, finding: Dict[str, Any], context: Any) -> Dict[str, Any]:
        category = finding.get('payload_category', 'UNKNOWN')
        diff_score = finding.get('diff_score', 0)
        
        impact = {
            "score": 0.1,  # Default Low
            "severity": "Low",
            "justification": "Insufficient data",
            "constraints": []
        }
        
        if category == "XSS":
            self._assess_xss(finding, context, impact)
        elif category == "LFI":
            self._assess_lfi(finding, context, impact)
        elif category == "SQLi":
            self._assess_sqli(finding, context, impact)
        elif category == "RCE":
            self._assess_rce(finding, context, impact)
            
        return impact

    def _assess_xss(self, finding, context, impact):
        # Heuristic: Reflected XSS is lower impact than stored (context needed)
        # Check CSP in passive intel? (Assumed available in context eventually)
        impact['score'] = 0.4
        impact['severity'] = "Medium"
        impact['justification'] = "Reflected script execution probable."
        
        if finding.get('payload_category') == 'Stored XSS': # If we had classification for stored
             impact['score'] = 0.7
             impact['severity'] = "High"

    def _assess_lfi(self, finding, context, impact):
        impact['score'] = 0.8
        impact['severity'] = "High"
        impact['justification'] = "Arbitrary file read confirmed."
        
        if "win.ini" in finding.get('payload', '') and context.os.get('linux', 0) > 0.8:
             # Contradiction?
             pass

    def _assess_sqli(self, finding, context, impact):
        impact['score'] = 0.9
        impact['severity'] = "Critical"
        impact['justification'] = "Database query manipulation confirmed."

    def _assess_rce(self, finding, context, impact):
        impact['score'] = 1.0
        impact['severity'] = "Critical"
        impact['justification'] = "Remote Code Execution verified."
