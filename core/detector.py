# -----------------------------------------------------------------------------
# HunterX - The Al-Assisted Vulnerability Hunter
# Developed by: NullC0d3
#
# This software is protected by copyright and intellectual property laws.
# Unauthorized reproduction, distribution, or reverse engineering is strictly prohibited.
# For authorized use only.
# -----------------------------------------------------------------------------
import re
from typing import List, Tuple

class Detector:
    def __init__(self):
        self.signatures = [
            # LFI / Path Traversal
            (r"root:x:0:0:", "Confidence: High - LFI (/etc/passwd)"),
            (r"\[font|extension\]", "Confidence: High - LFI (win.ini)"),
            (r"boot\.ini", "Confidence: Medium - LFI (boot.ini)"),
            (r"drivers\\etc\\hosts", "Confidence: High - LFI (Windows hosts)"),
            
            # RCE
            (r"uid=\d+\(root\)", "Confidence: Critical - RCE (id output)"),
            (r"Windows IP Configuration", "Confidence: Critical - RCE (ipconfig)"),
            (r"((www|ftp)\.|(mailto|file):)+", "Confidence: Low - Potential RCE/SSRF pattern"),
            
            # SQL Injection
            (r"SQL syntax", "Confidence: Medium - SQLi (Syntax Error)"),
            (r"mysql_fetch_array", "Confidence: Medium - SQLi (MySQL Error)"),
            (r"ORA-\d{5}", "Confidence: High - SQLi (Oracle Error)"),
            (r"PostgreSQL.*ERROR", "Confidence: High - SQLi (Postgres Error)"),
            (r"Microsoft OLE DB Provider", "Confidence: High - SQLi (MSSQL Error)"),
            
            # SSTI
            (r"49", "Confidence: Low - SSTI (Arithmetic match 7*7, context needed)"),
            (r"FreeMarker template error", "Confidence: High - SSTI (FreeMarker)"),
            
            # XXE
            (r"root:x:0:0:", "Confidence: High - XXE (via /etc/passwd)"),
            
            # SSRF
            (r"aws-keys", "Confidence: Medium - SSRF (Cloud Metadata hints)"),
            
            # XSS
            # Note: XSS usually requires browser confirmation, but we check reflection
            (r"<script>alert", "Confidence: Low - Reflected XSS (Naive)"),
        ]

    def scan(self, response_text: str) -> List[str]:
        """
        Scan response text for known vulnerability signatures.
        """
        matches = []
        for pattern, name in self.signatures:
            if re.search(pattern, response_text, re.IGNORECASE):
                matches.append(name)
        return matches

    def check_heuristics(self, baseline_text: str, response_text: str, payload: str) -> List[str]:
        """
        Check for heuristic indicators like reflection.
        """
        heuristics = []
        
        # 1. Reflection (XSS / SSTI)
        # Check if payload is reflected in response
        if payload in response_text:
            # Check if it was already in baseline (to avoid false positives on search pages)
            if payload not in baseline_text:
                heuristics.append("Confidence: Medium - Payload Reflected (Potential XSS/SSTI)")
                
        # 2. Key Differentiation
        # If payload was "id" and we see "uid=0", that's covered by signatures.
        # But if payload was "sleep(5)" and time > 5s? (Handled in engine/fingerprint time diff, not text)
            
        return heuristics
