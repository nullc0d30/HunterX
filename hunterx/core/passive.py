# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
from typing import Dict, Any
from .fingerprint import Fingerprint
from ..utils.utils import logger
import re

class PassiveIntel:
    """
    Stage 0 Analysis.
    Passive gathering from baseline response. No extra requests.
    """
    def __init__(self):
        pass

    def analyze(self, baseline: Fingerprint) -> Dict[str, Any]:
        """
        Analyze the baseline fingerprint for security posture and tech stack.
        """
        intel = {
            "security_headers": {},
            "tech_stack": [],
            "potential_endpoints": [],
            "comments": [],
            "grade": "U" # Unset
        }
        
        # 1. Header Analysis
        headers_lower = {k.lower(): v for k, v in baseline.headers.items()}
        
        sec_headers = [
            "content-security-policy",
            "strict-transport-security", 
            "x-content-type-options",
            "x-frame-options",
            "x-xss-protection"
        ]
        
        missing_headers = []
        for h in sec_headers:
            if h in headers_lower:
                intel["security_headers"][h] = "Present"
            else:
                missing_headers.append(h)
                intel["security_headers"][h] = "Missing"

        # 2. Tech Stack Hints
        server_val = baseline.headers.get("Server", "")
        if server_val:
            intel["tech_stack"].append(f"Server: {server_val}")
        powered_val = baseline.headers.get("X-Powered-By", "")
        if powered_val:
            intel["tech_stack"].append(f"PoweredBy: {powered_val}")
            
        # 3. HTML Analysis (Regex based, passive)
        body = baseline.text
        
        # Comments
        comments = re.findall(r"<!--(.*?)-->", body, re.DOTALL)
        for c in comments:
            clean = c.strip()
            if len(clean) > 0 and len(clean) < 200: # Ignore massive commented out code blocks for summary
                intel["comments"].append(clean)
                
        # API/Endpoints
        # Look for relative paths in JS or hrefs
        endpoints = re.findall(r"['\"](/[a-zA-Z0-9_./-]+)['\"]", body)
        # Filter common junk
        clean_endpoints = set()
        for ep in endpoints:
            if not any(x in ep for x in [".png", ".jpg", ".css", ".js", ".woff"]):
                clean_endpoints.add(ep)
        intel["potential_endpoints"] = list(clean_endpoints)[:10] # Show top 10

        logger.info(f"Passive Intel: Found {len(intel['tech_stack'])} tech indicators and {len(missing_headers)} missing security headers.")
        return intel
