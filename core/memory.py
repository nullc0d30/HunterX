# -----------------------------------------------------------------------------
# HunterX - The Al-Assisted Vulnerability Hunter
# Developed by: NullC0d3
#
# This software is protected by copyright and intellectual property laws.
# Unauthorized reproduction, distribution, or reverse engineering is strictly prohibited.
# For authorized use only.
# -----------------------------------------------------------------------------
from typing import Set, Dict
from datetime import datetime
from .utils import logger

class SessionMemory:
    """
    Tracks session-specific patterns to adapt behavior.
    Reduces noise by suppressing repeated failures or risky patterns.
    """
    def __init__(self):
        self.failed_patterns: Set[str] = set()
        self.blocked_payloads: Set[str] = set()
        self.waf_triggers: int = 0
        self.error_counts: Dict[str, int] = {}
        self.suppressed_categories: Set[str] = set()
        
    def record_block(self, payload: str, category: str):
        self.blocked_payloads.add(payload)
        self.waf_triggers += 1
        logger.warning(f"Memory: Block recorded for {category}. WAF Triggers: {self.waf_triggers}")
        
    def record_failure(self, category: str):
        if category not in self.error_counts:
            self.error_counts[category] = 0
        self.error_counts[category] += 1
        
        if self.error_counts[category] > 10:
            if category not in self.suppressed_categories:
                logger.info(f"Memory: Suppressing category '{category}' due to high failure rate.")
                self.suppressed_categories.add(category)
                
    def should_skip(self, payload: str, category: str) -> bool:
        if category in self.suppressed_categories:
            return True
        if payload in self.blocked_payloads:
            return True
        return False
