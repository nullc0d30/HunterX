# -----------------------------------------------------------------------------
# HunterX - The Al-Assisted Vulnerability Hunter
# Developed by: NullC0d3
#
# This software is protected by copyright and intellectual property laws.
# Unauthorized reproduction, distribution, or reverse engineering is strictly prohibited.
# For authorized use only.
# -----------------------------------------------------------------------------
import difflib
from .fingerprint import Fingerprint
from .utils import logger

class ResponseDiffer:
    def __init__(self):
        # Weight configuration for scoring
        self.weights = {
            "status": 0.4,
            "length": 0.2,
            "structure": 0.3,
            "keywords": 0.1
        }

    def diff(self, baseline: Fingerprint, current_response) -> dict:
        """
        Compare current response against baseline and calculate anomaly score.
        Returns a dict containing the score and details.
        """
        if not current_response:
            return {"score": 0, "reason": "No response"}

        score = 0.0
        reasons = []

        # 1. Status Code Change (Weighted)
        # If status changes from 200 to 500/200, it's interesting. 
        # 404 might be less interesting unless probing for files.
        status_score = 0
        if current_response.status_code != baseline.status_code:
            if current_response.status_code == 200:
                 status_score = 100 # High interest if we got a 200 where previously we didn't (or vice versa? context matters)
            elif current_response.status_code >= 500:
                status_score = 80 # Server error is good
            else:
                status_score = 40 # 403/404/etc
            reasons.append(f"Status changed: {baseline.status_code}->{current_response.status_code}")
        
        score += status_score * self.weights["status"]

        # 2. Content Length Change (Weighted)
        len_diff = abs(len(current_response.content) - baseline.content_length)
        if len_diff > 0:
            # Normalized length diff
            len_ratio = min(1.0, len_diff / (baseline.content_length + 1))
            len_score = len_ratio * 100
            if len_score > 10:
                reasons.append(f"Length diff: {len(current_response.content)} (+/- {len_diff})")
                score += len_score * self.weights["length"]

        # 3. Structural Similarity (Weighted)
        # Using QuickRatio for speed on large bodies
        if current_response.status_code == baseline.status_code: # Only compare structure if status is same-ish
            matcher = difflib.SequenceMatcher(None, baseline.text, current_response.text)
            similarity = matcher.quick_ratio()
            sim_score = (1.0 - similarity) * 100
            
            if sim_score > 5:
                reasons.append(f"Structure changed: {int(sim_score)}% deviation")
                score += sim_score * self.weights["structure"]

        # 4. Keyword Entropy (Bonus)
        # Check for error keywords that weren't in baseline
        error_keywords = ["error", "exception", "stack trace", "syntax", "root", "admin", "warning"]
        new_keywords = []
        base_lower = baseline.text.lower()
        curr_lower = current_response.text.lower()
        
        for kw in error_keywords:
            if kw in curr_lower and kw not in base_lower:
                new_keywords.append(kw)
        
        if new_keywords:
            reasons.append(f"New keywords found: {', '.join(new_keywords)}")
            score += 100 * self.weights["keywords"]

        # Normalize total score to 0-100
        total_score = min(100, int(score))
        
        return {
            "score": total_score,
            "reasons": reasons,
            "response": current_response
        }
