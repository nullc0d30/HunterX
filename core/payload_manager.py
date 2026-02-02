# -----------------------------------------------------------------------------
# HunterX - The Al-Assisted Vulnerability Hunter
# Developed by: NullC0d3
#
# This software is protected by copyright and intellectual property laws.
# Unauthorized reproduction, distribution, or reverse engineering is strictly prohibited.
# For authorized use only.
# -----------------------------------------------------------------------------
import random
from typing import List, Dict

class PayloadRanker:
    """
    AI-assisted ranking system. 
    It doesn't use neural networks (keep it fast/local), but uses 
    Reinforcement Learning (Multi-Armed Bandit approach) 
    to prioritize payload categories that are showing 'anomalies'.
    """
    def __init__(self):
        # Initial weights for payload categories
        self.category_weights: Dict[str, float] = {
            "RCE": 1.0,
            "LFI": 1.0,
            "SSTI": 1.0,
            "OPEN_REDIRECT": 1.0,
            "GENERIC": 0.5
        }
        self.learning_rate = 0.1

    def update_weight(self, category: str, anomaly_score: float):
        """
        Update the weight of a category based on the anomaly score (0-100).
        High anomaly score = Higher weight for that category.
        """
        if category not in self.category_weights:
            return
            
        # Normalize score 0-1
        normalized_reward = anomaly_score / 100.0
        
        # Simple Q-learning update
        current = self.category_weights[category]
        self.category_weights[category] = current + self.learning_rate * (normalized_reward - 0.5)

    def rank_payloads(self, payloads: List[Dict]) -> List[Dict]:
        """
        Re-rank a list of payloads based on their category weights.
        Payloads input format: [{"payload": "...", "category": "RCE"}, ...]
        """
        # Sort by weight of category, descending
        return sorted(payloads, key=lambda x: self.category_weights.get(x.get("category", "GENERIC"), 0.5), reverse=True)

    def get_efficiency_metrics(self):
        return self.category_weights
