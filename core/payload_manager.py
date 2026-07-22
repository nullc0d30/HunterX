# SPDX-License-Identifier: Proprietary
# Copyright NullC0d3 — HunterX v3.1
from typing import List, Dict

class PayloadRanker:
    """
    AI-assisted ranking system. 
    It doesn't use neural networks (keep it fast/local), but uses 
    Reinforcement Learning (Multi-Armed Bandit approach) 
    to prioritize payload categories that are showing 'anomalies'.
    """
    def __init__(self):
        self.category_weights: Dict[str, float] = {}
        self.learning_rate = 0.1
        self._default_weight = 1.0

    def update_weight(self, category: str, anomaly_score: float):
        """
        Update the weight of a category based on the anomaly score (0-100).
        High anomaly score = Higher weight for that category.
        """
        if category not in self.category_weights:
            self.category_weights[category] = self._default_weight
            
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
        return sorted(payloads, key=lambda x: self.category_weights.get(x.get("category", "GENERIC"), self._default_weight), reverse=True)

    def get_efficiency_metrics(self):
        return self.category_weights
