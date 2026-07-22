# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# All Rights Reserved.
#
# HunterX — AI-Assisted Vulnerability Hunter
from typing import List, Dict

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.cluster import DBSCAN
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False


class AnomalyCluster:
    """Groups similar anomaly findings using ML clustering to reduce noise."""

    def __init__(self, eps: float = 0.5, min_samples: int = 2):
        self.eps = eps
        self.min_samples = min_samples

    def cluster(self, findings: List[Dict]) -> List[Dict]:
        """Cluster findings by similarity of their text content."""
        if not HAS_SKLEARN or len(findings) < 2:
            return [{"cluster": 0, "findings": findings, "label": "all"}]

        texts = []
        for f in findings:
            text = f"{f.get('payload_category', '')} {f.get('payload', '')} {' '.join(f.get('findings', []))}"
            texts.append(text)

        try:
            vectorizer = TfidfVectorizer(max_features=100, stop_words="english")
            X = vectorizer.fit_transform(texts)

            clustering = DBSCAN(eps=self.eps, min_samples=self.min_samples, metric="cosine")
            labels = clustering.fit_predict(X)

            groups = {}
            for i, label in enumerate(labels):
                label_key = int(label)
                if label_key not in groups:
                    groups[label_key] = []
                groups[label_key].append(findings[i])

            result = []
            for label, cluster_findings in groups.items():
                label_name = "noise" if label == -1 else f"cluster_{label}"
                result.append({
                    "cluster": label,
                    "label": label_name,
                    "count": len(cluster_findings),
                    "findings": cluster_findings,
                })

            return sorted(result, key=lambda x: x["cluster"])

        except Exception:
            return [{"cluster": 0, "findings": findings, "label": "all"}]
