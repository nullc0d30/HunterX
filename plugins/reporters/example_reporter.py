import json
import os
from core.plugin_loader import plugin


@plugin("reporter")
class CSVReporter:
    """Example plugin: exports findings as CSV."""

    def export(self, results: list, output_dir: str):
        path = os.path.join(output_dir, "findings.csv")
        with open(path, "w") as f:
            f.write("category,payload,score,findings\n")
            for r in results:
                cat = r.get("payload_category", "")
                payload = r.get("payload", "").replace('"', '""')
                score = r.get("diff_score", 0)
                findings = "; ".join(r.get("findings", [])).replace('"', '""')
                f.write(f'"{cat}","{payload}",{score},"{findings}"\n')
