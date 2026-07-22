# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
import os
from core.plugin_loader import plugin
from core.legal import get_csv_header


@plugin("reporter")
class CSVReporter:
    """Example plugin: exports findings as CSV."""

    def export(self, results: list, output_dir: str):
        path = os.path.join(output_dir, "findings.csv")
        with open(path, "w") as f:
            f.write(get_csv_header())
            f.write("category,payload,score,findings\n")
            for r in results:
                cat = r.get("payload_category", "")
                payload = r.get("payload", "").replace('"', '""')
                score = r.get("diff_score", 0)
                findings = "; ".join(r.get("findings", [])).replace('"', '""')
                f.write(f'"{cat}","{payload}",{score},"{findings}"\n')
