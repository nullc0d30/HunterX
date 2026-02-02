# -----------------------------------------------------------------------------
# HunterX - The Al-Assisted Vulnerability Hunter
# Developed by: NullC0d3
#
# This software is protected by copyright and intellectual property laws.
# Unauthorized reproduction, distribution, or reverse engineering is strictly prohibited.
# For authorized use only.
# -----------------------------------------------------------------------------
import json
import os
from typing import List, Dict
from rich.console import Console
from rich.table import Table

console = Console()

class Reporter:
    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def save_json(self, results: List[Dict], filename="scan_results.json"):
        path = os.path.join(self.output_dir, filename)
        with open(path, "w") as f:
            json.dump(results, f, indent=4)
        console.print(f"[green][+] Report saved to {path}[/green]")

    def print_summary(self, results: List[Dict]):
        """
        Print a human-readable summary table of findings.
        """
        table = Table(title="HunterX Scan Summary")
        table.add_column("Category", style="cyan")
        table.add_column("Payload", style="magenta")
        table.add_column("Anomaly Score", style="red")
        table.add_column("Findings", style="yellow")

        # Sort by likelihood (Score)
        sorted_results = sorted(results, key=lambda x: x['diff_score'], reverse=True)

        for res in sorted_results:
            if res['diff_score'] > 0 or res['findings']:
                findings = ", ".join(res['findings']) if res['findings'] else "-"
                table.add_row(
                    res['payload_category'],
                    res['payload'][:50] + "..." if len(res['payload']) > 50 else res['payload'],
                    str(res['diff_score']),
                    findings
                )
        
        console.print(table)
