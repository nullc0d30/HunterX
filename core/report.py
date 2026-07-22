# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# All Rights Reserved.
#
# HunterX — AI-Assisted Vulnerability Hunter
# SPDX-License-Identifier: Proprietary
import json
import os
import zipfile
from datetime import datetime
from typing import List, Dict
from .legal import inject_json, inject_markdown, get_copyright_text
from .utils import logger, console
from rich.table import Table

class Reporter:
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
    def save_json(self, results: List[Dict]):
        path = os.path.join(self.output_dir, "scan_results.json")
        data_with_meta = inject_json({"findings": results})
        with open(path, "w") as f:
            json.dump(data_with_meta, f, indent=4)
        logger.info(f"[+] Report saved to {path}")

    def generate_final_report(self, results: List[Dict], chains: List[Dict], target: str, intel: Dict):
        """
        Generates a professional Markdown report and ZIP evidence pack.
        """
        md_content = self._build_markdown(results, chains, target, intel)
        
        # Save MD
        md_path = os.path.join(self.output_dir, "FINAL_REPORT.md")
        with open(md_path, "w") as f:
            f.write(md_content)
            
        # Create ZIP
        self._create_evidence_pack(md_path)

    def _build_markdown(self, results: List[Dict], chains: List[Dict], target: str, intel: Dict) -> str:
        date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        server_header = intel.get('security_headers', {}).get('Server', 'Unknown')
        
        # Filter vital findings
        critical_findings = [r for r in results if r.get('diff_score', 0) > 60]
        
        md_lines = [
            "# HunterX Security Assessment Report",
            "",
            f"**Target:** {target}",
            f"**Date:** {date_str}",
            f"**Tool:** HunterX v4.0 ({get_copyright_text()})",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            "",
            f"HunterX performed an automated, reasoning-based security assessment of **{target}**. The assessment utilized a multi-stage orchestration pipeline focusing on non-destructive verification of vulnerabilities.",
            "",
            f"**Overall Posture:** {'Critical Issues Found' if critical_findings else 'No Critical Issues Detected'}",
            f"**Technology Stack:** {server_header}",
            "",
            "---",
            "",
            "## 2. Key Findings",
            "",
        ]
        if not critical_findings:
            md_lines.append("*No high-confidence vulnerabilities were detected during this assessment.*\n")
        else:
            for i, f in enumerate(critical_findings, 1):
                md_lines.append(f"### {i}. {f.get('payload_category', 'Anomaly')} (Score: {f.get('diff_score')})")
                md_lines.append(f"- **Payload:** `{f.get('payload')}`")
                md_lines.append("- **Impact:** Potential for unauthorized access or execution.")
                md_lines.append("- **Verification:** Differential response analysis confirmed significant anomaly.")
                md_lines.append("")

        md_lines.extend([
            "---",
            "",
            "## 3. Attack Path Possibilities",
            "",
            "Based on verified findings, the Reasoning Engine identified the following potential attack chains. Note that these paths have **NOT** been executed.",
            "",
            "| Chain | Likelihood | Preconditions |",
            "|-------|------------|---------------|",
        ])
        if not chains:
            md_lines.append("| None Identified | - | - |")
        else:
            for c in chains:
                likelihood = c.get('likelihood', 'Unknown')
                pre = ', '.join(c.get('preconditions', []))
                md_lines.append(f"| {c['chain']} | {likelihood} | {pre} |")

        md_lines.extend([
            "",
            "---",
            "",
            "## 4. Methodology",
            "",
            "This assessment followed a strict **Safety-by-Design** protocol:",
            "1.  **Passive Analysis:** Zero-interaction gathering of headers and metadata.",
            "2.  **Probe Stage:** Low-noise anomaly detection.",
            "3.  **Verification:** Context-aware proofing without destructive payloads.",
            "",
            "**Constraint:** No file deletion, reverse shells, or persistence mechanisms were employed.",
        ])
        md = "\n".join(md_lines)
        md = inject_markdown(md, header=False, footer=True)
        return md

    def _create_evidence_pack(self, md_path: str):
        zip_path = os.path.join(self.output_dir, "evidence_pack.zip")
        try:
            with zipfile.ZipFile(zip_path, 'w') as zf:
                # Add Final Report
                zf.write(md_path, arcname="FINAL_REPORT.md")
                
                # Add JSON Results
                json_path = os.path.join(self.output_dir, "scan_results.json")
                if os.path.exists(json_path):
                    zf.write(json_path, arcname="raw_findings.json")
                    
                # Add Dashboard if exists
                dash_path = os.path.join(self.output_dir, "dashboard.html")
                if os.path.exists(dash_path):
                    zf.write(dash_path, arcname="dashboard.html")
                    
            logger.info(f"[+] Evidence Pack generated: {zip_path}")
        except Exception as e:
            logger.error(f"Failed to create evidence pack: {e}")

    def print_summary(self, results: List[Dict]):
        """Print rich console summary"""
        table = Table(title="HunterX Scan Summary")
        table.add_column("Category", style="cyan")
        table.add_column("Payload", style="magenta")
        table.add_column("Anomaly Score", style="green")
        table.add_column("Findings", style="yellow")
        
        count = 0
        for res in results:
            # Filter low scores for console noise reduction
            if res['diff_score'] > 20 or res.get('findings'):
                findings_text = str(res.get('findings', ''))
                table.add_row(
                    res['payload_category'],
                    res['payload'][:30] + "..." if len(res['payload']) > 30 else res['payload'],
                    str(res['diff_score']),
                    findings_text if findings_text else "-"
                )
                count += 1
                
        if count > 0:
            console.print(table)
        else:
            console.print("[yellow]No significant anomalies found to display.[/yellow]")
