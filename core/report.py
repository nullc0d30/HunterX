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
import zipfile
from datetime import datetime
from typing import List, Dict, Any
from .utils import logger, console
from rich.table import Table

class Reporter:
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
    def save_json(self, results: List[Dict]):
        path = os.path.join(self.output_dir, "scan_results.json")
        with open(path, "w") as f:
            json.dump(results, f, indent=4)
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
        
        md = f"""# HunterX Security Assessment Report

**Target:** {target}
**Date:** {date_str}
**Tool:** HunterX v3.0 (NullC0d3)

---

## 1. Executive Summary

HunterX performed an automated, reasoning-based security assessment of **{target}**. The assessment utilized a multi-stage orchestration pipeline focusing on non-destructive verification of vulnerabilities.

**Overall Posture:** {"Critical Issues Found" if critical_findings else "No Critical Issues Detected"}
**Technology Stack:** {server_header}

---

## 2. Key Findings

"""
        if not critical_findings:
            md += "*No high-confidence vulnerabilities were detected during this assessment.*\n"
        else:
            for i, f in enumerate(critical_findings, 1):
                md += f"### {i}. {f.get('payload_category', 'Anomaly')} (Score: {f.get('diff_score')})\n"
                md += f"- **Payload:** `{f.get('payload')}`\n"
                md += f"- **Impact:** Potential for unauthorized access or execution.\n"
                md += f"- **Verification:** Differential response analysis confirmed significant anomaly.\n\n"

        md += """---

## 3. Attack Path Possibilities

Based on verified findings, the Reasoning Engine identified the following potential attack chains. Note that these paths have **NOT** been executed.

| Chain | Likelihood | Preconditions |
|-------|------------|---------------|
"""
        if not chains:
             md += "| None Identified | - | - |\n"
        else:
            for c in chains:
                score = c.get('likelihood', 0.0)
                pre = ', '.join(c.get('preconditions', []))
                md += f"| {c['chain']} | {score:.2f} | {pre} |\n"

        md += """
---

## 4. Methodology

This assessment followed a strict **Safety-by-Design** protocol:
1.  **Passive Analysis:** Zero-interaction gathering of headers and metadata.
2.  **Probe Stage:** Low-noise anomaly detection.
3.  **Verification:** Context-aware proofing without destructive payloads.

**Constraint:** No file deletion, reverse shells, or persistence mechanisms were employed.

---

## 5. Disclaimer

This report is for authorized internal use only.
"""
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
