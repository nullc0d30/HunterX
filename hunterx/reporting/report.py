# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
# SPDX-License-Identifier: Proprietary
import json
import os
import zipfile
from datetime import datetime
from typing import Any, Dict, List, Optional
from ..core.legal import inject_json, inject_markdown, get_copyright_text
from ..utils.utils import logger, console
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

    def save_intelligence_json(self, engine) -> None:
        """Save intelligence layer outputs as separate JSON files."""
        data = {}
        if hasattr(engine, 'knowledge_graph') and engine.knowledge_graph:
            data["knowledge_graph"] = engine.knowledge_graph.to_dict()
        if hasattr(engine, 'attack_paths') and engine.attack_paths:
            data["attack_paths"] = engine.attack_paths
        if hasattr(engine, 'threat_model') and engine.threat_model:
            data["threat_model"] = engine.threat_model
        if hasattr(engine, 'risk_scores') and engine.risk_scores:
            data["risk_matrix"] = engine.risk_scores
        if hasattr(engine, 'mitre_mappings') and engine.mitre_mappings:
            data["mitre_mappings"] = engine.mitre_mappings
        if hasattr(engine, 'explanations') and engine.explanations:
            data["explanations"] = engine.explanations
        if hasattr(engine, 'scan_plan') and engine.scan_plan:
            data["scan_plan"] = engine.scan_plan

        if data:
            path = os.path.join(self.output_dir, "intelligence_report.json")
            with open(path, "w") as f:
                json.dump(inject_json(data), f, indent=4)
            logger.info(f"[+] Intelligence report saved to {path}")

    def generate_final_report(
        self,
        results: List[Dict],
        chains: List[Dict],
        target: str,
        intel: Dict,
        intelligence: Optional[Dict[str, Any]] = None,
    ):
        md_content = self._build_markdown(results, chains, target, intel, intelligence)

        md_path = os.path.join(self.output_dir, "FINAL_REPORT.md")
        with open(md_path, "w") as f:
            f.write(md_content)

        self._create_evidence_pack(md_path)

    def _build_markdown(
        self,
        results: List[Dict],
        chains: List[Dict],
        target: str,
        intel: Dict,
        intelligence: Optional[Dict[str, Any]] = None,
    ) -> str:
        date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        server_header = intel.get('security_headers', {}).get('Server', 'Unknown')

        critical_findings = [r for r in results if r.get('diff_score', 0) > 60]

        md_lines = [
            "# HunterX Security Assessment Report",
            "",
            f"**Target:** {target}",
            f"**Date:** {date_str}",
            f"**Tool:** HunterX v4.1 Intelligence Edition ({get_copyright_text()})",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            "",
            f"HunterX performed an automated, AI-powered security assessment of **{target}**. The assessment utilized a multi-stage orchestration pipeline with intelligence layer.",
            "",
            f"**Overall Posture:** {'Critical Issues Found' if critical_findings else 'No Critical Issues Detected'}",
            f"**Technology Stack:** {server_header}",
            "",
        ]

        if intelligence:
            kg = intelligence.get("knowledge_graph")
            if kg:
                md_lines.append(f"**Knowledge Graph:** {len(kg.get('nodes', []))} nodes, {len(kg.get('edges', []))} edges")

            risk_matrix = intelligence.get("risk_matrix", [])
            if risk_matrix:
                max_risk = max((r.get("risk", {}).get("normalized_score", 0) for r in risk_matrix), default=0)
                md_lines.append(f"**Maximum Risk Score:** {max_risk:.3f}")
                md_lines.append(f"**Findings Analyzed:** {len(risk_matrix)}")

            mitre = intelligence.get("mitre_mappings", [])
            if mitre:
                md_lines.append(f"**MITRE Techniques Mapped:** {len(mitre)}")

            explanations = intelligence.get("explanations", [])
            if explanations:
                md_lines.append(f"**AI Explanations Generated:** {len(explanations)}")

            attack_paths = intelligence.get("attack_paths", [])
            if attack_paths:
                md_lines.append(f"**Attack Paths Identified:** {len(attack_paths)}")

        md_lines.extend([
            "",
            "---",
            "",
            "## 2. Key Findings",
            "",
        ])
        if not critical_findings:
            md_lines.append("*No high-confidence vulnerabilities were detected.*\n")
        else:
            for i, f in enumerate(critical_findings, 1):
                risk_info = f.get("risk", {})
                risk_str = f" | Risk: {risk_info.get('severity', 'N/A')} ({risk_info.get('normalized_score', 0):.2f})" if risk_info else ""
                md_lines.append(f"### {i}. {f.get('payload_category', 'Anomaly')} (Score: {f.get('diff_score')}){risk_str}")
                md_lines.append(f"- **Payload:** `{f.get('payload')}`")
                md_lines.append(f"- **Technique:** {f.get('technique', 'standard')}")
                if f.get("findings"):
                    for ft in f["findings"][:3]:
                        md_lines.append(f"- {ft}")
                md_lines.append("")

        md_lines.extend([
            "---",
            "",
            "## 3. Attack Path Possibilities",
            "",
            "Based on verified findings, the Attack Chain Engine identified the following potential attack paths.",
            "",
        ])

        intelligence_paths = intelligence.get("attack_paths", []) if intelligence else []
        if intelligence_paths:
            md_lines.append("| Attack Path | Confidence | Risk | Steps |")
            md_lines.append("|-------------|------------|------|-------|")
            for ap in intelligence_paths[:10]:
                ap_name = ap.get("name", "Unknown")
                ap_conf = f"{ap.get('overall_confidence', 0):.2f}"
                ap_risk = f"{ap.get('total_risk', 0):.2f}"
                ap_steps = " -> ".join(s.get("target", "?") for s in ap.get("steps", []))
                md_lines.append(f"| {ap_name} | {ap_conf} | {ap_risk} | {ap_steps} |")
        elif chains:
            md_lines.append("| Chain | Likelihood | Preconditions |")
            md_lines.append("|-------|------------|---------------|")
            for c in chains:
                likelihood = c.get('likelihood', 'Unknown')
                pre = ', '.join(c.get('preconditions', []))
                md_lines.append(f"| {c['chain']} | {likelihood} | {pre} |")
        else:
            md_lines.append("| None Identified | - | - |")

        md_lines.extend([
            "",
            "---",
            "",
            "## 4. Risk Matrix",
            "",
        ])

        risk_matrix = intelligence.get("risk_matrix", []) if intelligence else []
        if risk_matrix:
            md_lines.append("| Finding | Likelihood | Exploitability | Exposure | Business Impact | Score | Severity |")
            md_lines.append("|---------|------------|----------------|----------|-----------------|-------|----------|")
            for rm in risk_matrix[:10]:
                r = rm.get("risk", {})
                md_lines.append(
                    f"| {rm.get('finding', '?')[:50]} "
                    f"| {r.get('likelihood', 0):.2f} "
                    f"| {r.get('exploitability', 0):.2f} "
                    f"| {r.get('exposure', 0):.2f} "
                    f"| {r.get('business_impact', 0):.2f} "
                    f"| {r.get('normalized_score', 0):.2f} "
                    f"| {r.get('severity', 'None')} |"
                )
        else:
            md_lines.append("*Risk analysis not performed.*")

        md_lines.extend([
            "",
            "---",
            "",
            "## 5. MITRE ATT&CK Mapping",
            "",
        ])

        mitre_mappings = intelligence.get("mitre_mappings", []) if intelligence else []
        if mitre_mappings:
            md_lines.append("| Finding | Technique ID | Technique | Tactics | CWE |")
            md_lines.append("|---------|-------------|-----------|---------|-----|")
            for m in mitre_mappings:
                md_lines.append(
                    f"| {m.get('finding_category', '?')} "
                    f"| {m.get('technique_id', '?')} "
                    f"| {m.get('technique_name', '?')} "
                    f"| {', '.join(m.get('tactics', []))} "
                    f"| {', '.join(m.get('cwe_ids', []))} |"
                )
        else:
            md_lines.append("*MITRE mapping not performed.*")

        md_lines.extend([
            "",
            "---",
            "",
            "## 6. Threat Model Summary",
            "",
        ])

        threat_model = intelligence.get("threat_model", {}) if intelligence else {}
        if threat_model:
            md_lines.append(f"- **Assets:** {len(threat_model.get('assets', []))}")
            md_lines.append(f"- **Data Flows:** {len(threat_model.get('data_flows', []))}")
            md_lines.append(f"- **Entry Points:** {len(threat_model.get('entry_points', []))}")
            md_lines.append(f"- **Trust Boundaries:** {len(threat_model.get('trust_boundaries', []))}")
            md_lines.append(f"- **Attack Surface:** {len(threat_model.get('attack_surface', []))}")
            if threat_model.get("critical_components"):
                for cc in threat_model["critical_components"]:
                    md_lines.append(f"- ⚠ **Critical:** {cc}")
        else:
            md_lines.append("*Threat model not generated.*")

        md_lines.extend([
            "",
            "---",
            "",
            "## 7. Evidence & Reasoning Trace",
            "",
        ])

        explanations = intelligence.get("explanations", []) if intelligence else []
        if explanations:
            for exp in explanations[:5]:
                md_lines.append(f"### {exp.get('finding_type', 'Finding')}")
                md_lines.append(f"- **Conclusion:** {exp.get('conclusion', 'N/A')}")
                md_lines.append(f"- **Confidence:** {exp.get('confidence', 0):.2f}")
                if exp.get("reasoning_steps"):
                    md_lines.append("- **Reasoning:**")
                    for rs in exp["reasoning_steps"]:
                        md_lines.append(f"  - {rs}")
                if exp.get("missing_evidence"):
                    md_lines.append("- **Missing Evidence:**")
                    for me in exp["missing_evidence"]:
                        md_lines.append(f"  - {me}")
                md_lines.append("")
        else:
            md_lines.append("*AI explanations not available.*")

        md_lines.extend([
            "---",
            "",
            "## 8. Purple Team Detection Rules",
            "",
        ])

        purple_rules = intelligence.get("purple_rules", {}) if intelligence else {}
        if purple_rules:
            for fmt, rules in purple_rules.items():
                if rules:
                    md_lines.append(f"- **{fmt.upper()}:** {len(rules)} rules generated")
        else:
            md_lines.append("*Purple team rules not generated.*")

        md_lines.extend([
            "",
            "---",
            "",
            "## 9. Methodology",
            "",
            "This assessment used the following methodology:",
            "1. **Observation:** Passive intelligence gathering and fingerprinting",
            "2. **Reasoning:** Context-aware payload selection and adaptation",
            "3. **Hypothesis Generation:** AI Planner creates testing strategy",
            "4. **Evidence Collection:** Multi-stage probing and verification",
            "5. **Verification:** Non-destructive confirmation of vulnerabilities",
            "6. **Risk Analysis:** Multi-dimensional risk scoring",
            "7. **Attack Graph:** Knowledge graph and path analysis",
            "8. **Reporting:** Comprehensive output with MITRE mapping and detection rules",
            "",
            "**Constraint:** No file deletion, reverse shells, or persistence mechanisms were employed.",
            "**Safety-by-Design:** All payloads are non-destructive by default.",
        ])

        md = "\n".join(md_lines)
        md = inject_markdown(md, header=False, footer=True)
        return md

    def _create_evidence_pack(self, md_path: str):
        zip_path = os.path.join(self.output_dir, "evidence_pack.zip")
        try:
            with zipfile.ZipFile(zip_path, 'w') as zf:
                zf.write(md_path, arcname="FINAL_REPORT.md")

                json_path = os.path.join(self.output_dir, "scan_results.json")
                if os.path.exists(json_path):
                    zf.write(json_path, arcname="raw_findings.json")

                dash_path = os.path.join(self.output_dir, "dashboard.html")
                if os.path.exists(dash_path):
                    zf.write(dash_path, arcname="dashboard.html")

                intel_path = os.path.join(self.output_dir, "intelligence_report.json")
                if os.path.exists(intel_path):
                    zf.write(intel_path, arcname="intelligence_report.json")

                graph_path = os.path.join(self.output_dir, "attack_graph.html")
                if os.path.exists(graph_path):
                    zf.write(graph_path, arcname="attack_graph.html")

                chains_path = os.path.join(self.output_dir, "attack_chains.html")
                if os.path.exists(chains_path):
                    zf.write(chains_path, arcname="attack_chains.html")

            logger.info(f"[+] Evidence Pack generated: {zip_path}")
        except Exception as e:
            logger.error(f"Failed to create evidence pack: {e}")

    def print_summary(self, results: List[Dict]):
        table = Table(title="HunterX Scan Summary")
        table.add_column("Category", style="cyan")
        table.add_column("Payload", style="magenta")
        table.add_column("Score", style="green")
        table.add_column("Risk", style="red")
        table.add_column("Findings", style="yellow")

        count = 0
        for res in results:
            if res['diff_score'] > 20 or res.get('findings'):
                findings_text = str(res.get('findings', ''))
                risk_sev = res.get("risk", {}).get("severity", "-")
                risk_str = f"[bold]{risk_sev}[/bold]" if risk_sev in ("Critical", "High") else risk_sev
                table.add_row(
                    res['payload_category'],
                    res['payload'][:30] + "..." if len(res['payload']) > 30 else res['payload'],
                    str(res['diff_score']),
                    risk_str,
                    findings_text if findings_text else "-"
                )
                count += 1

        if count > 0:
            console.print(table)
        else:
            console.print("[yellow]No significant anomalies found to display.[/yellow]")
