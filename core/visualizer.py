# -----------------------------------------------------------------------------
# HunterX - The Al-Assisted Vulnerability Hunter
# Developed by: NullC0d3
#
# This software is protected by copyright and intellectual property laws.
# Unauthorized reproduction, distribution, or reverse engineering is strictly prohibited.
# For authorized use only.
# -----------------------------------------------------------------------------
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.console import Console
from rich import box
from datetime import datetime
import os
import time

class SimpleVisualizer:
    def __init__(self, mode="cli", output_dir="reports"):
        self.mode = mode
        self.output_dir = output_dir
        self.console = Console()
        self.live = None
        
        # State
        self.stage = "PASSIVE"
        self.profile = "UNKNOWN"
        self.active_branches = []
        self.bloocked_count = 0
        self.request_count = 0
        self.start_time = time.time()
        self.findings = []
        self.risk_level = "LOW"
        
        if self.mode == "web":
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            self._write_html_template()

    def start(self):
        if self.mode == "cli":
            self.live = Live(self._generate_layout(), refresh_per_second=4, transient=True)
            self.live.start()

    def stop(self):
        if self.live:
            self.live.stop()

    def update(self, stage=None, request_count=None, blocked=None, branch=None, finding=None):
        if stage: self.stage = stage
        if request_count: self.request_count = request_count
        if blocked: 
            self.bloocked_count += 1
            self.risk_level = "ELEVATED" if self.bloocked_count < 3 else "BLOCKED"
            
        if branch: 
            if branch not in self.active_branches: self.active_branches.append(branch)
        if finding: 
            self.findings.append(finding)
            if self.risk_level == "LOW": self.risk_level = "ELEVATED"
        
        if self.mode == "cli" and self.live:
            self.live.update(self._generate_layout())
            
        if self.mode == "web":
            self._update_html()

    def print_status(self):
        """Used for log-based updates or final summary if live is off"""
        pass

    def _generate_layout(self):
        table = Table(box=box.SIMPLE, expand=True)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")
        
        duration = int(time.time() - self.start_time)
        
        table.add_row("Profile", f"[bold]{self.profile}[/bold]")
        table.add_row("Stage", f"[bold yellow]{self.stage}[/bold yellow]")
        table.add_row("Risk Level", f"[{'green' if self.risk_level=='LOW' else 'red'}]{self.risk_level}[/]")
        table.add_row("Requests", str(self.request_count))
        table.add_row("Blocked", str(self.bloocked_count))
        table.add_row("Duration", f"{duration}s")
        table.add_row("Branches", ", ".join(self.active_branches) if self.active_branches else "-")
        table.add_row("Findings", str(len(self.findings)))

        return Panel(
            table, 
            title="[bold green]HunterX Active Scan[/bold green]", 
            border_style="green"
        )

    def _write_html_template(self):
        # Initial write
        self._update_html()

    def _update_html(self):
        path = os.path.join(self.output_dir, "dashboard.html")
        
        findings_html = ""
        for f in self.findings:
            findings_html += f"<li style='color: #ff5555'>{f['payload_category']} (Score: {f['diff_score']})</li>"
            
        branches_html = ""
        for b in self.active_branches:
            branches_html += f"<li>{b}</li>"

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>HunterX Dashboard</title>
            <meta http-equiv="refresh" content="2">
            <style>
                body {{ font-family: 'Courier New', monospace; background: #0d0d0d; color: #e0e0e0; padding: 20px; }}
                .container {{ max_width: 800px; margin: 0 auto; }}
                .card {{ background: #1a1a1a; padding: 20px; border: 1px solid #333; margin-bottom: 20px; border-radius: 4px; }}
                h1 {{ color: #00ff00; border-bottom: 1px solid #333; padding-bottom: 10px; }}
                h3 {{ color: #00cc00; margin-top: 0; }}
                .stat-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }}
                .stat {{ padding: 10px; background: #222; }}
                .label {{ color: #888; font-size: 0.9em; }}
                .value {{ font-size: 1.2em; font-weight: bold; }}
                .risk-LOW {{ color: #00ff00; }}
                .risk-ELEVATED {{ color: #ffaa00; }}
                .risk-BLOCKED {{ color: #ff0000; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>HunterX Operational Dashboard</h1>
                
                <div class="card">
                    <h3>Status</h3>
                    <div class="stat-grid">
                        <div class="stat"><div class="label">Profile</div><div class="value">{self.profile}</div></div>
                        <div class="stat"><div class="label">Stage</div><div class="value">{self.stage}</div></div>
                        <div class="stat"><div class="label">Risk Level</div><div class="value risk-{self.risk_level}">{self.risk_level}</div></div>
                        <div class="stat"><div class="label">Requests</div><div class="value">{self.request_count}</div></div>
                        <div class="stat"><div class="label">Duration</div><div class="value">{int(time.time() - self.start_time)}s</div></div>
                    </div>
                </div>
                
                <div class="card">
                    <h3>Active Branches</h3>
                    <ul>{branches_html or '<li>No active branches</li>'}</ul>
                </div>
                
                <div class="card">
                    <h3>Verified Findings</h3>
                    <ul>{findings_html or '<li>No findings yet</li>'}</ul>
                </div>
                
                <div style="text-align: center; color: #555; font-size: 0.8em;">
                    HunterX v3.0 Product Edition
                </div>
            </div>
        </body>
        </html>
        """
        with open(path, "w") as f:
            f.write(html)
