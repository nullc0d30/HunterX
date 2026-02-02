# -----------------------------------------------------------------------------
# HunterX - The Al-Assisted Vulnerability Hunter
# Developed by: NullC0d3
#
# This software is protected by copyright and intellectual property laws.
# Unauthorized reproduction, distribution, or reverse engineering is strictly prohibited.
# For authorized use only.
# -----------------------------------------------------------------------------
import argparse
import os
import sys
from typing import List, Dict

# Ensure core modules are found
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.engine import Engine
from core.report import Reporter
from core.utils import logger, console
from core.classifier import PayloadClassifier
from core.profiles import PROFILES

BANNER = """
[bold red]
  _   _             _             __  __
 | | | |_   _ _ __ | |_ ___ _ __  \ \/ /
 | |_| | | | | '_ \| __/ _ \ '__|  \  / 
 |  _  | |_| | | | | ||  __/ |     /  \ 
 |_| |_|\__,_|_| |_|\__\___|_|    /_/\_\\
[/bold red]
[cyan]The AI-Assisted Vulnerability Hunter v3.0 by [bold yellow]NullC0d3[/bold yellow][/cyan]
[green]Production Edition[/green]
"""

def load_payloads(payload_dir: str, target_categories: List[str] = None) -> List[Dict]:
    payloads = []
    classifier = PayloadClassifier()
    
    if not os.path.exists(payload_dir):
        logger.error(f"Payload directory not found: {payload_dir}")
        return []

    for filename in os.listdir(payload_dir):
        path = os.path.join(payload_dir, filename)
        if not os.path.isfile(path):
            continue
            
        file_cats = classifier.classify_file(filename)
        
        if target_categories:
            if not any(c.lower() in [tc.lower() for tc in target_categories] for c in file_cats):
                continue
        
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = [l.strip() for l in f.readlines() if l.strip()]
            for line in lines:
                p_cat = file_cats[0]
                payloads.append({
                    "payload": line,
                    "category": p_cat,
                    "source_file": filename
                })
                
    logger.info(f"Loaded {len(payloads)} payloads from {payload_dir}")
    return payloads

def main():
    parser = argparse.ArgumentParser(description="HunterX - Vulnerability Hunting Framework v3.0")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-p", "--payload-dir", default="payloads", help="Directory containing payload files")
    parser.add_argument("-o", "--output-dir", default="reports", help="Directory to save reports")
    
    # v3 Arguments
    parser.add_argument("--profile", choices=["internal", "bounty", "gov"], default="bounty", help="Operator Profile (Default: bounty)")
    parser.add_argument("--auto", action="store_true", default=True, help="Enable auto-context/orchestration")
    parser.add_argument("--category", help="Comma-separated categories to scan")
    parser.add_argument("--stealth", choices=["low", "medium", "high"], default="medium", help="Stealth/Evasion level (Overrides profile if higher)")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads")
    parser.add_argument("--dry-run", action="store_true", help="Run logic without sending requests")
    parser.add_argument("--passive-only", action="store_true", help="Run Stage 0 Passive Intel only")
    parser.add_argument("--visual", choices=["cli", "web", "off"], default="cli", help="Visualization mode (Default: cli)")
    parser.add_argument("--evidence-level", choices=["low", "medium", "high"], default="medium", help="Detail of reports")
    parser.add_argument("--min-confidence", type=float, default=0.0, help="Minimum confidence threshold (0.0 - 1.0) for reporting findings")
    
    args = parser.parse_args()
    
    console.print(BANNER)
    
    if not args.url.startswith("http"):
        logger.error("URL must start with http:// or https://")
        sys.exit(1)
        
    target_cats = args.category.split(",") if args.category else None
    
    payloads = load_payloads(args.payload_dir, target_cats)
    if not payloads and not args.passive_only:
        logger.critical("No payloads loaded. Exiting.")
        sys.exit(1)
        
    options = {
        "profile": args.profile,
        "auto": args.auto,
        "stealth": args.stealth,
        "threads": args.threads,
        "dry_run": args.dry_run,
        "passive_only": args.passive_only,
        "visual": args.visual,
        "evidence_level": args.evidence_level,
        "output_dir": args.output_dir
    }
        
    engine = Engine(args.url, payloads, options)
    
    try:
        engine.start()
        
        # Reports
        if engine.results or getattr(engine, 'passive_intel', None):
            reporter = Reporter(args.output_dir)
            reporter.save_json(engine.results)
            
            # Helper for clean header name if passive intel exists
            intel_data = getattr(engine, 'passive_intel', {}).analyze(engine.baseline) if hasattr(engine, 'baseline') and engine.baseline else {}
            
            # Generate Professional Report Pack
            reporter.generate_final_report(
                engine.results, 
                engine.inferred_chains, 
                args.url,
                intel_data
            )
            
            # Print Summary
            reporter.print_summary(engine.results)
            
            # Print Chains
            if engine.inferred_chains:
                console.print("\n[bold red]Potential Attack Chains:[/bold red]")
                for chain in engine.inferred_chains:
                    console.print(f"- [yellow]{chain['chain']}[/yellow] ({chain.get('likelihood', 0.0)}): {chain['reason']}")
            
        else:
            if not args.dry_run:
                console.print("[yellow]Scan completed but no meaningful results returned.[/yellow]")
            else:
                console.print("[cyan]Dry run completed.[/cyan]")
            
    except KeyboardInterrupt:
        console.print("[bold red]Scan interrupted by user.[/bold red]")
        sys.exit(1)

if __name__ == "__main__":
    main()
