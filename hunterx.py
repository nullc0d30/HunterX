# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# All Rights Reserved.
#
# HunterX — AI-Assisted Vulnerability Hunter
import argparse
import os
import sys
import urllib.parse
from typing import List, Optional

from core.config import config, load_config_file
from core.engine import Engine
from core.report import Reporter
from core.utils import logger, console
from core.classifier import PayloadClassifier
from core.legal import get_copyright_text

BANNER = f"""
[bold red]
  _   _             _             __  __
 | | | |_   _ _ __ | |_ ___ _ __  \ \/ /
 | |_| | | | | '_ \| __/ _ \ '__|  \  / 
 |  _  | |_| | | | | ||  __/ |     /  \ 
 |_| |_|\__,_|_| |_|\__\___|_|    /_/\_\\
[/bold red]
[cyan]HunterX v4.0 — AI-Assisted Vulnerability Hunter by [bold yellow]NullC0d3[/bold yellow][/cyan]
[green]{get_copyright_text()}[/green]
[green]Production Edition — API | Auth | OOB | AI/ML | Plugins[/green]
"""


def classify_payload_files(payload_dir: str, target_categories: Optional[List[str]] = None):
    """Scan payload directory and return (filename, path, category) for matching files."""
    classifier = PayloadClassifier()
    if not os.path.exists(payload_dir):
        logger.error(f"Payload directory not found: {payload_dir}")
        return

    for filename in os.listdir(payload_dir):
        path = os.path.join(payload_dir, filename)
        if not os.path.isfile(path):
            continue
        file_cats = classifier.classify_file(filename)
        if target_categories:
            if not any(c.lower() in [tc.lower() for tc in target_categories] for c in file_cats):
                continue
        yield filename, path, file_cats[0]


def load_payloads(payload_dir: str, target_categories: Optional[List[str]] = None):
    """Lazily stream payloads from matching files. Only opens files whose category matches."""
    if not os.path.exists(payload_dir):
        logger.error(f"Payload directory not found: {payload_dir}")
        return

    matched_files = list(classify_payload_files(payload_dir, target_categories))
    if not matched_files:
        logger.warning(f"No payload files matched categories: {target_categories or 'all'}")
        return

    for filename, path, category in matched_files:
        file_size = os.path.getsize(path)
        if file_size > 50 * 1024 * 1024:
            logger.warning(f"Skipping oversized payload file: {filename} ({file_size // 1024 // 1024}MB)")
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    yield {"payload": line, "category": category, "source_file": filename}
        except Exception as e:
            logger.debug(f"Failed to read payload file {filename}: {e}")

    logger.info(f"Streamed payloads from {payload_dir} ({len(matched_files)} files)")


def main():
    parser = argparse.ArgumentParser(
        description="HunterX v4.0 — Vulnerability Hunting Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  hunterx -u http://target.com --profile bounty --visual cli
  hunterx -u http://target.com --profile gov --passive-only
  hunterx -u http://target.com --profile internal --auth bearer --token mytoken
  hunterx -u http://target.com --oob --collaborator http://burpcollab.net
  hunterx -u http://target.com --api-key mykey --sarif
  hunterx -u http://target.com --ai --ai-model llama3.2
  hunterx api --port 8443
  hunterx -f targets.txt --preset quick
        """,
    )

    # Core
    parser.add_argument("-u", "--url", help="Target URL")
    parser.add_argument("-f", "--targets-file", help="File containing multiple target URLs (one per line)")
    parser.add_argument("-p", "--payload-dir", default="payloads", help="Payload directory")
    parser.add_argument("-o", "--output-dir", default="reports", help="Output directory")
    parser.add_argument("-c", "--config", default="hunterx.yaml", help="YAML config file")

    # Profile & Mode
    parser.add_argument("--profile", choices=["internal", "bounty", "gov"], default="bounty", help="Operator profile")
    parser.add_argument("--preset", choices=["quick", "full", "stealth"], help="Scan preset (overrides individual flags)")
    parser.add_argument("--category", help="Comma-separated categories")
    parser.add_argument("--stealth", choices=["low", "medium", "high"], default="medium", help="Stealth level")
    parser.add_argument("--threads", type=int, default=5, help="Thread count")
    parser.add_argument("--dry-run", action="store_true", help="Logic only, no requests")
    parser.add_argument("--passive-only", action="store_true", help="Stage 0 only")
    parser.add_argument("--insecure", action="store_true", help="Disable SSL verification")

    # Auth
    parser.add_argument("--auth", choices=["none", "basic", "bearer", "cookie", "form"], default="none", help="Auth type")
    parser.add_argument("--username", help="Auth username")
    parser.add_argument("--password", help="Auth password")
    parser.add_argument("--token", help="Bearer token or session token")
    parser.add_argument("--cookie-file", help="JSON cookie file")
    parser.add_argument("--login-url", help="Form login URL")
    parser.add_argument("--login-data", help="Form login data as key=value,key2=value2")

    # OOB
    parser.add_argument("--oob", action="store_true", help="Enable OOB detection")
    parser.add_argument("--collaborator", help="Collaborator URL for OOB callbacks")

    # AI/ML
    parser.add_argument("--ai", action="store_true", help="Enable AI/LLM analysis")
    parser.add_argument("--ai-model", default="llama3.2", help="Ollama model name")
    parser.add_argument("--ai-endpoint", default="http://localhost:11434", help="Ollama endpoint")
    parser.add_argument("--no-cluster", action="store_true", help="Disable finding clustering")

    # Reporting
    parser.add_argument("--visual", choices=["cli", "web", "off"], default="cli", help="Visualization mode")
    parser.add_argument("--evidence-level", choices=["low", "medium", "high"], default="medium")
    parser.add_argument("--min-confidence", type=float, default=0.0)
    parser.add_argument("--sarif", action="store_true", help="Generate SARIF report")

    # API mode
    parser.add_argument("api", nargs="?", help="Run as API server: 'hunterx api'")
    parser.add_argument("--port", type=int, default=8443, help="API server port")
    parser.add_argument("--host", default="0.0.0.0", help="API server host")

    # Plugins
    parser.add_argument("--plugin-dirs", default="plugins/detectors,plugins/reporters,plugins/hooks",
                        help="Comma-separated plugin directories")

    args = parser.parse_args()

    # Load YAML config first, then override with env vars, then CLI
    if os.path.exists(args.config):
        load_config_file(args.config)
    config.apply_env_overrides()

    # Apply preset overrides
    if args.preset:
        try:
            import yaml
            with open(args.config) as f:
                cfg_data = yaml.safe_load(f) or {}
            preset = cfg_data.get("presets", {}).get(args.preset, {})
            for k, v in preset.items():
                setattr(config, k, v)
        except Exception:
            pass

    # Auth config
    if args.auth != "none":
        config.auth.type = args.auth
        if args.username:
            config.auth.username = args.username
        if args.password:
            config.auth.password = args.password
        if args.token:
            config.auth.token = args.token
        if args.cookie_file:
            config.auth.cookie_file = args.cookie_file
        if args.login_url:
            config.auth.login_url = args.login_url
        if args.login_data:
            pairs = args.login_data.split(",")
            for pair in pairs:
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    config.auth.login_data[k.strip()] = v.strip()

    # OOB config
    if args.oob:
        config.oob.enabled = True
        if args.collaborator:
            config.oob.collaborator_url = args.collaborator

    # AI config
    if args.ai:
        config.ai.enabled = True
        config.ai.model = args.ai_model
        config.ai.endpoint = args.ai_endpoint

    console.print(BANNER)

    # API server mode
    if args.api == "api":
        try:
            from api.server import start_api
            start_api(host=args.host, port=args.port)
            return
        except ImportError as e:
            logger.error(f"Cannot start API server: {e}. Install: pip install fastapi uvicorn")
            sys.exit(1)

    # Validate URL or targets file
    targets = []
    if args.url:
        targets.append(args.url)
    if args.targets_file:
        with open(args.targets_file) as f:
            targets.extend([line.strip() for line in f if line.strip()])

    if not targets:
        logger.error("Provide --url or --targets-file")
        sys.exit(1)

    for t in targets:
        parsed = urllib.parse.urlparse(t)
        if not parsed.scheme or not parsed.netloc:
            logger.error(f"Invalid URL: {t}")
            sys.exit(1)

    # Update config from CLI
    config.threads = args.threads
    if args.insecure:
        config.verify_ssl = False

    target_cats = args.category.split(",") if args.category else None
    plugin_dir_list = [d.strip() for d in args.plugin_dirs.split(",") if d.strip()]

    for target_url in targets:
        console.print(f"\n[bold]Scanning:[/bold] {target_url}")

        all_payloads = list(load_payloads(args.payload_dir, target_cats))

        if not all_payloads and not args.passive_only:
            logger.warning(f"No payloads for {target_url}, skipping.")
            continue

        options = {
            "profile": args.profile,
            "stealth": args.stealth,
            "threads": args.threads,
            "dry_run": args.dry_run,
            "passive_only": args.passive_only,
            "visual": args.visual,
            "evidence_level": args.evidence_level,
            "output_dir": args.output_dir,
            "insecure": args.insecure,
            "ai_enabled": args.ai,
            "time_based": True,
            "plugin_dirs": plugin_dir_list,
        }

        engine = Engine(target_url, all_payloads, options)

        try:
            engine.start()

            if engine.results or getattr(engine, 'passive_intel', None):
                reporter = Reporter(args.output_dir)
                reporter.save_json(engine.results)

                intel_data = {}
                if hasattr(engine, 'baseline') and engine.baseline:
                    intel_data = engine.passive_intel.analyze(engine.baseline)

                reporter.generate_final_report(
                    engine.results,
                    engine.inferred_chains,
                    target_url,
                    intel_data,
                )

                reporter.print_summary(engine.results)

                if engine.inferred_chains:
                    console.print("\n[bold red]Potential Attack Chains:[/bold red]")
                    for chain in engine.inferred_chains:
                        console.print(f"- [yellow]{chain['chain']}[/yellow] ({chain.get('likelihood', '?')}): {chain['reason']}")

            else:
                console.print("[yellow]No meaningful results.[/yellow]" if not args.dry_run else "[cyan]Dry run complete.[/cyan]")

        except KeyboardInterrupt:
            console.print("[bold red]Interrupted.[/bold red]")
            engine.stop()
            sys.exit(1)


if __name__ == "__main__":
    main()
