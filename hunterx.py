# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
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
[cyan]HunterX v6.0 — AI-Assisted Vulnerability Hunter by [bold yellow]NullC0d3[/bold yellow][/cyan]
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


def _handle_ai_command(args):
    """Handle AI provider subcommands."""
    from core.ai.manager import AIManager
    from core.ai.factory import AIFactory
    from core.ai.registry import ProviderRegistry
    from core.ai.config import AIConfigManager
    from core.ai.models import Message
    import json as _json

    cmd = args.ai_command

    if cmd == "providers":
        registry = ProviderRegistry()
        registry.discover()
        providers = registry.list_with_status()
        if args.json:
            console.print(_json.dumps(providers, indent=2))
        else:
            console.print("[bold]Registered AI Providers:[/bold]")
            for p in providers:
                status = "[green]OK[/green]" if p.get("healthy") else "[red]DOWN[/red]"
                console.print(f"  {p['name']:20s} {status}  ({p['class']}) models={p.get('model_count', '?')}")
            if not providers:
                console.print("[yellow]No providers registered[/yellow]")

    elif cmd == "health":
        registry = ProviderRegistry()
        registry.discover()
        if args.provider:
            status = registry.health_check(args.provider)
            if args.json:
                console.print(_json.dumps(status.to_dict(), indent=2))
            else:
                s = "[green]Healthy[/green]" if status.healthy else "[red]Unhealthy[/red]"
                console.print(f"{status.provider}: {s} ({status.latency_ms:.0f}ms, {status.model_count} models)")
        else:
            results = registry.health_check_all()
            if args.json:
                console.print(_json.dumps({k: v.to_dict() for k, v in results.items()}, indent=2))
            else:
                console.print("[bold]AI Provider Health:[/bold]")
                for name, status in results.items():
                    s = "[green]OK[/green]" if status.healthy else "[red]DOWN[/red]"
                    console.print(f"  {name:20s} {s}  {status.latency_ms:.0f}ms")

    elif cmd == "config":
        config = AIConfigManager.load()
        if args.json:
            console.print(_json.dumps(config.to_dict(), indent=2))
        else:
            console.print("[bold]AI Configuration:[/bold]")
            console.print(f"  Default provider: {config.default_provider or '(not set)'}")
            console.print(f"  Default model:    {config.default_model or '(not set)'}")
            console.print(f"  Enabled:          {config.enabled}")
            console.print(f"  Cache enabled:    {config.cache_enabled}")
            console.print(f"  Metrics enabled:  {config.metrics_enabled}")
            console.print(f"  Streaming:        {config.enable_streaming}")
            console.print(f"  Fallback:         {config.enable_fallback}")
            console.print(f"  Max retries:      {config.max_retries}")
            console.print(f"  Profiles:         {', '.join(config.profiles.keys()) or '(none)'}")

    elif cmd == "cache":
        manager = AIManager()
        stats = manager.get_cache_stats()
        if args.json:
            console.print(_json.dumps(stats, indent=2))
        else:
            console.print("[bold]AI Cache:[/bold]")
            console.print(f"  Enabled:   {stats.get('enabled', False)}")
            console.print(f"  Hits:      {stats.get('hits', 0)}")
            console.print(f"  Misses:    {stats.get('misses', 0)}")
            console.print(f"  Hit rate:  {stats.get('hit_rate', 0):.1%}")

    elif cmd == "metrics":
        manager = AIManager()
        metrics = manager.get_metrics()
        if args.json:
            console.print(_json.dumps(metrics, indent=2))
        else:
            console.print("[bold]AI Metrics:[/bold]")
            console.print(f"  Total requests:   {metrics.get('total_requests', 0)}")
            console.print(f"  Success rate:     {metrics.get('success_rate', 0):.1%}")
            console.print(f"  Total tokens:     {metrics.get('total_tokens', 0)}")
            console.print(f"  Est. cost:        ${metrics.get('total_cost_estimate', 0):.6f}")
            console.print(f"  Uptime:           {metrics.get('uptime_seconds', 0)}s")
            if metrics.get('providers'):
                console.print(f"\n  [bold]Per Provider:[/bold]")
                for pname, pmetrics in metrics['providers'].items():
                    console.print(f"    {pname}: {pmetrics.get('total_requests', 0)} req, "
                                 f"{pmetrics.get('success_rate', 0):.1%} success, "
                                 f"{pmetrics.get('avg_latency_ms', 0):.0f}ms avg")

    elif cmd == "test":
        manager = AIManager()
        prompt = args.prompt
        try:
            console.print(f"[cyan]Testing:[/cyan] provider={args.provider or 'default'}, model={args.model or 'default'}")
            console.print(f"[cyan]Prompt:[/cyan] {prompt}")
            response = manager.chat(
                messages=[Message.user(prompt)],
                provider=args.provider,
                model=args.model,
                max_tokens=100,
            )
            console.print(f"\n[green]Response:[/green] {response.content}")
            if response.usage:
                console.print(f"[dim]Tokens: {response.usage.total_tokens} "
                             f"(prompt={response.usage.prompt_tokens}, "
                             f"completion={response.usage.completion_tokens})[/dim]")
            console.print(f"[dim]Latency: {response.latency_ms:.0f}ms[/dim]")
            console.print(f"[dim]Model: {response.model}[/dim]")
        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")

    elif cmd == "models":
        registry = ProviderRegistry()
        registry.discover()
        try:
            manager = AIManager()
            models = manager.list_models(provider=args.provider)
            if args.json:
                console.print(_json.dumps([m.to_dict() for m in models], indent=2))
            else:
                console.print(f"[bold]Models for {args.provider or 'default'}:[/bold]")
                for m in models:
                    caps = ", ".join(c.value for c in m.capabilities[:5])
                    console.print(f"  {m.id:30s} ctx={m.context_length} caps=[{caps}]")
                if not models:
                    console.print("[yellow]No models returned[/yellow]")
        except Exception as e:
            console.print(f"[red]Error listing models:[/red] {e}")

    else:
        console.print("[yellow]Unknown AI command. Available: providers, health, config, cache, metrics, test, models[/yellow]")


def _handle_payload_command(args):
    """Handle payload intelligence subcommands."""
    from core.payload_sync import PayloadSyncManager
    from core.payload_index import PayloadIndexer
    from core.payload_search import PayloadSearchEngine
    from core.payload_reasoning import PayloadReasoning
    from core.payload_feedback import PayloadFeedbackLoop
    from core.payload_policy import PayloadExecutionPolicy, PolicyLevel
    from core.payload_graph import PayloadKnowledgeGraph
    from core.payload_provenance import PayloadProvenance
    from core.payload_ranking import PayloadRankingEngine
    from core.payload_context import PayloadContextEngine
    import json

    cmd = args.payload_command

    if cmd == "sync":
        sm = PayloadSyncManager()
        if args.release:
            success = sm.download_release()
        else:
            if args.force and os.path.exists(sm._repo_dir):
                import shutil
                shutil.rmtree(sm._repo_dir)
            success = sm.clone() if not os.path.exists(sm._repo_dir) else sm.pull()
        if success:
            console.print(f"[green]Sync complete:[/green] {sm.repo_info.file_count} files")
        else:
            console.print("[red]Sync failed[/red]")

    elif cmd == "index":
        indexer = PayloadIndexer()
        if args.categories:
            cats = [c.strip() for c in args.categories.split(",")]
            stats = indexer.index_categories(cats, force=args.force)
        else:
            stats = indexer.index_all(force=args.force)
        console.print(f"[green]Indexing complete:[/green] {stats.get('indexed', 0)} indexed, "
                     f"{stats.get('skipped', 0)} skipped, {stats.get('errors', 0)} errors")
        if args.json:
            console.print(json.dumps(stats, indent=2))

    elif cmd == "search":
        engine = PayloadSearchEngine()
        results = engine.search(args.query, limit=args.limit, category_filter=args.category)
        if args.json:
            console.print(json.dumps([r.payload.to_dict() for r in results], indent=2))
        else:
            if not results:
                console.print("[yellow]No results[/yellow]")
            else:
                for r in results:
                    p = r.payload
                    tech = ",".join(p.technology[:3]) if p.technology else ""
                    console.print(f"[cyan]{p.row_id:5d}[/cyan] [{p.category:20s}] {p.payload_text[:80].strip()}")
                    if tech:
                        console.print(f"      tech: {tech}")

    elif cmd == "info":
        indexer = PayloadIndexer()
        payload = indexer.get_by_id(args.payload_id)
        if not payload:
            console.print(f"[red]Payload {args.payload_id} not found[/red]")
            return
        reasoner = PayloadReasoning()
        explanation = reasoner.explain(payload, {"target": args.target})
        console.print(f"\n[bold]Payload #{payload.row_id}[/bold]")
        console.print(f"  [green]Category:[/green] {payload.category}")
        console.print(f"  [green]File:[/green] {payload.file_path}")
        console.print(f"  [green]Text:[/green] {payload.payload_text[:200]}")
        console.print(f"  [bold]Reasoning:[/bold]")
        console.print(f"  {explanation.reason}")
        if explanation.contributing_factors:
            console.print(f"  [bold]Factors:[/bold]")
            for f in explanation.contributing_factors:
                console.print(f"    - {f}")
        if explanation.warnings:
            console.print(f"  [bold yellow]Warnings:[/bold yellow]")
            for w in explanation.warnings:
                console.print(f"    - {w}")

    elif cmd == "stats":
        indexer = PayloadIndexer()
        stats = indexer.get_stats()
        console.print(f"[bold]Payload Index Statistics[/bold]")
        console.print(f"  Total payloads: {stats['total_payloads']}")
        console.print(f"  Categories:     {stats['categories']}")
        console.print(f"  DB path:        {stats['db_path']}")
        console.print(f"  Repo synced:    {stats['repo_synced']}")
        cats = indexer.get_categories()
        if cats:
            console.print(f"\n[bold]Categories:[/bold]")
            for c in cats[:20]:
                console.print(f"  {c['category']:25s} {c['count']:5d} payloads")

    elif cmd == "graph":
        graph = PayloadKnowledgeGraph()
        if args.graph_command == "build":
            stats = graph.build_graph_for_index(max_payloads=args.max)
            console.print(f"[green]Graph built:[/green] {stats.get('total_nodes', 0)} nodes, "
                         f"{stats.get('total_edges', 0)} edges")
        elif args.graph_command == "search":
            results = graph.search_nodes(args.query, node_type=args.node_type)
            if args.json:
                console.print(json.dumps(results, indent=2))
            else:
                if not results:
                    console.print("[yellow]No graph nodes found[/yellow]")
                else:
                    for r in results:
                        console.print(f"[cyan]{r['type']:20s}[/cyan] {r['label'][:60]}")
        elif args.graph_command == "stats":
            stats = graph.get_statistics()
            console.print(f"[bold]Knowledge Graph Statistics[/bold]")
            console.print(f"  Total nodes: {stats['total_nodes']}")
            console.print(f"  Total edges: {stats['total_edges']}")
            console.print(f"  Nodes by type: {stats['nodes_by_type']}")
            console.print(f"  Edges by relationship: {stats['edges_by_relationship']}")

    elif cmd == "feedback":
        feedback = PayloadFeedbackLoop()
        summary = feedback.get_summary()
        if args.json:
            console.print(json.dumps(summary, indent=2))
        else:
            console.print(f"[bold]Payload Feedback Statistics[/bold]")
            console.print(f"  Total records:     {summary['total']}")
            console.print(f"  Success rate:      {summary.get('success_rate', 0):.1%}")
            console.print(f"  Detection rate:    {summary.get('detection_rate', 0):.1%}")
            console.print(f"  Block rate:        {summary.get('block_rate', 0):.1%}")
            console.print(f"  Unique payloads:   {summary.get('unique_payloads', 0)}")
            if summary.get('categories'):
                console.print(f"  Categories tracked: {', '.join(summary['categories'].keys())}")
            top = feedback.get_top_performing(category=args.category)
            if top:
                console.print(f"\n[bold]Top Performing:[/bold]")
                for t in top[:5]:
                    console.print(f"  [{t['category']:20s}] rate={t['success_rate']:.1%} "
                                 f"attempts={t['attempts']} perf={t['performance_score']:.3f}")

    elif cmd == "policy":
        policy = PayloadExecutionPolicy()
        if args.level:
            policy.set_level(PolicyLevel(args.level))
            console.print(f"[green]Policy set to:[/green] {args.level}")
        if args.json:
            console.print(json.dumps(policy.to_dict(), indent=2))
        else:
            console.print(f"[bold]Payload Execution Policy:[/bold] {policy.config.level.value}")
            console.print(f"  Max per category: {policy.config.max_payloads_per_category}")
            console.print(f"  Allow dangerous:  {policy.config.allow_dangerous}")
            console.print(f"  Allow high noise: {policy.config.allow_high_noise}")
            console.print(f"  Max mutations:    {policy.config.max_mutations_per_payload}")
            console.print(f"  Max concurrent:   {policy.config.max_concurrent_payloads}")

    elif cmd == "provenance":
        prov = PayloadProvenance()
        if args.query:
            results = prov.search(args.query)
        else:
            stats = prov.get_stats()
            console.print(f"[bold]Provenance Statistics[/bold]")
            console.print(f"  Total records:    {stats['total_records']}")
            console.print(f"  With commit hash: {stats['with_commit_hash']}")
            console.print(f"  With checksum:    {stats['with_checksum']}")
            return
        if args.json:
            console.print(json.dumps([r.to_dict() for r in results], indent=2))
        else:
            if not results:
                console.print("[yellow]No provenance records found[/yellow]")
            else:
                for r in results[:20]:
                    console.print(f"  [{r.category:20s}] {r.file_path[:60]} "
                                 f"hash={r.payload_hash[:12]}")

    elif cmd == "top":
        feedback = PayloadFeedbackLoop()
        top = feedback.get_top_performing(category=args.category, top_n=args.limit)
        if args.json:
            console.print(json.dumps(top, indent=2))
        else:
            if not top:
                console.print("[yellow]No top performers yet — run some payloads first[/yellow]")
            else:
                console.print(f"[bold]Top {len(top)} Performing Payloads[/bold]")
                for i, t in enumerate(top, 1):
                    console.print(f"  {i:2d}. [{t['category']:20s}] rate={t['success_rate']:.1%} "
                                 f"attempts={t['attempts']} perf={t['performance_score']:.3f}")
                    console.print(f"      payload: {t['payload'][:80]}")

    else:
        console.print("[yellow]Unknown payload command. Available: sync, index, search, info, stats, "
                     "graph, feedback, policy, provenance, top[/yellow]")


def _handle_agents_command(args):
    """Handle agent subcommands."""
    from core.agents.registry import AgentRegistry
    from core.agents.plugins import (
        ReconAgent, ThreatModelingAgent, PlanningAgent, PayloadAgent,
        VerificationAgent, RiskAgent, ReportingAgent, PurpleTeamAgent,
        LearningAgent, CoordinatorAgent,
    )
    import json as _json

    registry = AgentRegistry()

    for agent_cls in [
        ReconAgent, ThreatModelingAgent, PlanningAgent, PayloadAgent,
        VerificationAgent, RiskAgent, ReportingAgent, PurpleTeamAgent,
        LearningAgent, CoordinatorAgent,
    ]:
        agent = agent_cls()
        registry.register(agent)

    cmd = args.agents_command

    if cmd == "list":
        agents = registry.list_agents()
        if args.json:
            console.print(_json.dumps(agents, indent=2))
        else:
            console.print("[bold]Registered Agents:[/bold]")
            for a in agents:
                state_color = "[green]" if a.get("state") == "idle" else "[yellow]"
                console.print(f"  {a['name']:25s} {state_color}{a['state']}[/]  id={a['agent_id'][:8]} caps={len(a.get('capabilities', []))}")
            console.print(f"\n[dim]Total: {len(agents)} agents[/dim]")

    elif cmd == "status":
        agents = registry.list_agents()
        if args.json:
            console.print(_json.dumps(agents, indent=2))
        else:
            console.print("[bold]Agent Status:[/bold]")
            for a in agents:
                state = a.get("state", "unknown")
                status = "[green]OK[/green]" if state in ("idle", "busy") else "[red]DOWN[/red]"
                console.print(f"  {a['name']:25s} {status}  state={state}  caps={', '.join(a.get('capabilities', []))}")

    elif cmd == "enable":
        agent = registry.get(args.agent_id)
        if agent:
            console.print(f"[green]Agent {agent.name} enabled[/green]")
        else:
            console.print(f"[red]Agent {args.agent_id} not found[/red]")

    elif cmd == "disable":
        agent = registry.get(args.agent_id)
        if agent:
            agent.shutdown()
            console.print(f"[yellow]Agent {agent.name} disabled[/yellow]")
        else:
            console.print(f"[red]Agent {args.agent_id} not found[/red]")

    else:
        console.print("[yellow]Unknown agents command. Available: list, status, enable, disable[/yellow]")


def _handle_workflow_command(args):
    """Handle workflow subcommands."""
    from core.agents.workflow import WorkflowEngine
    import json as _json

    engine = WorkflowEngine()
    cmd = args.workflow_command

    if cmd == "run":
        wf = engine.get(args.workflow_id)
        if wf:
            state = engine.run(args.workflow_id)
            console.print(f"[green]Workflow {args.workflow_id[:8]} completed with state: {state.value}[/green]")
        else:
            console.print(f"[red]Workflow {args.workflow_id} not found[/red]")

    elif cmd == "inspect":
        wf = engine.get(args.workflow_id)
        if wf:
            console.print(_json.dumps(wf.to_dict(), indent=2))
        else:
            console.print(f"[red]Workflow {args.workflow_id} not found[/red]")

    elif cmd == "graph":
        wf = engine.get(args.workflow_id)
        if wf:
            console.print("[bold]Workflow Dependency Graph:[/bold]")
            for step in wf.steps:
                deps = ", ".join(step.depends_on) if step.depends_on else "(none)"
                console.print(f"  {step.id[:8]} [{step.type.value:10s}] {step.name}")
                console.print(f"    depends_on: {deps}")
        else:
            console.print(f"[red]Workflow {args.workflow_id} not found[/red]")

    else:
        console.print("[yellow]Unknown workflow command. Available: run, inspect, graph[/yellow]")


def _handle_reasoning_command(args):
    """Handle reasoning subcommands."""
    from core.reasoning.validator import OutputValidator
    from core.reasoning.policies import PolicyManager, ReasoningSafetyLevel
    import json as _json

    cmd = args.reasoning_command

    if cmd == "inspect":
        console.print(f"[yellow]Goal {args.goal_id} — use hunterx workflow inspect for cached results[/yellow]")

    elif cmd == "validate":
        if args.output:
            policy = PolicyManager.from_safety_level(ReasoningSafetyLevel.BALANCED)
            result = OutputValidator.validate(args.output, policy)
            console.print(_json.dumps({
                "valid": result.valid,
                "confidence": result.confidence,
                "errors": result.errors,
                "warnings": result.warnings,
            }, indent=2))
        else:
            console.print("[yellow]Provide --output text to validate[/yellow]")

    else:
        console.print("[yellow]Unknown reasoning command. Available: inspect, validate[/yellow]")


def _handle_skills_command(args):
    """Handle skills subcommands."""
    from core.skills.registry import SkillRegistry
    from core.skills.loader import SkillLoader
    from core.skills.marketplace import SkillMarketplace
    from core.skills.telemetry import SkillTelemetry
    import json as _json

    registry = SkillRegistry()
    loader = SkillLoader(registry)
    loader.discover_builtin()

    cmd = args.skills_command

    if cmd == "list":
        skills = registry.list()
        if args.json:
            console.print(_json.dumps(skills, indent=2))
        else:
            console.print("[bold]Registered Skills:[/bold]")
            for s in skills:
                console.print(f"  {s['skill_id']:35s} v{s['version']:8s} [{s['risk_level']:8s}] {s['name']}")
            console.print(f"\n[dim]Total: {len(skills)} skills[/dim]")

    elif cmd == "info":
        skill = registry.get(args.skill_id)
        if skill:
            console.print(_json.dumps(skill.metadata.to_dict(), indent=2))
        else:
            console.print(f"[red]Skill not found: {args.skill_id}[/red]")

    elif cmd == "search":
        results = registry.search(args.query)
        if not results:
            console.print(f"[yellow]No skills matching '{args.query}'[/yellow]")
        else:
            console.print(f"[bold]Skills matching '{args.query}':[/bold]")
            for m in results:
                console.print(f"  {m.skill_id:35s} {m.name}")

    elif cmd == "install":
        marketplace = SkillMarketplace()
        skill_id = marketplace.install(args.path)
        if skill_id:
            console.print(f"[green]Installed skill: {skill_id}[/green]")
        else:
            console.print("[red]Installation failed[/red]")

    elif cmd == "uninstall":
        marketplace = SkillMarketplace()
        if marketplace.uninstall(args.skill_id):
            console.print(f"[green]Uninstalled skill: {args.skill_id}[/green]")
        else:
            console.print(f"[red]Failed to uninstall: {args.skill_id}[/red]")

    elif cmd == "enable":
        if registry.enable(args.skill_id):
            console.print(f"[green]Enabled skill: {args.skill_id}[/green]")
        else:
            console.print(f"[red]Skill not found: {args.skill_id}[/red]")

    elif cmd == "disable":
        registry.disable(args.skill_id)
        console.print(f"[yellow]Disabled skill: {args.skill_id}[/yellow]")

    elif cmd == "verify":
        marketplace = SkillMarketplace()
        result = marketplace.verify(args.skill_id)
        if result.get("verified"):
            console.print(f"[green]Skill {args.skill_id} verified successfully[/green]")
        else:
            console.print(f"[red]Skill {args.skill_id} verification failed: {result.get('error', 'unknown')}[/red]")

    elif cmd == "doctor":
        if args.skill_id:
            skill = registry.get(args.skill_id)
            if skill:
                console.print(f"[green]Skill {args.skill_id} is healthy[/green]")
                console.print(f"  Metadata: {skill.metadata.name} v{skill.metadata.version}")
                console.print(f"  Capabilities: {[c.value for c in skill.capabilities]}")
            else:
                console.print(f"[red]Skill {args.skill_id} not found[/red]")
        else:
            health = registry.health()
            console.print(f"[bold]Skill System Health:[/bold]")
            console.print(f"  Total skills: {health['total']}")
            console.print(f"  Enabled: {health['enabled']}")
            console.print(f"  Healthy: {health['healthy']}")

    elif cmd == "export":
        marketplace = SkillMarketplace()
        output = args.output or f"{args.skill_id}.zip"
        if marketplace.export_package(args.skill_id, output):
            console.print(f"[green]Exported skill to: {output}[/green]")
        else:
            console.print(f"[red]Export failed for: {args.skill_id}[/red]")

    elif cmd == "stats":
        telemetry = SkillTelemetry()
        if args.skill_id:
            stats = telemetry.get_stats(args.skill_id)
        else:
            stats = telemetry.get_summary()
        console.print(_json.dumps(stats, indent=2))

    else:
        console.print("[yellow]Unknown skills command. Available: list, info, search, install, uninstall, enable, disable, verify, doctor, export, stats[/yellow]")


def main():
    parser = argparse.ArgumentParser(
        description="HunterX v6.0 — Vulnerability Hunting Framework",
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

    # Sub-commands
    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # API server command
    api_parser = subparsers.add_parser("api", help="Run as API server")
    api_parser.add_argument("--port", type=int, default=8443, help="API server port")
    api_parser.add_argument("--host", default="0.0.0.0", help="API server host")

    # Payload Intelligence command
    payload_parser = subparsers.add_parser("payload", help="Payload Intelligence Platform commands")
    payload_sub = payload_parser.add_subparsers(dest="payload_command", help="Payload commands")

    p_sync = payload_sub.add_parser("sync", help="Sync payloads from upstream repository")
    p_sync.add_argument("--force", action="store_true", help="Force re-clone")
    p_sync.add_argument("--release", action="store_true", help="Download release instead of git clone")

    p_index = payload_sub.add_parser("index", help="Index payloads into search database")
    p_index.add_argument("--force", action="store_true", help="Re-index all payloads")
    p_index.add_argument("--categories", help="Comma-separated categories to index")

    p_search = payload_sub.add_parser("search", help="Search indexed payloads")
    p_search.add_argument("query", nargs="?", default="", help="Search query")
    p_search.add_argument("--category", help="Filter by category")
    p_search.add_argument("--limit", type=int, default=20, help="Max results")
    p_search.add_argument("--json", action="store_true", help="Output as JSON")

    p_info = payload_sub.add_parser("info", help="Get reasoning explanation for a payload")
    p_info.add_argument("payload_id", type=int, help="Payload ID")
    p_info.add_argument("--target", default="http://example.com", help="Target context URL")

    payload_sub.add_parser("stats", help="Show payload index statistics")

    p_graph = payload_sub.add_parser("graph", help="Payload knowledge graph commands")
    p_graph_sub = p_graph.add_subparsers(dest="graph_command")
    p_graph_build = p_graph_sub.add_parser("build", help="Build graph from index")
    p_graph_build.add_argument("--max", type=int, default=500, help="Max payloads to process")
    p_graph_search = p_graph_sub.add_parser("search", help="Search graph nodes")
    p_graph_search.add_argument("query", help="Search query")
    p_graph_search.add_argument("--type", dest="node_type", help="Filter by node type")
    p_graph_search.add_argument("--json", action="store_true", help="Output as JSON")
    p_graph_sub.add_parser("stats", help="Show knowledge graph statistics")

    p_feedback = payload_sub.add_parser("feedback", help="Show payload feedback statistics")
    p_feedback.add_argument("--category", help="Filter by category")
    p_feedback.add_argument("--json", action="store_true", help="Output as JSON")

    p_policy = payload_sub.add_parser("policy", help="View or set payload execution policy")
    p_policy.add_argument("--level", choices=["safe", "balanced", "aggressive", "research", "paranoid"], help="Set policy level")
    p_policy.add_argument("--json", action="store_true", help="Output as JSON")

    p_prov = payload_sub.add_parser("provenance", help="Query payload provenance records")
    p_prov.add_argument("query", nargs="?", default="", help="Search by path, filename, or hash")
    p_prov.add_argument("--json", action="store_true", help="Output as JSON")

    p_top = payload_sub.add_parser("top", help="Show top performing payloads")
    p_top.add_argument("--category", help="Filter by category")
    p_top.add_argument("--limit", type=int, default=10, help="Number of top payloads")
    p_top.add_argument("--json", action="store_true", help="Output as JSON")

    # Agents command
    agents_parser = subparsers.add_parser("agents", help="Agent management commands")
    agents_sub = agents_parser.add_subparsers(dest="agents_command", help="Agent commands")

    agents_list = agents_sub.add_parser("list", help="List registered agents")
    agents_list.add_argument("--json", action="store_true", help="Output as JSON")

    agents_status = agents_sub.add_parser("status", help="Show agent status")
    agents_status.add_argument("--json", action="store_true", help="Output as JSON")

    agents_enable = agents_sub.add_parser("enable", help="Enable an agent")
    agents_enable.add_argument("agent_id", help="Agent ID to enable")

    agents_disable = agents_sub.add_parser("disable", help="Disable an agent")
    agents_disable.add_argument("agent_id", help="Agent ID to disable")

    # Workflow command
    workflow_parser = subparsers.add_parser("workflow", help="Workflow management commands")
    workflow_sub = workflow_parser.add_subparsers(dest="workflow_command", help="Workflow commands")

    wf_run = workflow_sub.add_parser("run", help="Run a workflow")
    wf_run.add_argument("workflow_id", help="Workflow ID")

    wf_inspect = workflow_sub.add_parser("inspect", help="Inspect a workflow")
    wf_inspect.add_argument("workflow_id", help="Workflow ID")

    wf_graph = workflow_sub.add_parser("graph", help="Show workflow dependency graph")
    wf_graph.add_argument("workflow_id", help="Workflow ID")

    # Reasoning command
    reasoning_parser = subparsers.add_parser("reasoning", help="Reasoning engine commands")
    reasoning_sub = reasoning_parser.add_subparsers(dest="reasoning_command", help="Reasoning commands")

    rs_inspect = reasoning_sub.add_parser("inspect", help="Inspect reasoning result")
    rs_inspect.add_argument("goal_id", help="Goal ID to inspect")

    rs_validate = reasoning_sub.add_parser("validate", help="Validate reasoning output")
    rs_validate.add_argument("--output", default="", help="Output text to validate")

    # Skills command
    skills_parser = subparsers.add_parser("skills", help="Security Skills Framework commands")
    skills_sub = skills_parser.add_subparsers(dest="skills_command", help="Skills commands")

    skills_list = skills_sub.add_parser("list", help="List all skills")
    skills_list.add_argument("--json", action="store_true", help="Output as JSON")

    skills_info = skills_sub.add_parser("info", help="Show skill details")
    skills_info.add_argument("skill_id", help="Skill ID")

    skills_search = skills_sub.add_parser("search", help="Search skills")
    skills_search.add_argument("query", help="Search query")

    skills_install = skills_sub.add_parser("install", help="Install a skill package")
    skills_install.add_argument("path", help="Path to skill package (.zip or directory)")

    skills_uninstall = skills_sub.add_parser("uninstall", help="Uninstall a skill")
    skills_uninstall.add_argument("skill_id", help="Skill ID")

    skills_enable = skills_sub.add_parser("enable", help="Enable a skill")
    skills_enable.add_argument("skill_id", help="Skill ID")

    skills_disable = skills_sub.add_parser("disable", help="Disable a skill")
    skills_disable.add_argument("skill_id", help="Skill ID")

    skills_verify = skills_sub.add_parser("verify", help="Verify a skill installation")
    skills_verify.add_argument("skill_id", help="Skill ID")

    skills_doctor = skills_sub.add_parser("doctor", help="Run skill diagnostics")
    skills_doctor.add_argument("--skill-id", help="Specific skill to check")

    skills_export = skills_sub.add_parser("export", help="Export a skill package")
    skills_export.add_argument("skill_id", help="Skill ID")
    skills_export.add_argument("--output", default="", help="Output path")

    skills_stats = skills_sub.add_parser("stats", help="Show skill telemetry stats")
    skills_stats.add_argument("--skill-id", help="Filter by skill ID")

    # AI command
    ai_parser = subparsers.add_parser("ai", help="AI Provider commands")
    ai_sub = ai_parser.add_subparsers(dest="ai_command", help="AI commands")

    ai_providers = ai_sub.add_parser("providers", help="List registered AI providers")
    ai_providers.add_argument("--json", action="store_true", help="Output as JSON")

    ai_health = ai_sub.add_parser("health", help="Check AI provider health")
    ai_health.add_argument("--provider", help="Specific provider to check")
    ai_health.add_argument("--json", action="store_true", help="Output as JSON")

    ai_config = ai_sub.add_parser("config", help="View AI configuration")
    ai_config.add_argument("--json", action="store_true", help="Output as JSON")

    ai_cache = ai_sub.add_parser("cache", help="View AI cache statistics")
    ai_cache.add_argument("--json", action="store_true", help="Output as JSON")

    ai_metrics = ai_sub.add_parser("metrics", help="View AI metrics")
    ai_metrics.add_argument("--provider", help="Filter by provider")
    ai_metrics.add_argument("--json", action="store_true", help="Output as JSON")

    ai_test = ai_sub.add_parser("test", help="Test an AI provider")
    ai_test.add_argument("--provider", default="", help="Provider to test")
    ai_test.add_argument("--model", default="", help="Model to use")
    ai_test.add_argument("--prompt", default="Say hello in one word.", help="Test prompt")

    ai_models = ai_sub.add_parser("models", help="List models for a provider")
    ai_models.add_argument("--provider", default="", help="Provider name")
    ai_models.add_argument("--json", action="store_true", help="Output as JSON")

    # Intelligence layer
    parser.add_argument("--graph", action="store_true", help="Generate knowledge graph")
    parser.add_argument("--attack-graph", action="store_true", default=True,
                        help="Generate visual attack graph")
    parser.add_argument("--threat-model", action="store_true",
                        help="Generate threat model")
    parser.add_argument("--risk", action="store_true", help="Run risk analysis")
    parser.add_argument("--purple", action="store_true",
                        help="Generate purple team detection rules")
    parser.add_argument("--explain", action="store_true", default=True,
                        help="Generate AI explanations for findings")
    parser.add_argument("--browser", action="store_true",
                        help="Enable browser intelligence (requires Playwright)")
    parser.add_argument("--risk-profile", choices=["default", "pentest", "bug_bounty", "compliance"],
                        default="default", help="Risk scoring profile")
    parser.add_argument("--memory-db", action="store_true", default=True,
                        help="Use SQLite for adaptive memory persistence")

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
    if args.command == "api":
        try:
            from api.server import start_api
            start_api(host=args.host, port=args.port)
            return
        except ImportError as e:
            logger.error(f"Cannot start API server: {e}. Install: pip install fastapi uvicorn")
            sys.exit(1)

    # Payload Intelligence commands
    if args.command == "payload":
        _handle_payload_command(args)
        return

    # Agents commands
    if args.command == "agents":
        _handle_agents_command(args)
        return

    # Workflow commands
    if args.command == "workflow":
        _handle_workflow_command(args)
        return

    # Reasoning commands
    if args.command == "reasoning":
        _handle_reasoning_command(args)
        return

    # Skills commands
    if args.command == "skills":
        _handle_skills_command(args)
        return

    # AI Provider commands
    if args.command == "ai":
        _handle_ai_command(args)
        return

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
            # Intelligence layer options
            "intel": True,
            "graph": args.graph,
            "attack_graph": args.attack_graph,
            "threat_model": args.threat_model,
            "risk": args.risk,
            "purple": args.purple,
            "explain": args.explain,
            "browser": args.browser,
            "risk_profile": args.risk_profile,
            "memory_db": args.memory_db,
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

                # Build intelligence dict for enhanced report
                intelligence_data = {}
                if hasattr(engine, 'knowledge_graph') and engine.knowledge_graph:
                    intelligence_data["knowledge_graph"] = engine.knowledge_graph.to_dict()
                if hasattr(engine, 'attack_paths') and engine.attack_paths:
                    intelligence_data["attack_paths"] = engine.attack_paths
                if hasattr(engine, 'threat_model') and engine.threat_model:
                    intelligence_data["threat_model"] = engine.threat_model
                if hasattr(engine, 'risk_scores') and engine.risk_scores:
                    intelligence_data["risk_matrix"] = engine.risk_scores
                if hasattr(engine, 'mitre_mappings') and engine.mitre_mappings:
                    intelligence_data["mitre_mappings"] = engine.mitre_mappings
                if hasattr(engine, 'explanations') and engine.explanations:
                    intelligence_data["explanations"] = engine.explanations
                if hasattr(engine, 'scan_plan') and engine.scan_plan:
                    intelligence_data["scan_plan"] = engine.scan_plan
                if hasattr(engine, 'purple_rules') and engine.purple_rules:
                    intelligence_data["purple_rules"] = engine.purple_rules

                reporter.generate_final_report(
                    engine.results,
                    engine.inferred_chains,
                    target_url,
                    intel_data,
                    intelligence=intelligence_data if intelligence_data else None,
                )

                # Save intelligence JSON
                if intelligence_data:
                    reporter.save_intelligence_json(engine)

                reporter.print_summary(engine.results)

                if engine.inferred_chains:
                    console.print("\n[bold red]Potential Attack Chains:[/bold red]")
                    for chain in engine.inferred_chains:
                        console.print(f"- [yellow]{chain['chain']}[/yellow] ({chain.get('likelihood', '?')}): {chain['reason']}")

                # Intelligence layer summary
                if engine.attack_paths:
                    console.print(f"\n[bold cyan]Intelligence Layer:[/bold cyan]")
                    console.print(f"[green]- Attack Paths:[/green] {len(engine.attack_paths)}")
                    if engine.mitre_mappings:
                        console.print(f"[green]- MITRE Techniques:[/green] {len(engine.mitre_mappings)}")
                    if engine.risk_scores:
                        max_r = max((r.get("risk", {}).get("normalized_score", 0) for r in engine.risk_scores), default=0)
                        console.print(f"[green]- Max Risk Score:[/green] {max_r:.3f}")

            else:
                console.print("[yellow]No meaningful results.[/yellow]" if not args.dry_run else "[cyan]Dry run complete.[/cyan]")

        except KeyboardInterrupt:
            console.print("[bold red]Interrupted.[/bold red]")
            engine.stop()
            sys.exit(1)


if __name__ == "__main__":
    main()
