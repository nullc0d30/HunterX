import argparse
import itertools
import logging
import os
import sys
import urllib.parse
from typing import List, Optional

from .config.config import config, load_config_file
from .utils.utils import logger, console
from .core.classifier import PayloadClassifier
from .core.legal import get_copyright_text

__all__ = ["main", "load_payloads", "classify_payload_files"]

BANNER = r"""
  _   _             _             __  __
 | | | |_   _ _ __ | |_ ___ _ __  \ \/ /
 | |_| | | | | '_ \| __/ _ \ '__|  \  /
 |  _  | |_| | | | | ||  __/ |     /  \
 |_| |_|\__,_|_| |_|\__\___|_|    /_/\_\
HunterX v6.0.0 -- AI-Assisted Vulnerability Hunter by NullC0d3
{license}
"""

COMMANDS = {
    "scan", "module", "report", "doctor", "config", "update",
    "api", "payload", "agents", "workflow", "reasoning", "skills", "ai",
    "help",
}


def classify_payload_files(payload_dir: str, target_categories: Optional[List[str]] = None):
    classifier = PayloadClassifier()
    if not os.path.exists(payload_dir):
        logger.error("Payload directory not found: %s", payload_dir)
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
    if not os.path.exists(payload_dir):
        logger.error("Payload directory not found: %s", payload_dir)
        return
    matched_files = list(classify_payload_files(payload_dir, target_categories))
    if not matched_files:
        logger.warning("No payload files matched categories: %s", target_categories or "all")
        return
    for filename, path, category in matched_files:
        file_size = os.path.getsize(path)
        if file_size > 50 * 1024 * 1024:
            logger.warning("Skipping oversized payload file: %s (%dMB)", filename, file_size // 1024 // 1024)
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    yield {"payload": line, "category": category, "source_file": filename}
        except Exception as e:
            logger.debug("Failed to read payload file %s: %s", filename, e)
    logger.info("Streamed payloads from %s (%d files)", payload_dir, len(matched_files))


def _handle_ai_command(args):
    from .core.ai.manager import AIManager
    from .core.ai.registry import ProviderRegistry
    from .core.ai.config import AIConfigManager
    from .core.ai.models import Message
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
                console.print("  %-20s %s  (%s) models=%s" % (p["name"], status, p.get("class"), p.get("model_count", "?")))
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
                console.print("%s: %s (%.0fms, %d models)" % (status.provider, s, status.latency_ms, status.model_count))
        else:
            results = registry.health_check_all()
            if args.json:
                console.print(_json.dumps({k: v.to_dict() for k, v in results.items()}, indent=2))
            else:
                console.print("[bold]AI Provider Health:[/bold]")
                for name, status in results.items():
                    s = "[green]OK[/green]" if status.healthy else "[red]DOWN[/red]"
                    console.print("  %-20s %s  %.0fms" % (name, s, status.latency_ms))

    elif cmd == "config":
        cfg = AIConfigManager.load()
        if args.json:
            console.print(_json.dumps(cfg.to_dict(), indent=2))
        else:
            console.print("[bold]AI Configuration:[/bold]")
            console.print("  Default provider: %s" % (cfg.default_provider or "(not set)"))
            console.print("  Default model:    %s" % (cfg.default_model or "(not set)"))
            console.print("  Enabled:          %s" % cfg.enabled)
            console.print("  Cache enabled:    %s" % cfg.cache_enabled)
            console.print("  Metrics enabled:  %s" % cfg.metrics_enabled)
            console.print("  Streaming:        %s" % cfg.enable_streaming)
            console.print("  Fallback:         %s" % cfg.enable_fallback)
            console.print("  Max retries:      %s" % cfg.max_retries)
            console.print("  Profiles:         %s" % (", ".join(cfg.profiles.keys()) or "(none)"))

    elif cmd == "cache":
        manager = AIManager()
        stats = manager.get_cache_stats()
        if args.json:
            console.print(_json.dumps(stats, indent=2))
        else:
            console.print("[bold]AI Cache:[/bold]")
            console.print("  Enabled:   %s" % stats.get("enabled", False))
            console.print("  Hits:      %d" % stats.get("hits", 0))
            console.print("  Misses:    %d" % stats.get("misses", 0))
            console.print("  Hit rate:  %.1f%%" % (stats.get("hit_rate", 0) * 100))

    elif cmd == "metrics":
        manager = AIManager()
        metrics = manager.get_metrics()
        if args.json:
            console.print(_json.dumps(metrics, indent=2))
        else:
            console.print("[bold]AI Metrics:[/bold]")
            console.print("  Total requests:   %d" % metrics.get("total_requests", 0))
            console.print("  Success rate:     %.1f%%" % (metrics.get("success_rate", 0) * 100))
            console.print("  Total tokens:     %d" % metrics.get("total_tokens", 0))
            console.print("  Est. cost:        $%.6f" % metrics.get("total_cost_estimate", 0))
            console.print("  Uptime:           %ds" % metrics.get("uptime_seconds", 0))
            if metrics.get("providers"):
                console.print("\n  [bold]Per Provider:[/bold]")
                for pname, pmetrics in metrics["providers"].items():
                    console.print("    %s: %d req, %.1f%% success, %.0fms avg" % (
                        pname, pmetrics.get("total_requests", 0),
                        pmetrics.get("success_rate", 0) * 100,
                        pmetrics.get("avg_latency_ms", 0)))

    elif cmd == "test":
        manager = AIManager()
        prompt = args.prompt
        try:
            console.print("[cyan]Testing:[/cyan] provider=%s, model=%s" % (args.provider or "default", args.model or "default"))
            console.print("[cyan]Prompt:[/cyan] %s" % prompt)
            response = manager.chat(
                messages=[Message.user(prompt)],
                provider=args.provider,
                model=args.model,
                max_tokens=100,
            )
            console.print("\n[green]Response:[/green] %s" % response.content)
            if response.usage:
                console.print("[dim]Tokens: %d (prompt=%d, completion=%d)[/dim]" % (
                    response.usage.total_tokens, response.usage.prompt_tokens, response.usage.completion_tokens))
            console.print("[dim]Latency: %.0fms[/dim]" % response.latency_ms)
            console.print("[dim]Model: %s[/dim]" % response.model)
        except Exception as e:
            console.print("[red]Error:[/red] %s" % e)

    elif cmd == "models":
        registry = ProviderRegistry()
        registry.discover()
        try:
            manager = AIManager()
            models = manager.list_models(provider=args.provider)
            if args.json:
                console.print(_json.dumps([m.to_dict() for m in models], indent=2))
            else:
                console.print("[bold]Models for %s:[/bold]" % (args.provider or "default"))
                for m in models:
                    caps = ", ".join(c.value for c in m.capabilities[:5])
                    console.print("  %-30s ctx=%d caps=[%s]" % (m.id, m.context_length, caps))
                if not models:
                    console.print("[yellow]No models returned[/yellow]")
        except Exception as e:
            console.print("[red]Error listing models:[/red] %s" % e)

    else:
        console.print("[yellow]Unknown AI command. Available: providers, health, config, cache, metrics, test, models[/yellow]")


def _handle_payload_command(args):
    from .modules.payloads.payload_sync import PayloadSyncManager
    from .modules.payloads.payload_index import PayloadIndexer
    from .modules.payloads.payload_search import PayloadSearchEngine
    from .modules.payloads.payload_reasoning import PayloadReasoning
    from .modules.payloads.payload_feedback import PayloadFeedbackLoop
    from .modules.payloads.payload_policy import PayloadExecutionPolicy, PolicyLevel
    from .modules.payloads.payload_graph import PayloadKnowledgeGraph
    from .modules.payloads.payload_provenance import PayloadProvenance
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
            console.print("[green]Sync complete:[/green] %d files" % sm.repo_info.file_count)
        else:
            console.print("[red]Sync failed[/red]")

    elif cmd == "index":
        indexer = PayloadIndexer()
        if args.categories:
            cats = [c.strip() for c in args.categories.split(",")]
            stats = indexer.index_categories(cats, force=args.force)
        else:
            stats = indexer.index_all(force=args.force)
        console.print("[green]Indexing complete:[/green] %d indexed, %d skipped, %d errors" % (
            stats.get("indexed", 0), stats.get("skipped", 0), stats.get("errors", 0)))
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
                    console.print("[cyan]%5d[/cyan] [%s] %s" % (p.row_id, p.category[:20], p.payload_text[:80].strip()))
                    if tech:
                        console.print("      tech: %s" % tech)

    elif cmd == "info":
        indexer = PayloadIndexer()
        payload = indexer.get_by_id(args.payload_id)
        if not payload:
            console.print("[red]Payload %d not found[/red]" % args.payload_id)
            return
        reasoner = PayloadReasoning()
        explanation = reasoner.explain(payload, {"target": args.target})
        console.print("\n[bold]Payload #%d[/bold]" % payload.row_id)
        console.print("  [green]Category:[/green] %s" % payload.category)
        console.print("  [green]File:[/green] %s" % payload.file_path)
        console.print("  [green]Text:[/green] %s" % payload.payload_text[:200])
        console.print("  [bold]Reasoning:[/bold]")
        console.print("  %s" % explanation.reason)
        if explanation.contributing_factors:
            console.print("  [bold]Factors:[/bold]")
            for f in explanation.contributing_factors:
                console.print("    - %s" % f)
        if explanation.warnings:
            console.print("  [bold yellow]Warnings:[/bold yellow]")
            for w in explanation.warnings:
                console.print("    - %s" % w)

    elif cmd == "stats":
        indexer = PayloadIndexer()
        stats = indexer.get_stats()
        console.print("[bold]Payload Index Statistics[/bold]")
        console.print("  Total payloads: %d" % stats["total_payloads"])
        console.print("  Categories:     %d" % stats["categories"])
        console.print("  DB path:        %s" % stats["db_path"])
        console.print("  Repo synced:    %s" % stats["repo_synced"])
        cats = indexer.get_categories()
        if cats:
            console.print("\n[bold]Categories:[/bold]")
            for c in cats[:20]:
                console.print("  %-25s %5d payloads" % (c["category"], c["count"]))

    elif cmd == "graph":
        graph = PayloadKnowledgeGraph()
        if args.graph_command == "build":
            stats = graph.build_graph_for_index(max_payloads=args.max)
            console.print("[green]Graph built:[/green] %d nodes, %d edges" % (stats.get("total_nodes", 0), stats.get("total_edges", 0)))
        elif args.graph_command == "search":
            results = graph.search_nodes(args.query, node_type=args.node_type)
            if args.json:
                console.print(json.dumps(results, indent=2))
            else:
                if not results:
                    console.print("[yellow]No graph nodes found[/yellow]")
                else:
                    for r in results:
                        console.print("[cyan]%-20s[/cyan] %s" % (r["type"], r["label"][:60]))
        elif args.graph_command == "stats":
            stats = graph.get_statistics()
            console.print("[bold]Knowledge Graph Statistics[/bold]")
            console.print("  Total nodes: %d" % stats["total_nodes"])
            console.print("  Total edges: %d" % stats["total_edges"])
            console.print("  Nodes by type: %s" % stats["nodes_by_type"])
            console.print("  Edges by relationship: %s" % stats["edges_by_relationship"])

    elif cmd == "feedback":
        feedback = PayloadFeedbackLoop()
        summary = feedback.get_summary()
        if args.json:
            console.print(json.dumps(summary, indent=2))
        else:
            console.print("[bold]Payload Feedback Statistics[/bold]")
            console.print("  Total records:     %d" % summary["total"])
            console.print("  Success rate:      %.1f%%" % (summary.get("success_rate", 0) * 100))
            console.print("  Detection rate:    %.1f%%" % (summary.get("detection_rate", 0) * 100))
            console.print("  Block rate:        %.1f%%" % (summary.get("block_rate", 0) * 100))
            console.print("  Unique payloads:   %d" % summary.get("unique_payloads", 0))
            if summary.get("categories"):
                console.print("  Categories tracked: %s" % ", ".join(summary["categories"].keys()))
            top = feedback.get_top_performing(category=args.category)
            if top:
                console.print("\n[bold]Top Performing:[/bold]")
                for t in top[:5]:
                    console.print("  [%-20s] rate=%.1f%% attempts=%d perf=%.3f" % (
                        t["category"], t["success_rate"] * 100, t["attempts"], t["performance_score"]))

    elif cmd == "policy":
        policy = PayloadExecutionPolicy()
        if args.level:
            policy.set_level(PolicyLevel(args.level))
            console.print("[green]Policy set to:[/green] %s" % args.level)
        if args.json:
            console.print(json.dumps(policy.to_dict(), indent=2))
        else:
            console.print("[bold]Payload Execution Policy:[/bold] %s" % policy.config.level.value)
            console.print("  Max per category: %d" % policy.config.max_payloads_per_category)
            console.print("  Allow dangerous:  %s" % policy.config.allow_dangerous)
            console.print("  Allow high noise: %s" % policy.config.allow_high_noise)
            console.print("  Max mutations:    %d" % policy.config.max_mutations_per_payload)
            console.print("  Max concurrent:   %d" % policy.config.max_concurrent_payloads)

    elif cmd == "provenance":
        prov = PayloadProvenance()
        if args.query:
            results = prov.search(args.query)
        else:
            stats = prov.get_stats()
            console.print("[bold]Provenance Statistics[/bold]")
            console.print("  Total records:    %d" % stats["total_records"])
            console.print("  With commit hash: %d" % stats["with_commit_hash"])
            console.print("  With checksum:    %d" % stats["with_checksum"])
            return
        if args.json:
            console.print(json.dumps([r.to_dict() for r in results], indent=2))
        else:
            if not results:
                console.print("[yellow]No provenance records found[/yellow]")
            else:
                for r in results[:20]:
                    console.print("  [%-20s] %s hash=%s" % (r.category, r.file_path[:60], r.payload_hash[:12]))

    elif cmd == "top":
        feedback = PayloadFeedbackLoop()
        top = feedback.get_top_performing(category=args.category, top_n=args.limit)
        if args.json:
            console.print(json.dumps(top, indent=2))
        else:
            if not top:
                console.print("[yellow]No top performers yet -- run some payloads first[/yellow]")
            else:
                console.print("[bold]Top %d Performing Payloads[/bold]" % len(top))
                for i, t in enumerate(top, 1):
                    console.print("  %2d. [%-20s] rate=%.1f%% attempts=%d perf=%.3f" % (
                        i, t["category"], t["success_rate"] * 100, t["attempts"], t["performance_score"]))
                    console.print("      payload: %s" % t["payload"][:80])

    else:
        console.print("[yellow]Unknown payload command. Available: sync, index, search, info, stats, "
                      "graph, feedback, policy, provenance, top[/yellow]")


def _handle_agents_command(args):
    from .core.agents.registry import AgentRegistry
    from .core.agents.plugins import (
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
                console.print("  %-25s %s%s[/]  id=%s caps=%d" % (
                    a["name"], state_color, a["state"], a["agent_id"][:8], len(a.get("capabilities", []))))
            console.print("\n[dim]Total: %d agents[/dim]" % len(agents))

    elif cmd == "status":
        agents = registry.list_agents()
        if args.json:
            console.print(_json.dumps(agents, indent=2))
        else:
            console.print("[bold]Agent Status:[/bold]")
            for a in agents:
                state = a.get("state", "unknown")
                status = "[green]OK[/green]" if state in ("idle", "busy") else "[red]DOWN[/red]"
                console.print("  %-25s %s  state=%s  caps=%s" % (
                    a["name"], status, state, ", ".join(a.get("capabilities", []))))

    elif cmd == "enable":
        agent = registry.get(args.agent_id)
        if agent:
            console.print("[green]Agent %s enabled[/green]" % agent.name)
        else:
            console.print("[red]Agent %s not found[/red]" % args.agent_id)

    elif cmd == "disable":
        agent = registry.get(args.agent_id)
        if agent:
            agent.shutdown()
            console.print("[yellow]Agent %s disabled[/yellow]" % agent.name)
        else:
            console.print("[red]Agent %s not found[/red]" % args.agent_id)

    else:
        console.print("[yellow]Unknown agents command. Available: list, status, enable, disable[/yellow]")


def _handle_workflow_command(args):
    from .core.agents.workflow import WorkflowEngine
    import json as _json

    engine = WorkflowEngine()
    cmd = args.workflow_command

    if cmd == "run":
        wf = engine.get(args.workflow_id)
        if wf:
            state = engine.run(args.workflow_id)
            console.print("[green]Workflow %s completed with state: %s[/green]" % (args.workflow_id[:8], state.value))
        else:
            console.print("[red]Workflow %s not found[/red]" % args.workflow_id)

    elif cmd == "inspect":
        wf = engine.get(args.workflow_id)
        if wf:
            console.print(_json.dumps(wf.to_dict(), indent=2))
        else:
            console.print("[red]Workflow %s not found[/red]" % args.workflow_id)

    elif cmd == "graph":
        wf = engine.get(args.workflow_id)
        if wf:
            console.print("[bold]Workflow Dependency Graph:[/bold]")
            for step in wf.steps:
                deps = ", ".join(step.depends_on) if step.depends_on else "(none)"
                console.print("  %s [%s] %s" % (step.id[:8], step.type.value, step.name))
                console.print("    depends_on: %s" % deps)
        else:
            console.print("[red]Workflow %s not found[/red]" % args.workflow_id)

    else:
        console.print("[yellow]Unknown workflow command. Available: run, inspect, graph[/yellow]")


def _handle_reasoning_command(args):
    from .core.reasoning.validator import OutputValidator
    from .core.reasoning.policies import PolicyManager, ReasoningSafetyLevel
    import json as _json

    cmd = args.reasoning_command

    if cmd == "inspect":
        console.print("[yellow]Goal %s -- use hunterx workflow inspect for cached results[/yellow]" % args.goal_id)

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
    from .core.skills.registry import SkillRegistry
    from .core.skills.loader import SkillLoader
    from .core.skills.marketplace import SkillMarketplace
    from .core.skills.telemetry import SkillTelemetry
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
                console.print("  %-35s v%-8s [%-8s] %s" % (s["skill_id"], s["version"], s["risk_level"], s["name"]))
            console.print("\n[dim]Total: %d skills[/dim]" % len(skills))

    elif cmd == "info":
        skill = registry.get(args.skill_id)
        if skill:
            console.print(_json.dumps(skill.metadata.to_dict(), indent=2))
        else:
            console.print("[red]Skill not found: %s[/red]" % args.skill_id)

    elif cmd == "search":
        results = registry.search(args.query)
        if not results:
            console.print("[yellow]No skills matching '%s'[/yellow]" % args.query)
        else:
            console.print("[bold]Skills matching '%s':[/bold]" % args.query)
            for m in results:
                console.print("  %-35s %s" % (m.skill_id, m.name))

    elif cmd == "install":
        marketplace = SkillMarketplace()
        skill_id = marketplace.install(args.path)
        if skill_id:
            console.print("[green]Installed skill: %s[/green]" % skill_id)
        else:
            console.print("[red]Installation failed[/red]")

    elif cmd == "uninstall":
        marketplace = SkillMarketplace()
        if marketplace.uninstall(args.skill_id):
            console.print("[green]Uninstalled skill: %s[/green]" % args.skill_id)
        else:
            console.print("[red]Failed to uninstall: %s[/red]" % args.skill_id)

    elif cmd == "enable":
        if registry.enable(args.skill_id):
            console.print("[green]Enabled skill: %s[/green]" % args.skill_id)
        else:
            console.print("[red]Skill not found: %s[/red]" % args.skill_id)

    elif cmd == "disable":
        registry.disable(args.skill_id)
        console.print("[yellow]Disabled skill: %s[/yellow]" % args.skill_id)

    elif cmd == "verify":
        marketplace = SkillMarketplace()
        result = marketplace.verify(args.skill_id)
        if result.get("verified"):
            console.print("[green]Skill %s verified successfully[/green]" % args.skill_id)
        else:
            console.print("[red]Skill %s verification failed: %s[/red]" % (args.skill_id, result.get("error", "unknown")))

    elif cmd == "doctor":
        if args.skill_id:
            skill = registry.get(args.skill_id)
            if skill:
                console.print("[green]Skill %s is healthy[/green]" % args.skill_id)
                console.print("  Metadata: %s v%s" % (skill.metadata.name, skill.metadata.version))
                console.print("  Capabilities: %s" % [c.value for c in skill.capabilities])
            else:
                console.print("[red]Skill %s not found[/red]" % args.skill_id)
        else:
            health = registry.health()
            console.print("[bold]Skill System Health:[/bold]")
            console.print("  Total skills: %d" % health["total"])
            console.print("  Enabled: %d" % health["enabled"])
            console.print("  Healthy: %d" % health["healthy"])

    elif cmd == "export":
        marketplace = SkillMarketplace()
        output = args.output or "%s.zip" % args.skill_id
        if marketplace.export_package(args.skill_id, output):
            console.print("[green]Exported skill to: %s[/green]" % output)
        else:
            console.print("[red]Export failed for: %s[/red]" % args.skill_id)

    elif cmd == "stats":
        telemetry = SkillTelemetry()
        if args.skill_id:
            stats = telemetry.get_stats(args.skill_id)
        else:
            stats = telemetry.get_summary()
        console.print(_json.dumps(stats, indent=2))

    else:
        console.print("[yellow]Unknown skills command. Available: list, info, search, install, uninstall, "
                      "enable, disable, verify, doctor, export, stats[/yellow]")


def _handle_module_command(args):
    from .core.skills.registry import SkillRegistry
    from .core.skills.loader import SkillLoader
    import json as _json

    registry = SkillRegistry()
    loader = SkillLoader(registry)
    loader.discover_builtin()

    cmd = args.module_command

    if cmd == "list":
        skills = registry.list()
        if args.json:
            console.print(_json.dumps(skills, indent=2))
        else:
            console.print("[bold]Available Scan Modules:[/bold]")
            cats = {}
            for s in skills:
                cat = s.get("category", "uncategorized")
                cats.setdefault(cat, []).append(s)
            for cat in sorted(cats):
                console.print("\n  [cyan]%s:[/cyan]" % cat.upper())
                for s in cats[cat]:
                    console.print("    %-35s v%-8s [%-8s] %s" % (s["skill_id"], s["version"], s["risk_level"], s["name"]))
            console.print("\n[dim]Total: %d modules[/dim]" % len(skills))

    elif cmd == "info":
        loader = SkillLoader()
        module = registry.get(args.module_id)
        if module:
            console.print(_json.dumps(module.metadata.to_dict(), indent=2))
        else:
            console.print("[red]Module not found: %s[/red]" % args.module_id)

    elif cmd == "search":
        results = registry.search(args.query)
        if args.json:
            console.print(_json.dumps([m.skill_id for m in results], indent=2))
        else:
            if not results:
                console.print("[yellow]No modules matching '%s'[/yellow]" % args.query)
            else:
                console.print("[bold]Modules matching '%s':[/bold]" % args.query)
                for m in results:
                    console.print("  %-35s %s [%s]" % (m.skill_id, m.name, m.risk_level.value if hasattr(m.risk_level, "value") else m.risk_level))

    else:
        console.print("[yellow]Unknown module command. Available: list, info, search[/yellow]")


def _handle_report_command(args):
    import json as _json
    from .utils.utils import console

    output_dir = args.output_dir or "reports"

    if args.json:
        report_path = os.path.join(output_dir, "scan_results.json")
        if os.path.exists(report_path):
            with open(report_path) as f:
                data = _json.load(f)
            console.print(_json.dumps(data, indent=2))
        else:
            console.print("[yellow]No report found at %s[/yellow]" % report_path)
        return

    console.print("[bold]HunterX Report Overview[/bold]")
    console.print("  Output directory: %s" % output_dir)

    report_path = os.path.join(output_dir, "scan_results.json")
    if os.path.exists(report_path):
        with open(report_path) as f:
            data = _json.load(f)
        findings = data.get("findings", [])
        console.print("  Findings:         %d" % len(findings))
        if findings:
            by_severity = {}
            for f in findings:
                sev = f.get("severity", "unknown")
                by_severity[sev] = by_severity.get(sev, 0) + 1
            for sev in sorted(by_severity):
                console.print("    %s: %d" % (sev, by_severity[sev]))
    else:
        console.print("  [yellow]No scan results found -- run a scan first[/yellow]")

    console.print("\n[bold]System Information:[/bold]")
    console.print("  Python:   %s" % sys.version.split()[0])
    from . import __version__
    console.print("  HunterX:  v%s" % __version__)


def _handle_doctor_command(args):
    from .core.skills.registry import SkillRegistry
    from .core.skills.loader import SkillLoader
    from .utils.utils import console
    from . import __version__

    console.print("[bold]HunterX System Diagnostics[/bold]")
    console.print("")

    checks = 0
    passed = 0

    checks += 1
    console.print("[%s] Python %s" % ("CHECK", sys.version.split()[0]))
    if sys.version_info >= (3, 11):
        console.print("      [green]OK[/green] -- Python version meets minimum 3.11")
        passed += 1
    else:
        console.print("      [red]FAIL[/red] -- Python >= 3.11 required")

    checks += 1
    console.print("[%s] HunterX v%s" % ("CHECK", __version__))
    passed += 1

    checks += 1
    console.print("[%s] Configuration" % ("CHECK"))
    try:
        cfg_path = args.config if hasattr(args, "config") and args.config else "hunterx.yaml"
        if os.path.exists(cfg_path):
            console.print("      [green]OK[/green] -- Config file: %s" % cfg_path)
        else:
            console.print("      [yellow]WARN[/yellow] -- Config file not found: %s" % cfg_path)
        passed += 1
    except Exception as e:
        console.print("      [red]FAIL[/red] -- %s" % e)

    checks += 1
    console.print("[%s] Payload Directory" % ("CHECK"))
    payload_dir = args.payload_dir if hasattr(args, "payload_dir") and args.payload_dir else "payloads"
    if os.path.exists(payload_dir):
        files = [f for f in os.listdir(payload_dir) if os.path.isfile(os.path.join(payload_dir, f))]
        console.print("      [green]OK[/green] -- %s (%d files)" % (payload_dir, len(files)))
        passed += 1
    else:
        console.print("      [yellow]WARN[/yellow] -- Payload directory not found: %s" % payload_dir)
        passed += 1

    checks += 1
    console.print("[%s] Skills Registry" % ("CHECK"))
    try:
        registry = SkillRegistry()
        loader = SkillLoader(registry)
        loader.discover_builtin()
        skills = registry.list()
        console.print("      [green]OK[/green] -- %d skills loaded" % len(skills))
        passed += 1
    except Exception as e:
        console.print("      [red]FAIL[/red] -- %s" % e)

    checks += 1
    console.print("[%s] Dependency: requests" % ("CHECK"))
    try:
        import requests
        console.print("      [green]OK[/green] -- v%s" % requests.__version__)
        passed += 1
    except ImportError:
        console.print("      [red]FAIL[/red] -- requests not installed")

    checks += 1
    console.print("[%s] Dependency: rich" % ("CHECK"))
    try:
        from importlib.metadata import version as _ver
        console.print("      [green]OK[/green] -- v%s" % _ver("rich"))
        passed += 1
    except ImportError:
        console.print("      [red]FAIL[/red] -- rich not installed")

    checks += 1
    console.print("[%s] Dependency: yaml" % ("CHECK"))
    try:
        import importlib.util
        if importlib.util.find_spec("yaml"):
            console.print("      [green]OK[/green]")
            passed += 1
        else:
            console.print("      [yellow]WARN[/yellow] -- yaml not installed (config presets unavailable)")
    except Exception:
        console.print("      [yellow]WARN[/yellow] -- yaml not installed (config presets unavailable)")

    checks += 1
    console.print("[%s] AI/ML Runtime" % ("CHECK"))
    try:
        from .core.ai.registry import ProviderRegistry
        registry = ProviderRegistry()
        registry.discover()
        providers = registry.list_with_status()
        if providers:
            console.print("      [green]OK[/green] -- %d provider(s)" % len(providers))
            for p in providers:
                console.print("        %s: %s" % (p["name"], "[green]OK[/green]" if p.get("healthy") else "[yellow]not checked[/yellow]"))
        else:
            console.print("      [yellow]INFO[/yellow] -- No AI providers configured")
        passed += 1
    except Exception as e:
        console.print("      [yellow]WARN[/yellow] -- %s" % e)

    console.print("\n[bold]Result:[/bold] %d/%d checks passed" % (passed, checks))


def _handle_config_command(args):
    import json as _json

    if args.show:
        console.print("[bold]HunterX Configuration[/bold]")
        console.print("  Profile:          %s" % getattr(config, "profile", "bounty"))
        console.print("  Threads:          %d" % getattr(config, "threads", 5))
        console.print("  Stealth:          %s" % getattr(config, "stealth", "medium"))
        console.print("  Verify SSL:       %s" % getattr(config, "verify_ssl", True))
        console.print("  Payload dir:      %s" % getattr(config, "payload_dir", "payloads"))
        console.print("  Output dir:       %s" % getattr(config, "output_dir", "reports"))
        console.print("  Plugin dirs:      %s" % getattr(config, "plugin_dirs", "plugins/detectors,plugins/reporters,plugins/hooks"))
        console.print("  Config file:      %s" % args.config)
        if hasattr(config, "oob"):
            console.print("  OOB enabled:      %s" % getattr(config.oob, "enabled", False))
        if hasattr(config, "ai"):
            console.print("  AI enabled:       %s" % getattr(config.ai, "enabled", False))
            console.print("  AI model:         %s" % getattr(config.ai, "model", "llama3.2"))
        if hasattr(config, "auth"):
            console.print("  Auth type:        %s" % getattr(config.auth, "type", "none"))
        return

    cfg_path = args.config
    if not os.path.exists(cfg_path):
        console.print("[yellow]Config file not found: %s[/yellow]" % cfg_path)
        return

    with open(cfg_path) as f:
        content = f.read()

    try:
        import yaml
        data = yaml.safe_load(content)
        console.print("[bold]Configuration (%s):[/bold]" % cfg_path)
        console.print(_json.dumps(data, indent=2, default=str))
    except ImportError:
        console.print(content)


def _handle_update_command(args):
    from .modules.payloads.payload_sync import PayloadSyncManager

    console.print("[bold]HunterX Update[/bold]")
    sections = ["payloads", "modules"]

    if args.payloads or "all" in args.target:
        console.print("\n[cyan]Updating payloads...[/cyan]")
        sm = PayloadSyncManager()
        if args.force:
            import shutil
            if os.path.exists(sm._repo_dir):
                shutil.rmtree(sm._repo_dir)
            success = sm.clone()
        else:
            success = sm.clone() if not os.path.exists(sm._repo_dir) else sm.pull()
        if success:
            console.print("  [green]OK[/green] -- %d payload files" % sm.repo_info.file_count)
        else:
            console.print("  [red]FAIL[/red] -- Payload sync failed")

    if sections:
        console.print("\n[green]Update complete[/green]")


def _run_scan(target_url: str, args):
    from .engines.engine import Engine
    from .reporting.report import Reporter

    if args.config and os.path.exists(args.config):
        load_config_file(args.config)
    config.apply_env_overrides()

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

    if args.oob:
        config.oob.enabled = True
        if args.collaborator:
            config.oob.collaborator_url = args.collaborator

    if args.ai:
        config.ai.enabled = True
        config.ai.model = args.ai_model
        config.ai.endpoint = args.ai_endpoint

    parsed = urllib.parse.urlparse(target_url)
    if not parsed.scheme:
        target_url = "https://" + target_url
        parsed = urllib.parse.urlparse(target_url)
    if not parsed.scheme or not parsed.netloc:
        logger.error("Invalid target: %s", target_url)
        sys.exit(1)
    if parsed.scheme not in ("http", "https"):
        logger.error("Target scheme must be http or https, got: %s", parsed.scheme)
        sys.exit(1)

    config.threads = args.threads
    if args.insecure:
        config.verify_ssl = False

    target_cats = args.category.split(",") if args.category else None
    plugin_dir_list = [d.strip() for d in args.plugin_dirs.split(",") if d.strip()]

    all_payloads = load_payloads(args.payload_dir, target_cats)
    # peek emptiness without materializing all payloads
    try:
        first = next(all_payloads)
        all_payloads = itertools.chain([first], all_payloads)
    except StopIteration:
        all_payloads = iter([])
        if not args.passive_only:
            logger.warning("No payloads for %s, skipping.", target_url)

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
        if engine.results or getattr(engine, "passive_intel", None):
            reporter = Reporter(args.output_dir)
            reporter.save_json(engine.results)

            intel_data = {}
            if hasattr(engine, "baseline") and engine.baseline:
                intel_data = engine.passive_intel.analyze(engine.baseline)

            intelligence_data = {}
            if hasattr(engine, "knowledge_graph") and engine.knowledge_graph:
                intelligence_data["knowledge_graph"] = engine.knowledge_graph.to_dict()
            if hasattr(engine, "attack_paths") and engine.attack_paths:
                intelligence_data["attack_paths"] = engine.attack_paths
            if hasattr(engine, "threat_model") and engine.threat_model:
                intelligence_data["threat_model"] = engine.threat_model
            if hasattr(engine, "risk_scores") and engine.risk_scores:
                intelligence_data["risk_matrix"] = engine.risk_scores
            if hasattr(engine, "mitre_mappings") and engine.mitre_mappings:
                intelligence_data["mitre_mappings"] = engine.mitre_mappings
            if hasattr(engine, "explanations") and engine.explanations:
                intelligence_data["explanations"] = engine.explanations
            if hasattr(engine, "scan_plan") and engine.scan_plan:
                intelligence_data["scan_plan"] = engine.scan_plan
            if hasattr(engine, "purple_rules") and engine.purple_rules:
                intelligence_data["purple_rules"] = engine.purple_rules

            reporter.generate_final_report(
                engine.results,
                engine.inferred_chains,
                target_url,
                intel_data,
                intelligence=intelligence_data if intelligence_data else None,
            )

            if intelligence_data:
                reporter.save_intelligence_json(engine)

            reporter.print_summary(engine.results)

            if engine.inferred_chains:
                console.print("\n[bold red]Potential Attack Chains:[/bold red]")
                for chain in engine.inferred_chains:
                    console.print("- [yellow]%s[/yellow] (%s): %s" % (chain["chain"], chain.get("likelihood", "?"), chain["reason"]))

            if engine.attack_paths:
                console.print("\n[bold cyan]Intelligence Layer:[/bold cyan]")
                console.print("[green]- Attack Paths:[/green] %d" % len(engine.attack_paths))
                if engine.mitre_mappings:
                    console.print("[green]- MITRE Techniques:[/green] %d" % len(engine.mitre_mappings))
                if engine.risk_scores:
                    max_r = max((r.get("risk", {}).get("normalized_score", 0) for r in engine.risk_scores), default=0)
                    console.print("[green]- Max Risk Score:[/green] %.3f" % max_r)
        else:
            console.print("[yellow]No meaningful results.[/yellow]" if not args.dry_run else "[cyan]Dry run complete.[/cyan]")

    except KeyboardInterrupt:
        console.print("[bold red]Interrupted.[/bold red]")
        engine.stop()
        sys.exit(1)


def _detect_bare_target(argv: List[str]) -> List[str]:
    if len(argv) <= 1:
        return argv
    first = argv[1]
    if first.startswith("-") or first in COMMANDS:
        return argv
    return [argv[0], "scan"] + argv[1:]


def _build_scan_parser(subparsers):
    sp = subparsers.add_parser("scan", help="Run a vulnerability scan against a target URL")
    sp.add_argument("target", help="Target URL or domain (e.g. https://example.com)")
    sp.add_argument("-p", "--payload-dir", default="payloads", help="Payload file directory")
    sp.add_argument("-o", "--output-dir", default="reports", help="Scan report output directory")
    sp.add_argument("-c", "--config", default="hunterx.yaml", help="YAML configuration file path")
    sp.add_argument("--profile", choices=["internal", "bounty", "gov"], default="bounty", help="Operator profile (internal, bounty, gov)")
    sp.add_argument("--preset", choices=["quick", "full", "stealth"], help="Pre-defined scan preset")
    sp.add_argument("--category", help="Comma-separated skill categories to include")
    sp.add_argument("--stealth", choices=["low", "medium", "high"], default="medium", help="Evasion stealth level")
    sp.add_argument("--threads", type=int, default=5, help="Concurrent request threads")
    sp.add_argument("--dry-run", action="store_true", help="Verify scan logic, do not send requests")
    sp.add_argument("--passive-only", action="store_true", help="Reconnaissance stage only, no probing")
    sp.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")
    sp.add_argument("--auth", choices=["none", "basic", "bearer", "cookie", "form"], default="none", help="Authentication method")
    sp.add_argument("--username", help="Username for basic/form authentication")
    sp.add_argument("--password", help="Password for basic/form authentication")
    sp.add_argument("--token", help="Bearer/JWT token for token-based auth")
    sp.add_argument("--cookie-file", help="Path to JSON cookie file")
    sp.add_argument("--login-url", help="Form-based login endpoint URL")
    sp.add_argument("--login-data", help="Form login fields as key=value,key2=value2")
    sp.add_argument("--oob", action="store_true", help="Enable out-of-band (OOB) detection")
    sp.add_argument("--collaborator", help="OOB collaborator callback URL (e.g. Burp Collaborator)")
    sp.add_argument("--ai", action="store_true", help="Enable AI/LLM-powered analysis")
    sp.add_argument("--ai-model", default="llama3.2", help="AI model name (default: llama3.2)")
    sp.add_argument("--ai-endpoint", default="http://localhost:11434", help="AI provider API endpoint")
    sp.add_argument("--no-cluster", action="store_true", help="Disable AI finding clustering")
    sp.add_argument("--visual", choices=["cli", "web", "off"], default="cli", help="Output visualization mode")
    sp.add_argument("--evidence-level", choices=["low", "medium", "high"], default="medium", help="Evidence collection detail level")
    sp.add_argument("--min-confidence", type=float, default=0.0, help="Minimum confidence threshold (0.0-1.0)")
    sp.add_argument("--sarif", action="store_true", help="Generate SARIF 2.1 report")
    sp.add_argument("--graph", action="store_true", help="Build knowledge graph from findings")
    sp.add_argument("--attack-graph", action="store_true", default=True, help="Generate visual attack graph")
    sp.add_argument("--threat-model", action="store_true", help="Generate threat model report")
    sp.add_argument("--risk", action="store_true", help="Run risk scoring analysis")
    sp.add_argument("--purple", action="store_true", help="Generate purple team detection rules")
    sp.add_argument("--explain", action="store_true", default=True, help="Generate AI explanations for findings")
    sp.add_argument("--browser", action="store_true", help="Enable browser-based intelligence")
    sp.add_argument("--risk-profile", choices=["default", "pentest", "bug_bounty", "compliance"], default="default", help="Risk scoring profile")
    sp.add_argument("--memory-db", action="store_true", default=True, help="Enable SQLite adaptive memory")
    sp.add_argument("--plugin-dirs", default="plugins/detectors,plugins/reporters,plugins/hooks", help="Comma-separated plugin directories")


def _configure_logging(verbosity: int):
    level = logging.WARNING
    if verbosity >= 2:
        level = logging.DEBUG
    elif verbosity >= 1:
        level = logging.INFO
    elif verbosity <= -1:
        level = logging.ERROR
    root = logging.getLogger()
    root.setLevel(level)
    for h in root.handlers:
        h.setLevel(level)


def main():
    sys.argv = _detect_bare_target(sys.argv)

    parser = argparse.ArgumentParser(
        prog="hunterx",
        description="AI-Assisted Vulnerability Hunter  |  v6.0.0  |  Apache-2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  hunterx example.com                          Quick scan
  hunterx scan https://target.com --profile bounty  Full scan
  hunterx scan target.com --ai --ai-model llama3.2  AI-assisted scan
  hunterx scan target.com --oob                Out-of-band detection
  hunterx module list                          List modules
  hunterx report                               View reports
  hunterx doctor                               Diagnostics
  hunterx config --show                        Configuration
  hunterx update                               Update payloads
  hunterx api --port 8443                      API server
  hunterx --version                            Show version

Run 'hunterx <command> --help' for detailed subcommand help.
        """,
        add_help=False,
    )

    parser.add_argument("--help", action="help", default=argparse.SUPPRESS, help="Show this help and exit")
    parser.add_argument("--version", action="version", version="HunterX v6.0.0", help="Show version and exit")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Verbose output (-v: INFO, -vv: DEBUG)")
    parser.add_argument("-q", "--quiet", action="count", default=0, help="Silence output (errors only)")

    sub = parser.add_subparsers(dest="command", metavar="")

    _build_scan_parser(sub)

    module_sp = sub.add_parser("module", help="List and search security scan modules")
    module_sub = module_sp.add_subparsers(dest="module_command", metavar="")
    module_sub.add_parser("list", help="List all available scan modules").add_argument("--json", action="store_true", help="Output as JSON")
    module_info = module_sub.add_parser("info", help="Show detailed module information")
    module_info.add_argument("module_id", help="Module identifier")
    module_search = module_sub.add_parser("search", help="Search available modules by keyword")
    module_search.add_argument("query", help="Search term")
    module_search.add_argument("--json", action="store_true", help="Output as JSON")

    report_sp = sub.add_parser("report", help="View scan reports and system overview")
    report_sp.add_argument("-o", "--output-dir", default="reports", help="Scan report directory")
    report_sp.add_argument("--json", action="store_true", help="Output raw JSON to stdout")

    doctor_sp = sub.add_parser("doctor", help="Run system diagnostics and health checks")
    doctor_sp.add_argument("-p", "--payload-dir", default="payloads", help="Payload directory to check")
    doctor_sp.add_argument("-c", "--config", default="hunterx.yaml", help="Configuration file to validate")

    config_sp = sub.add_parser("config", help="View current HunterX configuration")
    config_sp.add_argument("--show", action="store_true", default=True, help="Display configuration (default)")
    config_sp.add_argument("-c", "--config", default="hunterx.yaml", help="Configuration file path")

    update_sp = sub.add_parser("update", help="Update payloads, modules, and components")
    update_sp.add_argument("target", nargs="?", default="all", help="Component to update (default: all)")
    update_sp.add_argument("--force", action="store_true", help="Force full re-download of all components")
    update_sp.add_argument("--release", action="store_true", help="Download release archive instead of git clone")
    update_sp.add_argument("--payloads", action="store_true", dest="payloads", help="Update payload data only")

    api_sp = sub.add_parser("api", help="Start the REST API server")
    api_sp.add_argument("--port", type=int, default=8443, help="API server listening port (default: 8443)")
    api_sp.add_argument("--host", default="0.0.0.0", help="API server bind address (default: 0.0.0.0)")

    payload_sp = sub.add_parser("payload", help="Payload Intelligence Platform management")
    payload_sub = payload_sp.add_subparsers(dest="payload_command", help="Payload management command")
    p_sync = payload_sub.add_parser("sync", help="Download payloads from upstream repository")
    p_sync.add_argument("--force", action="store_true", help="Re-clone instead of incremental pull")
    p_sync.add_argument("--release", action="store_true", help="Download release archive instead of cloning")
    p_index = payload_sub.add_parser("index", help="Build full-text search index from payload files")
    p_index.add_argument("--force", action="store_true", help="Re-index all payloads from scratch")
    p_index.add_argument("--categories", help="Comma-separated list of categories to index")
    p_search = payload_sub.add_parser("search", help="Search indexed payload database")
    p_search.add_argument("query", nargs="?", default="", help="Search query string")
    p_search.add_argument("--category", help="Filter results by category")
    p_search.add_argument("--limit", type=int, default=20, help="Maximum number of results (default: 20)")
    p_search.add_argument("--json", action="store_true", help="Output results as JSON")
    p_info = payload_sub.add_parser("info", help="Show reasoning explanation for a specific payload")
    p_info.add_argument("payload_id", type=int, help="Payload identifier")
    p_info.add_argument("--target", default="http://example.com", help="Target URL for context-aware reasoning")
    payload_sub.add_parser("stats", help="Display payload index statistics")
    p_graph = payload_sub.add_parser("graph", help="Manage payload knowledge graph")
    p_graph_sub = p_graph.add_subparsers(dest="graph_command")
    p_graph_build = p_graph_sub.add_parser("build", help="Build knowledge graph from indexed payloads")
    p_graph_build.add_argument("--max", type=int, default=500, help="Maximum payloads to process (default: 500)")
    p_graph_search = p_graph_sub.add_parser("search", help="Search knowledge graph nodes")
    p_graph_search.add_argument("query", help="Search term")
    p_graph_search.add_argument("--type", dest="node_type", help="Filter by node type")
    p_graph_search.add_argument("--json", action="store_true", help="Output as JSON")
    p_graph_sub.add_parser("stats", help="Show knowledge graph statistics")
    p_feedback = payload_sub.add_parser("feedback", help="Show user feedback statistics for payloads")
    p_feedback.add_argument("--category", help="Filter by category")
    p_feedback.add_argument("--json", action="store_true", help="Output as JSON")
    p_policy = payload_sub.add_parser("policy", help="View or set payload execution safety policy")
    p_policy.add_argument("--level", choices=["safe", "balanced", "aggressive", "research", "paranoid"], help="Set policy level")
    p_policy.add_argument("--json", action="store_true", help="Output as JSON")
    p_prov = payload_sub.add_parser("provenance", help="Query payload provenance history")
    p_prov.add_argument("query", nargs="?", default="", help="Search by path, filename, or hash")
    p_prov.add_argument("--json", action="store_true", help="Output as JSON")
    p_top = payload_sub.add_parser("top", help="Show top-performing payloads by effectiveness")
    p_top.add_argument("--category", help="Filter by payload category")
    p_top.add_argument("--limit", type=int, default=10, help="Number of top payloads to show (default: 10)")
    p_top.add_argument("--json", action="store_true", help="Output as JSON")

    agents_sp = sub.add_parser("agents", help="Manage multi-agent platform agents")
    agents_sub = agents_sp.add_subparsers(dest="agents_command", help="Agent management command")
    agents_list = agents_sub.add_parser("list", help="List all registered agents")
    agents_list.add_argument("--json", action="store_true", help="Output as JSON")
    agents_sub.add_parser("status", help="Show agent health and status").add_argument("--json", action="store_true", help="Output as JSON")
    agents_sub.add_parser("enable", help="Enable a specific agent").add_argument("agent_id", help="Agent identifier")
    agents_sub.add_parser("disable", help="Disable a specific agent").add_argument("agent_id", help="Agent identifier")

    workflow_sp = sub.add_parser("workflow", help="Manage and execute security workflows")
    workflow_sub = workflow_sp.add_subparsers(dest="workflow_command", help="Workflow command")
    workflow_sub.add_parser("run", help="Execute a workflow by ID").add_argument("workflow_id", help="Workflow identifier")
    workflow_sub.add_parser("inspect", help="Inspect workflow configuration").add_argument("workflow_id", help="Workflow identifier")
    workflow_sub.add_parser("graph", help="Visualize workflow dependency DAG").add_argument("workflow_id", help="Workflow identifier")

    reasoning_sp = sub.add_parser("reasoning", help="Interact with the AI reasoning engine")
    reasoning_sub = reasoning_sp.add_subparsers(dest="reasoning_command", help="Reasoning command")
    reasoning_sub.add_parser("inspect", help="Inspect reasoning result for a goal").add_argument("goal_id", help="Goal identifier")
    reasoning_sub.add_parser("validate", help="Validate reasoning output text").add_argument("--output", default="", help="Output text to validate")

    skills_sp = sub.add_parser("skills", help="Manage the Security Skills Framework")
    skills_sub = skills_sp.add_subparsers(dest="skills_command", help="Skills management command")
    skills_sub.add_parser("list", help="List all installed security skills").add_argument("--json", action="store_true", help="Output as JSON")
    skills_sub.add_parser("info", help="Show detailed skill information").add_argument("skill_id", help="Skill identifier")
    skills_sub.add_parser("search", help="Search available skills by keyword").add_argument("query", help="Search term")
    skills_sub.add_parser("install", help="Install a skill package from a path").add_argument("path", help="Path to skill package")
    skills_sub.add_parser("uninstall", help="Remove an installed skill").add_argument("skill_id", help="Skill identifier")
    skills_sub.add_parser("enable", help="Enable a skill by ID").add_argument("skill_id", help="Skill identifier")
    skills_sub.add_parser("disable", help="Disable a skill by ID").add_argument("skill_id", help="Skill identifier")
    skills_sub.add_parser("verify", help="Verify skill integrity and dependencies").add_argument("skill_id", help="Skill identifier")
    skills_doc = skills_sub.add_parser("doctor", help="Run skill system diagnostics")
    skills_doc.add_argument("--skill-id", help="Check a specific skill only")
    skills_export = skills_sub.add_parser("export", help="Export a skill as a distributable package")
    skills_export.add_argument("skill_id", help="Skill identifier")
    skills_export.add_argument("--output", default="", help="Output directory path")
    skills_sub.add_parser("stats", help="Show skill telemetry statistics").add_argument("--skill-id", help="Filter by skill identifier")

    ai_sp = sub.add_parser("ai", help="Manage AI providers and configuration")
    ai_sub = ai_sp.add_subparsers(dest="ai_command", help="AI management command")
    ai_providers_p = ai_sub.add_parser("providers", help="List registered AI providers")
    ai_providers_p.add_argument("--json", action="store_true", help="Output as JSON")
    ai_health_p = ai_sub.add_parser("health", help="Check AI provider connectivity")
    ai_health_p.add_argument("--provider", help="Check a specific provider only")
    ai_health_p.add_argument("--json", action="store_true", help="Output as JSON")
    ai_config_p = ai_sub.add_parser("config", help="View AI configuration settings")
    ai_config_p.add_argument("--json", action="store_true", help="Output as JSON")
    ai_cache_p = ai_sub.add_parser("cache", help="Show AI response cache statistics")
    ai_cache_p.add_argument("--json", action="store_true", help="Output as JSON")
    ai_metrics_p = ai_sub.add_parser("metrics", help="View AI provider usage metrics")
    ai_metrics_p.add_argument("--provider", help="Filter metrics by provider")
    ai_metrics_p.add_argument("--json", action="store_true", help="Output as JSON")
    ai_test_p = ai_sub.add_parser("test", help="Send a test prompt to an AI provider")
    ai_test_p.add_argument("--provider", default="", help="Provider name to test")
    ai_test_p.add_argument("--model", default="", help="Model name to use")
    ai_test_p.add_argument("--prompt", default="Say hello in one word.", help="Test prompt text")
    ai_models_p = ai_sub.add_parser("models", help="List available models for a provider")
    ai_models_p.add_argument("--provider", default="", help="Provider name")
    ai_models_p.add_argument("--json", action="store_true", help="Output as JSON")

    if len(sys.argv) == 1 or (len(sys.argv) == 2 and sys.argv[1] in ("-h", "--help")):
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    _configure_logging(args.verbose - args.quiet)

    console.print(BANNER.format(license=get_copyright_text()))

    try:
        if args.command == "scan":
            _run_scan(args.target, args)
        elif args.command == "module":
            _handle_module_command(args)
        elif args.command == "report":
            _handle_report_command(args)
        elif args.command == "doctor":
            _handle_doctor_command(args)
        elif args.command == "config":
            _handle_config_command(args)
        elif args.command == "update":
            _handle_update_command(args)
        elif args.command == "api":
            try:
                from .api.server import start_api
                start_api(host=args.host, port=args.port)
            except ImportError as e:
                logger.error("Cannot start API server: %s. Install: pip install fastapi uvicorn", e)
                sys.exit(1)
        elif args.command == "payload":
            _handle_payload_command(args)
        elif args.command == "agents":
            _handle_agents_command(args)
        elif args.command == "workflow":
            _handle_workflow_command(args)
        elif args.command == "reasoning":
            _handle_reasoning_command(args)
        elif args.command == "skills":
            _handle_skills_command(args)
        elif args.command == "ai":
            _handle_ai_command(args)
        else:
            console.print("[red]Unknown command: %s[/red]" % args.command)
            console.print("Run [bold]hunterx --help[/bold] for usage")
            sys.exit(1)

    except KeyboardInterrupt:
        console.print("\n[bold red]Interrupted by user.[/bold red]")
        sys.exit(130)
    except Exception as e:
        logger.exception("Unhandled error: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
