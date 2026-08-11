# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
import os
import time
from typing import Any, Dict, List

try:
    from fastapi import FastAPI, HTTPException, BackgroundTasks
    from pydantic import BaseModel
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

from .job_queue import queue
from .models import ScanStatus
from ..engines.engine import Engine
from ..reporting.report import Reporter
from ..utils.utils import logger
from ..core.legal import get_json_metadata

app = None

if HAS_FASTAPI:
    app = FastAPI(title="HunterX API", version="6.0.0")

    class ScanRequest(BaseModel):
        url: str
        profile: str = "bounty"
        threads: int = 5
        stealth: str = "medium"
        passive_only: bool = False
        dry_run: bool = False
        output_dir: str = "reports"
        insecure: bool = False
        # Intelligence layer options
        intel: bool = True
        threat_model: bool = False
        risk: bool = False
        purple: bool = False
        browser: bool = False
        risk_profile: str = "default"

    class ScanResponse(BaseModel):
        job_id: str
        status: str
        message: str

    def _run_scan_async(job_id: str, payloads: list, target_url: str, options: dict):
        try:
            queue.update(job_id, status=ScanStatus.RUNNING, progress=0.0)
            engine = Engine(target_url, payloads, options)
            engine.start()

            results = getattr(engine, "results", [])
            chains = getattr(engine, "inferred_chains", [])

            reporter = Reporter(options.get("output_dir", "reports"))
            reporter.save_json(results)

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

            reporter.generate_final_report(
                results, chains, target_url, {},
                intelligence=intelligence_data if intelligence_data else None,
            )

            if intelligence_data:
                reporter.save_intelligence_json(engine)

            result_payload = {
                "findings": results,
                "chains": chains,
                **intelligence_data,
            }

            queue.update(
                job_id,
                status=ScanStatus.COMPLETED,
                progress=1.0,
                results=result_payload,
                completed_at=time.time(),
            )
        except Exception as e:
            queue.update(job_id, status=ScanStatus.FAILED, error=str(e))

    @app.post("/scan", response_model=ScanResponse)
    async def start_scan(req: ScanRequest, bg: BackgroundTasks):
        from ..cli import load_payloads

        target_cats = None
        payloads = list(load_payloads("payloads", target_cats))

        options = {
            "profile": req.profile,
            "stealth": req.stealth,
            "threads": req.threads,
            "dry_run": req.dry_run,
            "passive_only": req.passive_only,
            "output_dir": req.output_dir,
            "insecure": req.insecure,
            "visual": "off",
            "intel": req.intel,
            "threat_model": req.threat_model,
            "risk": req.risk,
            "purple": req.purple,
            "browser": req.browser,
            "risk_profile": req.risk_profile,
            "attack_graph": True,
            "explain": True,
        }

        job = queue.create(req.url, req.profile, options)
        bg.add_task(_run_scan_async, job.id, payloads, req.url, options)

        return ScanResponse(job_id=job.id, status=job.status.value, message="Scan started")

    @app.get("/scan/{job_id}")
    async def get_scan(job_id: str):
        job = queue.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        return {
            "job_id": job.id,
            "status": job.status.value,
            "target": job.target_url,
            "progress": job.progress,
            "results_count": len(job.results),
            "error": job.error,
        }

    @app.get("/scan/{job_id}/results")
    async def get_results(job_id: str):
        job = queue.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        if job.status != ScanStatus.COMPLETED:
            raise HTTPException(status_code=400, detail="Scan not completed")
        return {"job_id": job.id, "results": job.results}

    @app.get("/health")
    async def health():
        meta = get_json_metadata()
        return {
            "status": "ok",
            "version": "6.0.0",
            "copyright": meta["_metadata"]["copyright"],
            "license": meta["_metadata"]["license"],
            "author": meta["_metadata"]["author"],
        }

    @app.get("/info")
    async def info():
        return get_json_metadata()

    @app.get("/scan/{job_id}/intelligence")
    async def get_intelligence(job_id: str):
        job = queue.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        if job.status != ScanStatus.COMPLETED:
            raise HTTPException(status_code=400, detail="Scan not completed")

        results = job.results or {}
        return {
            "job_id": job_id,
            "knowledge_graph": results.get("knowledge_graph"),
            "attack_paths": results.get("attack_paths"),
            "threat_model": results.get("threat_model"),
            "risk_matrix": results.get("risk_matrix"),
            "mitre_mappings": results.get("mitre_mappings"),
            "explanations": results.get("explanations"),
        }

    @app.get("/scan/{job_id}/graph")
    async def get_graph(job_id: str):
        job = queue.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        if job.status != ScanStatus.COMPLETED:
            raise HTTPException(status_code=400, detail="Scan not completed")

        results = job.results or {}
        return {"job_id": job_id, "knowledge_graph": results.get("knowledge_graph")}

    @app.get("/scan/{job_id}/attack-paths")
    async def get_attack_paths(job_id: str):
        job = queue.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        if job.status != ScanStatus.COMPLETED:
            raise HTTPException(status_code=400, detail="Scan not completed")

        results = job.results or {}
        return {"job_id": job_id, "attack_paths": results.get("attack_paths")}

    @app.get("/scan/{job_id}/risk")
    async def get_risk(job_id: str):
        job = queue.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        if job.status != ScanStatus.COMPLETED:
            raise HTTPException(status_code=400, detail="Scan not completed")

        results = job.results or {}
        return {"job_id": job_id, "risk_matrix": results.get("risk_matrix")}

    @app.get("/scan/{job_id}/mitre")
    async def get_mitre(job_id: str):
        job = queue.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        if job.status != ScanStatus.COMPLETED:
            raise HTTPException(status_code=400, detail="Scan not completed")

        results = job.results or {}
        return {"job_id": job_id, "mitre_mappings": results.get("mitre_mappings")}

    @app.get("/scan/{job_id}/reasoning")
    async def get_reasoning(job_id: str):
        job = queue.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        if job.status != ScanStatus.COMPLETED:
            raise HTTPException(status_code=400, detail="Scan not completed")

        results = job.results or {}
        return {"job_id": job_id, "explanations": results.get("explanations")}

    @app.get("/jobs")
    async def list_jobs():
        jobs = queue.list_all()
        return [
            {"id": j.id, "target": j.target_url, "status": j.status.value, "progress": j.progress}
            for j in jobs
        ]

    # ---- Payload Intelligence Platform API ----

    @app.get("/payload/stats")
    async def payload_stats():
        from ..modules.payloads.payload_index import PayloadIndexer
        indexer = PayloadIndexer()
        return indexer.get_stats()

    @app.get("/payload/categories")
    async def payload_categories():
        from ..modules.payloads.payload_index import PayloadIndexer
        indexer = PayloadIndexer()
        return {"categories": indexer.get_categories()}

    @app.get("/payload/search")
    async def payload_search(q: str = "", category: str = "", limit: int = 20, offset: int = 0):
        from ..modules.payloads.payload_search import PayloadSearchEngine
        engine = PayloadSearchEngine()
        cat = category if category else None
        results = engine.search(q, limit=limit, offset=offset, category_filter=cat)
        return {
            "total": len(results),
            "results": [r.payload.to_dict() for r in results],
        }

    @app.get("/payload/{payload_id}")
    async def payload_info(payload_id: int, target: str = "http://example.com"):
        from ..modules.payloads.payload_index import PayloadIndexer
        from ..modules.payloads.payload_reasoning import PayloadReasoning
        indexer = PayloadIndexer()
        payload = indexer.get_by_id(payload_id)
        if not payload:
            raise HTTPException(status_code=404, detail="Payload not found")
        reasoner = PayloadReasoning()
        explanation = reasoner.explain(payload, {"target": target})
        return {
            "payload": payload.to_dict(),
            "reasoning": explanation.to_dict(),
        }

    @app.post("/payload/sync")
    async def payload_sync(force: bool = False, use_release: bool = False):
        from ..modules.payloads.payload_sync import PayloadSyncManager
        sm = PayloadSyncManager()
        if use_release:
            success = sm.download_release()
        else:
            if force and os.path.exists(sm._repo_dir):
                import shutil
                shutil.rmtree(sm._repo_dir)
            success = sm.clone() if not os.path.exists(sm._repo_dir) else sm.pull()
        return {"success": success, "status": sm.status()}

    @app.post("/payload/index")
    async def payload_index(force: bool = False, categories: str = ""):
        from ..modules.payloads.payload_index import PayloadIndexer
        indexer = PayloadIndexer()
        if categories:
            cats = [c.strip() for c in categories.split(",")]
            stats = indexer.index_categories(cats, force=force)
        else:
            stats = indexer.index_all(force=force)
        return stats

    @app.get("/payload/policy")
    async def payload_policy_get():
        from ..modules.payloads.payload_policy import PayloadExecutionPolicy
        policy = PayloadExecutionPolicy()
        return policy.to_dict()

    @app.put("/payload/policy")
    async def payload_policy_set(level: str = "balanced"):
        from ..modules.payloads.payload_policy import PayloadExecutionPolicy, PolicyLevel
        try:
            pl = PolicyLevel(level)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid policy level: {level}")
        policy = PayloadExecutionPolicy(level=pl)
        return policy.to_dict()

    @app.get("/payload/feedback")
    async def payload_feedback(category: str = ""):
        from ..modules.payloads.payload_feedback import PayloadFeedbackLoop
        feedback = PayloadFeedbackLoop()
        cat = category if category else None
        summary = feedback.get_summary()
        top = feedback.get_top_performing(category=cat, top_n=10)
        return {"summary": summary, "top_performing": top}

    @app.get("/payload/graph/stats")
    async def payload_graph_stats():
        from ..modules.payloads.payload_graph import PayloadKnowledgeGraph
        graph = PayloadKnowledgeGraph()
        return graph.get_statistics()

    @app.get("/payload/graph/search")
    async def payload_graph_search(q: str, node_type: str = "", limit: int = 20):
        from ..modules.payloads.payload_graph import PayloadKnowledgeGraph
        graph = PayloadKnowledgeGraph()
        nt = node_type if node_type else None
        results = graph.search_nodes(q, node_type=nt, limit=limit)
        return {"results": results}

    @app.post("/payload/graph/build")
    async def payload_graph_build(max_payloads: int = 500):
        from ..modules.payloads.payload_graph import PayloadKnowledgeGraph
        graph = PayloadKnowledgeGraph()
        stats = graph.build_graph_for_index(max_payloads=max_payloads)
        return stats

    @app.get("/payload/provenance")
    async def payload_provenance(q: str = "", limit: int = 20):
        from ..modules.payloads.payload_provenance import PayloadProvenance
        prov = PayloadProvenance()
        if q:
            results = prov.search(q, limit=limit)
            return {"results": [r.to_dict() for r in results]}
        return prov.get_stats()

    @app.get("/payload/sync/status")
    async def payload_sync_status():
        from ..modules.payloads.payload_sync import PayloadSyncManager
        sm = PayloadSyncManager()
        return sm.status()

    # ---- AI Provider Abstraction Layer API ----

    @app.get("/ai/providers")
    async def ai_providers():
        from ..core.ai.registry import ProviderRegistry
        registry = ProviderRegistry()
        registry.discover()
        return {"providers": registry.list_with_status()}

    @app.get("/ai/health")
    async def ai_health(provider: str = ""):
        from ..core.ai.registry import ProviderRegistry
        registry = ProviderRegistry()
        registry.discover()
        if provider:
            status = registry.health_check(provider)
            return status.to_dict()
        results = registry.health_check_all()
        return {k: v.to_dict() for k, v in results.items()}

    @app.get("/ai/models")
    async def ai_models(provider: str = ""):
        from ..core.ai.manager import AIManager
        manager = AIManager()
        models = manager.list_models(provider=provider)
        return {"models": [m.to_dict() for m in models]}

    @app.get("/ai/metrics")
    async def ai_metrics():
        from ..core.ai.manager import AIManager
        manager = AIManager()
        return manager.get_metrics()

    @app.get("/ai/cache")
    async def ai_cache():
        from ..core.ai.manager import AIManager
        manager = AIManager()
        return manager.get_cache_stats()

    # ---- Multi-Agent System API ----

    @app.get("/agents")
    async def list_agents():
        from ..core.agents.registry import AgentRegistry
        from ..core.agents.plugins import (
            ReconAgent, ThreatModelingAgent, PlanningAgent, PayloadAgent,
            VerificationAgent, RiskAgent, ReportingAgent, PurpleTeamAgent,
            LearningAgent, CoordinatorAgent,
        )
        registry = AgentRegistry()
        for agent_cls in [
            ReconAgent, ThreatModelingAgent, PlanningAgent, PayloadAgent,
            VerificationAgent, RiskAgent, ReportingAgent, PurpleTeamAgent,
            LearningAgent, CoordinatorAgent,
        ]:
            registry.register(agent_cls())
        return {"agents": registry.list_agents()}

    @app.get("/agents/{agent_id}")
    async def get_agent(agent_id: str):
        from ..core.agents.registry import AgentRegistry
        registry = AgentRegistry()
        agent = registry.get(agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        return agent.health()

    @app.get("/workflows")
    async def list_workflows():
        from ..core.agents.workflow import WorkflowEngine
        engine = WorkflowEngine()
        return {"workflows": [w.to_dict() for w in engine.list_workflows()]}

    @app.get("/workflows/{workflow_id}")
    async def get_workflow(workflow_id: str):
        from ..core.agents.workflow import WorkflowEngine
        engine = WorkflowEngine()
        wf = engine.get(workflow_id)
        if not wf:
            raise HTTPException(status_code=404, detail="Workflow not found")
        return wf.to_dict()

    @app.post("/workflows/{workflow_id}/run")
    async def run_workflow(workflow_id: str):
        from ..core.agents.workflow import WorkflowEngine
        engine = WorkflowEngine()
        wf = engine.get(workflow_id)
        if not wf:
            raise HTTPException(status_code=404, detail="Workflow not found")
        state = engine.run(workflow_id)
        return {"workflow_id": workflow_id, "state": state.value}

    @app.get("/tasks")
    async def list_tasks():
        from ..core.agents.scheduler import AgentScheduler
        scheduler = AgentScheduler()
        return {"tasks": [t.to_dict() for t in scheduler.get_queue()]}

    @app.post("/goals")
    async def create_goal(goal_data: Dict[str, Any]):
        from ..core.reasoning.goals import Goal, GoalType, GoalPriority
        goal = Goal.create(
            goal_type=GoalType(goal_data.get("type", "custom")),
            objective=goal_data.get("objective", ""),
            context=goal_data.get("context", {}),
            priority=GoalPriority(goal_data.get("priority", "medium")),
        )
        return goal.to_dict()

    @app.get("/reasoning/{goal_id}")
    async def get_reasoning_by_goal(goal_id: str):
        from ..core.reasoning.engine import ReasoningOrchestrator
        engine = ReasoningOrchestrator()
        result = engine.inspect_reasoning(goal_id)
        if not result:
            raise HTTPException(status_code=404, detail="Reasoning result not found")
        return result.to_dict()

    @app.post("/reasoning/validate")
    async def validate_reasoning(data: Dict[str, Any]):
        from ..core.reasoning.validator import OutputValidator
        from ..core.reasoning.policies import PolicyManager, ReasoningSafetyLevel
        policy = PolicyManager.from_safety_level(ReasoningSafetyLevel.BALANCED)
        result = OutputValidator.validate(data.get("output", ""), policy)
        return {
            "valid": result.valid,
            "confidence": result.confidence,
            "errors": result.errors,
            "warnings": result.warnings,
        }

    @app.get("/events")
    async def list_events(event_type: str = "", limit: int = 50):
        from ..core.agents.events import EventBus, EventType
        bus = EventBus()
        et = EventType(event_type) if event_type else None
        events = bus.get_history(event_type=et, limit=limit)
        return {"events": [e.to_dict() for e in events]}

    @app.get("/state")
    async def get_system_state():
        from ..core.agents.state import StateManager
        mgr = StateManager()
        return mgr.to_dict()

    @app.get("/orchestrator/health")
    async def orchestrator_health():
        from ..core.agents.orchestrator import AgentOrchestrator
        orch = AgentOrchestrator()
        return orch.health()

    # ---- Skills Framework API ----

    @app.get("/skills")
    async def list_skills():
        from ..core.skills.registry import SkillRegistry
        from ..core.skills.loader import SkillLoader
        registry = SkillRegistry()
        loader = SkillLoader(registry)
        loader.discover_builtin()
        return {"skills": registry.list()}

    @app.get("/skills/{skill_id}")
    async def get_skill(skill_id: str):
        from ..core.skills.registry import SkillRegistry
        from ..core.skills.loader import SkillLoader
        registry = SkillRegistry()
        loader = SkillLoader(registry)
        loader.discover_builtin()
        skill = registry.get(skill_id)
        if not skill:
            raise HTTPException(status_code=404, detail="Skill not found")
        return skill.metadata.to_dict()

    @app.get("/skills/search")
    async def search_skills(q: str = ""):
        from ..core.skills.registry import SkillRegistry
        from ..core.skills.loader import SkillLoader
        registry = SkillRegistry()
        loader = SkillLoader(registry)
        loader.discover_builtin()
        results = registry.search(q)
        return {"results": [m.to_dict() for m in results]}

    @app.post("/skills/install")
    async def install_skill(path: str):
        from ..core.skills.marketplace import SkillMarketplace
        marketplace = SkillMarketplace()
        skill_id = marketplace.install(path)
        if not skill_id:
            raise HTTPException(status_code=400, detail="Installation failed")
        return {"skill_id": skill_id, "status": "installed"}

    @app.post("/skills/{skill_id}/enable")
    async def enable_skill(skill_id: str):
        from ..core.skills.registry import SkillRegistry
        registry = SkillRegistry()
        if registry.enable(skill_id):
            return {"skill_id": skill_id, "status": "enabled"}
        raise HTTPException(status_code=404, detail="Skill not found")

    @app.post("/skills/{skill_id}/disable")
    async def disable_skill(skill_id: str):
        from ..core.skills.registry import SkillRegistry
        registry = SkillRegistry()
        registry.disable(skill_id)
        return {"skill_id": skill_id, "status": "disabled"}

    @app.get("/skills/{skill_id}/verify")
    async def verify_skill(skill_id: str):
        from ..core.skills.marketplace import SkillMarketplace
        marketplace = SkillMarketplace()
        return marketplace.verify(skill_id)

    @app.get("/skills/stats")
    async def skills_stats():
        from ..core.skills.telemetry import SkillTelemetry
        telemetry = SkillTelemetry()
        return telemetry.get_summary()

    @app.post("/ai/chat")
    async def ai_chat(messages: List[Dict[str, str]], model: str = "", provider: str = "",
                      temperature: float = 0.7, max_tokens: int = 2048, json_mode: bool = False):
        from ..core.ai.manager import AIManager
        from ..core.ai.models import Message, MessageRole
        msgs = []
        for m in messages:
            try:
                role = MessageRole(m.get("role", "user"))
            except ValueError:
                role = MessageRole.USER
            msgs.append(Message(role=role, content=m.get("content", "")))
        manager = AIManager()
        response = manager.chat(
            messages=msgs, model=model, provider=provider,
            temperature=temperature, max_tokens=max_tokens, json_mode=json_mode,
        )
        return response.to_dict()


def start_api(host: str = "0.0.0.0", port: int = 8443):
    """Start the FastAPI server."""
    if not HAS_FASTAPI:
        logger.error("FastAPI not installed. Run: pip install fastapi uvicorn")
        return
    import uvicorn
    logger.info(f"Starting HunterX API on {host}:{port}")
    uvicorn.run(app, host=host, port=port, log_level="info")
