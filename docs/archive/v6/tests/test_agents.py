from __future__ import annotations

import pytest
from unittest.mock import patch

from core.agents.base import SecurityAgent
from core.agents.registry import AgentRegistry
from core.agents.capabilities import AgentCapability, CapabilityRegistry
from core.agents.events import EventBus, Event, EventType
from core.agents.messaging import MessageBus, AgentMessage, MessageType
from core.agents.state import StateManager, AgentState, WorkflowState
from core.agents.task import AgentTask, TaskStatus, TaskPriority
from core.agents.memory import AgentMemory
from core.agents.context import AgentContext
from core.agents.planner import AgentPlanner
from core.agents.scheduler import AgentScheduler
from core.agents.workflow import WorkflowEngine, Workflow, WorkflowStep, WorkflowStepType
from core.agents.coordinator import AgentCoordinator
from core.agents.orchestrator import AgentOrchestrator
from core.reasoning.goals import Goal, GoalType, GoalPriority
from core.reasoning.formatter import ReasoningResult
from core.reasoning.confidence import ConfidenceLevel


class TestSecurityAgent:
    def test_base_agent_abstract(self):
        with pytest.raises(TypeError):
            SecurityAgent()

    def test_concrete_agent(self):
        class TestAgent(SecurityAgent):
            def _on_execute(self, goal: Goal) -> ReasoningResult:
                return ReasoningResult(
                    goal_id=goal.id, goal_type="test", objective=goal.objective,
                    response="test", confidence=0.9, confidence_level=ConfidenceLevel.HIGH,
                    provider="test", model="test", latency_ms=0, cost=0,
                )

        agent = TestAgent(agent_id="test-id", name="TestAgent", version="2.0")
        assert agent.agent_id == "test-id"
        assert agent.name == "TestAgent"
        assert agent.version == "2.0"
        assert agent.state == AgentState.CREATED


class TestCapabilityRegistry:
    def test_register_and_get(self):
        CapabilityRegistry.clear()
        CapabilityRegistry.register("agent1", [AgentCapability.RECON, AgentCapability.THREAT_MODELING])
        caps = CapabilityRegistry.get_capabilities("agent1")
        assert AgentCapability.RECON in caps
        assert AgentCapability.THREAT_MODELING in caps

    def test_find_by_capability(self):
        CapabilityRegistry.clear()
        CapabilityRegistry.register("a1", [AgentCapability.RECON])
        CapabilityRegistry.register("a2", [AgentCapability.PAYLOAD_SELECTION])
        found = CapabilityRegistry.find_agents_by_capability(AgentCapability.RECON)
        assert "a1" in found
        assert "a2" not in found

    def test_find_by_multiple_capabilities(self):
        CapabilityRegistry.clear()
        CapabilityRegistry.register("a1", [AgentCapability.RECON, AgentCapability.THREAT_MODELING])
        CapabilityRegistry.register("a2", [AgentCapability.RECON])
        found = CapabilityRegistry.find_agents_by_capabilities([AgentCapability.RECON, AgentCapability.THREAT_MODELING])
        assert "a1" in found
        assert "a2" not in found

    def test_unregister(self):
        CapabilityRegistry.clear()
        CapabilityRegistry.register("a1", [AgentCapability.RECON])
        CapabilityRegistry.unregister("a1")
        assert CapabilityRegistry.get_capabilities("a1") == set()


class TestEventBus:
    def test_singleton(self):
        bus1 = EventBus()
        bus2 = EventBus()
        assert bus1 is bus2

    def test_publish_and_subscribe(self):
        bus = EventBus()
        received = []

        def handler(event: Event):
            received.append(event)

        bus.subscribe(EventType.TASK_STARTED, handler)
        bus.publish_event(EventType.TASK_STARTED, "test", {"id": "1"})
        assert len(received) == 1
        assert received[0].type == EventType.TASK_STARTED

    def test_wildcard_subscriber(self):
        bus = EventBus()
        received = []

        def handler(event: Event):
            received.append(event)

        bus.subscribe_all(handler)
        bus.publish_event(EventType.TASK_STARTED, "test")
        bus.publish_event(EventType.GOAL_CREATED, "test")
        assert len(received) == 2

    def test_get_history(self):
        bus = EventBus()
        bus.clear_history()
        bus.publish_event(EventType.TASK_STARTED, "test")
        bus.publish_event(EventType.TASK_FINISHED, "test")
        history = bus.get_history(limit=10)
        assert len(history) == 2

    def test_get_history_filtered(self):
        bus = EventBus()
        bus.clear_history()
        bus.publish_event(EventType.TASK_STARTED, "test")
        bus.publish_event(EventType.TASK_FINISHED, "test")
        history = bus.get_history(event_type=EventType.TASK_STARTED)
        assert len(history) == 1
        assert history[0].type == EventType.TASK_STARTED


class TestMessageBus:
    def test_singleton(self):
        mb1 = MessageBus()
        mb2 = MessageBus()
        assert mb1 is mb2

    def test_send_and_receive(self):
        bus = MessageBus()
        received = []

        def handler(msg: AgentMessage):
            received.append(msg)

        bus.register("agent1", handler)
        bus.send_message("sender", "agent1", {"data": "hello"}, MessageType.REQUEST)
        assert len(received) == 1
        assert received[0].payload["data"] == "hello"

    def test_broadcast(self):
        bus = MessageBus()
        received = []

        def handler(msg: AgentMessage):
            received.append(msg)

        bus.subscribe_broadcast(handler)
        msg = AgentMessage(id="1", type=MessageType.REQUEST, sender="s", recipient="*", payload={})
        bus.broadcast(msg)
        assert len(received) == 1


class TestStateManager:
    def test_set_and_get_state(self):
        mgr = StateManager()
        mgr.set_state("agent1", AgentState.IDLE)
        assert mgr.get_state("agent1") == AgentState.IDLE

    def test_get_history(self):
        mgr = StateManager()
        mgr.set_state("agent1", AgentState.CREATED)
        mgr.set_state("agent1", AgentState.INITIALIZING)
        mgr.set_state("agent1", AgentState.IDLE)
        history = mgr.get_history("agent1")
        assert len(history) == 3
        assert history[-1].state == AgentState.IDLE

    def test_checkpoint(self):
        mgr = StateManager()
        cp = mgr.save_checkpoint("agent1", {"results": ["a", "b"]})
        assert cp is not None
        data = mgr.load_checkpoint(cp)
        assert data == {"results": ["a", "b"]}

    def test_get_all_states(self):
        mgr = StateManager()
        mgr.set_state("a1", AgentState.IDLE)
        mgr.set_state("a2", AgentState.BUSY)
        states = mgr.get_all_states()
        assert states["a1"] == "idle"
        assert states["a2"] == "busy"


class TestAgentTask:
    def test_create(self):
        goal = Goal.create(GoalType.RECON, "test")
        task = AgentTask.create(agent_id="agent1", goal=goal, priority=TaskPriority.HIGH)
        assert task.agent_id == "agent1"
        assert task.goal.id == goal.id
        assert task.priority == TaskPriority.HIGH
        assert task.status == TaskStatus.PENDING

    def test_to_dict(self):
        goal = Goal.create(GoalType.RECON, "test")
        task = AgentTask.create(agent_id="agent1", goal=goal)
        d = task.to_dict()
        assert d["agent_id"] == "agent1"
        assert d["priority"] == str(TaskPriority.MEDIUM.value)
        assert d["status"] == "pending"


class TestAgentMemory:
    def test_store_and_retrieve(self):
        mem = AgentMemory()
        mem.store("agent1", "key1", {"value": 42})
        assert mem.retrieve("agent1", "key1") == {"value": 42}

    def test_retrieve_missing(self):
        mem = AgentMemory()
        assert mem.retrieve("agent1", "nonexistent") is None

    def test_search(self):
        mem = AgentMemory()
        mem.store("agent1", "sql_finding", {"type": "SQL injection"})
        mem.store("agent1", "xss_finding", {"type": "XSS"})
        results = mem.search("agent1", "SQL")
        assert len(results) == 1
        assert results[0].key == "sql_finding"

    def test_forget(self):
        mem = AgentMemory()
        mem.store("agent1", "key1", "value1")
        assert mem.forget("agent1", "key1") is True
        assert mem.retrieve("agent1", "key1") is None

    def test_clear_agent(self):
        mem = AgentMemory()
        mem.store("agent1", "k1", "v1")
        mem.store("agent2", "k2", "v2")
        mem.clear_agent("agent1")
        assert mem.retrieve("agent1", "k1") is None
        assert mem.retrieve("agent2", "k2") == "v2"

    def test_get_stats(self):
        mem = AgentMemory()
        mem.store("agent1", "k1", "v1")
        stats = mem.get_stats()
        assert stats["total_entries"] == 1


class TestAgentContext:
    def test_defaults(self):
        ctx = AgentContext()
        assert ctx.target_url == ""
        assert ctx.findings == []
        assert ctx.technologies == []

    def test_to_dict(self):
        ctx = AgentContext(target_url="http://example.com", technologies=["Python", "Django"])
        d = ctx.to_dict()
        assert d["target_url"] == "http://example.com"
        assert d["technologies"] == ["Python", "Django"]


class TestAgentRegistry:
    def test_singleton(self):
        r1 = AgentRegistry()
        r2 = AgentRegistry()
        assert r1 is r2

    def test_register_and_get(self):
        from core.agents.plugins import ReconAgent
        registry = AgentRegistry()
        agent = ReconAgent(agent_id="test-recon")
        registry.register(agent)
        retrieved = registry.get("test-recon")
        assert retrieved is not None
        assert retrieved.name == "ReconAgent"
        registry.unregister("test-recon")

    def test_list_agents(self):
        from core.agents.plugins import ReconAgent, PayloadAgent
        registry = AgentRegistry()
        registry.register(ReconAgent(agent_id="r1"))
        registry.register(PayloadAgent(agent_id="p1"))
        agents = registry.list_agents()
        assert len(agents) >= 2
        registry.unregister("r1")
        registry.unregister("p1")

    def test_find_by_capability(self):
        from core.agents.plugins import ReconAgent
        registry = AgentRegistry()
        agent = ReconAgent(agent_id="recon-1")
        registry.register(agent)
        found = registry.find_by_capability(AgentCapability.RECON)
        assert len(found) >= 1
        registry.unregister("recon-1")


class TestAgentPlanner:
    def test_create_plan(self):
        from core.agents.plugins import ReconAgent
        registry = AgentRegistry()
        agent = ReconAgent(agent_id="planner-recon")
        registry.register(agent)
        planner = AgentPlanner(registry)
        goals = [Goal.create(GoalType.RECON, "scan target")]
        plan = planner.create_plan(goals)
        assert plan.total_tasks == 1
        assert plan.tasks[0].agent_id == agent.agent_id
        registry.unregister("planner-recon")


class TestAgentScheduler:
    def test_schedule_and_queue(self):
        scheduler = AgentScheduler()
        goal = Goal.create(GoalType.RECON, "test")
        task = AgentTask.create(agent_id="agent1", goal=goal)
        scheduler.schedule(task)
        queue = scheduler.get_queue()
        assert len(queue) == 1
        assert queue[0].id == task.id

    def test_cancel_task(self):
        scheduler = AgentScheduler()
        goal = Goal.create(GoalType.RECON, "test")
        task = AgentTask.create(agent_id="agent1", goal=goal)
        scheduler.schedule(task)
        assert scheduler.cancel(task.id) is True
        assert len(scheduler.get_queue()) == 0


class TestWorkflowEngine:
    def test_register_and_get(self):
        engine = WorkflowEngine()
        wf = Workflow(id="wf1", name="test-workflow")
        engine.register(wf)
        assert engine.get("wf1") is not None

    def test_run_workflow(self):
        engine = WorkflowEngine()
        step = WorkflowStep(id="step1", type=WorkflowStepType.WAIT, name="wait", wait_seconds=0.01)
        wf = Workflow(id="wf2", name="test", steps=[step])
        engine.register(wf)
        state = engine.run("wf2")
        assert state == WorkflowState.COMPLETED

    def test_cancel_workflow(self):
        engine = WorkflowEngine()
        wf = Workflow(id="wf3", name="test")
        engine.register(wf)
        assert engine.cancel("wf3") is True
        assert engine.get("wf3").state == WorkflowState.CANCELLED

    def test_list_workflows(self):
        engine = WorkflowEngine()
        engine.register(Workflow(id="wf4", name="a"))
        engine.register(Workflow(id="wf5", name="b"))
        assert len(engine.list_workflows()) >= 2


class TestAgentCoordinator:
    def test_route_goal_no_agents(self):
        coordinator = AgentCoordinator()
        goal = Goal.create(GoalType.RECON, "test")
        result = coordinator._route_goal(goal)
        assert result is not None
        assert "No capable agents" in result.response

    def test_coordinate_goals(self):
        coordinator = AgentCoordinator()
        goals = [Goal.create(GoalType.RECON, "test")]
        results = coordinator.coordinate_goals(goals)
        assert len(results) == 1


class TestAgentOrchestrator:
    def test_initial_state(self):
        orch = AgentOrchestrator()
        health = orch.health()
        assert health["orchestrator"] == "running"
        assert health["agents"] >= 0

    def test_create_goal(self):
        orch = AgentOrchestrator()
        goal = orch.create_goal("test objective", {"goal_type": "recon"}, GoalPriority.HIGH)
        assert goal.objective == "test objective"
        assert goal.priority == GoalPriority.HIGH

    def test_submit_goal(self):
        orch = AgentOrchestrator()
        goal = orch.create_goal("test")
        with pytest.raises(Exception):
            orch.submit_goal(goal)

    def test_get_results(self):
        orch = AgentOrchestrator()
        assert orch.get_results() == {}

    def test_get_agent_memory(self):
        orch = AgentOrchestrator()
        assert orch.get_agent_memory() is not None


class TestDefaultAgents:
    @pytest.fixture
    def mock_reasoning(self):
        with patch("core.agents.base.SecurityAgent._reason") as mock:
            mock.return_value = ReasoningResult(
                goal_id="test", goal_type="recon", objective="test",
                response="test response", confidence=0.9,
                confidence_level=ConfidenceLevel.HIGH,
                provider="test", model="test", latency_ms=100, cost=0,
            )
            yield mock

    def test_recon_agent(self):
        from core.agents.plugins import ReconAgent
        agent = ReconAgent()
        assert AgentCapability.RECON in agent.capabilities
        assert agent.supports_parallel() is True

    def test_threat_modeling_agent(self):
        from core.agents.plugins import ThreatModelingAgent
        agent = ThreatModelingAgent()
        assert AgentCapability.THREAT_MODELING in agent.capabilities

    def test_planning_agent(self):
        from core.agents.plugins import PlanningAgent
        agent = PlanningAgent()
        assert AgentCapability.PLANNING in agent.capabilities

    def test_payload_agent(self):
        from core.agents.plugins import PayloadAgent
        agent = PayloadAgent()
        assert AgentCapability.PAYLOAD_SELECTION in agent.capabilities
        assert agent.supports_parallel() is True

    def test_verification_agent(self):
        from core.agents.plugins import VerificationAgent
        agent = VerificationAgent()
        assert AgentCapability.VERIFICATION in agent.capabilities

    def test_risk_agent(self):
        from core.agents.plugins import RiskAgent
        agent = RiskAgent()
        assert AgentCapability.RISK_ANALYSIS in agent.capabilities

    def test_reporting_agent(self):
        from core.agents.plugins import ReportingAgent
        agent = ReportingAgent()
        assert AgentCapability.REPORTING in agent.capabilities

    def test_purple_team_agent(self):
        from core.agents.plugins import PurpleTeamAgent
        agent = PurpleTeamAgent()
        assert AgentCapability.PURPLE_TEAM in agent.capabilities

    def test_learning_agent(self):
        from core.agents.plugins import LearningAgent
        agent = LearningAgent()
        assert AgentCapability.LEARNING in agent.capabilities

    def test_coordinator_agent(self):
        from core.agents.plugins import CoordinatorAgent
        agent = CoordinatorAgent()
        assert AgentCapability.COORDINATION in agent.capabilities

    def test_agent_create_goals(self, mock_reasoning):
        from core.agents.plugins import ReconAgent
        agent = ReconAgent()
        goals = agent.create_goals("test target", {"url": "http://example.com"})
        assert len(goals) >= 1
        assert goals[0].type == GoalType.RECON

    def test_agent_health(self, mock_reasoning):
        from core.agents.plugins import ReconAgent
        agent = ReconAgent()
        health = agent.health()
        assert health["name"] == "ReconAgent"
        assert health["state"] == "created"

    def test_agent_accepts_goal(self, mock_reasoning):
        from core.agents.plugins import ReconAgent
        agent = ReconAgent()
        goal = Goal.create(GoalType.RECON, "test")
        assert agent.accepts(goal) is True
        goal2 = Goal.create(GoalType.PAYLOAD_SELECTION, "test")
        assert agent.accepts(goal2) is False
