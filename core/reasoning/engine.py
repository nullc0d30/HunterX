from __future__ import annotations

import json
import time
from typing import Dict, List, Optional

from ..ai.manager import AIManager
from ..ai.models import Message
from ..utils import logger

from .confidence import ConfidenceLevel, ConfidenceScorer
from .consensus import ConsensusEngine, ConsensusMethod, IndividualResponse
from .formatter import ReasoningResult
from .goals import Goal, GoalStatus
from .memory import ReasoningMemory
from .planner import ReasoningPlan, ReasoningPlanner
from .policies import PolicyManager, ReasoningPolicy, ReasoningSafetyLevel
from .prompts import ReasoningPromptManager
from .validator import OutputValidator, ValidationResult


class ReasoningOrchestrator:
    def __init__(
        self,
        ai_manager: Optional[AIManager] = None,
        policy: Optional[ReasoningPolicy] = None,
        memory: Optional[ReasoningMemory] = None,
        consensus: Optional[ConsensusEngine] = None,
        planner: Optional[ReasoningPlanner] = None,
    ):
        self._ai_manager = ai_manager or AIManager()
        self._policy = policy or PolicyManager.from_safety_level(ReasoningSafetyLevel.BALANCED)
        self._memory = memory or ReasoningMemory()
        self._consensus = consensus or ConsensusEngine()
        self._planner = planner or ReasoningPlanner()
        self._confidence = ConfidenceScorer()

    @property
    def policy(self) -> ReasoningPolicy:
        return self._policy

    @policy.setter
    def policy(self, policy: ReasoningPolicy) -> None:
        self._policy = policy

    def reason(
        self,
        goal: Goal,
        provider: str = "",
        model: str = "",
        profile: str = "",
    ) -> ReasoningResult:
        goal.status = GoalStatus.PROCESSING
        start_time = time.monotonic()

        try:
            prompt = self._build_prompt(goal)
            messages = [
                Message.system(prompt["system"]),
                Message.user(prompt["user"]),
            ]

            response = self._ai_manager.chat(
                messages=messages,
                provider=provider,
                model=model,
                profile=profile,
                temperature=0.3,
                max_tokens=4096,
            )

            latency_ms = (time.monotonic() - start_time) * 1000

            validation = self._validate_output(response.content)

            normalized = None
            if validation.normalized_output:
                normalized = validation.normalized_output
            elif response.content:
                try:
                    parsed = json.loads(response.content)
                    if isinstance(parsed, dict):
                        normalized = parsed
                    else:
                        normalized = {"data": parsed}
                except (json.JSONDecodeError, ValueError):
                    normalized = {"text": response.content}

            confidence = min(response.usage.total_tokens / 4096 if response.usage else validation.confidence, validation.confidence)
            confidence = max(confidence, 0.1)

            result = ReasoningResult(
                goal_id=goal.id,
                goal_type=goal.type.value,
                objective=goal.objective,
                response=response.content,
                confidence=confidence,
                confidence_level=self._confidence.score_to_level(confidence),
                provider=response.provider,
                model=response.model,
                latency_ms=latency_ms,
                cost=response.usage.total_tokens * 0.000002 if response.usage else 0.0,
                normalized_output=normalized,
                validation_errors=validation.errors,
                validation_warnings=validation.warnings,
                created_at=start_time,
            )

            if validation.valid or not self._policy.validate_output:
                goal.status = GoalStatus.COMPLETED
            else:
                goal.status = GoalStatus.FAILED
                logger.warning(f"Reasoning validation failed for goal {goal.id}: {validation.errors}")

            goal.completed_at = start_time

            if self._policy.cache_results:
                self._memory.store(result)

            return result

        except Exception as e:
            goal.status = GoalStatus.FAILED
            latency_ms = (time.monotonic() - start_time) * 1000
            logger.error(f"Reasoning failed for goal {goal.id}: {e}")
            return ReasoningResult(
                goal_id=goal.id,
                goal_type=goal.type.value,
                objective=goal.objective,
                response=str(e),
                confidence=0.0,
                confidence_level=ConfidenceLevel.INSUFFICIENT_DATA,
                provider="",
                model="",
                latency_ms=latency_ms,
                cost=0.0,
                validation_errors=[str(e)],
            )

    def reason_with_consensus(
        self,
        goal: Goal,
        providers: List[str],
        method: ConsensusMethod = ConsensusMethod.CONFIDENCE_AGGREGATION,
    ) -> ReasoningResult:
        goal.status = GoalStatus.PROCESSING
        start_time = time.monotonic()

        prompt = self._build_prompt(goal)
        messages = [
            Message.system(prompt["system"]),
            Message.user(prompt["user"]),
        ]

        individual_responses: List[IndividualResponse] = []
        for provider in providers:
            try:
                pstart = time.monotonic()
                response = self._ai_manager.chat(
                    messages=messages,
                    provider=provider,
                    temperature=0.3,
                    max_tokens=4096,
                )
                platency = (time.monotonic() - pstart) * 1000
                validation = self._validate_output(response.content)
                ind_conf = validation.confidence
                individual_responses.append(IndividualResponse(
                    provider=response.provider,
                    model=response.model,
                    content=response.content,
                    confidence=ind_conf,
                    latency_ms=platency,
                ))
            except Exception as e:
                logger.warning(f"Consensus provider {provider} failed: {e}")

        if not individual_responses:
            goal.status = GoalStatus.FAILED
            goal.completed_at = start_time
            return ReasoningResult(
                goal_id=goal.id,
                goal_type=goal.type.value,
                objective=goal.objective,
                response="All consensus providers failed",
                confidence=0.0,
                confidence_level=ConfidenceLevel.INSUFFICIENT_DATA,
                provider="",
                model="",
                latency_ms=(time.monotonic() - start_time) * 1000,
                cost=0.0,
                validation_errors=["All consensus providers failed"],
            )

        consensus = self._consensus.reach_consensus(individual_responses, method=method)
        total_latency = (time.monotonic() - start_time) * 1000

        validation = self._validate_output(consensus.final_response)

        result = ReasoningResult(
            goal_id=goal.id,
            goal_type=goal.type.value,
            objective=goal.objective,
            response=consensus.final_response,
            confidence=consensus.agreement,
            confidence_level=consensus.agreement_level,
            provider=", ".join(r.provider for r in individual_responses),
            model=individual_responses[0].model if individual_responses else "",
            latency_ms=total_latency,
            cost=0.0,
            normalized_output=validation.normalized_output,
            consensus=consensus,
            validation_errors=validation.errors,
            validation_warnings=validation.warnings,
        )

        if validation.valid or not self._policy.validate_output:
            goal.status = GoalStatus.COMPLETED
        else:
            goal.status = GoalStatus.FAILED
        goal.completed_at = start_time

        if self._policy.cache_results:
            self._memory.store(result)

        return result

    def reason_batch(
        self,
        goals: List[Goal],
        provider: str = "",
        model: str = "",
    ) -> List[ReasoningResult]:
        results: List[ReasoningResult] = []
        ordered = self._planner.prioritize_goals(goals)
        for goal in ordered:
            result = self.reason(goal, provider=provider, model=model)
            results.append(result)
        return results

    def reason_plan(
        self,
        plan: ReasoningPlan,
        provider: str = "",
        model: str = "",
    ) -> List[ReasoningResult]:
        return self.reason_batch(plan.goals, provider=provider, model=model)

    def get_memory(self) -> ReasoningMemory:
        return self._memory

    def get_planner(self) -> ReasoningPlanner:
        return self._planner

    def inspect_reasoning(self, goal_id: str) -> Optional[ReasoningResult]:
        entry = self._memory.retrieve(goal_id)
        if entry:
            return ReasoningResult(
                goal_id=entry.goal_id,
                goal_type=entry.goal_type,
                objective=entry.objective,
                response=entry.response,
                confidence=entry.confidence,
                confidence_level=self._confidence.score_to_level(entry.confidence),
                provider=entry.provider,
                model=entry.model,
                latency_ms=0,
                cost=0,
            )
        return None

    def _build_prompt(self, goal: Goal) -> Dict[str, str]:
        template = ReasoningPromptManager.get(goal.type.value)
        if template:
            try:
                context_for_format = {}
                for key in template.variables:
                    if key in goal.context:
                        context_for_format[key] = goal.context[key]
                    else:
                        context_for_format[key] = str(goal.context.get(key, ""))
                return template.format(**context_for_format)
            except (KeyError, ValueError) as e:
                logger.debug(f"Template format failed for {goal.type.value}, using generic: {e}")

        return {
            "system": "You are a security analysis expert. Analyze the given context and provide structured reasoning.",
            "user": f"Objective: {goal.objective}\n\nContext: {json.dumps(goal.context, indent=2)}\n\nExpected Output: {goal.expected_output}",
        }

    def _validate_output(self, output: str) -> ValidationResult:
        return OutputValidator.validate(output, self._policy)

    def set_ai_manager(self, manager: AIManager) -> None:
        self._ai_manager = manager
