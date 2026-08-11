from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from ...utils.utils import logger
from .manager import AIManager
from .models import Message


class LLMAnalyzer:
    def __init__(self, manager: Optional[AIManager] = None):
        self._manager = manager or AIManager()

    def analyze_finding(self, finding: Dict[str, Any], context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self._manager._config.enabled:
            return None

        prompt = f"""You are a security analyst. Analyze this vulnerability finding:

Category: {finding.get('payload_category', 'Unknown')}
Payload: {finding.get('payload', '')}
Diff Score: {finding.get('diff_score', 0)}
Detections: {finding.get('findings', [])}

Target Context: {json.dumps(context, indent=2)}

Respond in JSON format:
{{"classification": "real/false_positive/ambiguous",
"severity": "low/medium/high/critical",
"explanation": "brief analysis",
"next_steps": ["step1", "step2"]}}"""

        try:
            response = self._manager.chat(
                messages=[Message.user(prompt)],
                temperature=0.3,
                max_tokens=1024,
            )
            text = response.content
            json_start = text.find("{")
            json_end = text.rfind("}") + 1
            if json_start >= 0 and json_end > json_start:
                return json.loads(text[json_start:json_end])
        except Exception as e:
            logger.debug(f"LLMAnalyzer: analysis failed: {e}")

        return None

    def batch_analyze(self, findings: List[Dict[str, Any]], context: Dict[str, Any]) -> List[Dict[str, Any]]:
        enriched: List[Dict[str, Any]] = []
        for f in findings:
            llm_result = self.analyze_finding(f, context)
            if llm_result:
                f["llm_analysis"] = llm_result
            enriched.append(f)
        return enriched

    def suggest_remediation(self, finding: Dict[str, Any]) -> Optional[str]:
        if not self._manager._config.enabled:
            return None

        prompt = f"""Suggest a fix for this vulnerability:
Category: {finding.get('payload_category', 'Unknown')}
Detail: {finding.get('findings', '')}
Payload: {finding.get('payload', '')}

Provide a concise remediation recommendation (2-3 sentences)."""

        try:
            response = self._manager.chat(
                messages=[Message.user(prompt)],
                temperature=0.3,
                max_tokens=512,
            )
            return response.content.strip()
        except Exception as e:
            logger.debug(f"LLMAnalyzer: remediation failed: {e}")
            return None

    def set_manager(self, manager: AIManager) -> None:
        self._manager = manager
