from __future__ import annotations

from typing import Any, Dict, List, Optional

from .metadata import RiskLevel, SkillMetadata
from .policy import SkillPolicy
from .result import SkillResult, SkillStatus


class SkillValidator:
    @staticmethod
    def validate_target(target: str) -> Optional[str]:
        if not target:
            return "Target is required"
        if len(target) < 2:
            return "Target too short"
        if len(target) > 8192:
            return "Target exceeds maximum length"
        return None

    @staticmethod
    def validate_policy(skill_metadata: SkillMetadata, policy: SkillPolicy) -> List[str]:
        warnings: List[str] = []
        if skill_metadata.risk_level == RiskLevel.CRITICAL and not policy.allow_destructive:
            warnings.append("Skill risk level is CRITICAL but policy does not allow destructive operations")
        if skill_metadata.risk_level == RiskLevel.HIGH and not policy.allow_intrusive:
            warnings.append("Skill risk level is HIGH but policy does not allow intrusive operations")
        return warnings

    @staticmethod
    def validate_result(result: SkillResult, min_confidence: float = 0.0) -> bool:
        if result.status != SkillStatus.COMPLETED:
            return False
        if result.confidence < min_confidence:
            return False
        return True

    @staticmethod
    def validate_evidence(result: SkillResult) -> List[str]:
        issues: List[str] = []
        if not result.evidence and result.confidence > 0.5:
            issues.append("High confidence but no evidence provided")
        for ev in result.evidence:
            if "source" not in ev:
                issues.append("Evidence missing 'source' field")
        return issues

    @staticmethod
    def validate_safety(result: SkillResult, policy: SkillPolicy) -> List[str]:
        issues: List[str] = []
        if result.risk_score > 0.8 and not policy.allow_destructive:
            issues.append("Result risk score exceeds policy limit")
        if result.noise_score > 0.8 and policy.safety_level.value == "safe":
            issues.append("Result noise score exceeds safe policy limit")
        return issues

    @staticmethod
    def validate_schema(data: Dict[str, Any], schema: Dict[str, Any]) -> List[str]:
        errors: List[str] = []
        required = schema.get("required", [])
        for field_name in required:
            if field_name not in data:
                errors.append(f"Missing required field: {field_name}")
        properties = schema.get("properties", {})
        for field_name, field_value in data.items():
            if field_name in properties:
                expected_type = properties[field_name].get("type")
                if expected_type == "string" and not isinstance(field_value, str):
                    errors.append(f"Field '{field_name}' should be a string")
                elif expected_type == "number" and not isinstance(field_value, (int, float)):
                    errors.append(f"Field '{field_name}' should be a number")
                elif expected_type == "boolean" and not isinstance(field_value, bool):
                    errors.append(f"Field '{field_name}' should be a boolean")
        return errors
