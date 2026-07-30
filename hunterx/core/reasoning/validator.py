from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .policies import ReasoningPolicy


@dataclass
class ValidationResult:
    valid: bool
    confidence: float = 0.0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    normalized_output: Optional[Dict[str, Any]] = None


class OutputValidator:
    HALLUCINATION_PATTERNS = [
        "i don't have access",
        "as an ai",
        "i cannot",
        "i am an ai",
        "i'm an ai",
        "i am not able",
        "i'm not able",
        "unable to provide",
        "cannot provide",
        "i apologize",
        "i'm sorry",
        "as a language model",
        "as an assistant",
        "safety guidelines",
        "ethical guidelines",
        "i cannot help",
        "cannot assist",
    ]

    @classmethod
    def validate(
        cls,
        output: str,
        policy: ReasoningPolicy,
        expected_schema: Optional[Dict[str, Any]] = None,
    ) -> ValidationResult:
        errors: List[str] = []
        warnings: List[str] = []

        output_lower = output.lower().strip()

        for pattern in cls.HALLUCINATION_PATTERNS:
            if pattern in output_lower:
                warnings.append(f"Possible hallucination indicator: '{pattern}' found")

        if len(output) < 10:
            errors.append("Output too short (< 10 characters)")

        if expected_schema:
            schema_errors = cls._validate_json_schema(output, expected_schema)
            errors.extend(schema_errors)

        confidence = cls._estimate_confidence(output, errors, warnings)

        normalized = None
        if not errors:
            try:
                parsed = json.loads(output)
                if isinstance(parsed, dict):
                    normalized = parsed
            except (json.JSONDecodeError, ValueError):
                normalized = {"text": output}

        return ValidationResult(
            valid=len(errors) == 0 and confidence >= policy.min_confidence,
            confidence=confidence,
            errors=errors,
            warnings=warnings,
            normalized_output=normalized,
        )

    @classmethod
    def _validate_json_schema(cls, output: str, schema: Dict[str, Any]) -> List[str]:
        errors: List[str] = []
        try:
            data = json.loads(output)
            if not isinstance(data, dict):
                errors.append("Output is not a JSON object")
                return errors
            required = schema.get("required", [])
            for field_name in required:
                if field_name not in data:
                    errors.append(f"Missing required field: {field_name}")
            properties = schema.get("properties", {})
            for field_name, field_value in data.items():
                if field_name in properties:
                    prop_type = properties[field_name].get("type")
                    if prop_type and not isinstance(field_value, cls._get_json_type(prop_type)):
                        errors.append(f"Field '{field_name}' should be type '{prop_type}'")
        except json.JSONDecodeError:
            errors.append("Output is not valid JSON")
        return errors

    @classmethod
    def _get_json_type(cls, type_name: str) -> type:
        mapping = {
            "string": str,
            "number": (int, float),
            "integer": int,
            "boolean": bool,
            "array": list,
            "object": dict,
        }
        return mapping.get(type_name, str)

    @classmethod
    def _estimate_confidence(cls, output: str, errors: List[str], warnings: List[str]) -> float:
        confidence = 1.0
        confidence -= len(errors) * 0.2
        confidence -= len(warnings) * 0.1
        if len(output) > 5000:
            confidence -= 0.1
        if len(output) < 50:
            confidence -= 0.2
        return max(0.0, min(1.0, confidence))

    @classmethod
    def normalize_response(cls, output: str) -> Dict[str, Any]:
        try:
            data = json.loads(output)
            if isinstance(data, dict):
                return data
            return {"text": output, "structured": data}
        except (json.JSONDecodeError, ValueError):
            pass
        return {"text": output}
