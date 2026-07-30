# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from .payload_metadata import PayloadMetadata


class PolicyLevel(str, Enum):
    SAFE = "safe"
    BALANCED = "balanced"
    AGGRESSIVE = "aggressive"
    RESEARCH = "research"
    PARANOID = "paranoid"


DANGER_THRESHOLDS = {
    PolicyLevel.SAFE: 0.3,
    PolicyLevel.BALANCED: 0.6,
    PolicyLevel.AGGRESSIVE: 0.85,
    PolicyLevel.RESEARCH: 1.0,
    PolicyLevel.PARANOID: 0.2,
}

NOISE_THRESHOLDS = {
    PolicyLevel.SAFE: 0.5,
    PolicyLevel.BALANCED: 0.7,
    PolicyLevel.AGGRESSIVE: 0.9,
    PolicyLevel.RESEARCH: 1.0,
    PolicyLevel.PARANOID: 0.3,
}


@dataclass
class PolicyConfig:
    level: PolicyLevel = PolicyLevel.BALANCED
    max_payloads_per_category: int = 10
    allow_dangerous: bool = False
    allow_high_noise: bool = False
    require_auth: bool = False
    require_https: bool = False
    require_safe_encoding: bool = False
    max_payload_size: int = 8192
    min_confidence: float = 0.0
    allowed_categories: List[str] = field(default_factory=list)
    blocked_categories: List[str] = field(default_factory=list)
    allowed_technologies: List[str] = field(default_factory=list)
    blocked_technologies: List[str] = field(default_factory=list)
    allowed_techniques: List[str] = field(default_factory=list)
    blocked_techniques: List[str] = field(default_factory=list)
    max_concurrent_payloads: int = 5
    rate_limit_per_second: float = 10.0
    respect_robots_txt: bool = True
    respect_cookies: bool = True
    enable_waf_evasion: bool = True
    enable_mutation: bool = True
    max_mutations_per_payload: int = 5
    log_all_requests: bool = True
    record_feedback: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level.value,
            "max_payloads_per_category": self.max_payloads_per_category,
            "allow_dangerous": self.allow_dangerous,
            "allow_high_noise": self.allow_high_noise,
            "require_auth": self.require_auth,
            "require_https": self.require_https,
            "require_safe_encoding": self.require_safe_encoding,
            "max_payload_size": self.max_payload_size,
            "min_confidence": self.min_confidence,
            "allowed_categories": self.allowed_categories,
            "blocked_categories": self.blocked_categories,
            "allowed_technologies": self.allowed_technologies,
            "blocked_technologies": self.blocked_technologies,
            "allowed_techniques": self.allowed_techniques,
            "blocked_techniques": self.blocked_techniques,
            "max_concurrent_payloads": self.max_concurrent_payloads,
            "rate_limit_per_second": self.rate_limit_per_second,
            "respect_robots_txt": self.respect_robots_txt,
            "respect_cookies": self.respect_cookies,
            "enable_waf_evasion": self.enable_waf_evasion,
            "enable_mutation": self.enable_mutation,
            "max_mutations_per_payload": self.max_mutations_per_payload,
            "log_all_requests": self.log_all_requests,
            "record_feedback": self.record_feedback,
        }


LEVEL_PRESETS: Dict[PolicyLevel, Dict[str, Any]] = {
    PolicyLevel.SAFE: {
        "max_payloads_per_category": 5,
        "allow_dangerous": False,
        "allow_high_noise": False,
        "require_auth": True,
        "require_https": True,
        "require_safe_encoding": True,
        "max_payload_size": 2048,
        "min_confidence": 0.7,
        "enable_waf_evasion": False,
        "enable_mutation": False,
        "max_mutations_per_payload": 0,
        "max_concurrent_payloads": 2,
        "rate_limit_per_second": 2.0,
    },
    PolicyLevel.BALANCED: {
        "max_payloads_per_category": 10,
        "allow_dangerous": False,
        "allow_high_noise": False,
        "require_auth": False,
        "require_https": False,
        "require_safe_encoding": False,
        "max_payload_size": 8192,
        "min_confidence": 0.4,
        "enable_waf_evasion": True,
        "enable_mutation": True,
        "max_mutations_per_payload": 5,
        "max_concurrent_payloads": 5,
        "rate_limit_per_second": 10.0,
    },
    PolicyLevel.AGGRESSIVE: {
        "max_payloads_per_category": 25,
        "allow_dangerous": True,
        "allow_high_noise": True,
        "require_auth": False,
        "require_https": False,
        "require_safe_encoding": False,
        "max_payload_size": 32768,
        "min_confidence": 0.2,
        "enable_waf_evasion": True,
        "enable_mutation": True,
        "max_mutations_per_payload": 10,
        "max_concurrent_payloads": 15,
        "rate_limit_per_second": 50.0,
    },
    PolicyLevel.RESEARCH: {
        "max_payloads_per_category": 100,
        "allow_dangerous": True,
        "allow_high_noise": True,
        "require_auth": False,
        "require_https": False,
        "require_safe_encoding": False,
        "max_payload_size": 1048576,
        "min_confidence": 0.0,
        "enable_waf_evasion": True,
        "enable_mutation": True,
        "max_mutations_per_payload": 25,
        "max_concurrent_payloads": 50,
        "rate_limit_per_second": 200.0,
    },
    PolicyLevel.PARANOID: {
        "max_payloads_per_category": 3,
        "allow_dangerous": False,
        "allow_high_noise": False,
        "require_auth": True,
        "require_https": True,
        "require_safe_encoding": True,
        "max_payload_size": 1024,
        "min_confidence": 0.9,
        "enable_waf_evasion": False,
        "enable_mutation": False,
        "max_mutations_per_payload": 0,
        "max_concurrent_payloads": 1,
        "rate_limit_per_second": 1.0,
        "log_all_requests": True,
        "record_feedback": True,
    },
}


class PayloadExecutionPolicy:
    def __init__(self, level: PolicyLevel = PolicyLevel.BALANCED):
        self.config = PolicyConfig(level=level)
        self._apply_preset()

    def _apply_preset(self) -> None:
        preset = LEVEL_PRESETS.get(self.config.level, {})
        for key, value in preset.items():
            setattr(self.config, key, value)

    def set_level(self, level: PolicyLevel) -> None:
        self.config.level = level
        self._apply_preset()

    def evaluate(
        self,
        payload: str,
        metadata: PayloadMetadata,
        category: Optional[str] = None,
        technique: Optional[str] = None,
    ) -> Tuple[bool, str]:
        if self.config.blocked_categories:
            cat = category or metadata.category
            if any(b.lower() == cat.lower() for b in self.config.blocked_categories):
                return False, f"Category '{cat}' is blocked by policy"

        if self.config.allowed_categories:
            cat = category or metadata.category
            if not any(a.lower() == cat.lower() for a in self.config.allowed_categories):
                return False, f"Category '{cat}' is not in allowed list"

        if self.config.blocked_technologies:
            for tech in metadata.technology:
                if any(b.lower() == tech.lower() for b in self.config.blocked_technologies):
                    return False, f"Technology '{tech}' is blocked by policy"

        if self.config.blocked_techniques:
            if technique and any(b.lower() == technique.lower() for b in self.config.blocked_techniques):
                return False, f"Technique '{technique}' is blocked by policy"

        if self.config.allowed_techniques:
            if technique and not any(a.lower() == technique.lower() for a in self.config.allowed_techniques):
                return False, f"Technique '{technique}' is not in allowed list"

        if not self.config.allow_dangerous:
            danger = metadata.danger_level
            threshold = DANGER_THRESHOLDS.get(self.config.level, 0.6)
            if danger > threshold:
                return False, f"Danger level {danger:.2f} exceeds threshold {threshold}"

        if not self.config.allow_high_noise:
            noise = metadata.noise_level
            threshold = NOISE_THRESHOLDS.get(self.config.level, 0.6)
            if noise > threshold:
                return False, f"Noise level {noise:.2f} exceeds threshold {threshold}"

        if self.config.max_payload_size > 0:
            if len(payload) > self.config.max_payload_size:
                return False, f"Payload size {len(payload)} exceeds max {self.config.max_payload_size}"

        if self.config.min_confidence > 0:
            conf = metadata.reliability
            if conf < self.config.min_confidence:
                return False, f"Confidence {conf:.2f} below minimum {self.config.min_confidence}"

        if self.config.require_safe_encoding and metadata.encoding != "plain":
            return False, f"Encoding '{metadata.encoding}' not allowed by policy"

        return True, "Allowed by policy"

    def filter_payloads(
        self,
        payloads: List[Dict[str, Any]],
        metadata_map: Optional[Dict[str, PayloadMetadata]] = None,
    ) -> List[Dict[str, Any]]:
        allowed: List[Dict[str, Any]] = []
        for p in payloads:
            payload_text = p.get("payload", p.get("payload_text", ""))
            category = p.get("category", "GENERIC")
            technique = p.get("technique")

            meta = None
            if metadata_map:
                key = p.get("payload_hash", payload_text[:32])
                meta = metadata_map.get(key)
            if not meta:
                meta = PayloadMetadata(category=category)

            ok, _ = self.evaluate(payload_text, meta, category, technique)
            if ok:
                allowed.append(p)

        if self.config.max_payloads_per_category > 0:
            per_cat: Dict[str, List[Dict[str, Any]]] = {}
            for p in allowed:
                cat = p.get("category", "GENERIC")
                if cat not in per_cat:
                    per_cat[cat] = []
                per_cat[cat].append(p)
            result: List[Dict[str, Any]] = []
            for cat, items in per_cat.items():
                result.extend(items[:self.config.max_payloads_per_category])
            return result

        return allowed

    def to_dict(self) -> Dict[str, Any]:
        return self.config.to_dict()
