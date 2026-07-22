# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# All Rights Reserved.
#
# HunterX — AI-Assisted Vulnerability Hunter
import os
from dataclasses import field, dataclass
from typing import List, Dict, Optional


@dataclass
class AuthConfig:
    type: str = "none"
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None
    cookie_file: Optional[str] = None
    login_url: Optional[str] = None
    login_data: Dict[str, str] = field(default_factory=dict)


@dataclass
class OOBConfig:
    enabled: bool = False
    collaborator_url: Optional[str] = None


@dataclass
class AIConfig:
    enabled: bool = False
    provider: str = "ollama"
    model: str = "llama3.2"
    endpoint: str = "http://localhost:11434"


@dataclass
class Config:
    # Target
    timeout: int = 15
    retries: int = 3
    verify_ssl: bool = True

    # Stealth
    min_delay: float = 0.5
    max_delay: float = 2.5
    block_if_403: bool = True

    # Payload & Fuzzing
    threads: int = 5

    # Thresholds
    probe_anomaly_threshold: int = 30
    confirm_anomaly_threshold: int = 50
    max_verify_per_category: int = 5
    failure_suppression_threshold: int = 10
    diff_length_score_cap: float = 10.0

    # Rate limiting
    max_rps: float = 10.0

    # Headers
    user_agents: List[str] = field(default_factory=lambda: [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
    ])

    base_headers: dict = field(default_factory=lambda: {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
    })

    # Sub-configs
    auth: AuthConfig = field(default_factory=AuthConfig)
    oob: OOBConfig = field(default_factory=OOBConfig)
    ai: AIConfig = field(default_factory=AIConfig)

    def apply_env_overrides(self):
        env_map = {
            "HX_TIMEOUT": ("timeout", int),
            "HX_THREADS": ("threads", int),
            "HX_MAX_RPS": ("max_rps", float),
            "HX_VERIFY_SSL": ("verify_ssl", lambda v: v.lower() in ("true", "1", "yes")),
            "HX_PROBE_THRESHOLD": ("probe_anomaly_threshold", int),
            "HX_CONFIRM_THRESHOLD": ("confirm_anomaly_threshold", int),
            "HX_MAX_VERIFY": ("max_verify_per_category", int),
            "HX_OUTPUT_DIR": ("output_dir", str),
            "HX_AUTH_TYPE": ("auth", "type", str),
            "HX_AUTH_TOKEN": ("auth", "token", str),
            "HX_AI_ENABLED": ("ai", "enabled", lambda v: v.lower() in ("true", "1", "yes")),
            "HX_AI_MODEL": ("ai", "model", str),
            "HX_OOB_URL": ("oob", "collaborator_url", str),
        }
        for env_var, path in env_map.items():
            val = os.environ.get(env_var)
            if val is not None:
                # path is either (attr, converter) or (parent, attr, converter)
                if len(path) == 2:
                    attr_name, converter = path
                    parents = ()
                else:
                    *parents, attr_name, converter = path
                target = self
                for parent in parents:
                    target = getattr(target, parent)
                try:
                    setattr(target, attr_name, converter(val))
                except (ValueError, TypeError):
                    pass


config = Config()


def load_config_file(path: str = "hunterx.yaml") -> Config:
    """Load YAML config file and merge into global config."""
    if not os.path.exists(path):
        return config
    try:
        import yaml
        with open(path) as f:
            data = yaml.safe_load(f) or {}
    except Exception:
        return config

    mapping = {
        "profile": "profile",
        "stealth": "stealth",
        "threads": "threads",
        "timeout": "timeout",
        "retries": "retries",
        "verify_ssl": "verify_ssl",
        "max_rps": "max_rps",
        "probe_anomaly_threshold": "probe_anomaly_threshold",
        "confirm_anomaly_threshold": "confirm_anomaly_threshold",
        "max_verify_per_category": "max_verify_per_category",
        "failure_suppression_threshold": "failure_suppression_threshold",
        "diff_length_score_cap": "diff_length_score_cap",
        "output_dir": "output_dir",
        "evidence_level": "evidence_level",
        "min_confidence": "min_confidence",
        "visual": "visual",
    }
    for yaml_key, config_attr in mapping.items():
        if yaml_key in data:
            setattr(config, config_attr, data[yaml_key])

    if "auth" in data:
        for k, v in data["auth"].items():
            if hasattr(config.auth, k) and v is not None:
                setattr(config.auth, k, v)
    if "oob" in data:
        for k, v in data["oob"].items():
            if hasattr(config.oob, k) and v is not None:
                setattr(config.oob, k, v)
    if "ai" in data:
        for k, v in data["ai"].items():
            if hasattr(config.ai, k) and v is not None:
                setattr(config.ai, k, v)

    return config
