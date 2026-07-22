# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.config import Config, AuthConfig, OOBConfig, AIConfig


def test_config_defaults():
    c = Config()
    assert c.timeout == 15
    assert c.retries == 3
    assert c.verify_ssl is True
    assert c.threads == 5
    assert c.probe_anomaly_threshold == 30
    assert c.confirm_anomaly_threshold == 50
    assert c.max_verify_per_category == 5
    assert c.max_rps == 10.0


def test_config_auth_defaults():
    a = AuthConfig()
    assert a.type == "none"
    assert a.username is None
    assert a.token is None


def test_config_oob_defaults():
    o = OOBConfig()
    assert o.enabled is False
    assert o.collaborator_url is None


def test_config_ai_defaults():
    a = AIConfig()
    assert a.enabled is False
    assert a.provider == "ollama"
    assert a.model == "llama3.2"
    assert a.endpoint == "http://localhost:11434"


def test_config_env_override(monkeypatch):
    c = Config()
    monkeypatch.setenv("HX_TIMEOUT", "30")
    monkeypatch.setenv("HX_THREADS", "10")
    monkeypatch.setenv("HX_MAX_RPS", "5.0")
    monkeypatch.setenv("HX_VERIFY_SSL", "false")
    monkeypatch.setenv("HX_AI_ENABLED", "true")
    monkeypatch.setenv("HX_AI_MODEL", "llama3.1")
    c.apply_env_overrides()
    assert c.timeout == 30
    assert c.threads == 10
    assert c.max_rps == 5.0
    assert c.verify_ssl is False
    assert c.ai.enabled is True
    assert c.ai.model == "llama3.1"


def test_config_no_env_override(monkeypatch):
    c = Config()
    monkeypatch.setenv("HX_TIMEOUT", "invalid")
    c.apply_env_overrides()
    assert c.timeout == 15


def test_config_user_agents_list():
    c = Config()
    assert len(c.user_agents) >= 4
    for ua in c.user_agents:
        assert "Mozilla" in ua or "Gecko" in ua
