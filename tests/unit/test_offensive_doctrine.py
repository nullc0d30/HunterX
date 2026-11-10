"""Tests for offensive doctrine plugin."""

import pytest
from hunterx.plugins.skill_offensive_doctrine.activator import activate, confirmation_message
from hunterx.plugins.skill_offensive_doctrine.state_block import DoctrineState
from hunterx.plugins.skill_offensive_doctrine.modes import resolve_mode
from hunterx.plugins.skill_offensive_doctrine.policies import is_kill

def test_activator():
    assert activate("HUNT MODE") is True
    assert activate("doctrine on") is True
    assert activate("normal") is False
    assert "LOADED" in confirmation_message()

def test_state():
    s = DoctrineState(target="example.com", scope="in-scope")
    out = s.summary()
    assert "TARGET | example.com" in out
    assert "SCOPE | in-scope" in out

def test_modes():
    assert resolve_mode("RECON MODE") == "hunt surface"
    assert resolve_mode("WEB MODE") == "hunt --scope web"

def test_policies():
    assert is_kill("open redirect alone") is True
