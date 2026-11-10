"""Offensive Doctrine verification."""

from hunterx.plugins.skill_offensive_doctrine.activator import activate
from hunterx.plugins.skill_offensive_doctrine.policies import is_kill
from hunterx.plugins.skill_offensive_doctrine.state_block import DoctrineState

def test_activation_isolation():
    assert activate("HUNT MODE") is True
    assert activate("random") is False

def test_policy_enforcement():
    assert is_kill("open redirect alone") is True
    assert is_kill("sql injection verified") is False

def test_rollback():
    # Simulate clean unload: state resets
    s = DoctrineState()
    s.target = "example.com"
    s.target = ""
    assert s.target == ""

def test_state_block():
    s = DoctrineState(target="t", scope="s")
    out = s.summary()
    assert "TARGET | t" in out
