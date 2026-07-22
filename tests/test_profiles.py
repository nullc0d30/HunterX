# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# All Rights Reserved.
#
# HunterX — AI-Assisted Vulnerability Hunter
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.profiles import get_profile, PROFILES

def test_all_profiles_exist():
    assert "internal" in PROFILES
    assert "bounty" in PROFILES
    assert "gov" in PROFILES

def test_get_profile_internal():
    p = get_profile("internal")
    assert p.name == "internal"
    assert p.min_delay == 0.1
    assert p.max_delay == 0.5
    assert p.hard_cap_total_requests == 1000
    assert not p.abort_on_waf

def test_get_profile_bounty():
    p = get_profile("bounty")
    assert p.name == "bounty"
    assert p.min_delay == 1.0
    assert p.max_delay == 3.0
    assert p.hard_cap_total_requests == 500
    assert p.abort_on_waf

def test_get_profile_gov():
    p = get_profile("gov")
    assert p.name == "gov"
    assert p.min_delay == 5.0
    assert p.max_delay == 15.0
    assert p.hard_cap_total_requests == 100

def test_get_profile_fallback():
    p = get_profile("unknown")
    assert p.name == "bounty"

def test_profile_immutability():
    p = get_profile("gov")
    assert p.max_retries == 1
    assert p.max_payloads_per_stage == 5
