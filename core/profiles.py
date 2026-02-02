# -----------------------------------------------------------------------------
# HunterX - The Al-Assisted Vulnerability Hunter
# Developed by: NullC0d3
#
# This software is protected by copyright and intellectual property laws.
# Unauthorized reproduction, distribution, or reverse engineering is strictly prohibited.
# For authorized use only.
# -----------------------------------------------------------------------------
from dataclasses import dataclass, field
from typing import Dict, Tuple

@dataclass
class OperatorProfile:
    name: str
    description: str
    # Stealth / Timing
    min_delay: float
    max_delay: float
    jitter: float
    backoff_factor: float
    
    # Limitations
    max_retries: int
    max_payloads_per_stage: int
    hard_cap_total_requests: int
    
    # Sensitivity
    abort_on_waf: bool
    abort_threshold_score: int # If error rate/noise score exceeds this

# PRESETS
PROFILE_INTERNAL = OperatorProfile(
    name="internal",
    description="Aggressive Internal Red Team",
    min_delay=0.1,
    max_delay=0.5,
    jitter=0.1,
    backoff_factor=1.5,
    max_retries=3,
    max_payloads_per_stage=50,
    hard_cap_total_requests=1000,
    abort_on_waf=False,
    abort_threshold_score=100
)

PROFILE_BOUNTY = OperatorProfile(
    name="bounty",
    description="Standard Bug Hunting (Careful)",
    min_delay=1.0,
    max_delay=3.0,
    jitter=0.5,
    backoff_factor=2.0,
    max_retries=2,
    max_payloads_per_stage=20,
    hard_cap_total_requests=500,
    abort_on_waf=True,
    abort_threshold_score=50
)

PROFILE_GOV = OperatorProfile(
    name="gov",
    description="Low-and-Slow regulated operation",
    min_delay=5.0,
    max_delay=15.0,
    jitter=2.0,
    backoff_factor=4.0,
    max_retries=1,
    max_payloads_per_stage=5,
    hard_cap_total_requests=100,
    abort_on_waf=True,
    abort_threshold_score=20
)

PROFILES = {
    "internal": PROFILE_INTERNAL,
    "bounty": PROFILE_BOUNTY,
    "gov": PROFILE_GOV
}

def get_profile(name: str) -> OperatorProfile:
    return PROFILES.get(name.lower(), PROFILE_BOUNTY)
