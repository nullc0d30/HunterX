import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from core.time_based import TimeBasedDetector

def test_time_based_payloads_exist():
    tbd = TimeBasedDetector()
    assert "SQLI_TIME" in tbd.TIMING_PAYLOADS
    assert "SSTI_TIME" in tbd.TIMING_PAYLOADS
    assert "RCE_TIME" in tbd.TIMING_PAYLOADS

def test_time_based_payload_structure():
    tbd = TimeBasedDetector()
    for cat, payloads in tbd.TIMING_PAYLOADS.items():
        assert len(payloads) > 0
        for payload, delay in payloads:
            assert isinstance(payload, str)
            assert isinstance(delay, (int, float))
            assert delay > 0
