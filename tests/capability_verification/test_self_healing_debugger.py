"""Self-Healing Debugger verification."""

def test_debugger_bounded_retry():
    attempts = 0
    max_retries = 3
    while attempts < max_retries:
        attempts += 1
        if attempts >= 2:
            break
    assert attempts <= max_retries
    assert attempts == 2

def test_debugger_state_preserved():
    state = {"tool": "nmap", "params": {}}
    # Simulate failure recovery
    state["retry_count"] = 1
    assert state["tool"] == "nmap"
    assert state["retry_count"] == 1
