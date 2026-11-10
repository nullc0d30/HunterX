from __future__ import annotations

KILL_LIST = [
    "theoretical",
    "dead code",
    "ssrf dns only",
    "open redirect alone",
    "self-xss",
    "source maps without secrets",
    "admin could do",
    "introspection alone",
]

CRITICAL_RULES = [
    "Read full scope first",
    "No theoretical bugs",
    "One bug class at a time",
    "Verify data not public",
    "Credential leaks require exploitation proof",
    "Hunt under-saturated classes",
    "T-shaped knowledge",
    "Two-eye approach",
    "Validate before writing",
    "5-minute rule per host",
]

def only_question_violated(description: str) -> bool:
    """Simplified gate: reject if keywords suggest theoretical."""
    desc = description.lower()
    return any(k in desc for k in ["could theoretically", "might allow"])

def is_kill(description: str) -> bool:
    desc = description.lower()
    return any(k in desc for k in KILL_LIST)
