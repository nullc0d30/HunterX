from __future__ import annotations

MODE_MAP = {
    "RECON MODE": "hunt surface",
    "WEB MODE": "hunt --scope web",
    "API MODE": "tools execute --capability api-security",
    "LLM MODE": "hunt --capability llm-agent-injection",
    "MOBILE MODE": "hunt --capability mobile-runtime",
    "SRC MODE": "tools execute --capability source-review",
    "PAYLOAD <class>": "tools execute --capability <class> --mode payload",
    "EXPLOIT MODE": "finding proof",
    "REPORT MODE": "report generate --template offensive_writeup",
    "TRIAGE": "mission decisions",
    "CHAIN": "hunt paths",
    "BYPASS <thing>": "mission decisions --bypass",
    "WRITEUP": "report generate",
    "STATE": "state",
    "RESET": "mission cancel",
}

def resolve_mode(mode_name: str) -> str:
    return MODE_MAP.get(mode_name, mode_name)
