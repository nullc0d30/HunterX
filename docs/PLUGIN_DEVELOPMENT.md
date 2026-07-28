---
layout: default
title: HunterX Plugin Development Guide v6.0.0 — HunterX v6.0.0
description: Plugin development guide for HunterX v6.0.0. Detector, Reporter, Hook, Agent, and Skill plugin development with SDK.
permalink: /plugin-development/
---

# HunterX Plugin Development Guide v6.0.0

HunterX v6.0.0 supports extensibility through a plugin architecture with five plugin types: Detector, Reporter, Hook, Agent, and Skill plugins. This document describes how to develop each type.

---

## Plugin Discovery

Plugins are Python files discovered at startup by `core/plugin_loader.py`. Any `.py` file placed in a configured plugin directory is imported and its decorators are automatically registered.

Default plugin directories:
- `plugins/detectors/`
- `plugins/reporters/`
- `plugins/hooks/`

Custom directories can be specified via the `--plugin-dirs` CLI flag as a comma-separated list.

---

## 1. Detector Plugins

Detector plugins implement custom vulnerability detection logic. They are registered using the `@detect` decorator and receive scan context at runtime.

### Anatomy

```python
"""Detects custom vulnerability pattern."""
from core.plugin_loader import detect

@detect(name="custom_detector", category="CUSTOM", weight=1.0)
def detect_custom(session, payload, response, findings):
    if "vulnerable_pattern" in response.text:
        return {"type": "CUSTOM", "severity": "high", "evidence": response.text[:200]}
    return None
```

### Parameters

| Parameter  | Type     | Description                              |
|------------|----------|------------------------------------------|
| `session`  | object   | Active scanner session context            |
| `payload`  | string   | Injected payload for the current request |
| `response` | object   | HTTP response from the target             |
| `findings` | list     | Accumulated findings from prior detectors |

### Return Value

Return a dictionary with `type`, `severity`, and `evidence` keys, or `None` if no vulnerability is detected. The returned dict is appended to the findings list.

### Decorator Arguments

| Argument   | Type   | Default | Description                       |
|------------|--------|---------|-----------------------------------|
| `name`     | string | required | Unique plugin identifier          |
| `category` | string | required | Vulnerability category label      |
| `weight`   | float  | `1.0`   | Detection priority weight         |

---

## 2. Reporter Plugins

Reporter plugins export scan findings in custom output formats. They are registered using the `@report` decorator.

### Anatomy

```python
"""Custom CSV reporter."""
from core.plugin_loader import report

@report(name="csv_exporter", format="csv")
def export_csv(findings, output_dir):
    import csv, os
    path = os.path.join(output_dir, "findings.csv")
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["type", "severity", "url"])
        writer.writeheader()
        writer.writerows(findings)
    return path
```

### Parameters

| Parameter    | Type | Description                |
|--------------|------|----------------------------|
| `findings`   | list | All findings from the scan |
| `output_dir` | str  | Directory for output files |

### Return Value

Return the file path (string) of the generated report.

### Decorator Arguments

| Argument | Type   | Default  | Description                    |
|----------|--------|----------|--------------------------------|
| `name`   | string | required | Unique plugin identifier       |
| `format` | string | required | Output format label (e.g. csv) |

---

## 3. Hook Plugins

Hook plugins execute post-scan automation tasks. They are registered using the `@hook` decorator.

### Anatomy

```python
"""Slack notification hook."""
from core.plugin_loader import hook

@hook(name="slack_notify", stage="post")
def notify_slack(findings, output_dir):
    import requests
    webhook = "https://hooks.slack.com/services/..."
    requests.post(webhook, json={"text": f"Scan complete: {len(findings)} findings"})
```

### Parameters

| Parameter    | Type | Description                |
|--------------|------|----------------------------|
| `findings`   | list | All findings from the scan |
| `output_dir` | str  | Directory for output files |

### Return Value

Return value is ignored.

### Decorator Arguments

| Argument | Type   | Default  | Description                       |
|----------|--------|----------|-----------------------------------|
| `name`   | string | required | Unique plugin identifier          |
| `stage`  | string | required | Hook execution stage (e.g. post)  |

---

## 4. Agent Plugins

Agent plugins implement autonomous security agents using the agent framework. See `AGENTS.md` for a complete reference.

### Anatomy

```python
from core.agents.base import SecurityAgent
from core.agents.capabilities import AgentCapability
from core.reasoning.goals import GoalType

class MyAgent(SecurityAgent):
    @property
    def name(self) -> str:
        return "my_agent"

    @property
    def capabilities(self) -> list[AgentCapability]:
        return [AgentCapability.RECON]

    async def execute(self, goal):
        # Agent execution logic
        pass
```

### Required Members

| Member         | Type        | Description                            |
|----------------|-------------|----------------------------------------|
| `name`         | property    | Unique agent identifier string         |
| `capabilities` | property    | List of `AgentCapability` enum values  |
| `execute`      | async method | Main execution entry point             |

Place agent plugins in `plugins/agents/` (add this directory to `--plugin-dirs` if needed).

---

## 5. Skill Plugins

Skill plugins provide reusable capabilities consumable by agents. See `SECURITY_SKILLS_FRAMEWORK.md` for a complete reference.

### Anatomy

```python
from core.skills.base import SecuritySkill
from core.skills.metadata import SkillMetadata
from core.skills.capability import SkillCapability

class MySkill(SecuritySkill):
    @property
    def metadata(self) -> SkillMetadata:
        ...

    @property
    def capabilities(self) -> list[SkillCapability]:
        ...

    async def execute(self, context, params=None):
        ...
```

### Required Members

| Member         | Type        | Description                           |
|----------------|-------------|---------------------------------------|
| `metadata`     | property    | `SkillMetadata` describing the skill  |
| `capabilities` | property    | List of `SkillCapability` enum values |
| `execute`      | async method | Execution logic with context/params   |

Place skill plugins in `plugins/skills/` (add this directory to `--plugin-dirs` if needed).

---

## Configuration

Plugin directories are resolved at startup:

```bash
hunterx --plugin-dirs plugins/detectors,plugins/reporters,plugins/hooks,plugins/agents,plugins/skills
```

If no `--plugin-dirs` flag is provided, HunterX defaults to:

```
plugins/detectors,plugins/reporters,plugins/hooks
```

### Import Mechanism

`core/plugin_loader.py` walks each specified directory, imports every `.py` file, and invokes all registered decorators (`@detect`, `@report`, `@hook`). Agent and Skill plugins use class-based registration via their respective base classes and are discovered through the agent and skill loader modules.

---

## Best Practices

1. **Isolation** — Each plugin should be self-contained with no cross-plugin dependencies.
2. **Error handling** — Wrap external I/O in try/except blocks to avoid crashing the scan.
3. **Idempotency** — Hooks and reporters should be safe to run multiple times.
4. **Naming** — Use descriptive, unique names for each plugin to avoid registration collisions.
5. **Performance** — Keep detector logic lean; heavy computation degrades scan throughput.
6. **Documentation** — Include a module-level docstring describing the plugin's purpose.
