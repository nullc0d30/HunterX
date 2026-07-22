---
layout: default
title: Plugin System — HunterX Extensibility
description: >-
  Extend HunterX vulnerability scanner with custom detector plugins, reporter
  plugins, and post-scan hooks. Decorator-based API with automatic discovery
  and lifecycle hooks.
---

# Plugin System

HunterX features a decorator-based plugin system for extending functionality. Plugins are auto-discovered from `plugins/` subdirectories.

---

## Plugin Types

| Type | Decorator | Lifecycle | Purpose |
|------|-----------|-----------|---------|
| Detector | `@detector(name)` | Per-response | Analyze response text for signatures |
| Reporter | `@reporter(name)` | Post-scan | Export results to custom formats |
| Hook | `@hook(event)` | Scan lifecycle | Run code at scan events |

---

## Detector Plugin

```python
# plugins/detectors/custom_detector.py
from core.plugin_loader import detector

@detector("jwt_leak")
def detect_jwt(response_text):
    """Detect JWT tokens leaked in responses."""
    import re
    pattern = r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"
    matches = re.findall(pattern, response_text)
    if matches:
        return [("Critical", f"JWT token leaked: {matches[0][:50]}...")]
    return []
```

## Reporter Plugin

```python
# plugins/reporters/csv_exporter.py
from core.plugin_loader import reporter
import csv

@reporter("csv")
def export_csv(results, output_dir):
    path = f"{output_dir}/findings.csv"
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["category", "score", "findings"])
        writer.writeheader()
        for r in results:
            writer.writerow({
                "category": r.get("payload_category"),
                "score": r.get("diff_score"),
                "findings": "; ".join(r.get("findings", [])),
            })
    return path
```

## Hook Plugin

```python
# plugins/hooks/slack_notifier.py
from core.plugin_loader import hook
import requests

@hook("after_scan")
def notify_slack(results, url):
    count = sum(1 for r in results if r.get("findings"))
    message = f"HunterX scan complete for {url}: {count} findings"
    # requests.post("https://hooks.slack.com/...", json={"text": message})
```

---

## Available Hook Events

| Event | When | Payload |
|-------|------|---------|
| `before_scan` | Before scan starts | `url` |
| `after_scan` | After scan completes | `results`, `url` |

---

## Plugin Discovery

Plugins are auto-discovered from:

```
plugins/
├── detectors/      # .py files with @detector decorators
├── reporters/      # .py files with @reporter decorators
└── hooks/          # .py files with @hook decorators
```

Custom directories can be specified via the `plugin_dirs` option.
