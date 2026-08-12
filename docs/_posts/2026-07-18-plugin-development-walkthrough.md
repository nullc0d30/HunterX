---
layout: post
title: Plugin Development with HunterX — A Complete Walkthrough
description: >-
  Complete guide to building custom plugins for HunterX. Detector plugins,
  reporter plugins, and hook plugins with practical code examples and best
  practices.
date: 2026-07-18
author: Ahmed Awad (NullC0d3)
categories: [technical, extensions]
---

## Plugin Development with HunterX

> **Version note.** This article was published before HunterX v7.0.0 and
> describes the retired v6-era plugin system (`hunterx.plugin` decorators and
> the `plugins/` directory). The v7 architecture replaced this with the Tool
> Integration SDK and tool-intelligence layer — see
> [Tool Ecosystem]({{ '/tool-ecosystem/' | relative_url }}) and
> [v7 Tool Integration SDK]({{ '/v7-tool-integration-sdk/' | relative_url }}).
> The code below is preserved as a historical reference only.

HunterX has a decorator-based plugin system with three plugin types: detector, reporter, and hook.

## Plugin Types

### Detector Plugin

Analyze HTTP responses for vulnerabilities:

```python
from hunterx.plugin import detector

@detector("custom_header_check")
class CustomHeaderDetector:
    """Check for missing security headers."""

    def detect(self, response, context):
        headers = response.headers
        missing = []

        if "X-Frame-Options" not in headers:
            missing.append("X-Frame-Options")

        if "Content-Security-Policy" not in headers:
            missing.append("Content-Security-Policy")

        if missing:
            return {
                "name": "Missing Security Headers",
                "category": "config",
                "severity": "medium",
                "evidence": {
                    "missing": missing,
                    "url": response.url
                }
            }
        return None
```

### Reporter Plugin

Export results in custom formats:

```python
from hunterx.plugin import reporter

@reporter("csv")
class CSVReporter:
    def report(self, results, output_path):
        import csv
        path = output_path.with_suffix(".csv")
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["name", "severity", "url", "category"])
            for finding in results.findings:
                writer.writerow([
                    finding.name, finding.severity,
                    finding.url, finding.category
                ])
        return path
```

### Hook Plugin

Execute code at scan lifecycle events:

```python
from hunterx.plugin import hook

@hook("scan_complete")
def send_slack_notification(results, context):
    """Send notification when scan completes."""
    webhook_url = os.environ.get("SLACK_WEBHOOK")
    if webhook_url:
        payload = {
            "text": f"Scan complete: {len(results.findings)} findings"
        }
        requests.post(webhook_url, json=payload)
```

## Installation

Place plugin files in the `plugins/` directory. They are auto-discovered at startup.

## Best Practices

- One plugin per file
- Use descriptive decorator names
- Return `None` from detectors that don't match
- Handle exceptions gracefully
- Test plugins independently
