---
layout: default
title: Tutorials — HunterX Hands-On Guides
description: >-
  Step-by-step tutorials for HunterX vulnerability scanner. Learn to configure,
  run, and extend HunterX with practical examples for Red Team ops, bug
  bounty, and CI/CD integration.
---

## Tutorials

Step-by-step hands-on guides for HunterX.

<ul>
{% for tutorial in site.tutorials %}
  <li>
    <a href="{{ tutorial.url | relative_url }}">{{ tutorial.title }}</a>
    {% if tutorial.description %}
    <p>{{ tutorial.description }}</p>
    {% endif %}
  </li>
{% endfor %}
</ul>

## Available Tutorials

1. **Basic Scanning** — Single-target and multi-target scans, passive mode
2. **Authenticated Scanning** — Form login, bearer token, cookie jar, JWT
3. **API Server Usage** — REST API scan job management
4. **Profile Selection** — Internal vs Bounty vs Gov profiles
5. **Plugin Development** — Custom detectors, reporters, hooks
6. **Reporting** — SARIF, HTML, attack graphs, ZIP evidence packages
7. **Docker Deployment** — Production container setup
8. **CI/CD Integration** — GitHub Actions, GitLab CI, Jenkins
9. **AI/ML Features** — LLM analysis and anomaly detection

## Related Guides

- [Quickstart Guide]({{ '/quickstart' | relative_url }})
- [Examples]({{ '/examples' | relative_url }})
- [Installation]({{ '/installation' | relative_url }})
- [CLI Reference]({{ '/cli' | relative_url }})

## Contribute a Tutorial

Tutorials are welcome via pull request. See the [contributing guide]({{ '/contributing' | relative_url }}).
