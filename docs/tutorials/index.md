---
layout: default
title: Tutorials — HunterX Hands-On Guides
description: >-
  Step-by-step tutorials for HunterX vulnerability scanner. Learn to configure,
  run, and extend HunterX with practical examples for Red Team ops, bug
  bounty, and CI/CD integration.
---

# Tutorials

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

## Tutorial Topics

1. **Basic Scanning**: Single-target, multi-target, passive mode
2. **Advanced Configuration**: Custom headers, proxies, timeouts
3. **Authenticated Scanning**: Form login, bearer token, cookie jar
4. **Profile Selection**: Internal vs Bounty vs Gov profiles
5. **API Server Usage**: REST API scan job management
6. **Plugin Development**: Custom detectors, reporters, hooks
7. **Reporting**: SARIF, HTML, ZIP evidence packages
8. **Docker Deployment**: Production container setup
9. **CI/CD Integration**: GitHub Actions, GitLab CI, Jenkins
10. **AI/ML Features**: LLM analysis and anomaly detection

## Contribute a Tutorial

Tutorials are welcome via pull request. See the [contributing guide](https://github.com/nullc0d30/HunterX/blob/main/CONTRIBUTING.md).
