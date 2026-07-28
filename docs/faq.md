---
layout: default
title: Frequently Asked Questions — HunterX
description: >-
  Comprehensive FAQ covering HunterX vulnerability scanner: licensing, features,
  architecture, usage, Docker, API, plugins, comparisons, and troubleshooting.
  Apache 2.0 open-source.
faq_page: true
---

# Frequently Asked Questions

<div itemscope itemtype="https://schema.org/FAQPage">
{% capture faq_items %}

1. **What is HunterX?**
   HunterX is an open-source, AI-assisted vulnerability assessment and penetration testing framework. It uses a 4-stage reasoning pipeline — passive intel, probe, confirm, verify — to identify security vulnerabilities in web applications and APIs. Licensed under Apache 2.0.

2. **Who should use HunterX?**
   HunterX is designed for professional Red Team operators, penetration testers, bug bounty hunters, security researchers, and DevOps engineers who need an automated, context-aware vulnerability scanner with safety-by-design guardrails.

3. **Is HunterX open source?**
   Yes. HunterX is fully open source under the Apache License 2.0. You can view, fork, modify, and distribute the code in accordance with the license terms.

4. **Why Apache 2.0?**
   Apache 2.0 is a permissive open-source license that allows forking, modification, and redistribution while requiring attribution. It is the industry standard for security tools and is used by OWASP ZAP, Kubernetes, and many other projects.

5. **How is HunterX different from traditional scanners?**
   Traditional scanners rely on brute-force payload matching. HunterX uses a reasoning engine that builds a baseline fingerprint, analyzes response differentials, considers authentication state, operator profile, and contextual signals before increasing confidence in a finding. It is safer, more accurate, and more explainable.

6. **How does the 4-stage pipeline work?**
   Stage 0 (Passive Intel) gathers target context from headers and detects WAF, WebSocket endpoints, and GraphQL. Stage 1 (Probe) sends diverse probes across attack categories. Stage 2 (Confirm) deepens probes in categories showing anomalies. Stage 3 (Verify) safely verifies confirmed vulnerabilities.

7. **Does HunterX support Docker?**
    Yes. HunterX provides a multi-stage Docker image available on Docker Hub at `nullc0d30/hunterx`. The container runs as a non-root user, supports linux/amd64 and linux/arm64, and follows security best practices.

8. **Can I run HunterX as an API server?**
   Yes. HunterX includes a built-in FastAPI REST server. Start it with `python hunterx.py api --port 8443`. Submit scan jobs via `POST /scan`, poll results via `GET /scan/{id}`, check health via `GET /health`.

9. **Does HunterX support authenticated scanning?**
   Yes. HunterX supports Basic Auth, Bearer Token, Cookie Jar (from JSON file), and Form Login authentication. Configure via CLI flags or the `hunterx.yaml` configuration file.

10. **What vulnerability types can HunterX detect?**
    HunterX detects 200+ vulnerability signatures including LFI/Path Traversal, RCE/Command Injection, SQL Injection, SSTI, SSRF, XSS, Open Redirect, and XXE.

11. **Does HunterX support WebSocket testing?**
    Yes. HunterX can detect WebSocket endpoints from page content, test connections, and send test messages. Custom WebSocket fuzzing can be implemented via the plugin system.

12. **Does HunterX support GraphQL testing?**
    Yes. HunterX performs GraphQL introspection queries, batch attack testing, and depth-limit testing.

13. **Can I develop custom plugins for HunterX?**
    Yes. HunterX has a decorator-based plugin system supporting detector plugins, reporter plugins, and post-scan hook plugins. Plugins are auto-discovered from the `plugins/` directory.

14. **Does HunterX use AI or machine learning?**
    Yes, optionally. HunterX integrates with Ollama for LLM-based automated finding analysis and remediation suggestions, and scikit-learn for DBSCAN anomaly clustering. Both features are gracefully disabled when dependencies are unavailable.

15. **What is OOB detection?**
    Out-of-band (OOB) detection identifies blind XXE, SSRF, and RCE vulnerabilities by sending payloads that trigger external callbacks to a collaborator server. HunterX supports configurable collaborator URLs.

16. **What is time-based detection?**
    Time-based detection identifies blind SQL injection and NoSQL injection vulnerabilities by measuring response delays. HunterX sends payloads with known delay functions and compares actual vs expected response times.

17. **Does HunterX have WAF evasion?**
    Yes. HunterX includes 50+ WAF detection signatures, auto-abort on WAF detection, and a payload mutation engine that generates encoding, SQL, and LFI variants for evasion.

18. **What reporting formats are supported?**
    Markdown (human-readable), JSON (machine-parsable), SARIF 2.1 (VS Code/GitHub CodeQL integration), HTML (visual dashboard), and ZIP (evidence package).

19. **Can I use HunterX in CI/CD pipelines?**
    Yes. HunterX runs in Docker and can be integrated into GitHub Actions, GitLab CI, Jenkins, or any CI/CD platform. SARIF output integrates natively with GitHub CodeQL.

20. **What Python versions are supported?**
    Python 3.11, 3.12, and 3.13 are officially supported and tested in CI.

21. **How is HunterX licensed for commercial use?**
    HunterX is Apache 2.0 licensed, which permits commercial use. If your organization uses it commercially, please consider supporting the project via GitHub Sponsors.

22. **Can I contribute to HunterX?**
    Yes. Contributions are welcome. See the CONTRIBUTING.md guide for fork workflow, commit conventions, and the DCO (Developer Certificate of Origin) requirement.

23. **How do I report a security vulnerability in HunterX?**
    Use GitHub Private Vulnerability Reporting (Security tab) or open a regular issue requesting a secure communication channel. Do NOT post vulnerability details in public issues.

24. **Does HunterX have a roadmap?**
    Yes. The v6.0.0 roadmap focuses on ecosystem growth: community skill repository, additional AI providers (Anthropic, Google Gemini), CI/CD pipeline plugins (GitHub Actions, GitLab CI), SIEM connectors, and collaborative scanning. See the full ROADMAP.md.

25. **How does HunterX compare to Nuclei?**
    Nuclei is a fast template-based scanner using YAML templates. HunterX is a reasoning-driven framework with a 4-stage pipeline, response differential analysis, and context-aware scoring. Both are complementary — Nuclei excels at template-based checks, HunterX excels at depth and reasoning.

26. **How does HunterX compare to OWASP ZAP?**
    OWASP ZAP is a mature GUI-based intercepting proxy with a broad feature set. HunterX is a CLI/API-first framework designed for automation and Red Team ops. HunterX's reasoning pipeline and safety-by-design approach are unique differentiators.

27. **Can I run HunterX on Windows?**
    Yes. HunterX is written in Python and runs on Windows, macOS, and Linux. Docker is recommended for Windows for consistent behavior.

28. **Does HunterX require external services?**
    No. HunterX works fully offline. AI/ML features (Ollama, scikit-learn) and OOB detection (collaborator URL) are optional and disabled by default.

29. **What is the maximum number of targets I can scan?**
    HunterX supports single-target (`-u URL`), multi-target file (`-f targets.txt`), and API-driven scanning. Limits are governed by the operator profile (e.g., Bounty: 500 requests, Gov: 100 requests).

30. **How do I cite HunterX in academic research?**
    Use the CITATION.cff file or the BibTeX entry in the README. Example: `@software{hunterx2026, author = {Ahmed Awad (NullC0d3)}, title = {HunterX: AI-Assisted Vulnerability Hunter}, version = {6.0.0}, year = {2026}, license = {Apache-2.0}, url = {https://github.com/nullc0d30/HunterX} }`

31. **What is the plugin API?**
    HunterX plugins use decorators: `@detector(name)` for response analysis, `@reporter(name)` for output formats, and `@hook(event)` for scan lifecycle callbacks. Plugins are auto-discovered from the `plugins/` directory.

32. **Does HunterX support rate limiting?**
    Yes. HunterX uses a token-bucket algorithm for rate limiting. The maximum requests per second (`max_rps`) is configurable via YAML, CLI, or the `HX_MAX_RPS` environment variable.

33. **Can I run HunterX in passive mode?**
    Use the `--dry-run` flag for logic verification without sending any requests.

34. **What is the destructive payload blocklist?**
    HunterX includes a hard-coded, non-bypassable blocklist of destructive payloads including `rm -rf`, `mkfs`, `dd if=`, fork bombs, reverse shells, and SQL write statements. These are blocked at the code level before any request is sent.

{% endcapture %}

{% assign items = faq_items | split: '**' %}

{% for item in items %}
  {% if item contains '?' %}
    {% assign parts = item | split: '**' %}
    {% assign question = parts[0] | strip %}
    {% assign answer_parts = item | split: '  ' %}
    {% if answer_parts.size > 1 %}
      {% assign answer = answer_parts[1] | strip_newlines | strip %}
    {% endif %}
<div itemscope itemprop="mainEntity" itemtype="https://schema.org/Question">
  <h3 itemprop="name">{{ question | prepend: '**' | markdownify | strip_html | strip }}</h3>
  <div itemscope itemprop="acceptedAnswer" itemtype="https://schema.org/Answer">
    <div itemprop="text">{{ answer | markdownify }}</div>
  </div>
</div>
  {% endif %}
{% endfor %}

</div>
