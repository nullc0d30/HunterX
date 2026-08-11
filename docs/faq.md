---
layout: default
title: Frequently Asked Questions — HunterX
keywords: FAQ, troubleshooting, bug bounty, open source security, HunterX v7, vulnerability validation, PoC
description: >-
  Comprehensive FAQ covering HunterX v7: what it is, who it is for, how it
  differs from traditional scanners, licensing, features, architecture, usage,
  Docker, API, tool ecosystem, proof and PoC, and troubleshooting. Apache 2.0
  open-source.
faq_page: true
---

## Frequently Asked Questions

<div itemscope itemtype="https://schema.org/FAQPage">
{% capture faq_items %}

1. **What is HunterX?**
   HunterX v7 is an AI-assisted vulnerability discovery, validation and proof engine. It plans, orchestrates, executes, validates, correlates and reports authorized security assessments by integrating open-source security tools. It does not stop at candidate detections — it validates findings with evidence, engineers and replays proofs and PoCs, and produces report-ready output. Licensed under Apache 2.0.

2. **Who should use HunterX?**
   HunterX is designed for bug bounty hunters, penetration testers, red teams, security researchers, application security engineers, and DevSecOps / security engineering teams who need authorized, evidence-driven security assessment with safety-by-design guardrails.

3. **Is HunterX open source?**
   Yes. HunterX is fully open source under the Apache License 2.0. You can view, fork, modify, and distribute the code in accordance with the license terms.

4. **Why Apache 2.0?**
   Apache 2.0 is a permissive open-source license that allows forking, modification, and redistribution while requiring attribution. It is a common choice for security tooling.

5. **How is HunterX different from traditional scanners?**
   Traditional scanners emit candidates ("Possible SQL Injection — Confidence 87%"). HunterX carries each candidate through the full investigation: DISCOVER → REASON → TEST → VERIFY → PROVE → GENERATE PoC → VALIDATE → REPORT. A finding becomes report-ready only when it carries evidence, reproducibility, impact, PoC and confidence. HunterX also orchestrates the open-source security-tool ecosystem rather than replacing it.

6. **How does the HunterX workflow work?**
   HunterX organizes work as missions. The workflow is DISCOVER → FINGERPRINT → REASON → HYPOTHESIZE → PROBE → VERIFY → PROVE → POC → REPLAY → CORRELATE → REPORT. Findings move through a lifecycle: DETECTED → SUSPECTED → VALIDATING → VALIDATED → PROVEN → CONFIRMED → REPORT_READY.

7. **What is the Proof & PoC Validation Engine?**
   It is the v7 capability that transforms a validated hypothesis into a report-ready finding using proof contracts, minimal safe proofs, replay, reproducibility, evidence-driven impact and confidence. PoCs are structured artifacts (never arbitrary executable scripts). See [PoC & Validation](/poc-validation/).

8. **Does HunterX support Docker?**
   Yes. HunterX provides a multi-stage Docker image available on Docker Hub at `nullc0d30/hunterx`. The container runs as a non-root user and follows security best practices.

9. **Can I run HunterX as an API server?**
   Yes. HunterX v7 includes a FastAPI REST application (`hunterx.api.app:create_app`). Install the `api` extra, run with uvicorn, and use optional API-key authentication (admin/read-only roles).

10. **What does HunterX integrate with?**
    HunterX integrates with 92 registered open-source security tools across recon, scanning, crawling, fuzzing, parameters, validation, secrets, SAST, proxies, exploitation and knowledge resources. Each tool's integration status is documented — never overclaimed. See [Tool Ecosystem](/tool-ecosystem/).

11. **What vulnerability types does HunterX cover?**
    Discovery, validation and proof across classes including SQL/NoSQL injection, XSS, SSRF, path traversal/LFI, RCE indicators, IDOR/BOLA, SSTI, XXE, authentication and authorization, API/GraphQL, open redirect, CORS, sensitive information exposure, misconfiguration, known vulnerable components, dependency vulnerabilities, cloud exposure and novel/unknown behavior.

12. **Does HunterX use AI or machine learning?**
    Yes. AI-assisted reasoning flows through a decoupled AI provider layer. Reasoning is grounded in canonical observations and evidence — a high AI confidence score is never a substitute for evidence.

13. **What is OOB detection / validation?**
    Out-of-band (OOB) callbacks (e.g., via Interactsh) support validation of blind vulnerabilities such as SSRF and XXE using controlled callback infrastructure and correlation tokens.

14. **What reporting formats are supported?**
    Markdown (human-readable), JSON (machine-parsable), SARIF 2.1 (VS Code / GitHub CodeQL integration), HTML (visual dashboard), PDF, and package (ZIP evidence bundles).

15. **Can I use HunterX in CI/CD pipelines?**
    Yes. HunterX runs in Docker and can be integrated into GitHub Actions, GitLab CI, Jenkins, or any CI/CD platform. SARIF output integrates with GitHub CodeQL, and a REST API supports programmatic orchestration.

16. **What Python versions are supported?**
    Python 3.11 and later are supported (`requires-python = ">=3.11"`), including 3.12, 3.13 and 3.14.

17. **How is HunterX licensed for commercial use?**
    HunterX is Apache 2.0 licensed, which permits commercial use. If your organization uses it commercially, please consider supporting the project.

18. **Can I contribute to HunterX?**
    Yes. Contributions are welcome. See the [Contributing Guide](/contributing/) for fork workflow, commit conventions, and the DCO (Developer Certificate of Origin) requirement.

19. **How do I report a security vulnerability in HunterX?**
    Use GitHub Private Vulnerability Reporting (Security tab) or the process described in [SECURITY.md](/security/).

20. **Does HunterX require external services?**
    No. HunterX works offline. AI providers are optional; OOB callback infrastructure (e.g., Interactsh) is used only when configured.

21. **Can I run HunterX on Windows?**
    Yes. HunterX runs on Linux, macOS and Windows. Docker is recommended for consistent behavior.

22. **Does HunterX enforce safety?**
    Yes. HunterX enforces scope and authorization guards, a safety policy, sandboxing, evidence-gated confidence, secret masking and hardened XML parsing. The proof engine is not a weaponization engine — data destruction, persistence, reverse shells, DoS and mass data extraction are never scheduled.

23. **What is the finding lifecycle?**
    DETECTED → SUSPECTED → VALIDATING → VALIDATED → PROVEN → CONFIRMED → REPORT_READY, with FALSE_POSITIVE and INCONCLUSIVE branches. A detection is never automatically a validated finding.

24. **What is reproducibility in HunterX?**
    Reproducibility is measured over repeated replays of a proof/PoC. REPRODUCIBLE requires at least two successful replays with no failures. A single "executed once" is never "reproducible."

25. **How does HunterX compare to Nuclei?**
    Nuclei is a fast template-based scanner. HunterX is an AI-assisted discovery, validation and proof engine that integrates Nuclei as a fully-supported tool and adds evidence-driven validation, proof/PoC engineering and report generation. See [HunterX vs Nuclei](/comparisons/vs-nuclei/).

26. **How does HunterX compare to OWASP ZAP?**
    OWASP ZAP is a GUI-based intercepting proxy and scanner. HunterX is a CLI/API/Docker-first orchestration and proof engine that integrates ZAP as a proxy/web-security tool. See [HunterX vs OWASP ZAP](/comparisons/vs-zap/).

27. **How does HunterX compare to Burp Suite?**
    Burp Suite is a commercial, GUI-centric web testing platform. HunterX is open source (Apache 2.0), automation-first, and centered on evidence-driven validation and proof. See [HunterX vs Burp Suite](/comparisons/vs-burp/).

28. **How does HunterX compare to OpenVAS?**
    OpenVAS is a signature-driven network vulnerability scanner. HunterX is an AI-assisted discovery, validation and proof engine; OpenVAS is registered in the toolchain manifest as a known resource. See [HunterX vs OpenVAS](/comparisons/vs-openvas/).

29. **Does HunterX claim guaranteed discovery of zero-days?**
    No. HunterX supports hypothesis-driven discovery and investigation of unknown or application-specific behaviors, but it does not claim guaranteed autonomous discovery of zero-days.

30. **How do I cite HunterX in academic research?**
    Use the CITATION.cff file in the repository, which provides the recommended citation metadata for HunterX.

31. **What is the Tool Integration SDK?**
    It is the v7 SDK that defines how tool adapters register, execute and produce canonical observations through guarded execution — proof code never invokes subprocess directly. See [Tool Integration SDK](/v7-tool-integration-sdk/).

32. **What is TIDB?**
    TIDB is the v7 persistence layer: SQL storage (SQLite default, PostgreSQL supported) with Alembic migrations, events, audit and versioning. See [Persistence (TIDB)](/v7-tidb/).

33. **Does HunterX maintain its own payload database?**
    HunterX integrates community-maintained knowledge resources such as [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings), SecLists and FuzzDB as payload/wordlist resources in the toolchain. It documents these as third-party knowledge sources.

34. **What Python architectures are supported?**
    Linux, macOS and Windows. See [SUPPORTED_PLATFORMS.md](https://github.com/nullc0d30/HunterX/blob/main/SUPPORTED_PLATFORMS.md) in the repository.

35. **Is there a responsible-use policy?**
    Yes. HunterX is an authorized cybersecurity testing and research platform. You are responsible for obtaining appropriate authorization before testing any system and for complying with applicable laws and terms of service. See [Responsible Use](/responsible-use/).

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
