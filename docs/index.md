---
layout: default
title: HunterX — AI-Assisted Offensive Security Framework
keywords: HunterX, Red Team Framework, Offensive Security, vulnerability scanner, penetration testing, AI-assisted security, attack surface analysis, PayloadsAllTheThings, payload library, payload knowledge base, DAST, SARIF, OWASP, OWASP Community, Security Scanner, Web Application Security, API Security
description: >-
  HunterX is an AI-assisted offensive security framework combining intelligent
  reconnaissance, adaptive vulnerability discovery, payload orchestration, and
  explainable reasoning. Observe · Hypothesize · Probe · Verify.
---

<!-- ===== HERO ===== -->
<div class="lp-hero">
  <img src="{{ '/assets/images/logo.png' | relative_url }}" alt="HunterX Official Logo" class="lp-hero-logo">
  <h1>HunterX</h1>
  <div class="subtitle">AI-Assisted Offensive Security Framework</div>
  <div class="pipeline"><span>Observe</span> &rarr; <span>Hypothesize</span> &rarr; <span>Probe</span> &rarr; <span>Verify</span></div>
  <p>HunterX combines intelligent reconnaissance, adaptive vulnerability discovery, payload orchestration, and explainable security reasoning into a single modular platform. No external scanners required.</p>
  <div class="lp-hero-actions">
    <a href="{{ '/installation' | relative_url }}" class="primary">Install HunterX</a>
    <a href="{{ '/quickstart' | relative_url }}" class="secondary">Quickstart</a>
    <a href="https://github.com/nullc0d30/HunterX" class="secondary">GitHub</a>
  </div>
  <div class="lp-hero-badges">
    <a href="https://github.com/nullc0d30/HunterX/releases"><img src="https://img.shields.io/github/v/release/nullc0d30/HunterX?style=flat-square&logo=github" alt="Release"></a>
    <a href="https://pypi.org/project/hunterx/"><img src="https://img.shields.io/pypi/v/hunterx?style=flat-square&logo=pypi" alt="PyPI"></a>
    <a href="https://github.com/nullc0d30/HunterX/actions"><img src="https://img.shields.io/github/actions/workflow/status/nullc0d30/HunterX/test.yml?style=flat-square&label=tests" alt="Tests"></a>
    <a href="https://www.apache.org/licenses/LICENSE-2.0"><img src="https://img.shields.io/badge/license-Apache%202.0-green?style=flat-square" alt="License"></a>
    <a href="https://hub.docker.com/r/nullc0d30/hunterx"><img src="https://img.shields.io/docker/pulls/nullc0d30/hunterx?style=flat-square&logo=docker" alt="Docker"></a>
    <a href="https://python.org"><img src="https://img.shields.io/pypi/pyversions/hunterx?style=flat-square&logo=python" alt="Python"></a>
    <a href="https://github.com/astral-sh/ruff"><img src="https://img.shields.io/badge/ruff-0%20errors-brightgreen?style=flat-square" alt="Ruff"></a>
    <a href="https://github.com/nullc0d30/HunterX"><img src="https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey?style=flat-square" alt="Platform"></a>
    <a href="https://pypi.org/project/hunterx/"><img src="https://img.shields.io/pypi/dm/hunterx?style=flat-square&logo=pypi" alt="Downloads"></a>
    <a href="https://owasp.org/www-community/Vulnerability_Scanning_Tools"><img src="https://img.shields.io/badge/OWASP%20Community-listed-green?style=flat-square" alt="OWASP Community"></a>
  </div>
</div>

<!-- ===== WHY HUNTERX? ===== -->
<div class="lp-section fade-in">
  <div class="lp-section-header">
    <h2>Why HunterX?</h2>
    <p>Traditional scanners rely on payload volume and signature matching. HunterX reasons about what vulnerabilities <em>might</em> exist before probing, then verifies with evidence.</p>
  </div>
  <div class="lp-compare-table">
    <table>
      <thead>
        <tr>
          <th>Tool</th>
          <th>AI / Reasoning</th>
          <th>Multi-Agent</th>
          <th>Payload Intelligence</th>
          <th>Reporting</th>
          <th>Architecture</th>
        </tr>
      </thead>
      <tbody>
        <tr class="highlight">
          <td>HunterX</td>
          <td>LLM-native (multi-provider)</td>
          <td>10 agents, DAG workflows</td>
          <td>FTS5-indexed, 5-level policy</td>
          <td>SARIF, HTML, graph, purple team</td>
          <td>Unified Python framework</td>
        </tr>
        <tr>
          <td>Nmap</td>
          <td>&mdash;</td>
          <td>&mdash;</td>
          <td>&mdash;</td>
          <td>XML</td>
          <td>C, single-purpose</td>
        </tr>
        <tr>
          <td>Nuclei</td>
          <td>&mdash;</td>
          <td>&mdash;</td>
          <td>&mdash;</td>
          <td>JSON</td>
          <td>Go, template engine</td>
        </tr>
        <tr>
          <td>Metasploit</td>
          <td>&mdash;</td>
          <td>&mdash;</td>
          <td>&mdash;</td>
          <td>Console</td>
          <td>Ruby, framework</td>
        </tr>
        <tr>
          <td>Amass</td>
          <td>&mdash;</td>
          <td>&mdash;</td>
          <td>&mdash;</td>
          <td>JSON</td>
          <td>Go, single-purpose</td>
        </tr>
        <tr>
          <td>ffuf</td>
          <td>&mdash;</td>
          <td>&mdash;</td>
          <td>&mdash;</td>
          <td>JSON</td>
          <td>Go, single-purpose</td>
        </tr>
      </tbody>
    </table>
  </div>
</div>

<!-- ===== KEY FEATURES ===== -->
<div class="lp-section fade-in" style="background:var(--bg-alt);padding-top:4rem;padding-bottom:4rem;max-width:100%;">
  <div style="max-width:var(--max-width);margin:0 auto;padding:0 1.5rem;">
    <div class="lp-section-header">
      <h2>Key Features</h2>
      <p>Everything you need for depth-oriented security assessment in a single platform.</p>
    </div>
    <div class="lp-card-grid">
      <div class="lp-card">
        <span class="lp-card-icon">&#9881;</span>
        <h3>41 Security Skills</h3>
        <p>Built-in skills covering web, API, cloud, and infrastructure security. Each carries MITRE ATT&CK, OWASP, CWE, and CAPEC metadata.</p>
      </div>
      <div class="lp-card">
        <span class="lp-card-icon">&#129302;</span>
        <h3>Reasoning Engine</h3>
        <p>18 goal types across vulnerability detection, risk assessment, exploit verification, and remediation planning with multi-call consensus.</p>
      </div>
      <div class="lp-card">
        <span class="lp-card-icon">&#9729;</span>
        <h3>Multi-Agent Platform</h3>
        <p>10 specialized agents collaborate through event/message buses with DAG-based workflows, checkpoint/resume, and isolated memory.</p>
      </div>
      <div class="lp-card">
        <span class="lp-card-icon">&#9889;</span>
        <h3>AI Provider Abstraction</h3>
        <p>Decoupled AI provider layer supporting OpenAI and Ollama with caching, metrics, middleware, retry, and circuit breaker.</p>
      </div>
      <div class="lp-card">
        <span class="lp-card-icon">&#128220;</span>
        <h3>Payload Intelligence</h3>
        <p>SQLite + FTS5-indexed payload repository with 5-level safety policy, 10-family mutation engine, provenance tracking, and feedback loop.</p>
      </div>
      <div class="lp-card">
        <span class="lp-card-icon">&#128221;</span>
        <h3>Community Payload Knowledge</h3>
        <p>Payloads are sourced from the community-maintained <a href="https://github.com/swisskyrepo/PayloadsAllTheThings">PayloadsAllTheThings</a> knowledge base, synchronized and indexed locally with provenance tracking.</p>
      </div>
      <div class="lp-card">
        <span class="lp-card-icon">&#128200;</span>
        <h3>Knowledge Graph</h3>
        <p>Entity-relationship store for findings, targets, payloads, and attack paths. Enables cross-scan correlation and relationship analysis.</p>
      </div>
      <div class="lp-card">
        <span class="lp-card-icon">&#128737;</span>
        <h3>Threat Modeling</h3>
        <p>STRIDE/LINDDUN categorization, trust boundary mapping, automated threat scenarios, and kill chain analysis.</p>
      </div>
      <div class="lp-card">
        <span class="lp-card-icon">&#128196;</span>
        <h3>Enterprise Reporting</h3>
        <p>JSON, Markdown, SARIF 2.1 (VS Code / CodeQL), HTML, attack graphs, purple team detection rules, and ZIP evidence packages.</p>
      </div>
      <div class="lp-card">
        <span class="lp-card-icon">&#128274;</span>
        <h3>Safety-by-Design</h3>
        <p>Non-bypassable destructive payload blocklist, WAF detection with auto-abort, configurable rate limiting, and policy-driven execution.</p>
      </div>
      <div class="lp-card">
        <span class="lp-card-icon">&#127793;</span>
        <h3>Community Recognition</h3>
        <p>HunterX is listed in the OWASP Community Vulnerability Scanning Tools catalog.</p>
        <p style="margin-top:0.5rem;"><a href="https://owasp.org/www-community/Vulnerability_Scanning_Tools">View on OWASP &rarr;</a></p>
      </div>
    </div>
  </div>
</div>

<!-- ===== ARCHITECTURE ===== -->
<div class="lp-section fade-in">
  <div class="lp-section-header">
    <h2>Architecture</h2>
    <p>Layered design with clear component responsibilities and defined communication interfaces.</p>
  </div>
  <div class="lp-architecture">
<pre>
                    +---------------------------+
                    |    CLI / API / Docker      |
                    +---------------------------+
                               |
                    +---------------------------+
                    |  Orchestration Engine      |
                    |  Observe &rarr; Hypothesize &rarr;  |
                    |  Probe &rarr; Verify          |
                    +------------+--------------+
                               |
                    +---------------------------+
                    |   Agents Platform          |
                    |   10 agents               |
                    |   Event / Message Bus     |
                    |   Workflow &amp; Checkpoint   |
                    +------------+--------------+
                               |
                    +---------------------------+
                    |   Reasoning Engine        |
                    |   18 goal types           |
                    |   Planner &amp; Validator     |
                    |   Multi-call Consensus    |
                    +------------+--------------+
                               |
                    +---------------------------+
                    |   Skills Registry         |
                    |   41 skills               |
                    |   Executor &amp; Policy       |
                    |   Cache                   |
                    +------------+--------------+
                               |
                    +---------------------------+
                    |   Payload Intelligence    |
                    |   FTS5 index              |
                    |   Mutation engine         |
                    |   Feedback loop           |
                    +------------+--------------+
                               |
                    +---------------------------+
                    |   Knowledge Graph         |
                    |   Entity relations        |
                    |   Attack paths            |
                    |   Context                 |
                    +------------+--------------+
                               |
                    +---------------------------+
                    |   Threat Modeling         |
                    |   STRIDE &amp; LINDDUN       |
                    |   Kill chains             |
                    |   Trust boundaries        |
                    +------------+--------------+
                               |
                    +---------------------------+
                    |    AI Provider            |
                    |   OpenAI / Ollama         |
                    |   Sessions &amp; Caching      |
                    |   Metrics                 |
                    +------------+--------------+
                               |
                    +---------------------------+
                    |        Reporter           |
                    |   JSON / MD / SARIF       |
                    |   HTML / Graph            |
                    +---------------------------+
</pre>
    <p style="text-align:center;margin-top:1rem;">Payload Intelligence is backed by the community-maintained
    <a href="https://github.com/swisskyrepo/PayloadsAllTheThings">PayloadsAllTheThings</a> knowledge base
    (<code>hunterx payload sync</code>).</p>
  </div>
</div>

<!-- ===== WORKFLOW ===== -->
<div class="lp-section fade-in" style="background:var(--bg-alt);padding-top:4rem;padding-bottom:4rem;max-width:100%;">
  <div style="max-width:var(--max-width);margin:0 auto;padding:0 1.5rem;">
    <div class="lp-section-header">
      <h2>Assessment Workflow</h2>
      <p>The HunterX reasoning pipeline drives every scan through four distinct phases.</p>
    </div>
    <div class="lp-workflow">
<pre>
  +----------+     +----------+     +----------+     +----------+     +----------+
  |  Target  |     |  Recon   |     |Reasoning |     | Payload  |     |Reporting |
  |  Input   | &rarr;  |  Intel   | &rarr;  | Engine   | &rarr;  |  Intel   | &rarr;  |  Output  |
  | URL/     |     | Finger-  |     | Hypothes-|     | Select   |     | JSON/MD  |
  | Domain   |     | printing |     | ize      |     | Mutate   |     | SARIF    |
  +----------+     | WAF Det. |     | Plan     |     | Execute  |     | HTML     |
                   +----------+     | Verify   |     +----------+     | Graph    |
                                    +----------+                      +----------+
                                              \                          /
                                               \  +----------------+   /
                                                &rarr; | Verification  | &larr;
                                                    | Agent         |
                                                    | Confidence    |
                                                    | Scoring       |
                                                    | FP Filtering  |
                                                    +----------------+
</pre>
    <p style="text-align:center;margin-top:1rem;">Payload selection draws on the locally indexed
    <a href="https://github.com/swisskyrepo/PayloadsAllTheThings">PayloadsAllTheThings</a> knowledge base
    with provenance tracking.</p>
  </div>
</div>
</div>

<!-- ===== SHOWCASE ===== -->
<div class="lp-section fade-in">
  <div class="lp-section-header">
    <h2>Showcase</h2>
    <p>HunterX in action &mdash; from reconnaissance through reporting.</p>
  </div>
  <div class="lp-showcase">
    <div class="lp-showcase-item">
      <div class="lp-showcase-placeholder">
        <code>hunterx scan target.com --profile bounty --preset quick</code>
      </div>
      <div class="caption">CLI Scan Execution</div>
    </div>
    <div class="lp-showcase-item">
      <div class="lp-showcase-placeholder" style="aspect-ratio:16/12;">
        <code>SARIF 2.1 &bull; HTML &bull; Knowledge Graph</code>
      </div>
      <div class="caption">Reporting Formats</div>
    </div>
    <div class="lp-showcase-item">
      <div class="lp-showcase-placeholder">
        <code>41 Skills &bull; 18 Goals &bull; 10 Agents</code>
      </div>
      <div class="caption">Architecture Overview</div>
    </div>
  </div>
</div>

<!-- ===== COMMUNITY ===== -->
<div class="lp-section fade-in" style="background:var(--bg-alt);padding-top:4rem;padding-bottom:4rem;max-width:100%;">
  <div style="max-width:var(--max-width);margin:0 auto;padding:0 1.5rem;">
    <div class="lp-section-header">
      <h2>Community</h2>
      <p>HunterX is open-source and community-driven. Apache 2.0 licensed.</p>
    </div>
    <div class="lp-community-links">
      <a href="https://github.com/nullc0d30/HunterX" class="lp-community-link">
        <span class="link-icon">&#9733;</span>
        <div><div class="link-text">GitHub</div><div class="link-desc">Star &amp; fork the repository</div></div>
      </a>
      <a href="https://github.com/nullc0d30/HunterX/issues" class="lp-community-link">
        <span class="link-icon">&#9888;</span>
        <div><div class="link-text">Issues</div><div class="link-desc">Report bugs &amp; request features</div></div>
      </a>
      <a href="https://github.com/nullc0d30/HunterX/discussions" class="lp-community-link">
        <span class="link-icon">&#9993;</span>
        <div><div class="link-text">Discussions</div><div class="link-desc">Ask questions &amp; share ideas</div></div>
      </a>
      <a href="{{ '/blog' | relative_url }}" class="lp-community-link">
        <span class="link-icon">&#128214;</span>
        <div><div class="link-text">Blog</div><div class="link-desc">News, guides &amp; deep dives</div></div>
      </a>
      <a href="{{ '/roadmap' | relative_url }}" class="lp-community-link">
        <span class="link-icon">&#128197;</span>
        <div><div class="link-text">Roadmap</div><div class="link-desc">What&rsquo;s coming next</div></div>
      </a>
      <a href="{{ '/contributing' | relative_url }}" class="lp-community-link">
        <span class="link-icon">&#128187;</span>
        <div><div class="link-text">Contributing</div><div class="link-desc">How to get involved</div></div>
      </a>
    </div>
  </div>
</div>

<!-- ===== RELATED PROJECTS ===== -->
<div class="lp-section fade-in" style="padding-top:2rem;padding-bottom:2rem;">
  <div class="lp-section-header" style="margin-bottom:1.5rem;">
    <h2 style="font-size:1.2rem;">Related Projects</h2>
  </div>
  <div style="display:flex;justify-content:center;flex-wrap:wrap;gap:1rem;">
    <a href="https://ahmedawadresearch.github.io" style="padding:0.5rem 1rem;border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-size:0.9rem;">Ahmed Awad Research</a>
    <a href="https://anubisxframework.github.io/" style="padding:0.5rem 1rem;border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-size:0.9rem;">AnubisX Framework</a>
  </div>
</div>

<!-- ===== ABOUT ===== -->
<div class="lp-section fade-in">
  <div class="lp-section-header">
    <h2>About</h2>
    <p>HunterX is built with a focus on reasoning-driven security assessment, safety-by-design, and multi-format reporting (JSON, HTML, SARIF).</p>
  </div>
  <div class="lp-about-grid">
    <div class="lp-about-card">
      <h3>&#128100; Author</h3>
      <p><strong>Ahmed Awad</strong> (NullC0d3) &mdash; Cybersecurity Threat Intelligence Analyst and open-source developer. Creator of HunterX, AnubisX Framework, and RabbitHole.</p>
      <p style="margin-top:0.5rem;"><a href="{{ '/about-author' | relative_url }}">Learn more &rarr;</a></p>
    </div>
    <div class="lp-about-card">
      <h3>&#127919; Mission</h3>
      <p>Democratize intelligent vulnerability assessment by combining AI-assisted reasoning with comprehensive security testing in a single, extensible open-source platform.</p>
    </div>
    <div class="lp-about-card">
      <h3>&#128752; Responsible Use</h3>
      <p>HunterX is provided exclusively for authorized security testing. Users are solely responsible for obtaining authorization before scanning any target.</p>
      <p style="margin-top:0.5rem;"><a href="{{ '/responsible-use' | relative_url }}">Read the policy &rarr;</a></p>
    </div>
    <div class="lp-about-card">
      <h3>&#128214; License</h3>
      <p>Released under the Apache License, Version 2.0. Free to use, modify, and distribute for any purpose.</p>
      <p style="margin-top:0.5rem;"><a href="{{ '/license' | relative_url }}">View license &rarr;</a></p>
    </div>
  </div>
</div>

<!-- ===== DOCS CTA ===== -->
<div class="lp-docs-cta fade-in">
  <h2>Documentation</h2>
  <p>Explore the complete documentation, API reference, tutorials, and guides.</p>
  <a href="{{ '/documentation' | relative_url }}" class="primary">Browse Documentation &rarr;</a>
</div>
