---
layout: default
title: HunterX — AI-Assisted Vulnerability Discovery, Validation & Proof Engine
keywords: HunterX, HunterX v7, AI vulnerability scanner, AI penetration testing, AI-assisted vulnerability discovery, vulnerability validation, PoC generation, proof of concept security, bug bounty tools, penetration testing tools, red team framework, offensive security platform, open source vulnerability scanner, web application security, API security, cloud security, security reconnaissance, security automation, security testing
description: >-
  HunterX is an AI-assisted vulnerability discovery, validation and proof
  engine for authorized cybersecurity testing and research. It plans,
  orchestrates, executes, validates, correlates and reports security
  assessments by integrating open-source security tools — from discovery to
  verified findings, PoC, evidence, reproducibility, impact and report-ready
  output. Apache 2.0.
---

<!-- ===== HERO ===== -->
<div class="lp-hero">
  <img src="{{ '/assets/images/logo.png' | relative_url }}" alt="HunterX Official Logo" class="lp-hero-logo">
  <h1>HunterX</h1>
  <div class="subtitle">AI-Assisted Vulnerability Discovery, Validation &amp; Proof Engine</div>
  <div class="pipeline"><span>Find it.</span> <span>Verify it.</span> <span>Prove it.</span> <span>Report it.</span></div>
  <p>Not just another scanner. HunterX combines reconnaissance, security tooling, AI-assisted reasoning, vulnerability validation, PoC generation and validation, evidence collection, correlation, and report generation into one workflow.</p>
  <div class="lp-hero-actions">
    <a href="{{ '/installation' | relative_url }}" class="primary">Install HunterX</a>
    <a href="{{ '/quickstart' | relative_url }}" class="secondary">Quickstart</a>
    <a href="https://github.com/nullc0d30/HunterX" class="secondary">GitHub</a>
  </div>
  <div class="lp-hero-badges">
    <a href="https://github.com/nullc0d30/HunterX/releases"><img src="https://img.shields.io/github/v/release/nullc0d30/HunterX?style=flat-square&logo=github" alt="Release"></a>
    <a href="https://github.com/nullc0d30/HunterX/actions"><img src="https://img.shields.io/github/actions/workflow/status/nullc0d30/HunterX/test.yml?style=flat-square&label=tests" alt="Tests"></a>
    <a href="https://www.apache.org/licenses/LICENSE-2.0"><img src="https://img.shields.io/badge/license-Apache%202.0-green?style=flat-square" alt="License"></a>
    <a href="https://hub.docker.com/r/nullc0d30/hunterx"><img src="https://img.shields.io/badge/docker-multi--stage-2496ED?style=flat-square&logo=docker" alt="Docker"></a>
    <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.11%2B-blue?style=flat-square&logo=python" alt="Python"></a>
    <a href="https://github.com/nullc0d30/HunterX"><img src="https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey?style=flat-square" alt="Platform"></a>
  </div>
</div>

<!-- ===== WHY HUNTERX? ===== -->
<div class="lp-section fade-in">
  <div class="lp-section-header">
    <h2>Why HunterX?</h2>
    <p>HunterX is not designed merely to tell you that a vulnerability might exist. It takes the investigation further — DISCOVER &rarr; REASON &rarr; TEST &rarr; VERIFY &rarr; PROVE &rarr; GENERATE PoC &rarr; VALIDATE &rarr; REPORT.</p>
  </div>
  <div class="lp-compare-table">
    <table>
      <thead>
        <tr>
          <th>Capability</th>
          <th>Traditional Scanner</th>
          <th>HunterX v7</th>
        </tr>
      </thead>
      <tbody>
        <tr class="highlight">
          <td>Output</td>
          <td>Candidate / &ldquo;Possible&rdquo; finding + confidence</td>
          <td>Validated finding + evidence + reproducibility + impact + PoC</td>
        </tr>
        <tr>
          <td>Validation</td>
          <td>Signature match</td>
          <td>Evidence-driven hypothesis testing &amp; proof contracts</td>
        </tr>
        <tr>
          <td>PoC</td>
          <td>&mdash;</td>
          <td>Minimal safe PoC generation, replay &amp; validation</td>
        </tr>
        <tr>
          <td>Reporting</td>
          <td>Raw JSON</td>
          <td>Report-ready: Markdown, HTML, JSON, SARIF, PDF, package</td>
        </tr>
        <tr>
          <td>Tooling</td>
          <td>Single engine</td>
          <td>Orchestrates 92 open-source security tools</td>
        </tr>
        <tr>
          <td>Intelligence</td>
          <td>&mdash;</td>
          <td>Target intelligence, cloud/SaaS intelligence, knowledge graph</td>
        </tr>
      </tbody>
    </table>
  </div>
  <p style="text-align:center;margin-top:1.5rem;color:var(--text-muted);">Less noise. More verified findings.</p>
</div>

<!-- ===== DETECTION TO PROOF ===== -->
<div class="lp-section fade-in" style="background:var(--bg-alt);padding-top:4rem;padding-bottom:4rem;max-width:100%;">
  <div style="max-width:var(--max-width);margin:0 auto;padding:0 1.5rem;">
    <div class="lp-section-header">
      <h2>From Detection to Proof</h2>
      <p>A vulnerability detection is not a validated finding. HunterX carries every candidate through the full investigation.</p>
    </div>
    <div class="lp-workflow">
<pre>
  SQL Injection
     &darr;
  Affected asset
     &darr;
  Endpoint
     &darr;
  Parameter
     &darr;
  Observed behavior
     &darr;
  Verification
     &darr;
  Evidence
     &darr;
  Minimal reproducible PoC
     &darr;
  PoC validation
     &darr;
  Impact assessment
     &darr;
  Report-ready finding
</pre>
    </div>
    <p style="text-align:center;margin-top:1.5rem;">
      <strong>Vulnerability + Evidence + Reproducibility + Impact + PoC = Validated Finding</strong>
    </p>
  </div>
</div>

<!-- ===== HOW HUNTERX WORKS ===== -->
<div class="lp-section fade-in">
  <div class="lp-section-header">
    <h2>How HunterX Works</h2>
    <p>HunterX orchestrates the security-tool ecosystem — it reasons, correlates, verifies, proves and reports, rather than replacing the tools you already use.</p>
  </div>
  <div class="lp-workflow">
<pre>
  DISCOVER
     &darr;
  FINGERPRINT
     &darr;
  REASON
     &darr;
  HYPOTHESIZE
     &darr;
  PROBE
     &darr;
  VERIFY
     &darr;
  PROVE
     &darr;
  POC
     &darr;
  REPLAY
     &darr;
  CORRELATE
     &darr;
  REPORT
</pre>
  </div>
</div>

<!-- ===== SECURITY COVERAGE ===== -->
<div class="lp-section fade-in" style="background:var(--bg-alt);padding-top:4rem;padding-bottom:4rem;max-width:100%;">
  <div style="max-width:var(--max-width);margin:0 auto;padding:0 1.5rem;">
    <div class="lp-section-header">
      <h2>Security Coverage</h2>
      <p>Discovery, validation and proof across the vulnerability classes HunterX is designed for.</p>
    </div>
    <div class="lp-card-grid">
      <div class="lp-card"><span class="lp-card-icon">&#128187;</span><h3>Web Application Security</h3><p>SQL/NoSQL injection, XSS, SSTI, XXE, path traversal/LFI, command-injection indicators, open redirect, CORS and security misconfiguration.</p></div>
      <div class="lp-card"><span class="lp-card-icon">&#128279;</span><h3>API &amp; GraphQL Security</h3><p>API discovery, OpenAPI/Postman parsing, GraphQL introspection, broken access control (IDOR/BOLA), authentication and authorization.</p></div>
      <div class="lp-card"><span class="lp-card-icon">&#9729;</span><h3>Cloud &amp; SaaS Attack Surface</h3><p>Provider detection, cloud resource intelligence, exposure/environment classification and topology for AWS, Azure, GCP, OCI, Cloudflare and more.</p></div>
      <div class="lp-card"><span class="lp-card-icon">&#128736;</span><h3>Network &amp; Infrastructure</h3><p>Port/service/version discovery, OSINT, DNS intelligence and live-host service discovery orchestrated through the toolchain.</p></div>
      <div class="lp-card"><span class="lp-card-icon">&#128273;</span><h3>Secrets &amp; Code Analysis</h3><p>Secret scanning (Gitleaks, TruffleHog, detect-secrets), SAST (Semgrep) and dependency scanning for source/code assessments.</p></div>
      <div class="lp-card"><span class="lp-card-icon">&#129302;</span><h3>Novel / Unknown Behavior</h3><p>Hypothesis-driven discovery and investigation of unknown or application-specific behaviors — without claiming guaranteed zero-day discovery.</p></div>
    </div>
  </div>
</div>

<!-- ===== TOOL ECOSYSTEM ===== -->
<div class="lp-section fade-in">
  <div class="lp-section-header">
    <h2>Built to Work With the Security Tooling Ecosystem</h2>
    <p>HunterX orchestrates the ecosystem rather than owning every security capability itself.</p>
  </div>
  <div class="lp-card-grid">
    <div class="lp-card"><span class="lp-card-icon">&#128269;</span><h3>Recon / Asset Discovery</h3><p>Amass, Subfinder, Assetfinder, Findomain, DNSx, MassDNS, Shuffledns, theHarvester, BBOT and more.</p></div>
    <div class="lp-card"><span class="lp-card-icon">&#128225;</span><h3>Network / Port Scanning</h3><p>Naabu, Nmap, Masscan and RustScan.</p></div>
    <div class="lp-card"><span class="lp-card-icon">&#127760;</span><h3>HTTP / Crawling / Discovery</h3><p>HTTPx, WhatWeb, Katana, Gospider, Hakrawler, GAU, Waybackurls and URLFinder.</p></div>
    <div class="lp-card"><span class="lp-card-icon">&#9881;</span><h3>Fuzzing / Content Discovery</h3><p>FFUF, Feroxbuster, Gobuster and Dirsearch.</p></div>
    <div class="lp-card"><span class="lp-card-icon">&#128295;</span><h3>Parameter / Endpoint Discovery</h3><p>Arjun, ParamSpider, Kiterunner, LinkFinder, SecretFinder and xnLinkFinder.</p></div>
    <div class="lp-card"><span class="lp-card-icon">&#128737;</span><h3>Vulnerability Detection / Validation</h3><p>Nuclei, Dalfox, XSStrike, SQLmap, Ghauri, Commix, Interactsh, Tplmap, SSTImap, XXEinjector, GraphQLmap and InQL.</p></div>
    <div class="lp-card"><span class="lp-card-icon">&#128272;</span><h3>Source / Code / Secret Analysis</h3><p>Gitleaks, TruffleHog and Semgrep.</p></div>
    <div class="lp-card"><span class="lp-card-icon">&#128172;</span><h3>Proxy / Web Security</h3><p>OWASP ZAP and mitmproxy.</p></div>
    <div class="lp-card"><span class="lp-card-icon">&#128298;</span><h3>Exploitation / Security Research</h3><p>Metasploit, SearchSploit and ExploitDB.</p></div>
    <div class="lp-card"><span class="lp-card-icon">&#128214;</span><h3>Knowledge / Payload Resources</h3><p>PayloadsAllTheThings, SecLists and FuzzDB.</p></div>
  </div>
  <p style="text-align:center;margin-top:1.5rem;"><a href="{{ '/tool-ecosystem' | relative_url }}">Explore the full Tool Ecosystem &rarr;</a></p>
</div>

<!-- ===== POC & VALIDATION ===== -->
<div class="lp-section fade-in" style="background:var(--bg-alt);padding-top:4rem;padding-bottom:4rem;max-width:100%;">
  <div style="max-width:var(--max-width);margin:0 auto;padding:0 1.5rem;">
    <div class="lp-section-header">
      <h2>PoC &amp; Validation</h2>
      <p>Proof is part of vulnerability validation — not an afterthought.</p>
    </div>
    <div class="lp-workflow">
<pre>
  HYPOTHESIS &rarr; PROOF CONTRACT &rarr; REQUIRED EVIDENCE &rarr; MINIMAL PROOF
  STRATEGY &rarr; PROOF CONSTRUCTION &rarr; SAFETY VALIDATION &rarr; SCOPE
  VALIDATION &rarr; EXECUTION &rarr; REPLAY &rarr; EVIDENCE EVALUATION &rarr;
  IMPACT &rarr; CONFIDENCE &rarr; VALIDATED FINDING &rarr; REPRODUCTION PACKAGE
  &rarr; REPORT
</pre>
    </div>
    <div class="lp-card-grid">
      <div class="lp-card"><span class="lp-card-icon">&#9989;</span><h3>Proof Contracts</h3><p>Per-class contracts define preconditions, allowed/forbidden actions, required evidence and expected behavior for SQLi, XSS, SSRF, LFI, IDOR, SSTI, XXE and more.</p></div>
      <div class="lp-card"><span class="lp-card-icon">&#128260;</span><h3>Replay &amp; Reproducibility</h3><p>PoCs are replayed deterministically; reproducibility requires repeated successful replays — never a single run.</p></div>
      <div class="lp-card"><span class="lp-card-icon">&#128202;</span><h3>Evidence-Driven Impact</h3><p>Impact is classified strictly from captured evidence; confidence is a versioned, weighted policy over named factors — never a universal percentage.</p></div>
      <div class="lp-card"><span class="lp-card-icon">&#128274;</span><h3>Safety-by-Design</h3><p>Minimal safe proofs. No data destruction, persistence, reverse shells, DoS or mass data extraction is ever scheduled.</p></div>
    </div>
    <p style="text-align:center;margin-top:1.5rem;"><a href="{{ '/poc-validation' | relative_url }}">Learn about the PoC &amp; Proof engine &rarr;</a></p>
  </div>
</div>

<!-- ===== TARGET INTELLIGENCE ===== -->
<div class="lp-section fade-in">
  <div class="lp-section-header">
    <h2>Target Intelligence</h2>
    <p>HunterX maintains structured target intelligence instead of treating every scan as an isolated command.</p>
  </div>
  <div class="lp-card-grid">
    <div class="lp-card"><span class="lp-card-icon">&#128230;</span><h3>Assets &amp; Targets</h3><p>A persistent view of the surface under assessment.</p></div>
    <div class="lp-card"><span class="lp-card-icon">&#128200;</span><h3>Observations &amp; Findings</h3><p>Canonical, normalized results from every tool run, correlated into findings.</p></div>
    <div class="lp-card"><span class="lp-card-icon">&#128221;</span><h3>Evidence &amp; History</h3><p>Provenance-backed evidence and target snapshots, diffs and change detection.</p></div>
    <div class="lp-card"><span class="lp-card-icon">&#128506;</span><h3>Relationships &amp; Topology</h3><p>How assets, services and cloud resources relate — feeding correlation.</p></div>
    <div class="lp-card"><span class="lp-card-icon">&#128204;</span><h3>Mission State</h3><p>Checkpoint/resume, campaign state and tool-result records.</p></div>
    <div class="lp-card"><span class="lp-card-icon">&#9729;</span><h3>Cloud Intelligence</h3><p>Cloud/SaaS attack-surface intelligence persisted alongside target data.</p></div>
  </div>
</div>

<!-- ===== CLOUD & SAAS ===== -->
<div class="lp-section fade-in" style="background:var(--bg-alt);padding-top:4rem;padding-bottom:4rem;max-width:100%;">
  <div style="max-width:var(--max-width);margin:0 auto;padding:0 1.5rem;">
    <div class="lp-section-header">
      <h2>Cloud &amp; SaaS Intelligence</h2>
      <p>Evidence-backed cloud and SaaS attack-surface intelligence for authorized targets.</p>
    </div>
    <div class="lp-card-grid">
      <div class="lp-card"><span class="lp-card-icon">&#9742;</span><h3>Provider Coverage</h3><p>AWS, Azure, GCP, OCI, Cloudflare, DigitalOcean, Akamai, Fastly, Vercel, Netlify, Heroku, Render, Fly.io, Supabase, Firebase, Kubernetes and Docker.</p></div>
      <div class="lp-card"><span class="lp-card-icon">&#128506;</span><h3>Topology</h3><p>Account/region/resource relationships and cloud architecture edges.</p></div>
      <div class="lp-card"><span class="lp-card-icon">&#128273;</span><h3>Exposure &amp; Environment</h3><p>Exposure classification and production/staging/dev environment classification.</p></div>
      <div class="lp-card"><span class="lp-card-icon">&#128274;</span><h3>Passive by Design</h3><p>Built from static evidence (DNS, TLS, HTTP headers, HTML/JS, OpenAPI). Never authenticates to cloud accounts, never accesses cloud resources, never retrieves secrets.</p></div>
    </div>
    <p style="text-align:center;margin-top:1.5rem;"><a href="{{ '/v7-cloud-saas-intelligence' | relative_url }}">Read the Cloud &amp; SaaS Intelligence reference &rarr;</a></p>
  </div>
</div>

<!-- ===== KNOWLEDGE GRAPH ===== -->
<div class="lp-section fade-in">
  <div class="lp-section-header">
    <h2>Knowledge Graph &amp; Attack Paths</h2>
    <p>HunterX correlates results across tools and missions into a knowledge graph of entities and relationships — enabling cross-scan correlation, attack-path analysis and context-aware reasoning.</p>
  </div>
  <div class="lp-workflow">
<pre>
  Targets &harr; Assets &harr; Observations &harr; Findings &harr; Evidence &harr; Proofs &harr; Attack Paths
</pre>
  </div>
</div>

<!-- ===== REPORTING ===== -->
<div class="lp-section fade-in" style="background:var(--bg-alt);padding-top:4rem;padding-bottom:4rem;max-width:100%;">
  <div style="max-width:var(--max-width);margin:0 auto;padding:0 1.5rem;">
    <div class="lp-section-header">
      <h2>Reporting</h2>
      <p>The workflow does not end at detection. HunterX turns validated findings into structured, professional reports.</p>
    </div>
    <div class="lp-card-grid">
      <div class="lp-card"><span class="lp-card-icon">&#128196;</span><h3>Markdown &amp; HTML</h3><p>Human-readable findings and visual dashboards.</p></div>
      <div class="lp-card"><span class="lp-card-icon">&#128203;</span><h3>JSON &amp; SARIF 2.1</h3><p>Machine-parsable output; VS Code / GitHub CodeQL integration.</p></div>
      <div class="lp-card"><span class="lp-card-icon">&#128190;</span><h3>PDF &amp; Packages</h3><p>Document export and ZIP evidence bundles.</p></div>
      <div class="lp-card"><span class="lp-card-icon">&#128200;</span><h3>Report Contents</h3><p>Finding, asset, endpoint, parameter, evidence, verification, PoC, reproduction, impact, confidence, relationships, risk/context and remediation where supported.</p></div>
    </div>
  </div>
</div>

<!-- ===== USE CASES ===== -->
<div class="lp-section fade-in">
  <div class="lp-section-header">
    <h2>Who Uses HunterX</h2>
    <p>An AI-powered offensive security platform for the people doing authorized security work.</p>
  </div>
  <div class="lp-card-grid">
    <div class="lp-card"><span class="lp-card-icon">&#127919;</span><h3>Bug Bounty Hunters</h3><p>Evidence-backed findings, minimal reproducible PoCs and report-ready packages.</p></div>
    <div class="lp-card"><span class="lp-card-icon">&#128737;</span><h3>Penetration Testers</h3><p>Structured missions, professional reports, remediation and retest planning.</p></div>
    <div class="lp-card"><span class="lp-card-icon">&#128064;</span><h3>Red Teams</h3><p>Mission orchestration, attack-path planning, cloud/SaaS intelligence and correlation.</p></div>
    <div class="lp-card"><span class="lp-card-icon">&#129302;</span><h3>Security Researchers</h3><p>Hypothesis-driven investigation of unknown and application-specific behaviors.</p></div>
    <div class="lp-card"><span class="lp-card-icon">&#128295;</span><h3>Application Security Engineers</h3><p>Validated findings with PoC, impact and confidence instead of candidate noise.</p></div>
    <div class="lp-card"><span class="lp-card-icon">&#128267;</span><h3>DevSecOps &amp; Security Teams</h3><p>CI/CD integration, SARIF, REST API and reproducible results.</p></div>
  </div>
</div>

<!-- ===== ARCHITECTURE ===== -->
<div class="lp-section fade-in" style="background:var(--bg-alt);padding-top:4rem;padding-bottom:4rem;max-width:100%;">
  <div style="max-width:var(--max-width);margin:0 auto;padding:0 1.5rem;">
    <div class="lp-section-header">
      <h2>Architecture</h2>
      <p>A Clean Architecture Python core with clear component responsibilities and defined communication interfaces.</p>
    </div>
    <div class="lp-architecture">
<pre>
                +-----------------------------+
                |  CLI / API / Docker          |
                +-----------------------------+
                           |
                +-----------------------------+
                |  Mission & Workflow Engines  |
                |  Orchestrate &rarr; Reason &rarr;      |
                |  Validate &rarr; Prove &rarr; Report   |
                +-------------+---------------+
                           |
                +-----------------------------+
                |  Toolchain Intelligence      |
                |  92 tools &middot; SDK &middot; Parser/  |
                |  Normalizer &middot; Chaining      |
                +-------------+---------------+
                           |
                +-----------------------------+
                |  Proof / PoC Engine          |
                |  Contracts &middot; Replay &middot;      |
                |  Reproducibility &middot; Impact   |
                +-------------+---------------+
                           |
                +-----------------------------+
                |  Target Intelligence &amp; TIDB  |
                |  Assets &middot; Findings &middot;         |
                |  Evidence &middot; Cloud &middot; Topology |
                +-------------+---------------+
                           |
                +-----------------------------+
                |  Knowledge Graph &amp; Events    |
                |  Correlation &middot; Attack Paths |
                +-------------+---------------+
                           |
                +-----------------------------+
                |  Reporter                   |
                |  MD / HTML / JSON / SARIF / |
                |  PDF / package              |
                +-----------------------------+
</pre>
    </div>
  </div>
</div>

<!-- ===== INTEGRATIONS ===== -->
<div class="lp-section fade-in">
  <div class="lp-section-header">
    <h2>Integrations</h2>
    <p>HunterX integrates with the open-source security ecosystem and your pipeline.</p>
  </div>
  <div class="lp-card-grid">
    <div class="lp-card"><span class="lp-card-icon">&#128279;</span><h3>Security Tools</h3><p>92 registered tools across recon, scanning, crawling, fuzzing, parameters, validation, secrets, SAST, proxies, exploitation and knowledge resources.</p></div>
    <div class="lp-card"><span class="lp-card-icon">&#129302;</span><h3>AI Providers</h3><p>LLM-native reasoning through a decoupled AI provider layer.</p></div>
    <div class="lp-card"><span class="lp-card-icon">&#128267;</span><h3>CI/CD</h3><p>Docker images, SARIF export for GitHub CodeQL, and a REST API for pipeline integration.</p></div>
    <div class="lp-card"><span class="lp-card-icon">&#128451;</span><h3>Persistence</h3><p>SQL (SQLite default, PostgreSQL supported) via TIDB with Alembic migrations.</p></div>
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
      <a href="{{ '/contributing' | relative_url }}" class="lp-community-link">
        <span class="link-icon">&#128187;</span>
        <div><div class="link-text">Contributing</div><div class="link-desc">How to get involved</div></div>
      </a>
      <a href="{{ '/changelog' | relative_url }}" class="lp-community-link">
        <span class="link-icon">&#128197;</span>
        <div><div class="link-text">Changelog</div><div class="link-desc">What&rsquo;s new in v7</div></div>
      </a>
    </div>
  </div>
</div>

<!-- ===== INSTALL ===== -->
<div class="lp-docs-cta fade-in">
  <h2>Installation</h2>
  <p>Requirements: Python 3.11+ on Linux, macOS or Windows.</p>
  <p style="font-family:var(--font-mono);font-size:0.9rem;background:var(--bg-code);border:1px solid var(--border);border-radius:var(--radius);padding:0.75rem 1rem;max-width:640px;margin:0 auto 1.5rem;overflow-x:auto;">
    curl -sSL https://raw.githubusercontent.com/nullc0d30/HunterX/main/install.sh | sudo bash
  </p>
  <div style="display:flex;justify-content:center;flex-wrap:wrap;gap:0.75rem;margin-bottom:1.5rem;">
    <a href="{{ '/installation' | relative_url }}" class="primary">Installation Guide</a>
    <a href="{{ '/quickstart' | relative_url }}" class="primary" style="background:var(--gradient-end);">Quickstart</a>
  </div>
  <p><a href="{{ '/documentation' | relative_url }}">Browse Documentation &rarr;</a></p>
</div>

<!-- ===== RESPONSIBLE USE ===== -->
<div class="lp-section fade-in">
  <div class="lp-section-header">
    <h2>Responsible Use</h2>
    <p>HunterX is an authorized cybersecurity testing and research platform. It is designed to be used only against systems you own or are explicitly authorized to test. You are responsible for obtaining appropriate authorization before testing any system and for complying with all applicable laws and terms of service.</p>
  </div>
  <div style="text-align:center;">
    <a href="{{ '/responsible-use' | relative_url }}" class="primary" style="display:inline-flex;align-items:center;padding:0.75rem 1.5rem;border-radius:var(--radius);background:var(--accent);color:#fff;font-weight:600;">Read the Responsible Use policy &rarr;</a>
  </div>
</div>

<!-- ===== IDENTITY ===== -->
<div class="lp-section fade-in" style="padding-top:2rem;padding-bottom:1rem;">
  <div class="lp-section-header">
    <h2 style="font-size:1.4rem;">About HunterX</h2>
    <p>HunterX is created and maintained by <strong>Ahmed Awad (AKA NullC0d3)</strong>.
    The canonical project is the GitHub repository
    <a href="https://github.com/nullc0d30/HunterX">nullc0d30/HunterX</a>.</p>
  </div>
</div>

<!-- ===== ABOUT ===== -->
<div class="lp-section fade-in" style="padding-top:1rem;padding-bottom:2rem;">
  <div class="lp-about-grid">
    <div class="lp-about-card">
      <h3>&#128100; Author</h3>
      <p><strong>Ahmed Awad</strong> (NullC0d3) &mdash; Cybersecurity Threat Intelligence Analyst and open-source developer. Creator and maintainer of HunterX.</p>
      <p style="margin-top:0.5rem;"><a href="{{ '/about-author' | relative_url }}">Learn more &rarr;</a></p>
    </div>
    <div class="lp-about-card">
      <h3>&#127919; Mission</h3>
      <p>Democratize intelligent vulnerability assessment by combining AI-assisted reasoning with evidence-driven validation, proof and reporting in a single, extensible open-source platform.</p>
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
