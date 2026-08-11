---
layout: default
title: Red Team Framework — HunterX v7 Mission Orchestration
keywords: red team, red team framework, red team tools, red team automation, offensive security platform, red team operations, attack path planning, adversarial simulation, mission orchestration
description: >-
  How HunterX v7 supports red team operations: mission orchestration,
  attack-path planning, cloud and SaaS intelligence, knowledge-graph
  correlation, evidence-driven findings and professional reporting for
  authorized red team engagements.
---

# Red Team Framework

HunterX is an **AI-powered offensive security platform** built for the way red
teams work: plan a mission, orchestrate many tools, understand the target and
its cloud footprint, and produce findings that decision-makers can act on.

## Mission orchestration for red teams

HunterX v7 organizes work as **missions** — full-spectrum assessment campaigns
that can be created, run, checkpointed, resumed and finalized:

- `hunterx mission create/start/status/pause/resume/cancel/finalize`
- `hunterx hunt ...` for full-spectrum missions
- `hunterx mission plan/replan/paths/explain` for adaptive mission planning

## Attack-path planning

Adaptive mission planning selects the next best action with explanation:
attack-path planning, replanning and explainable next-best-action selection
keep the mission moving toward validated findings.

## Cloud & SaaS intelligence

Red team engagements increasingly target cloud and SaaS attack surface.
HunterX provides evidence-backed cloud/SaaS intelligence for authorized
targets — provider detection, cloud resource intelligence, exposure and
environment classification, and topology — across AWS, Azure, GCP, OCI,
Cloudflare, DigitalOcean, Akamai, Fastly, Vercel, Netlify, Heroku, Render,
Fly.io, Supabase, Firebase, Kubernetes and Docker. Cloud intelligence is
passive and never accesses cloud resources.

## Knowledge graph & correlation

Results across tools and missions are correlated into a knowledge graph of
entities and relationships (targets, assets, observations, findings, evidence,
proofs, attack paths), enabling cross-scan correlation and context-aware
reasoning.

## Evidence-driven findings

Red team findings need to survive scrutiny. HunterX validates with evidence,
engineers minimal safe proofs and PoCs, replays them for reproducibility, and
produces professional reports (Markdown, HTML, JSON, SARIF, PDF, package).

## Tools for red team operations

HunterX orchestrates the ecosystem: Amass, Subfinder, Findomain, Nmap, Naabu,
Masscan, HTTPx, Katana, FFUF, Nuclei, SQLmap, Dalfox, Metasploit (execution
only), SearchSploit, ExploitDB and more. See the
[Tool Ecosystem](/tool-ecosystem/) for the full list with integration status.

## Responsible use

HunterX is authorized security testing and research. Red team operations must
have written authorization, defined scope, and rules of engagement. The
platform enforces scope and authorization guards and a safety policy. See
[Responsible Use](/responsible-use/).

## Getting started

- [Installation](/installation/)
- [Quickstart](/quickstart/)
- [Mission Orchestration](/v7-autonomous-mission-orchestration/)
- [Adaptive Mission Planning](/v7-adaptive-mission-planning/)
- [Cloud & SaaS Intelligence](/v7-cloud-saas-intelligence/)
