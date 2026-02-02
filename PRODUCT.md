# HunterX Product Identity

## Overview
HunterX is a professional, decision-driven offensive framework designed for Red Team operations. It prioritizes accuracy, stealth, and safety over speed. Unlike traditional scanners, HunterX employs a strict 4-stage orchestration pipeline to ensure evidence-grade results with zero false positives and minimal noise.

## 🛑 Safety & Guardrails
HunterX performs **NON-DESTRUCTIVE VERIFICATION ONLY**.

### Hard Guardrails
The following actions are **strictly blocked** at the kernel level and cannot be bypassed via CLI flags:
- **File System Modification**: `rm`, `del`, `mkfs`, `dd`, `chmod`, `chown`
- **Reverse Shells**: `nc -e`, `bash -i`, `sh -i`, `python -c socket`
- **Data Exfiltration**: `wget`, `curl` (in payloads), `dns` exfil patterns
- **Database Writes**: `INTO OUTFILE`, `LOAD_FILE` (write context), `DROP TABLE`
- **System Destabilization**: `fork bombs`, `shutdown`, `reboot`, `init`

Any payload matching these signatures is silently dropped and logged as a security violation.

## 🏗️ Architecture

### 1. Passive Intelligence (Stage 0)
- Analyzes security headers (CSP, HSTS, CORS).
- Parses HTML structure for framework hints.
- Scrapes comments and metadata.
- **Zero Active Payloads**.

### 2. Adaptive Orchestration
- **Stage 1 (Probe)**: Sends minimal, low-noise probes (<10% corpus). Aborts if no anomalies.
- **Stage 2 (Confirm)**: Context-aware testing on identified vectors.
- **Stage 3 (Verify)**: Safe, non-destructive proof-of-concept execution.

### 3. Reasoning Engine
- Maps verified findings to potential attack chains (e.g., LFI -> Log Poisoning).
- Provides "Possibilities" analysis without executing dangerous chains.

## 🎭 Operator Profiles
- **BOUNTY**: Balanced approach for standard engagements.
- **INTERNAL**: Higher thoroughness, faster pace for permitted internal networks.
- **GOV**: Extreme stealth, high delays, low request caps for sensitive operations.

## 🛡️ Stealth
- Persistent sessions with jitter.
- Adaptive backoff on 429/5xx errors.
- CAPTCHA detection hard-stops.
- Probabilistic WAF avoidance.
