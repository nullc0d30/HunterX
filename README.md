# HunterX
**Automated Decision Support for Offensive Operations**

HunterX is a production-grade orchestration framework designed for professional Red Teams. Developed by **NullC0d3**, it acts as a reasoning engine and precision instrument, replacing noise with decision support. It is engineered to verify vulnerabilities with extreme operational safety, explainability, and stealth.

---

## Why HunterX?

Traditional vulnerability scanners rely on volume—flooding targets with thousands of requests to find low-hanging fruit. This approach triggers WAFs, alerts SOCs, and risks destabilizing services.

HunterX takes a different approach. It functions as a **reasoning companion**, not a brute-force engine. It observes, hypothesizes, probes, and verifies. By treating payloads as data and orchestration as logic, HunterX achieves high-confidence verification with a fraction of the traffic, making it suitable for long-running, sensitive engagements where detection is not an option.


![Alt text](https://github.com/nullc0d30/HunterX/blob/main/Screenshot%202026-02-03%20032706.png)


---

## Key Capabilities

- **Reasoning-Based Verification**: Maps verified findings to potential attack chains (e.g., LFI leading to Log Poisoning) without executing dangerous steps.
- **Strict Orchestration**: A deterministic 4-stage pipeline that ensures requests are only sent when justified by prior evidence.
- **Passive Intelligence**: extensive analysis of headers, DOM, and metadata before a single active payload is released.
- **Operator Profiles**: Immutable behavioral profiles (Government, Internal, Bounty) that strictly enforce engagement Rules of Engagement (RoE).
- **Extreme Stealth**: Automatic jitter, adaptive backoff on error rates, and connection persistence to mimic human behavior.
- **Non-Destructive**: Core architecture prevents execution of destructive payloads or system-altering commands.
- **Fully Explainable**: Every decision, branch, and abort trigger is logged for post-engagement audit.

---

## How HunterX Thinks

HunterX operates on a strictly gated pipeline. It never escalates without confidence.

1.  **Stage 0: Passive Intelligence**
    Analyzing the target surface (Headers, CSP, HTML Comments, Frameworks). Zero active payloads.
2.  **Stage 1: Probe**
    Sending minimal, low-noise indicators (<10% of corpus) to detect anomalies.
3.  **Stage 2: Confirm**
    Context-aware correlations. If the target is Linux/PHP, HunterX will not send Windows/ASP payloads.
4.  **Stage 3: Verify**
    Safe, non-destructive proof-of-concept execution to confirm exploitability without damage.

---

## Quick Start

### Installation

```bash
pip install -r requirements.txt
```

### Usage Examples

**Standard Assessment (Bug Bounty Profile)**
Run a balanced assessment with active context awareness and CLI visualization.
```bash
python hunterx.py -u http://target.com --profile bounty --visual cli
```

**High-Sensitivity Operation (Gov Profile)**
Run in strictly passive mode with extreme delays. No active payloads will be sent.
```bash
python hunterx.py -u http://target.com --profile gov --passive-only
```

**Simulation / Dry Run**
Verify logic and orchestration paths without sending a single network packet.
```bash
python hunterx.py -u http://target.com --dry-run --visual cli
```

### Docker Deployment

Build and run the verified production image. For detailed production usage, see [Docker Guide](README.docker.md).

```bash
Docker Pull nullc0d30/hunterx:stable
docker run --rm -v $(pwd)/reports:/data nullc0d30/hunterx:stable -u http://target.com -o /data
```

---

## Operator Visualization

HunterX provides situational awareness without the noise of a heavy GUI.

-   **CLI Dashboard (Default)**: A lightweight, real-time terminal view showing active branches, risk levels, and request caps.
-   **Web Dashboard**: A local, read-only HTML report (`reports/dashboard.html`) that auto-refreshes for multi-monitor setups.

*Design Philosophy: Maximum operator visibility, minimum target footprint.*

---

## Safety by Design

Safety is not a feature; it is a constraint. HunterX implements non-bypassable guardrails at the codebase level.

-   **Destructive Blocklist**: Payloads containing `rm`, `nc -e`, `> /dev/tcp`, or SQL write primitives are actively blocked and dropped.
-   **Immutable Profiles**: Once a profile (e.g., `GOV`) is selected, its limits on request rates and retries cannot be overridden during runtime.
-   **Verification Only**: HunterX stops at proof. It does not exploit, persist, or extract sensitive bulk data.

---

## Target Audience

-   **Red Teams**: For modeling complex attack paths without burning infrastructure.
-   **Internal Security Teams**: For regression testing and safe verification of remediation.
-   **Regulated Environments**: For assessments requiring strict adherence to request caps and timing windows.
-   **Bug Bounty Hunters**: For distinguishing signal from noise in hardened targets.

---

## What HunterX Is NOT

-   It is **NOT** a vulnerability scanner. It will not fuzz every parameter with 10,000 strings.
-   It is **NOT** an exploitation framework. It does not provide shells or C2 connections.
-   It is **NOT** a brute-force tool. It does not crack passwords or directories.
-   It is **NOT** a mass reconnaissance engine. It focuses on depth and logic, not width.

---

## Disclaimer

HunterX is a specialized tool for authorized security auditing and educational purposes only. It is the responsibility of the user to ensure they have explicit permission to test any target. The authors accept no liability for misuse or damage caused by this software. Use responsibly and ethically.
