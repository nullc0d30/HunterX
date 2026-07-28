# Security Skills SDK — Developer Guide

> **HunterX v6.0.0**  
> Build custom security analysis skills for the HunterX platform.

---

## Table of Contents

1. [Overview](#overview)
2. [Skill Lifecycle](#skill-lifecycle)
3. [Base Class Reference](#base-class-reference)
4. [SkillMetadata](#skillmetadata)
5. [SkillCapability](#skillcapability)
6. [SkillResult](#skillresult)
7. [SkillContext](#skillcontext)
8. [Complete Example](#complete-example)
9. [Packaging & Distribution](#packaging--distribution)

---

## Overview

The HunterX Security Skills SDK enables developers to create custom security analysis modules that integrate seamlessly with the HunterX scanning engine. Skills are Python classes that inherit from `SecuritySkill` and implement a defined interface for discovery, validation, execution, and result reporting.

---

## Skill Lifecycle

A skill passes through five stages during its lifetime in the HunterX engine:

```
  SkillLoader       SkillRegistry      SkillValidator      SkillExecutor       SkillResult
       |                  |                   |                   |                  |
       |  discover class  |                   |                   |                  |
       |----------------->|                   |                   |                  |
       |                  |  store metadata   |                   |                  |
       |                  |------------------>|                   |                  |
       |                  |                   |  check policy     |                  |
       |                  |                   |------------------>|                  |
       |                  |                   |                   |  run with cache  |
       |                  |                   |                   |  & telemetry     |
       |                  |                   |                   |----------------->|
       |                  |                   |                   |                  |
       |                  |                   |                   |            return result
```

| Stage | Component | Description |
|---|---|---|
| 1 | `SkillLoader` | Discovers the skill class by scanning registered paths or packages |
| 2 | `SkillRegistry` | Stores the skill with its metadata for lookup and dependency resolution |
| 3 | `SkillValidator` | Checks policy compliance, permission requirements, and context compatibility |
| 4 | `SkillExecutor` | Executes the skill with caching, telemetry, timeout enforcement, and retry logic |
| 5 | `SkillResult` | Returns a structured result object with findings, evidence, and risk data |

---

## Base Class Reference

**Module:** `core/skills/base.py`  
**Class:** `SecuritySkill`

### Required Abstract Methods

Every skill must implement the following three methods:

#### `metadata` (property) -> `SkillMetadata`

Returns the skill's metadata descriptor. This is the identity card of your skill and is used by the registry for filtering, dependency resolution, and marketplace display.

```python
@property
def metadata(self) -> SkillMetadata:
    ...
```

#### `capabilities` (property) -> `list[SkillCapability]`

Returns a list of capability enums that this skill provides. Used by the validator to ensure the skill matches the requested scan profile.

```python
@property
def capabilities(self) -> list[SkillCapability]:
    ...
```

#### `execute(self, context, params=None)` -> `SkillResult`

The core logic of your skill. Receives a `SkillContext` and optional parameters; returns a `SkillResult`.

```python
async def execute(self, context: SkillContext, params: Optional[dict] = None) -> SkillResult:
    ...
```

### Optional Methods

These methods are hooks called at specific points in the lifecycle. Override them to add custom behaviour.

| Method | Signature | Purpose |
|---|---|---|
| `initialize` | `async def initialize(self) -> None` | Set up resources (network clients, model loading, etc.) |
| `validate` | `async def validate(self, context: SkillContext) -> bool` | Pre-execution validation; return `False` to skip execution |
| `verify` | `async def verify(self, result: SkillResult) -> bool` | Post-execution verification of result integrity |
| `cleanup` | `async def cleanup(self) -> None` | Release resources (close connections, free memory) |
| `explain` | `def explain(self, result: SkillResult) -> str` | Return a human-readable explanation of the result |
| `estimate_cost` | `async def estimate_cost(self, context: SkillContext) -> float` | Return estimated execution cost in credits |
| `estimate_duration` | `async def estimate_duration(self, context: SkillContext) -> float` | Return estimated execution time in seconds |
| `risk_level` | `def risk_level(self) -> RiskLevel` | Return the inherent risk level of this skill's operations |

---

## SkillMetadata

**Module:** `core/skills/metadata.py`

The `SkillMetadata` class describes a skill's identity, scope, security profile, and compatibility.

### Fields

| Field | Type | Description |
|---|---|---|
| `skill_id` | `str` | Unique identifier (e.g., `"custom_analyzer"`) |
| `name` | `str` | Human-readable name |
| `description` | `str` | Description of what the skill does |
| `version` | `str` | Semantic version string |
| `author` | `str` | Author or organisation name |
| `license` | `str` | SPDX license identifier |
| `tags` | `list[str]` | Free-form tags for discovery |
| `categories` | `list[str]` | High-level categories (`"RECON"`, `"ANALYSIS"`, `"VERIFICATION"`, `"CLOUD"`) |
| `required_capabilities` | `list[SkillCapability]` | Capabilities the target must satisfy for this skill to run |
| `supported_protocols` | `list[str]` | Protocols the skill understands (e.g., `["http", "https", "ws"]`) |
| `supported_technologies` | `list[str]` | Technology identifiers (e.g., `["nginx", "custom-fw"]`) |
| `supported_languages` | `list[str]` | Programming languages the skill can analyse |
| `risk_level` | `RiskLevel` | Inherent risk of running this skill |
| `noise_level` | `NoiseLevel` | How detectable/log-heavy the skill is |
| `safety_policy` | `dict` | Safety constraints for execution |
| `dependencies` | `list[str]` | Skill IDs that must run before this one |
| `mitre_techniques` | `list[str]` | MITRE ATT&CK technique IDs |
| `owasp_categories` | `list[str]` | OWASP API Security categories |
| `cwe_ids` | `list[str]` | Common Weakness Enumeration IDs |
| `capec_ids` | `list[str]` | Common Attack Pattern Enumeration IDs |
| `cvss_reference` | `str` | CVSS vector string reference |
| `required_permissions` | `list[str]` | Permission tokens required at runtime |
| `expected_artifacts` | `list[str]` | Artifact keys the skill is expected to produce |
| `timeout_seconds` | `int` | Maximum execution time before forced termination |
| `retry_allowed` | `bool` | Whether the engine may retry on failure |
| `max_retries` | `int` | Maximum number of retries |

### RiskLevel Enum

| Value | Description |
|---|---|
| `NONE` | No risk; passive information gathering |
| `LOW` | Minimal interaction, read-only probes |
| `MEDIUM` | Active probing with low impact potential |
| `HIGH` | Exploitative techniques that may affect services |
| `CRITICAL` | Destructive or invasive operations |

### NoiseLevel Enum

| Value | Description |
|---|---|
| `SILENT` | No logs or traffic beyond normal requests |
| `LOW` | Minimal additional requests |
| `MEDIUM` | Moderate number of detectable requests |
| `HIGH` | Heavy probing easily detected by monitoring |
| `AGGRESSIVE` | Extreme traffic generation or brute-force |

---

## SkillCapability

**Module:** `core/skills/capability.py`

The `SkillCapability` enum defines 45 capabilities across four categories.

### RECON (8)

| Capability | Description |
|---|---|
| `TECHNOLOGY_DETECTION` | Identify technologies, frameworks, libraries |
| `HTTP_ANALYSIS` | Analyse HTTP headers, methods, status codes |
| `TLS_ANALYSIS` | Inspect TLS certificates, cipher suites, protocol versions |
| `COOKIE_ANALYSIS` | Examine cookie attributes, flags, values |
| `DNS_INTELLIGENCE` | Resolve DNS records, perform lookups |
| `SUBDOMAIN_ENUMERATION` | Enumerate subdomains for a target domain |
| `WAF_FINGERPRINTING` | Detect and identify Web Application Firewalls |
| `FINGERPRINT_CORRELATION` | Correlate fingerprints across targets |

### ANALYSIS (14)

| Capability | Description |
|---|---|
| `AUTH_ANALYSIS` | Analyse authentication mechanisms |
| `JWT_ANALYSIS` | Inspect and test JWT tokens |
| `OAUTH_ANALYSIS` | Audit OAuth flows and configurations |
| `CORS_ANALYSIS` | Test Cross-Origin Resource Sharing policies |
| `CSP_ANALYSIS` | Evaluate Content Security Policy headers |
| `CSRF` | Test Cross-Site Request Forgery protections |
| `CLICKJACKING` | Test for clickjacking vulnerabilities |
| `OPEN_REDIRECT` | Detect open redirect endpoints |
| `GRAPHQL` | Introspect and test GraphQL endpoints |
| `WEBSOCKET` | Analyse WebSocket handshake and messages |
| `REST_API` | Fuzz and analyse REST API endpoints |
| `OPENAPI` | Validate OpenAPI specification compliance |
| `GRPC` | Interact with and test gRPC services |

### VERIFICATION (12)

| Capability | Description |
|---|---|
| `DIRECTORY_ENUMERATION` | Enumerate directories and files |
| `FILE_UPLOAD` | Test file upload functionality |
| `LFI` | Test Local File Inclusion |
| `RFI` | Test Remote File Inclusion |
| `SSRF` | Test Server-Side Request Forgery |
| `XXE` | Test XML External Entity injection |
| `SSTI` | Test Server-Side Template Injection |
| `SQL_INJECTION` | Test SQL injection |
| `NOSQL_INJECTION` | Test NoSQL injection |
| `COMMAND_INJECTION` | Test OS command injection |
| `PATH_TRAVERSAL` | Test path traversal |
| `DESERIALIZATION` | Test insecure deserialisation |

### CLOUD (11)

| Capability | Description |
|---|---|
| `SECRETS_DETECTION` | Detect exposed secrets and credentials |
| `CLOUD_METADATA` | Query cloud instance metadata services |
| `S3` | Enumerate and test AWS S3 buckets |
| `AZURE_BLOB` | Enumerate and test Azure Blob Storage |
| `GCP_STORAGE` | Enumerate and test GCP Cloud Storage |
| `KUBERNETES` | Interact with Kubernetes API and resources |
| `DOCKER` | Interact with Docker daemon and containers |
| `CI_CD_SECRETS` | Detect secrets in CI/CD pipeline artifacts |

---

## SkillResult

**Module:** `core/skills/result.py`

Returned by `execute()`. Contains findings, evidence, risk scoring, and mappings.

### Fields

| Field | Type | Description |
|---|---|---|
| `skill_id` | `str` | The ID of the skill that produced this result |
| `status` | `str` | One of `PASS`, `FAIL`, `ERROR`, `UNKNOWN` |
| `confidence` | `float` | Confidence score (0.0 - 1.0) |
| `summary` | `str` | One-line summary of the finding |
| `details` | `dict` | Structured detail data |
| `evidence` | `list` | Raw evidence items (headers, responses, payloads) |
| `artifacts` | `list` | Generated artifacts for downstream skills |
| `purple_team_rules` | `dict` | Sigma or custom detection rules |
| `mitre_mappings` | `list[str]` | MITRE ATT&CK technique IDs |
| `cwe_mappings` | `list[str]` | CWE IDs |
| `capec_mappings` | `list[str]` | CAPEC IDs |
| `risk_score` | `float` | Computed risk score (0.0 - 10.0) |
| `severity` | `str` | `"info"`, `"low"`, `"medium"`, `"high"`, `"critical"` |
| `duration_ms` | `int` | Execution duration in milliseconds |
| `error` | `str` | Error message if status is `ERROR` |
| `metadata` | `dict` | Additional free-form metadata |

### Status Values

| Status | Meaning |
|---|---|
| `PASS` | Vulnerability or finding confirmed |
| `FAIL` | No vulnerability found |
| `ERROR` | Skill encountered an execution error |
| `UNKNOWN` | Result is indeterminate |

---

## SkillContext

**Module:** `core/skills/context.py`

The `SkillContext` object is passed to `execute()` and provides access to target information, the knowledge graph, the threat model, and engine services.

| Property | Type | Description |
|---|---|---|
| `target_url` | `str` | The URL under test |
| `technologies` | `list` | Technologies already identified on the target |
| `protocols` | `list[str]` | Protocols in use by the target |
| `knowledge_graph` | `object` | Graph of discovered relationships and findings |
| `threat_model` | `object` | Current threat model for the target |
| `payloads` | `object` | Payload generator for injection testing |
| `risk_engine` | `object` | Risk scoring engine |
| `browser` | `object` | Headless browser controller (Playwright) |
| `session` | `object` | HTTP session manager |
| `policy` | `object` | Active security policy constraints |
| `evidence_level` | `str` | Required evidence detail level |

---

## Complete Example

Below is a fully implemented skill that demonstrates every available hook and field.

```python
from core.skills.base import SecuritySkill
from core.skills.metadata import SkillMetadata, RiskLevel, NoiseLevel
from core.skills.capability import SkillCapability
from core.skills.context import SkillContext
from core.skills.result import SkillResult
from typing import Optional


class CustomAnalyzer(SecuritySkill):
    @property
    def metadata(self) -> SkillMetadata:
        return SkillMetadata(
            skill_id="custom_analyzer",
            name="Custom Technology Analyzer",
            description="Analyzes custom technology patterns in HTTP responses",
            version="1.0.0",
            author="Your Name",
            license="MIT",
            tags=["custom", "analysis", "fingerprint"],
            categories=["RECON"],
            supported_protocols=["http", "https"],
            supported_technologies=["custom-fw", "custom-auth"],
            supported_languages=["python", "javascript"],
            risk_level=RiskLevel.LOW,
            noise_level=NoiseLevel.SILENT,
            safety_policy={"passive_only": True},
            dependencies=[],
            mitre_techniques=["T1592", "T1592.001"],
            owasp_categories=["API1"],
            cwe_ids=["CWE-200"],
            capec_ids=["CAPEC-170"],
            cvss_reference="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            required_permissions=["network:http"],
            expected_artifacts=["technology_fingerprints"],
            timeout_seconds=30,
            retry_allowed=True,
            max_retries=2,
        )

    @property
    def capabilities(self) -> list[SkillCapability]:
        return [SkillCapability.TECHNOLOGY_DETECTION, SkillCapability.HTTP_ANALYSIS]

    async def initialize(self) -> None:
        # Setup: load patterns, initialise clients, etc.
        self._patterns = {"X-Custom": r"v(\d+\.\d+\.\d+)"}

    async def validate(self, context: SkillContext) -> bool:
        # Skip if target is not reachable
        return context.target_url is not None

    async def execute(self, context: SkillContext, params: Optional[dict] = None) -> SkillResult:
        target = context.target_url
        findings = []
        evidence = []

        # Simulated detection logic
        for header, pattern in self._patterns.items():
            # ... perform HTTP analysis using context.session ...
            findings.append({"header": header, "matched": True})
            evidence.append(f"header: {header}: v1.0.0")

        confidence = 0.85 if findings else 0.0
        status = "PASS" if findings else "FAIL"

        return SkillResult(
            skill_id=self.metadata.skill_id,
            status=status,
            confidence=confidence,
            summary="Detected custom technology fingerprints" if findings else "No custom technology detected",
            details={"target": target, "findings": findings},
            evidence=evidence,
            artifacts=[{"type": "technology_fingerprints", "data": findings}],
            mitre_mappings=["T1592.001"],
            cwe_mappings=["CWE-200"],
            risk_score=1.5 if findings else 0.0,
            severity="low" if findings else "info",
        )

    async def verify(self, result: SkillResult) -> bool:
        # Verify evidence is well-formed
        return len(result.evidence) > 0 if result.status == "PASS" else True

    async def cleanup(self) -> None:
        self._patterns = None

    def explain(self, result: SkillResult) -> str:
        if result.status == "PASS":
            return f"Found {len(result.evidence)} technology fingerprint(s) on target."
        return "No technology fingerprints detected."

    async def estimate_cost(self, context: SkillContext) -> float:
        return 0.5  # credits

    async def estimate_duration(self, context: SkillContext) -> float:
        return 5.0  # seconds

    def risk_level(self) -> RiskLevel:
        return RiskLevel.LOW
```

---

## Packaging & Distribution

Skills can be packaged and distributed via the HunterX CLI for use across environments or submission to the skill marketplace.

### Export a Skill

```bash
hunterx skills export custom_analyzer --output custom_analyzer.zip
```

This creates a zip archive containing the skill Python file and any associated assets (configuration files, wordlists, models, etc.).

### Install a Skill

```bash
hunterx skills install custom_analyzer.zip
```

The skill is extracted to the HunterX skills directory and registered for discovery on the next engine start.

### Archive Contents

```
custom_analyzer.zip
  |-- custom_analyzer.py        # Skill implementation
  |-- assets/                   # (optional) Supporting files
  |     |-- wordlist.txt
  |     |-- patterns.json
  |-- requirements.txt          # (optional) Python dependencies
```

> **Note:** Python dependencies listed in `requirements.txt` are resolved at install time. All dependencies must be pure-Python or available as platform-independent wheels.
