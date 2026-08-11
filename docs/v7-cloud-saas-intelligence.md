---
layout: default
title: HunterX v7 Cloud & SaaS Attack-Surface Intelligence — Architecture & Reference
description: >-
  Architecture and reference for the Wave 11 Cloud & SaaS Attack-Surface
  Intelligence capability: evidence-based cloud provider detection, account/
  subscription/project modeling, regions, resources, services, endpoints with
  control/data/identity/management plane classification, environments, identity
  & IAM indicators, SaaS platforms & integrations, webhooks, third-party
  dependencies, secret-management indicators, exposure indicators as
  intelligence (never vulnerabilities), historical change detection,
  differential analysis, TIDB mapping, Knowledge Graph relationships, events,
  reporting and the security boundary.
permalink: /v7-cloud-saas-intelligence/
---

# HunterX v7 Cloud & SaaS Attack-Surface Intelligence — Architecture & Reference

**Status:** Ratified (Sprint 017)
**Version:** 1.0.0
**Capability:** Cloud & SaaS Attack-Surface Intelligence · Wave 11
**Owner:** HunterX Architecture Council

---

## 1. Purpose / Scope

The Cloud & SaaS Attack-Surface Intelligence capability discovers, classifies,
correlates, normalizes, persists, graphs, diffs, historizes and reports the
**cloud and SaaS infrastructure associated with an authorized target**. It
transforms fragmented observations (DNS records, TLS metadata, HTTP headers,
technology observations, JavaScript SDK references, documentation text and
previously persisted TIDB intelligence) into a **unified, evidence-backed
infrastructure graph** that answers:

- Which cloud providers are associated with the target?
- Which accounts / subscriptions / projects / organizations / tenants are evidenced?
- Which regions are involved?
- Which cloud resources exist and which are internet-facing?
- Which services are exposed (storage, compute, database, container, Kubernetes, serverless, messaging)?
- Which API gateways / CDNs / load balancers are involved?
- Which IAM indicators exist?
- Which SaaS platforms are integrated, and via which OAuth/API/webhook integration?
- What third-party dependencies exist?
- Which environments are represented?
- What changed since the previous observation, with what evidence?

**Security boundary — this is intelligence and discovery, not exploitation.**
The capability never authenticates to cloud accounts, never accesses cloud
resources, never touches metadata services, never retrieves secrets, never
enumerates private objects, never connects to databases, never interacts with
Kubernetes control planes, never tests IAM permissions and never exploits
anything. Cloud exposure indicators are persisted as **intelligence**, never as
validated vulnerabilities.

Hard constraints:

- **No second database or graph.** The TIDB is the system of record; topology
  edges live in the existing `tidb_topology_relationships` table.
- **No auto-enablement of discovered hosts.** Everything discovered is
  intelligence; scope expansion requires explicit operator action.
- **No credentials.** The capability never uses, validates or persists cloud
  credentials, access keys, secret values, tokens or private keys.
- **Deterministic.** Confidence, classification, correlation and diffing are
  pure functions of observable evidence.

Scope: `src/hunterx/domain/cloud/`, `src/hunterx/tools/cloud/`,
`src/hunterx/application/cloud.py`, `src/hunterx/domain/entities/tidb/cloud_intelligence.py`,
`src/hunterx/infrastructure/db/sql/tidb_models/cloud_intelligence_models.py`,
the `cloud.*` event family, topology kind/relationship additions, the Alembic
migration `7ea0dbfc111d`, `config/capabilities/cloud-saas-intelligence.json`,
`tests/golden/cloud/` and the acceptance/security/performance suites.

---

## 2. Design Goals

1. **Evidence-based detection.** A provider is never inferred from branding
   alone; every detection carries a deterministic signature, a strength and an
   evidence fragment.
2. **Unified cloud model.** Every cloud subject (provider → account → region →
   resource → service → endpoint) is normalized to a canonical, persisted form.
3. **Intelligence-only.** Exposure indicators are metadata; the capability never
   verifies, exploits or validates them.
4. **Deterministic confidence.** Identical evidence always yields identical
   scores; no randomness anywhere.
5. **Secret-safe.** Sensitive values are redacted, masked or fingerprinted before
   they reach any observation or record.

---

## 3. Cloud Model

The capability models the canonical cloud attack-surface hierarchy:

```
DOMAIN
  → HOST
    → SERVICE
      → CLOUD PROVIDER
        → ACCOUNT / SUBSCRIPTION / PROJECT / ORGANIZATION / TENANT
          → REGION
            → RESOURCE
              → SERVICE
                → ENDPOINT (control / data / identity / management / developer plane)
                  → EXPOSURE (public / private / internal)
```

And the SaaS dependency model:

```
APPLICATION
  → SAAS PROVIDER
    → SAAS INTEGRATION (oauth / api / webhook / analytics / payment / ...)
      → OAUTH CLIENT / API / WEBHOOK
        → EXTERNAL SERVICE
```

Every record carries: provider, service, resource, region, environment, plane,
exposure, evidence, source, tool, mission, execution, first/last seen and
deterministic confidence.

---

## 4. Providers

The provider catalog (`src/hunterx/domain/cloud/providers.py`) detects, with
evidence, the following cloud / platform providers:

| Provider | Examples detected via |
|---|---|
| AWS | `.amazonaws.com`, `.cloudfront.net`, `execute-api.`, `Server: AmazonS3`, `x-amz-*`, TLS org `Amazon`, tech `AWS`, JS `@aws-sdk` |
| Azure | `.azurewebsites.net`, `.blob.core.windows.net`, `.azure-api.net`, `x-ms-*`, TLS org `Microsoft`, JS `@azure/` |
| Google Cloud | `.appspot.com`, `.cloudfunctions.net`, `.run.app`, `.storage.googleapis.com`, `x-goog-*`, TLS org `Google` |
| Oracle Cloud | `.oraclecloud.com`, `.objectstorage.`, `.oci.customer-oci.com` |
| Cloudflare | `.cloudflare.net`, `.workers.dev`, `cf-ray`, TLS org `Cloudflare` |
| DigitalOcean | `.digitaloceanspaces.com`, `.ondigitalocean.app` |
| Akamai | `.akamaiedge.net`, `X-Akamai-*` |
| Fastly | `.fastly.net`, `X-Served-By` |
| Vercel | `.vercel.app`, `x-vercel-*` |
| Netlify | `.netlify.app`, `x-nf-request-id` |
| Heroku | `.herokuapp.com` |
| Render | `.onrender.com` |
| Fly.io | `.fly.dev` |
| Supabase | `.supabase.co` |
| Firebase | `.firebaseapp.com`, `.web.app`, JS `firebase` |
| Kubernetes | `kube-apiserver`, `ingress-nginx`, `X-Kubernetes-Pod-Name`, tech `Kubernetes` |
| Docker | `hub.docker.com`, `.docker.io`, tech `Docker` |

Provider detection is **evidence-based**: each signature carries a strength
(strong/moderate/weak) and the analyzer records the matching evidence fragment.
Provider is never inferred from branding alone (a page merely mentioning "AWS"
is not treated as AWS hosting).

---

## 5. Accounts, Subscriptions & Projects

The analyzer extracts **non-secret identifiers** that map to cloud scoping
units:

- **AWS** 12-digit account ids, IAM role/user ARNs (`arn:aws:iam::…`).
- **Azure** subscription / tenant GUIDs.
- **GCP** project ids (`projects/{project}`).

These are recorded as `CloudAccountObservation` (kind `account` /
`subscription` / `project` / `organization` / `tenant`) and are **never
validated** against the provider. The capability never enumerates unrelated
accounts.

---

## 6. Regions & Environments

- **Regions** are extracted from hostnames (`us-east-1`, `us-central1`,
  `eastus`) and from documentation text via deterministic regex patterns, then
  persisted as `CloudRegionObservation`.
- **Environments** are classified from evidence subjects (`production`,
  `staging`, `development`, `testing`, `qa`, `sandbox`, `preview`, `dr`,
  `unknown`). Production is never assumed from a single weak naming indicator;
  the classifier records the strongest observed signal with low confidence when
  ambiguous.

---

## 7. Resources, Services & Planes

- **CloudServiceObservation** captures the canonical service (S3, EC2, Lambda,
  App Service, Cloud Run, …) with a service family (`ServiceCategory`) and an
  endpoint.
- **CloudResourceObservation** captures the resource identifier (bucket name,
  instance id, function name, cluster, database, queue, …) — identifier only,
  never contents.
- **CloudEndpointObservation** carries a canonical **plane** classification:
  `control`, `data`, `identity`, `management`, `developer`, `unknown`, derived
  from well-known consoles, hostname signals and the owning service family.
  Every endpoint also carries an **exposure** classification: `public`,
  `public-indicator`, `private-indicator`, `internal-indicator`, `unknown`.

Resource-family specific observations are emitted for storage, compute,
serverless, container, Kubernetes, database, message infrastructure, API
gateway, CDN, load balancer and CI/CD.

---

## 8. Storage, Compute, Container & Kubernetes

- **Storage** — S3/object/blob/file indicators with a public-exposure
  classification; never enumerated or downloaded.
- **Compute** — VM/instance/application and serverless/function indicators.
- **Container** — registries (ECR/ACR/Artifact Registry/Docker) and image
  references; never pulled.
- **Kubernetes** — cluster indicators (EKS/AKS/GKE/k8s), ingresses, services,
  namespaces, dashboards and Helm references; the capability never touches a
  Kubernetes control plane.

---

## 9. Serverless, Databases & Messaging

- **Serverless** — Lambda, Azure Functions, Cloud Functions, Cloud Run,
  Workers and edge functions are surfaced as compute/function indicators and
  correlated with their API endpoints.
- **Databases** — RDS/Aurora/DynamoDB/Cosmos DB/Cloud SQL/Firestore/Supabase
  and managed PostgreSQL/MySQL indicators with exposure metadata; never
  connected to.
- **Messaging** — SQS/SNS/EventBridge/Pub/Sub/Service Bus/Event Grid/Kafka
  indicators; never published to.

---

## 10. API Gateways, CDNs & Load Balancers

- **API Gateways** — API Gateway, API Management, CloudFront + origin, edge
  functions.
- **CDNs** — CloudFront, Azure CDN/Front Door, Cloudflare, Fastly, Akamai.
- **Load Balancers** — ELB/ALB, Application Gateway, Traffic Manager.

Each is correlated with the domain, the API, the backend and the provider and
persisted in the graph.

---

## 11. IAM & Identity

Correlated with Sprints 015–016, the capability records **non-secret** identity
and IAM indicators: service accounts, managed identities, users, roles
(including `assume-role` indicators), OAuth clients, workload identity,
federated identity and documented permission indicators (e.g. `s3:GetObject`
from infrastructure documentation). Identities are metadata only and are never
used, impersonated or tested.

---

## 12. CI/CD

The capability identifies GitHub Actions, GitLab CI, Jenkins, CircleCI, Azure
DevOps, AWS CodeBuild/Pipeline, Google Cloud Build, Vercel/Netlify deployments
and container registries as `CiCdResourceObservation` records. It never
retrieves build credentials or secrets.

---

## 13. Secret Management

The capability detects secret-management **indicators** only — AWS Secrets
Manager, Azure Key Vault, GCP Secret Manager, Vault, Doppler, 1Password
references, secret references and environment-variable references (e.g.
`AWS_SECRET_ACCESS_KEY`, `DATABASE_URL`, `WEBHOOK_SECRET`). References are
stored as names and SHA-256 **fingerprints**; values are never persisted,
retrieved or validated.

---

## 14. SaaS

The capability detects SaaS platforms (GitHub, GitLab, Slack, Microsoft 365,
Google Workspace, Atlassian, Notion, Salesforce, HubSpot, Zendesk, Datadog,
Sentry, PagerDuty, Twilio, SendGrid, Mailgun, Stripe, Shopify, Auth0, Okta,
analytics and more) from hostnames, SDK references, technology observations and
documentation — always evidence-based.

SaaS **integrations** are modeled with an integration type (oauth / api /
webhook / analytics / payment / email / monitoring / error-tracking / crm /
support / identity / ci-cd / cloud-storage / communication), an endpoint, an
authentication-mechanism indicator and a scope (metadata only).

---

## 15. Webhooks

Inbound/outbound webhook endpoints (Slack, Teams, Zapier, Telegram, Discord,
custom `/webhooks/` routes) are modeled with a direction, provider, event-type
indicators and a signing-mechanism indicator. Signatures are never forged and
no arbitrary webhook requests are sent.

---

## 16. Third-Party Dependencies

Third-party dependencies are correlated (application → third party → provider
→ API) from technology observations and script asset hosts, persisted as
`CloudDependencyObservation`.

---

## 17. Cloud Exposure Indicators

Exposure indicators are persisted as **intelligence, never vulnerabilities**:

- public storage endpoint
- public admin interface
- exposed management endpoint
- missing-auth indicator
- documented resource
- debug endpoint
- unusual exposure
- **dangling-resource** (potential stale deployment: a domain points at a
  provider hostname while documentation indicates decommissioning)

Dangling indicators are classified as `Potential` and never reported as a
"takeover vulnerability". The capability never performs takeover.

---

## 18. Historical Intelligence & Differential Analysis

`CloudHistory.compare(historical, current)` produces deterministic
added/removed/changed records keyed by each subject's canonical deduplication
key. The application service persists changes and publishes
`cloud.change.detected` events. Re-running the same snapshot produces zero
changes; comparing different missions detects asset, provider, resource,
exposure, SaaS, identity, integration, region, environment and architecture
changes.

---

## 19. Evidence

Every cloud record includes provenance: source, tool, mission, execution,
timestamp, asset, provider, service, resource, detection method, raw evidence
reference (masked), normalized value and deterministic confidence. Evidence
fragments are persisted as `CloudEvidence` records linked to their subject.

---

## 20. Confidence

Confidence is deterministic and explainable:

- **Strong:** direct DNS relationship, direct HTTP headers, provider-specific
  hostname, valid documented resource, cloud metadata embedded in
  configuration, multiple independent observations.
- **Medium:** strong naming correlation, TLS correlation, known SDK/service
  indicators.
- **Weak:** generic technology naming, single heuristic, historical-only
  evidence.

Scoring combines a per-source reliability base, the strongest evidence
strength, corroboration boosts, conflict discounts and historical stability —
all pure functions (`src/hunterx/domain/cloud/confidence.py`).

---

## 21. Sensitive Data Protection

The capability never persists cloud credentials, access keys, secret keys,
session tokens, OAuth secrets, private keys, API secrets, webhook secrets,
database credentials or secret values. Protection mechanisms
(`src/hunterx/domain/cloud/redaction.py`):

- **Redaction** — evidence values matching secret patterns are fully masked.
- **Hashing** — secret references are stored as SHA-256 fingerprints.
- **Metadata-only** — identifiers store metadata; secrets store references only.

---

## 22. TIDB Mapping

The capability persists 32 canonical entities
(`src/hunterx/domain/entities/tidb/cloud_intelligence.py`) into 32 TIDB tables
(migration `7ea0dbfc111d`):

`CloudRun`, `CloudProvider`, `CloudAccount`, `CloudRegion`, `CloudResource`,
`CloudService`, `CloudEndpoint`, `CloudEnvironment`, `CloudIdentity`,
`CloudRole`, `CloudPermission`, `CloudIntegration`, `SaaSProvider`,
`SaaSApplication`, `SaaSIntegration`, `Webhook`, `CloudDependency`,
`StorageResource`, `ComputeResource`, `ContainerResource`,
`KubernetesResource`, `DatabaseResource`, `MessageInfrastructure`,
`ApiGatewayResource`, `CdnResource`, `LoadBalancerResource`, `CiCdResource`,
`SecretManagementIndicator`, `CloudExposureIndicator`, `CloudObservation`,
`CloudEvidence`, `CloudChange`.

Persistence goes through the generic `TidbRepositoryFactory` (SQL or in-memory);
no separate cloud database exists. Entities are pure dataclasses extending
`TidbEntity`; the registry auto-pairs `XxxModel ↔ Xxx` by name.

---

## 23. Knowledge Graph (Topology)

The capability projects cloud edges into the existing TIDB topology:

- `Domain → CloudProvider` (`hosted_on`)
- `CloudAccount → CloudProvider` (`belongs_to`)
- `CloudRegion → CloudProvider` (`part_of`)
- `CloudResource → CloudProvider` / `CloudResource → CloudEnvironment` (`belongs_to`)
- `Domain → CloudResource` / `Domain → CloudEndpoint` (`hosted_on`)
- `CloudProvider → CloudEndpoint` (`exposes`)
- `Domain → SaaSProvider` (`uses`)
- `SaaSIntegration → SaaSProvider` (`uses`)
- `SaaSProvider → Webhook` (`uses`)
- `Domain → CDN` (`hosted_on`)

New topology kinds (`cloud_provider`, `cloud_account`, `cloud_region`,
`cloud_resource`, `cloud_service`, `cloud_endpoint`, `cloud_environment`,
`cloud_identity`, `saas_provider`, `saas_integration`, `webhook`,
`storage_resource`, `compute_resource`, `container_resource`,
`kubernetes_resource`, `database_resource`, `api_gateway`, `ci_cd_resource`) and
relationship types (`contains`, `hosts`) were added to
`src/hunterx/domain/topology/enums.py`.

---

## 24. Events

The capability publishes the `cloud.*` event family (category `CLOUD`,
`EventSeverity.INFO`):

- `cloud.intelligence.started`, `cloud.phase.started`,
  `cloud.intelligence.completed`, `cloud.intelligence.failed`
- `cloud.provider.discovered`, `cloud.account.discovered`,
  `cloud.region.discovered`, `cloud.resource.discovered`,
  `cloud.service.discovered`, `cloud.endpoint.discovered`
- `cloud.storage.discovered`, `cloud.compute.discovered`,
  `cloud.container.discovered`, `cloud.kubernetes.discovered`,
  `cloud.serverless.discovered`, `cloud.database.discovered`
- `cloud.gateway.discovered`, `cloud.cdn.discovered`,
  `cloud.load_balancer.discovered`
- `cloud.identity.discovered`, `cloud.iam.discovered`,
  `cloud.environment.discovered`
- `cloud.saas.discovered`, `cloud.saas_integration.discovered`,
  `cloud.webhook.discovered`, `cloud.dependency.discovered`,
  `cloud.exposure.discovered`
- `cloud.change.detected`, `cloud.conflict.detected`,
  `cloud.correlation.completed`

---

## 25. Reporting

`CloudQueryService` answers the full inventory query surface: providers,
accounts, regions, resources, services, endpoints, environments, identities,
roles, permissions, integrations, SaaS providers, SaaS applications, SaaS
integrations, webhooks, dependencies, storage, compute, containers, Kubernetes,
databases, message infrastructure, API gateways, CDNs, load balancers, CI/CD,
secret-management indicators, exposure indicators, observations, changes, runs
and a compact summary.

---

## 26. Module Reference

| Module | Contents |
|---|---|
| `src/hunterx/domain/cloud/models.py` | canonical observation dataclasses, `CloudTarget`, `CloudEvidence`, `CloudInput`, `CloudAnalysis`, `CloudBatch`, serialization bridge |
| `src/hunterx/domain/cloud/providers.py` | `ProviderCatalog`, `ProviderMatch`, `ProviderSignature`, region/account extraction |
| `src/hunterx/domain/cloud/analyzer.py` | `CloudAnalyzer` — evidence-based detector set |
| `src/hunterx/domain/cloud/classification.py` | `CloudClassifier` — service category, plane, exposure, environment |
| `src/hunterx/domain/cloud/confidence.py` | `CloudConfidenceEngine`, `CloudConfidencePolicy` |
| `src/hunterx/domain/cloud/scope.py` | `CloudScopePolicy`, `CloudScopeEnforcer` |
| `src/hunterx/domain/cloud/strategy.py` | `CloudStrategy`, `CloudStrategyBuilder` |
| `src/hunterx/domain/cloud/correlator.py` | `CloudCorrelator`, `CloudCorrelationResult` |
| `src/hunterx/domain/cloud/conflicts.py` | `CloudConflictResolver` |
| `src/hunterx/domain/cloud/history.py` | `CloudHistory`, `CloudHistoryComparison` |
| `src/hunterx/domain/cloud/validator.py` | `CloudValidator` |
| `src/hunterx/domain/cloud/redaction.py` | secret redaction, fingerprinting |
| `src/hunterx/tools/cloud/` | `cloud-analysis` adapter, registry, TIP registration |
| `src/hunterx/application/cloud.py` | `CloudService`, `CloudQueryService` |
| `src/hunterx/domain/entities/tidb/cloud_intelligence.py` | 32 TIDB entities |
| `src/hunterx/infrastructure/db/sql/tidb_models/cloud_intelligence_models.py` | 32 ORM models |
| `alembic/versions/7ea0dbfc111d_cloud_saas_intelligence_tables.py` | schema migration |
| `config/capabilities/cloud-saas-intelligence.json` | machine-readable capability contract |

---

## 27. Security & Scope Behavior

- **Target admission:** the target must pass the `CloudScopePolicy` before any
  analysis runs.
- **Per-observation filter:** out-of-scope observations are never persisted.
- **No scope expansion:** discovered cloud intelligence never expands a mission.
- **No external requests:** the analyzer consumes supplied static material
  only; it never requests cloud resources, metadata services or discovered
  hosts.
- **No credentials:** the capability never uses, validates or persists
  credentials.
- **No exploitation:** no cloud exploitation, no takeover, no bucket/object
  enumeration, no database connections, no Kubernetes API access, no IAM
  testing, no OAuth/webhook abuse, no SSRF.

---

## 28. Testing

- **Unit tests** (`tests/unit/test_cloud_domain.py`, `test_cloud_analyzer.py`,
  `test_cloud_service.py`, `test_cloud_tip.py`) — models, provider detection,
  AWS/Azure/GCP/Cloudflare/SaaS detection, DNS/TLS correlation, storage/
  compute/container/Kubernetes/serverless/database/gateway/CDN/IAM indicators,
  SaaS integration, webhooks, history, differential, scope and security.
- **Integration tests** (`tests/integration/test_cloud_platform.py`) — platform
  wiring and end-to-end mission persistence.
- **Acceptance tests** (`tests/acceptance/test_cloud_acceptance.py`) — one test
  per acceptance criterion, provenance, deterministic confidence, exposure-as-
  intelligence, full query surface.
- **Security tests** (`tests/security/test_cloud_security.py`) — credential/
  token/secret leakage, cross-target/cross-mission contamination, scope bypass,
  parser abuse, graph explosion, webhook/OAuth secret leakage, metadata-endpoint
  handling, no-exploitation.
- **Performance tests** (`tests/performance/test_cloud_benchmarks.py`) —
  bundle analysis, 1k-observation correlation, 1k-record inventory queries,
  merged-confidence and history-diff baselines.
- **Golden datasets** (`tests/golden/cloud/`) — deterministic fixtures for AWS,
  Azure, GCP, Cloudflare+SaaS, multi-cloud, Kubernetes, stale/dangling
  resources and a false-positive plain site.

---

## 29. Verification

Gates at sprint close:

- `python -m pytest tests/unit tests/component tests/integration tests/golden tests/security tests/acceptance tests/architecture tests/engineering -m "not tools"` — **1661 passed**.
- `python -m ruff check src/hunterx tests` — clean for all touched files
  (remaining findings are pre-existing in untouched javascript/api modules).
- `python -m alembic upgrade head && python -m alembic downgrade base` —
  applied and rolled back cleanly.
- `python -m alembic check` — no new operations for the cloud tables
  (pre-existing JS table drift is unrelated and unchanged).

---

## 30. References

- `docs/bible/02 - Architecture.md`, `docs/bible/08 - Unified Security Schema.md`
- `docs/v7-foundation.md`, `docs/v7-tidb.md`
- `docs/v7-tool-integration-sdk.md`, `docs/v7-event-bus-observability.md`
- `docs/v7-reconnaissance-capability.md`, `docs/v7-dns-intelligence.md`
- `docs/v7-technology-fingerprinting.md`, `docs/v7-authentication-intelligence.md`
- `docs/v7-authorization-intelligence.md`
- `config/capabilities/cloud-saas-intelligence.json`
