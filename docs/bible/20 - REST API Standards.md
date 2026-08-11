# 20 — REST API Standards

**Status:** Ratified
**Version:** 1.0.0
**Applies to:** `hunterx/api`, OpenAPI schema, clients, webhooks

---

## 1. Purpose

The REST API exposes the platform programmatically and is the basis for
integrations, CI/CD, and the future GUI. It follows **REST conventions**,
**OpenAPI 3.1**, and **async job semantics** for long operations.

---

## 2. API Versioning

- **URL prefix:** `/api/v1`, `/api/v2`, ... (major version).
- Breaking changes bump the major version; additive changes are backward-compatible.
- A deprecated endpoint remains for at least two minor releases with
  `Deprecation` headers and sunset date.
- `GET /api/v1/health` and `GET /api/v1/version` are unversioned at the root.

---

## 3. Authentication

Four modes (configurable per deployment):

1. **API keys** — `Authorization: Bearer <key>`; keys are scoped (resource +
   engagement) and revocable.
2. **OAuth2 / OIDC** — bearer JWT; RBAC claims; audience pinned.
3. **mTLS** — client certificates for machine-to-machine.
4. **Local username/password** — argon2id hashed; session cookies (HTTP-only,
   SameSite).

- Unauthenticated → `401` with `WWW-Authenticate`.
- Authorization failures → `403` (never `404` to avoid info leaks on RBAC).
- Token/key hashes only stored server-side (no plaintext).

---

## 4. Schemas

- OpenAPI 3.1 generated from the FastAPI app; published as the contract.
- Request/response models are pydantic v2, derived from the Unified Security
  Schema (`08`).
- Naming: camelCase in JSON (OpenAPI convention), snake_case internally.
- Every model carries `schema_version`.
- Dates: ISO-8601 UTC `Z`. IDs: opaque strings.

---

## 5. Common Response Envelope

Standard list/object responses:

```json
{
  "data": { ... },
  "meta": { "correlation_id": "...", "requested_at": "...", "duration_ms": 12 }
}
```

List responses additionally:

```json
{
  "data": [ ... ],
  "pagination": {
    "page": 1, "page_size": 50,
    "total": 123, "total_pages": 3,
    "next": "/api/v1/findings?page=2&page_size=50",
    "previous": null
  }
}
```

---

## 6. Async Job Model

Long operations (mission start, report generation, tool sync, exports):

```
POST /api/v1/missions            → 202 Accepted
Location: /api/v1/jobs/{job_id}

GET /api/v1/jobs/{job_id}
{
  "data": {
    "job_id": "...", "status": "running|succeeded|failed|cancelled",
    "progress": 0.42,
    "result_ref": "/api/v1/missions/{id}",
    "error": null | { "code": "...", "message": "..." }
  }
}
```

- Jobs are idempotent-create: clients may supply `Idempotency-Key` header.
- Job status may be streamed via `Accept: text/event-stream` (SSE) or webhook.

---

## 7. Pagination

- Page-based: `?page=1&page_size=50` (default 50, max 500).
- Cursor-based (for high-volume collections): `?cursor=...&limit=100`.
- `page_size` validated; overflow capped.
- Consistent ordering (by id or created_at) for stable pages.

---

## 8. Filtering & Sorting

- Filters via query params: `?severity=high&status=new&mission_id=...`.
- Range filters: `?epss_min=0.5&created_after=2026-01-01T00:00:00Z`.
- Field filters follow `08` field names (camelCase JSON).
- Sorting: `?sort=-created_at` (prefix `-` = desc).
- Filter/sort whitelists prevent arbitrary column exposure; invalid → `422`.

---

## 9. Errors

Uniform error envelope:

```json
{
  "error": {
    "code": "HX-SCOPE-001",
    "message": "Target outside engagement scope",
    "details": { ... },
    "retryable": false,
    "correlation_id": "..."
  }
}
```

| Status | Meaning |
|--------|---------|
| 400 | Malformed request / validation |
| 401 | Unauthenticated |
| 403 | Forbidden (RBAC/scope) |
| 404 | Not found |
| 409 | Conflict (duplicate, state conflict) |
| 422 | Schema validation failed (details list) |
| 429 | Rate limited (`Retry-After`) |
| 500 | Internal (safe message, no stack) |
| 503 | Unavailable (degradation; `Retry-After`) |

- Error codes match `17` taxonomy; stable across releases.
- No internal stack traces, no secrets, no SQL in error bodies.

---

## 10. Rate Limiting

- Per-user and per-token limits; configurable.
- Response headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining`,
  `X-RateLimit-Reset`.
- `429` includes `Retry-After`; clients must honor it.
- Burst allowances for `GET /health`.

---

## 11. Security Headers & Controls

- TLS 1.2+; HSTS (TLS deployments).
- `Content-Security-Policy`, `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy`.
- CORS: allow-list only; credentials mode explicit.
- Body size limits; multipart upload size limits; request timeouts.
- CSRF tokens for cookie-auth routes.
- Payload validation at boundary (pydantic); no HTML rendering of user input.
- Audit event emitted for every state-changing call (`18` §6).

---

## 12. Idempotency & Concurrency

- Mutations accept `Idempotency-Key`; duplicate keys return the original result.
- Optimistic concurrency: `If-Match`/`ETag` on mutable resources (findings,
  missions, users).
- Destructive endpoints require explicit confirm flags in the body.

---

## 13. Webhooks

- `POST /api/v1/webhooks` registers a subscription (event pattern + URL +
  signing secret).
- Events follow the Event Bus taxonomy (`18` §3).
- Delivery: HMAC-signed, retried with backoff, dead-lettered after limit.
- `GET /api/v1/webhooks/{id}/deliveries` for delivery audit.

---

## 14. Health & Observability

- `GET /api/v1/health`: liveness (always 200 when process up).
- `GET /api/v1/health/ready`: readiness (DB, cache, queue, providers) — 503
  when not ready.
- `GET /api/v1/metrics`: Prometheus exposition (admin).
- All requests emit `hx_http_*` metrics and traces (`18`).

---

## 15. API Design Conventions

- Resources in plural nouns; sub-resources for owned collections
  (`/missions/{id}/findings`).
- HTTP verbs meaningful: GET/HEAD, POST (create), PATCH (partial update),
  PUT (replace), DELETE.
- PATCH for mutable state transitions; POST for actions
  (`/missions/{id}/approve`).
- Response bodies omit null fields unless meaningful.

---

## 16. OpenAPI & Client Generation

- `/openapi.json` and `/docs` served by the API.
- Client SDKs generated from OpenAPI during release; checked for drift in CI.
- Examples in OpenAPI for every endpoint (validated against schemas).

---

## 17. References

- `08 - Unified Security Schema.md` (models)
- `13 - Security Standards.md` §11 (API/network security)
- `17 - Error Handling Standards.md` (error taxonomy)
- `18 - Logging Standards.md` (metrics/traces)
- `19 - CLI Standards.md` (parity)
