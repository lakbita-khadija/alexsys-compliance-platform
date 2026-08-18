# Core ↔ AI Service Integration

**Audience: the engineer building the AI Service.** This is the complete
contract. You should not need to read Core's source to build a client.

Everything below was generated or verified against the running service;
deterministic examples live in `tests/contracts/fixtures/`.

---

## 1. The one-paragraph version

Core owns the truth. Findings, resources, scans and compliance scores are
produced and owned by Core; you reason *over* them. You reach them
through this REST API and **never through Core's database**. Every call
carries a bearer JWT whose `tenant_id` claim decides what you can see —
you cannot request another tenant's data, and there is no parameter that
would let you try.

---

## 2. Base URL

```bash
CIQ_CORE_API_BASE_URL=http://core-stub:9000     # local development
CIQ_CORE_API_BASE_URL=https://core.internal     # deployed
```

All data endpoints live under `/api/v1`. Operational endpoints
(`/health`, `/version`, `/.well-known/jwks.json`) sit outside it
deliberately — they are not part of the versioned data contract and will
not move when the API version does.

---

## 3. Authentication

Send an RS256 JWT on every `/api/v1` request:

```
Authorization: Bearer <token>
```

### Required claims

| Claim | Value | Notes |
|---|---|---|
| `sub` | your service identity | e.g. `ai-service` |
| `tenant_id` | the tenant | **This decides what you can read.** |
| `roles` | `["reader"]` | `scanner` additionally allows `POST /scans` |
| `iss` | `complianceiq-core` | verified |
| `aud` | `complianceiq` | verified |
| `exp` | expiry | verified |

### Verifying tokens yourself

Fetch and cache the public keys:

```bash
curl $CIQ_CORE_API_BASE_URL/.well-known/jwks.json
```

Verify with `algorithms=["RS256"]` **explicitly**. Never let the library
pick the algorithm from the token header: a token claiming `alg: none`,
or one signed with HS256 using the public key as an HMAC secret, will
otherwise verify successfully and lets anyone forge any identity. Core
pins the algorithm for exactly this reason, and there are tests for both
attacks.

The public key is public — it verifies, it cannot sign. Only Core holds
the private key.

---

## 4. Endpoints

| Method | Path | Returns | Role |
|---|---|---|---|
| GET | `/api/v1/findings` | `Page<Finding>` | reader |
| GET | `/api/v1/findings/ai-contract` | `Page<AiFindingContract>` | reader |
| GET | `/api/v1/findings/{id}` | `Finding` | reader |
| GET | `/api/v1/findings/{id}/ai-contract` | `AiFindingContract` | reader |
| GET | `/api/v1/scores` | `Page<ComplianceScore>` | reader |
| GET | `/api/v1/scores/current` | `ComplianceScore` | reader |
| POST | `/api/v1/scans` | `202 ScanSubmission` | **scanner** |
| GET | `/api/v1/scans` | `ScanResource[]` | reader |
| GET | `/api/v1/scans/{scan_key}` | `ScanResource` | reader |
| GET | `/api/v1/scans/{scan_id}/attack-paths` | `AttackPathListResponse` | reader |
| GET | `/api/v1/attack-paths/{id}` | `AttackPathResource` | reader |
| GET | `/health` · `/version` · `/.well-known/jwks.json` | — | none |

Generate a client from `GET /openapi.json` — it is the authoritative
machine-readable contract, and a copy is checked in at
`tests/contracts/fixtures/openapi.json`.

---

## 5. Which finding shape to use

There are two, and the choice matters.

### `AiFindingContract` — the frozen 11-field shape

Exactly the fields `contracts/ai_service` specifies, and exactly the
payload you already expect:

```json
{
  "id": "...", "tenant_id": "...", "resource_id": "...", "rule_id": "...",
  "framework": "...", "control_id": "...", "domain": "...",
  "status": "fail", "severity": "critical", "evidence": {}, "detected_at": "..."
}
```

Use it if you want a shape that will not gain fields. **`status` here is
two-valued** (`pass` / `fail`).

**Findings that cannot be represented are omitted**, not coerced. That
means INDETERMINATE findings, and findings whose `framework`/`domain`
fall outside the contract's closed vocabulary. Consequence you must
handle: `total` counts all matches, so `len(items)` can be smaller than
your page size, and paging by `total` may overshoot. Page until `items`
is empty rather than computing page count from `total`.

### `Finding` — the full API shape

Everything above plus `region`, `account_id`, `scan_key`,
`logical_finding_id`, `risk`, `confidence` — and **`status` is
three-valued**.

It also carries graph and attack-path context:

| Field | Meaning |
|---|---|
| `related_attack_path_ids` | Paths this resource lies on. Ids only — resolve via `/api/v1/attack-paths/{id}` |
| `related_resources` | Neighbours whose state is part of why the rule concluded what it did |
| `indeterminate_resources` | Neighbours whose contribution could **not** be determined |
| `graph_context` | The resource's neighbourhood. **Detail endpoint only** — `null` in a page means *not requested*, not *no context* |

Two traps worth naming before you build against them:

- **`related_attack_path_ids` is not the inverse of a path's
  `contributing_finding_ids`.** The first is status-agnostic ("is my
  resource on this path"); the second lists failures only ("what creates
  this risk"). A passing finding on a path resource appears in one and
  not the other. Do not round-trip between them expecting a fixed point.
- **`indeterminate_resources` is separate on purpose.** Merging it into
  `related_resources` would present a data gap as a confirmed
  relationship — the same mistake as treating `indeterminate` as `pass`.

### The thing to get right: `indeterminate`

`indeterminate` means *the check could not be evaluated from the data
collected*. It is **not** a pass.

If your enrichment, scoring or summarisation treats it as one, you
reintroduce "hidden compliance" — a customer reads a clean dashboard
while an unevaluated control silently fails — which is the exact failure
Core's three-valued rule engine exists to prevent. Either surface it as
unknown or exclude it; never round it up.

### Identity: `id` vs `logical_finding_id`

- `id` — **physical**. Unique to one finding in one scan. Changes every
  scan.
- `logical_finding_id` — **logical**. Stable across scans for the same
  issue on the same resource. This is what you key enrichment,
  deduplication and history on.

Caching AI output against `id` means re-enriching everything after every
scan. Key on `logical_finding_id`.

Treat `logical_finding_id` as **opaque**. It contains `:`, and so do ARNs
and Azure resource ids, so splitting it does not reliably recover its
parts. The components are returned as separate fields when you need them.

---

## 6. Pagination

Every list endpoint returns:

```json
{ "items": [...], "total": 1284, "limit": 50, "offset": 0, "has_more": true }
```

`limit` defaults to **50**, maximum **100**. Exceeding it is a `422`, not
a silent clamp — so you learn you did not get everything.

Ordering is deterministic and always carries a unique tiebreaker, so
pages neither overlap nor drop rows.

---

## 7. Filters

`GET /api/v1/findings` accepts: `framework`, `severity`, `status`,
`lifecycle_state`, `domain`, `provider`, `resource_id`, `rule_id`,
`scan_key`, `account_id`, `detected_after`, `detected_before`, `sort`,
`limit`, `offset`.

Enum values are closed; an unknown one is a `422` listing what is
allowed.

**There is no `tenant_id` filter.** Sending one has no effect — the
tenant comes from your token. This is not an oversight to work around.

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "$CIQ_CORE_API_BASE_URL/api/v1/findings?severity=critical&status=fail&limit=50"
```

---

## 8. Errors

Every error — validation, auth, not-found, unexpected — has one shape:

```json
{
  "error": {
    "code": "not_found",
    "message": "finding not found",
    "correlation_id": "…",
    "details": {}
  }
}
```

Branch on `code`; it is stable and part of the contract. `message` is for
humans and may be reworded.

| Code | Status | Meaning |
|---|---|---|
| `authentication_error` | 401 | Missing, malformed, expired or badly signed token |
| `authorization_error` | 403 | Authenticated, wrong role |
| `not_found` | 404 | Absent **or** belongs to another tenant — indistinguishable by design |
| `validation_error` | 422 | Malformed request or bad enum |
| `invalid_filter` | 422 | Filter combination rejected |
| `scan_conflict` | 409 | A scan for this target is already running |
| `service_unavailable` | 503 | Dependency down, or scan submission unconfigured |
| `internal_error` | 500 | Unexpected. Quote the `correlation_id` |

401 never says *why*. That is deliberate — distinguishing "expired" from
"bad signature" is a free oracle for an attacker — so do not try to parse
a reason out of it.

---

## 9. Correlation IDs

Send `X-Correlation-ID` and Core preserves it; omit it and Core generates
one. It comes back on every response, including errors.

```
Dashboard ──X-Correlation-ID: abc123──▶ Core ──same id──▶ AI Service
```

**Please propagate it.** One id across three services is the difference
between tracing a bug and guessing. Core logs it on every request and
stamps it into audit events, including ones written minutes later by a
background scan.

---

## 10. Scans are asynchronous

`POST /api/v1/scans` returns **202** with an id and a status. The scan has
**not** run:

```json
{ "scan_key": "…", "status": "queued", "tenant_id": "acme", "submitted_at": "…" }
```

Poll `GET /api/v1/scans/{scan_key}` until `status` is terminal:
`completed`, `partial`, `failed`, or `cancelled`.

**`partial` is not success.** It means the scan ran but could not
enumerate everything — typically a permission denial on one service.
Anything that service would have covered was *not verified*. Check
`errors[]`, and do not present a partial scan as a clean bill of health.

Requires the `scanner` role, separate from `reader`, because a scan
spends money and calls real cloud APIs.

---

## 11. Local development

```bash
docker compose --profile stub up core-stub
# → http://localhost:9000
```

The stub is the **real** application — real routing, real JWT
verification, real tenant scoping, real error envelope — over in-memory
data. No PostgreSQL, no cloud credentials, no migrations. It seeds six
findings across `fail`, `pass` and `indeterminate` so you can exercise
every branch, including the one that matters most.

It prints a ready-to-use 24-hour token at startup
(`app.state.stub_token`). That key is generated per process and grants
access only to fabricated data.

Deterministic fixtures for offline unit tests:

```
tests/contracts/fixtures/
├── finding.json                     ├── error_unauthorized.json
├── finding_ai_contract.json         ├── error_not_found.json
├── page_findings.json               ├── error_validation.json
├── page_findings_ai_contract.json   ├── error_forbidden.json
├── page_scores.json                 ├── jwks.json
├── scan_submission_202.json         ├── health.json · version.json
├── attack_path.json                 └── openapi.json
└── attack_path_list.json
```

All generated from live responses, so they cannot drift from the real
API.

---

## 12. Invariants Core will not break without a version bump

1. Core is the source of truth for findings. AI enrichment never becomes
   authoritative.
2. You reach data through this API, never Core's database.
3. The JWT `tenant_id` is authoritative; no request parameter overrides it.
4. Every finding returned belongs to the authenticated tenant.
5. `AiFindingContract` stays exactly 11 fields.
6. Error `code` values are stable.
7. Breaking changes ship as `/api/v2`; `v1` keeps working.
8. Correlation IDs propagate.
9. AI-generated remediation is **never** applied automatically by Core.

**Additive changes may appear in `v1`** — new optional fields on `Finding`,
new error codes, new endpoints. Ignore unknown fields rather than
failing on them, or an additive change becomes an outage.

---

## 13. Known gaps

Stated so you do not design around something that is not there:

- **GCP is not implemented.** `provider` accepts `aws` and `azure`;
  `gcp` is a 422.
- **Scan submission returns 503 in the default deployment** until an
  operator configures a cloud credential reference and rule catalog
  path. The pipeline is built and tested; its configuration is
  deployment-specific.
- **No webhooks or streaming.** Polling only.
- **No rate limiting yet.** Do not rely on its absence.
- **No token revocation.** Expiry is the only revocation mechanism, so
  keep lifetimes short.
