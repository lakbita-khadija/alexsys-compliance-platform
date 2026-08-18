# Authentication Verification Matrix

> Executive view. Detail in
> [cloud-auth-readiness.md](cloud-auth-readiness.md) and
> [core-auth-readiness.md](core-auth-readiness.md).
>
> Audit only — no application code was modified. Regression baseline
> unchanged: **1512 passed, 60 skipped, 0 failed**; `ruff` clean; `mypy`
> clean.

---

## The two layers, kept separate

```
CLOUD AUTHENTICATION                    APPLICATION AUTHENTICATION
ComplianceIQ → AWS / Azure              user / service → Core → JWT → API

purpose: collect resources              purpose: authorize callers, isolate tenants
verdict: 🔴 NOT READY                    verdict: ✅ READY to verify
         ⚠️ never run live                        🟡 issuance incomplete
```

They fail differently and must not be reported together. The
application layer is strong; the cloud layer is not.

---

## Component matrix

`YES` / `PARTIAL` / `NO`. Never `YES` merely because a file exists.

| Component | Code Exists | Unit Tests | Integration Tests | Security Tests | Production Ready |
|---|---|---|---|---|---|
| AWS credentials | YES | YES | NO | PARTIAL | 🟡 ⚠️ |
| AWS session | YES | YES (mocked) | NO¹ | PARTIAL | 🟡 ⚠️ |
| AWS STS validation | PARTIAL² | PARTIAL | NO | NO | 🔴 |
| Azure credentials | YES | NO | NO¹ | NO | 🟡 ⚠️ |
| Azure token | PARTIAL³ | NO | NO¹ | NO | 🔴 ⚠️ |
| Azure tenant/subscription | NO⁴ | — | — | — | 🔴 |
| Tenant ↔ cloud account binding | **NO** | — | — | — | 🔴 |
| JWT issuance | YES | NO⁵ | YES | PARTIAL | 🟡 |
| JWT verification | YES | NO⁵ | YES | **YES (32)** | ✅ |
| RBAC | YES | NO | YES | YES | 🟡 |
| Tenant isolation | YES | YES | YES (real DB) | YES | ✅ |
| Audit — scan lifecycle | YES | YES | YES | NO | 🟡 |
| Audit — security events | **NO** | — | — | — | 🔴 |
| Secret redaction | YES | YES | YES (real DB) | YES | ✅ |
| Correlation ID | YES | NO | YES | PARTIAL | ✅ |

¹ Opt-in suites exist and are among the 60 skipped every run; they have never executed.
² `sts:GetCallerIdentity` is called; its answer is used as a label, never compared.
³ `DefaultAzureCredential` is constructed; no token is acquired until the first API call.
⁴ No validation code exists for either.
⁵ Covered through the API security suite rather than a dedicated unit file.

---

## Failure-case classification

### AWS

| Case | Status |
|---|---|
| Missing credentials | 🟡 PARTIAL |
| Invalid credentials | ✅ HANDLED |
| Expired credentials | 🟡 PARTIAL — never refreshed |
| **Wrong AWS account** | 🔴 **NOT HANDLED** |
| AccessDenied | ✅ HANDLED |
| Throttling | ✅ HANDLED |
| Network failure | ✅ HANDLED |
| Partial permissions | ✅ HANDLED |
| Role assumption failure | ✅ HANDLED |
| Region misconfiguration | 🟡 PARTIAL |

### Azure

| Case | Status |
|---|---|
| Missing credentials | 🟡 PARTIAL — surfaces late |
| Invalid client secret | 🟡 PARTIAL — surfaces late |
| Expired credentials | 🟡 PARTIAL |
| **Wrong tenant** | 🔴 **NOT HANDLED** |
| **Wrong subscription** | 🔴 **NOT HANDLED** |
| Insufficient RBAC | ✅ HANDLED |
| Graph permission denial | ➖ N/A — no Graph client exists |
| Throttling | 🟡 PARTIAL — no retry on the Azure path |
| Token acquisition failure | 🟡 PARTIAL |
| API/network failure | ✅ HANDLED |

---

## Tenant isolation scenarios

| Test | Scenario | Result |
|---|---|---|
| A | Tenant A → tenant B's finding | ✅ 404, indistinguishable from nonexistent |
| B | Tenant A → tenant B's attack path | ✅ 404, existence not revealed |
| C | Tenant A → tenant B graph nodes | ✅ Impossible by construction |
| D | Valid token, manipulated body `tenant_id` | ✅ Rejected |
| E | Valid token, malicious query parameters | ✅ Ignored; scope stays tenant A |

All five pass. **The caveat is upstream:** these protect data already
attributed to a tenant, and attribution at collection time is not
verifiable — see the P0 list.

---

## P0 — must fix before any production claim

| # | Finding | Layer |
|---|---|---|
| 1 | **No tenant ↔ cloud account binding exists.** Misconfigured credentials attribute another account's estate to a tenant; every downstream control then correctly protects the wrong data | Cloud |
| 2 | **AWS account identity is discovered but never validated** — `GetCallerIdentity` is a label, not a gate | Cloud |
| 3 | **Azure `tenant_id` does not constrain authentication** — `interactive_browser_tenant_id` scopes only the interactive-browser credential, so the field reads as a control and is not one | Cloud |
| 4 | **Azure subscription is never validated**, and the code comment asserting no identity round trip is needed is incorrect | Cloud |

All four are the same class of defect: **identity is asserted by
configuration and never verified against the provider.**

---

## P1

| # | Finding | Layer |
|---|---|---|
| 5 | Security audit events (`AUTHENTICATION_FAILED`, `AUTHORIZATION_FAILED`, `TENANT_ISOLATION_VIOLATION`) declared but **never emitted** | Core |
| 6 | No credential verification precedes token issuance; Core-as-IdP vs resource-server decision unrecorded | Core |
| 7 | No `ExternalId` on `AssumeRole` — the standard confused-deputy defence is not offered | Cloud |
| 8 | Assumed-role sessions never refreshed — a long scan fails partway, non-retryably | Cloud |
| 9 | `AzureSessionFactory` has zero unit tests | Cloud |
| 10 | No throttling/retry on the Azure path | Cloud |
| 11 | Raw SDK exception text embedded in persisted `scan_errors` | Cloud |

## P2 / P3

`admin` role gates nothing · no key rotation mechanism · no audit-trail
API · `NoCredentialsError` mis-categorized · region validated as
non-blank only · no permissions preflight · no unit test file for
`jwt_tokens.py` · no `exp` clock leeway · RBAC enforced at one layer

---

## Live verification required

**No cloud authentication code in this repository has ever run against a
real AWS account or Azure subscription.** The 60 skipped tests in every
run are those suites.

Required before any production readiness claim:

- AWS: default chain, named profile, cross-account `AssumeRole`
- AWS: a scan exceeding the assumed-role session lifetime
- AWS: a genuinely partial-permission role, end to end
- Azure: `DefaultAzureCredential` under managed identity **and** service
  principal — to confirm or refute the tenant-scoping finding (P0 #3)
- Azure: wrong-subscription and wrong-tenant configurations
- Azure: actual `HttpResponseError` text under 403/429, to settle the
  redaction question with evidence rather than inference

Core authentication needs no live cloud verification; it is exercised
through the real FastAPI app over in-memory adapters, with routing,
authentication, tenant scoping and error handling all real.

---

## One-line summary

> **Application authentication is production-grade. Cloud authentication
> is well-structured, secret-safe, and unverified — it authenticates
> successfully without ever confirming *what it authenticated to*.**
