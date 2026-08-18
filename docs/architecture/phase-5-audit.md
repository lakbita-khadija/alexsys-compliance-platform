# Phase 5 — Pre-Implementation Audit & Gap Analysis

> **Status: audit only. No Phase 5 code has been written.**
> Every statement about the existing codebase below was verified by
> reading the source in this repository. Where the Phase 5 brief and the
> existing architecture conflict, the conflict is stated rather than
> silently resolved.

---

## 0. Executive summary

Phases 1–4 left a stronger foundation for Phase 5 than the brief seems
to assume. Four things the brief asks to design **already exist and are
tested**, and rebuilding them would be the single biggest mistake
available here:

| Brief asks for | Already exists | Where |
|---|---|---|
| §7 Finding contract | `Finding` entity + an **11-field AI contract with an ACL** | `domain/findings/models.py`, `contracts/ai_service/` |
| §8 NormalizedResource contract | Provider-neutral entity + contract DTO | `domain/resources/models.py`, `contracts/ai_service/models.py` |
| §25 Finding lifecycle | `LogicalFinding` + `LifecycleState` state machine | `domain/scans/lifecycle.py` |
| §26 Scan lifecycle | `Scan` aggregate + 6-state machine + persistence | `domain/scans/models.py` |
| §24 Data model | 6 tables, 18 indexes, 17 CHECKs, Alembic | `infrastructure/persistence/` |
| §12 Tenant isolation | Enforced in domain, ports, queries, use case | `domain/tenants/isolation.py` + repositories |

What genuinely does **not** exist, at all:

- **Any HTTP layer.** Zero `fastapi`, zero `pydantic` imports repo-wide.
- **Any authentication.** Zero JWT, zero auth ports, no `User` concept.
- **`ComplianceScore` as a first-class entity.** Only a `score` *property*
  on a Phase 4 read model.
- **Async/job-oriented scan execution.** `ScanCloudAccount.run()` is
  synchronous and in-process.
- **GCP.** `CloudProvider` has exactly two members: `AWS`, `AZURE`.
- **Audit trail.** No `AuditEvent` anywhere.

**Six conflicts** between the brief and the existing architecture need a
decision before implementation. They are §1 below. Four are blocking.

---

## 1. Conflicts requiring a decision

### C1 — Directory layout (BLOCKING, highest impact)

§4 mandates:

```
src/complianceiq/domain/entities/, value_objects/, policies/, services/, ports/
```

The repository has, and Phases 1–4 are built on:

```
domain/  application/  infrastructure/  contracts/     (flat, at repo root)
```

Adopting §4's layout means rewriting the import statements of **293
files**, moving 132 mypy-checked modules, rewriting `pyproject.toml`
packaging, and updating the Alembic migration's module path. It is
mechanical, high-risk, and delivers **zero functional value**.

It also directly contradicts §39: *"DO NOT rewrite existing working
architecture unnecessarily. Preserve backward compatibility."*

The two instructions cannot both be satisfied. **Recommendation: keep the
existing flat layout and add `presentation/` alongside it.** The
*architectural* rule §4 actually cares about — presentation → application
→ domain ports ← infrastructure — is already enforced and AST-tested; it
is a property of the dependency graph, not of directory nesting.

### C2 — The AI Finding contract is frozen at 11 fields (BLOCKING)

`contracts/ai_service/models.py` states plainly:

> "exactly these 11 fields, no more … **the AI Service rejects
> unknown/extra fields**"

§7 asks to evaluate adding `title`, `description`, `remediation`,
`provider`, `service`, `region`, `scan_id`, `first_seen_at`,
`last_seen_at`, `lifecycle status`, `metadata`.

Adding any of those to that payload **breaks the AI Service**, which
another engineer is building against it right now.

There is a second, subtler problem: `finding_to_contract()` **rejects
INDETERMINATE findings outright** — the AI contract has no third status
value. But `GET /api/v1/findings` must be able to return
INDETERMINATE findings, because hiding them is precisely the "hidden
compliance" the three-valued rule engine exists to prevent.

So the REST `Finding` schema and the AI `FindingContract` **cannot be the
same object**. Proposed resolution (§4 of this document's companion
design, pending approval):

- REST `FindingResource` schema = the richer API view (all 11 + the
  additive fields that are already persisted), status is 3-valued.
- `FindingContract` stays **byte-identical** at 11 fields, reachable via
  an explicit projection (a `?view=ai` parameter or a dedicated media
  type — to be decided in the design doc).
- Neither is silently redefined. §22's "never independently redefine the
  same model differently" is honoured by *deriving* both from the domain
  entity, not by making one alias the other.

### C3 — GCP is not implemented anywhere (BLOCKING on scope)

§4 and §9 list `infrastructure/cloud/gcp/` and require a working GCP
connector. Today `CloudProvider` is a closed two-value enum, and adding
GCP means: enum value, SDK dependencies, collectors, normalizers, rule
catalog, Terraform fixtures, unit + integration tests, and a CHECK
constraint migration.

For scale reference, Azure alone was eight tracked work items and
produced ~27 rules, 5 collectors and 5 normalizers. GCP is a comparable
body of work and is **orthogonal to everything else in Phase 5** (API,
auth, scoring, audit).

### C4 — JWT issuance implies a subject store that does not exist (BLOCKING)

§13: *"The Core Service is responsible for JWT issuance"* with claims
`sub`, `tenant_id`, `roles`.

There is no `User` entity, no credential store, no login flow, and §36's
Definition of Done never mentions one. Issuing a token requires knowing
*who* is being issued one and how they authenticated.

Three coherent readings, materially different in size:

1. **Service-to-service only** — tokens minted for the AI Service and the
   dashboard via a client-credentials style grant against configured
   clients. No user store. Smallest, and matches §14/§15 where the
   consumer is the AI Service.
2. **Full user authentication** — `User` entity, password hashing, login
   endpoint, refresh tokens, role assignment. Large, and pulls in
   account-management concerns §27 never mentions.
3. **Issuance for development/testing only** — a dev-mode token endpoint
   plus JWKS, with real identity delegated to an external IdP later.

### C5 — Scan execution is synchronous (design decision)

§26 wants `POST /scans` → `202 Accepted` → `{scan_id, status: queued}`,
with a pipeline `queued → running → collecting → normalizing →
evaluating → scoring → completed`.

Today `ScanCloudAccount.run()` runs the whole pipeline inline and
returns a `ScanResult`. Phase 4's `ScanStatus` already has
`QUEUED/RUNNING/COMPLETED/PARTIAL/FAILED/CANCELLED` with enforced
transitions — but no runner, queue, or worker.

Note two frictions with §26's proposed pipeline:

- Phase 4's `PARTIAL` is **absent from §26's list** but must be kept: it
  is what distinguishes "scanned everything" from "was denied KMS", and
  the domain aggregate refuses to mark an errored scan `COMPLETED`.
- `collecting/normalizing/evaluating/scoring` are *phases within
  RUNNING*, not peers of it. Modelling them as top-level states would
  break the existing tested state machine and its CHECK constraints.
  Recommendation: keep the 6 states, add an optional `phase` field for
  progress reporting.

### C6 — `pyproject.toml` does not declare Phase 4's dependencies (defect)

`sqlalchemy`, `psycopg`, and `alembic` are imported by
`infrastructure/persistence/` and exercised by 47 tests, but appear
**nowhere** in `[project.dependencies]`. A clean `pip install .` produces
a package that cannot import its own persistence layer.

This is a real pre-existing defect, unrelated to the Phase 5 brief, and
should be fixed regardless of the decisions above.

---

## 2. What exists — the inventory Phase 5 builds on

### 2.1 Domain (unchanged by Phase 5)

| Module | Provides |
|---|---|
| `domain/findings/models.py` | `Finding` (11 core + 10 internal fields), `Evidence`, `FindingStatus` (3-valued) |
| `domain/resources/models.py` | `NormalizedResource`, `ResourceRelationship` |
| `domain/scans/models.py` | `Scan`, `ScanTarget`, `ScanCounts`, `ScanError`, `ScanStatus` |
| `domain/scans/lifecycle.py` | `LogicalFinding`, `LifecycleState` (open/resolved/reopened/suppressed) |
| `domain/compliance/models.py` | `ComplianceFramework`, `ControlMapping`, `ComplianceAssessment`, `ComplianceStatus` |
| `domain/rules/` | `Rule`, 32-operator DSL, three-valued Kleene evaluation |
| `domain/graph/` | `ResourceGraph` |
| `domain/tenants/isolation.py` | `ensure_same_tenant` — the canonical isolation check |
| `domain/shared/` | `TenantId`/`FindingId`/… , `Severity`, `CloudProvider`, `UNKNOWN_ACCOUNT` |

### 2.2 Application

Use cases: `ScanCloudAccount`, `EvaluateRules`, `BuildResourceGraph`,
`PersistScanResult`, `QueryFindings`, `DetectDrift`, `EnrichRisk`,
`ManageTenant`, `AnalyzeAttackPaths`.

Ports: `BaseCollector`, `LoadRuleCatalog`, `FindingRepositoryPort`,
and Phase 4's five persistence repositories + `UnitOfWork`.

**Directly reusable by Phase 5's API**, already tenant-scoped and
paginated in shape:

```python
ScanHistoryQueryRepository.get_compliance_snapshot(tenant_id, scan_key)
ScanHistoryQueryRepository.get_compliance_history(tenant_id, provider, account_id, since, limit)
ScanHistoryQueryRepository.count_findings_by(tenant_id, scan_key, dimension)
ScanHistoryQueryRepository.get_rule_regressions(tenant_id, limit)
FindingSnapshotRepository.get_for_scan(tenant_id, scan_key, status, severity)
FindingSnapshotRepository.get_history(tenant_id, logical_finding_id, limit)
```

`ComplianceSnapshot.score` already excludes INDETERMINATE from the
denominator and returns `None` rather than a misleading 100% — the
scoring semantics §11 wants are half-built and correct.

### 2.3 Gaps against §7's proposed Finding fields

| §7 field | Status today |
|---|---|
| `provider` | Not on `Finding`. On `NormalizedResource` and `Scan`; derivable |
| `region` | **Exists** (`Finding.region`) |
| `scan_id` | **Exists** (`Finding.scan_id`, plus Phase 4 `scan_key`) |
| `first_seen_at` / `last_seen_at` | **Exist**, on `LogicalFinding`, not `Finding` |
| lifecycle status | **Exists** as `LogicalFinding.state` |
| `title` / `description` / `remediation` | **Exist on the Rule**, persisted in `rule_versions`, joinable |
| `service` | On `Rule.service`; deliberately *not* derived from `resource_type` (documented, non-mechanical) |
| `metadata` | Does not exist; would need justification before adding |

The important consequence: **almost nothing new needs to be stored.**
Most of §7's list is a *join and projection* problem at the API layer,
not a schema change. That is a much smaller and safer change.

---

## 3. Blocking questions

The four decisions in C1, C2, C3 and C4 change what gets built, in ways
that cannot be reversed cheaply afterwards. They are being put to the
repository owner before any Phase 5 code is written, per §39's
"ONLY THEN implement".

Everything not blocked by those answers — the dependency-declaration fix
(C6), the API surface design, the error/pagination/correlation contracts,
the scoring domain model, and the audit trail — is answer-independent and
proceeds regardless.
