# Phase 4 — Pre-Implementation Audit of Phase 1–3

> **Status: audit only. No code was changed while producing this document.**
> Every claim below was verified by reading the source or by executing it.
> Where something was executed, the command and its real output are shown.

---

## 0. Executive summary

Phase 3 is in good shape for persistence: the Finding contract is rich,
identity is deterministic, and tenant scoping is enforced at every layer.

However, the audit found **three defects that block a correct Phase 4**,
one of which also breaks Phase 3's own production scan path. They are
reported first because they change what Phase 4 must do.

| # | Severity | Defect | Blocks |
|---|---|---|---|
| 1 | **BLOCKER** | `ScanCloudAccount` builds the ResourceGraph but never passes it to `EvaluateRules` — any scan whose catalog contains a relationship rule raises | Phase 3 production scans, and any Phase 4 end-to-end persistence test |
| 2 | **BLOCKER** | `scan_id` is `tenant:provider:timestamp` — it does **not** include the account, so two accounts scanned in the same tenant at the same instant produce the same `scan_id` | Using `scan_id` as a primary key |
| 3 | **HIGH** | `logical_finding_id` renders `account_id=None` as the literal string `"None"`, and its `:` separator collides with ARNs | Cross-account logical-finding identity; parsing the id back |

---

## 1. Defect 1 — the scan pipeline is wired incorrectly (BLOCKER)

`application/scanning/scan_cloud_account.py:79-89` builds the graph and
then does not use it:

```python
graph = self._build_graph.build(tenant_id=tenant_id, resources=resources)   # line 79
scan_id = f"{tenant_id!s}:{provider.value}:{scanned_at.isoformat()}"        # line 81

findings = self._evaluate_rules.evaluate(
    tenant_id=tenant_id,
    resources=resources,
    detected_at=scanned_at,
    scan_id=scan_id,
    rule_ids=scan_configuration.rule_ids,
    # graph=graph   <-- MISSING
)
```

`EvaluateRules.evaluate()` accepts `graph`, and
`domain/rules/conditions.py` deliberately **raises** rather than
returning `INDETERMINATE` when a `relationship` node is evaluated with no
graph ("this is a caller wiring problem, not a data gap"). That decision
is correct — and this is exactly the wiring problem it was designed to
catch.

**Verified by execution** (real scan path, real AWS catalog, two related
resources):

```
!!! REAL SCAN PATH FAILS: InvalidRuleCondition
    a 'relationship' condition requires both 'graph' and 'resources_by_id'
    to be supplied to evaluate_condition() — this is a caller wiring
    problem, not a data gap
```

### Why 704 passing tests did not catch it

| Test path | Uses `ScanCloudAccount`? | Uses the real catalog? | Result |
|---|---|---|---|
| `tests/unit/application/test_scan_cloud_account.py` | yes | **no** — fake catalog, no relationship rules | passes, bug invisible |
| `tests/unit/application/test_evaluate_rules.py` | no — calls `EvaluateRules` directly **with** `graph=` | n/a | passes, bypasses the bug |
| `tests/conformance/` | no — `RunConformanceScenario` supplies its own graph | yes | passes, bypasses the bug |
| `tests/integration/{aws,azure}/` | **yes** | **yes** | **all 60 skipped** (no cloud credentials) |

The only path that would have caught it is the one that cannot run in
this environment. This is the concrete cost of the "prepared, not
verified" gap reported at the end of Phase 3.

### Impact on Phase 4

Phase 4's whole purpose is to persist the output of a scan. An
end-to-end "scan → persist → query" test must call `ScanCloudAccount`.
With the real 68-rule catalog, that call currently raises. **Phase 4
cannot be tested end-to-end until this one line is fixed.**

---

## 2. Defect 2 — `scan_id` is not unique per scan (BLOCKER for a PK)

```python
scan_id = f"{tenant_id!s}:{provider.value}:{scanned_at.isoformat()}"
```

The account/subscription being scanned is **absent**. `ScanCloudAccount`
scans one account per call, but nothing in the id says *which*.

**Verified by execution:**

```
scan_id (acct A): acme:aws:2026-01-01T00:00:00+00:00
scan_id (acct B): acme:aws:2026-01-01T00:00:00+00:00
COLLIDE across accounts? True
```

Two scans of two different AWS accounts, same tenant, same timestamp,
produce a byte-identical `scan_id`. It therefore cannot be the primary
key of a `scans` table without risking a unique-constraint violation
that would surface as a scan failure in production.

Secondary issue: the value is derived from wall-clock time supplied by
the caller. Two scans of the *same* account at the same instant also
collide, and the id is not opaque — it embeds semantics that a consumer
may be tempted to parse.

---

## 3. Defect 3 — `logical_finding_id` cross-account collision (HIGH)

`application/rules/evaluate_rules.py`:

```python
logical_finding_id = f"{tenant_id!s}:{resource.account_id!s}:{resource.resource_id!s}:{rule.id!s}"
```

`{...!s}` on `None` renders the literal string `"None"`.

**Verified by execution:**

```
logical_finding_id w/ account_id=None: acme:None:bucket-1:s3-bucket-public
COLLIDE across accounts when account_id is None? True
```

`account_id` is `None` whenever `sts:GetCallerIdentity` is denied (AWS —
documented as deliberately non-fatal). Two different accounts in that
state produce the same logical id for the same resource id and rule.
Since `logical_finding_id` is precisely the key the finding lifecycle
(`first_seen` / `last_seen` / `RESOLVED` / `REOPENED`) hangs off, a
collision here **merges two tenants' — or two accounts' — security
history into one row**.

Also, the `:` separator appears inside ARNs, so the id is not
round-trippable:

```
logical id containing an ARN:
  acme:123456789012:arn:aws:kms:us-east-1:123456789012:key/abc:kms-key-rotation-disabled
field count when split on ':' -> 9 (expected 4) => NOT parseable back
```

Phase 4 must therefore treat `logical_finding_id` as an **opaque string**
and never parse it — and must store the components as separate columns.

---

## 4. Existing contracts (the source of truth Phase 4 must respect)

### 4.1 `Finding` — `domain/findings/models.py`

| Field | Type | Notes for persistence |
|---|---|---|
| `id` | `FindingId` | Physical, per-scan identity |
| `tenant_id` | `TenantId` | Isolation root — **must** be on every table |
| `resource_id` | `ResourceId` | |
| `rule_id` | `RuleId` | |
| `framework`, `control_id`, `domain` | `str` (required, non-blank) | |
| `status` | `FindingStatus` = fail / pass / indeterminate | |
| `severity` | `Severity` = critical / high / medium / low | |
| `evidence` | `Evidence(data: Mapping)` | → JSONB |
| `detected_at` | tz-aware `datetime` | enforced by `__post_init__` |
| `scan_id` | `str \| None` | |
| `rule_version` | `str \| None` | |
| `region`, `environment` | `str \| None` | |
| `version` | `int` ≥ 1 | |
| `superseded_by` | `FindingId \| None` | cannot equal `id` |
| `related_attack_path_ids` | `tuple[AttackPathId, ...]` | |
| `related_drift_event_ids` | `tuple[str, ...]` | |
| `risk`, `confidence` | `float \| None`, 0–100 | |
| `account_id` | `str \| None` | Phase 3B |
| `logical_finding_id` | `str \| None` | Phase 3B — lifecycle key |

Frozen, `slots=True`, validated in `__post_init__`.

### 4.2 What `Finding` does **not** carry

`title`, `description`, `rationale`, `remediation`, `framework_mappings`,
and `tags` live on **`Rule`**, not on `Finding`. Part 6 of the brief asks
Phase 4 to persist them.

They are *derivable* at persist time (the `Rule` is in the catalog), but
they are **rule-version-scoped**, not finding-scoped. Denormalising them
onto every finding row would multiply a ~2 KB remediation block by every
resource × every scan.

**Recommendation:** persist rule metadata once per `(rule_id,
rule_version)` in a `rule_versions` table and join. This preserves every
field the brief lists, loses no information, and keeps the findings table
narrow. Documented as a deliberate deviation from a literal reading of
Part 6.

### 4.3 `NormalizedResource` — `domain/resources/models.py`

`resource_id`, `resource_type`, `cloud_provider`, `tenant_id`, `region`,
`attributes` (Mapping), `tags` (Mapping), `relationships`
(tuple of `ResourceRelationship`), `collected_at`, `account_id`.

Maps cleanly onto Part 5's "structured columns + JSONB" split.

### 4.4 `ScanResult` — `application/scanning/dtos.py`

`scan_id`, `tenant_id`, `provider`, `scanned_at`, `resources`, `graph`,
`findings`, `attack_paths`, `drift_events`.

**No status, no timing, no error channel, no counts.** Everything Part 3
requires of a `Scan` record is new in Phase 4. `ScanResult` is a
*successful, completed* result type only — it has no representation for
QUEUED / RUNNING / PARTIAL / FAILED.

### 4.5 Enums available today

`CloudProvider` = aws, azure (AZURE documented as extensible)
`Severity` = critical, high, medium, low
`FindingStatus` = fail, pass, indeterminate
`Confidence` = high, medium, low
`RelationshipType` = 8 closed values

### 4.6 The existing persistence port

`application/findings/finding_repository.py` already defines
`FindingRepositoryPort` with a single `query(tenant_id)` method, and its
docstring says concrete persistence is "`infrastructure/persistence/
[FUTURE]`". **Phase 4 is that future.** This port must be extended
additively, not replaced — `QueryFindings` depends on it.

---

## 5. Current lifecycle (what exists vs what Phase 4 adds)

**Today:** collect → verify → build graph → evaluate rules → attack paths
→ (risk: not wired) → drift → return `ScanResult` → **discarded**.

There is no scan record, no status, no persistence, no history, and no
finding lifecycle. Every concept in Parts 3, 7 and 9 is new.

`AnalyzeAttackPaths` is a documented placeholder returning `()`, and risk
enrichment is deliberately not invoked. Phase 4 must persist the columns
without pretending these are populated.

---

## 6. Identity model

| Concept | Today | Phase 4 treatment |
|---|---|---|
| `Finding.id` | `{logical}:{scan_id}` | Physical/per-scan. Natural key of `finding_snapshots` |
| `logical_finding_id` | `{tenant}:{account}:{resource}:{rule}` | Lifecycle key. **Opaque** — store components as columns, never parse |
| `scan_id` | `{tenant}:{provider}:{ts}` | **Not unique** (defect 2) |
| `TenantId` etc. | validated non-blank value objects | Persist as `TEXT NOT NULL` |

Deterministic, no `uuid4()` anywhere — verified in Phase 3 by AST check.
Phase 4 must preserve that: **no random surrogate keys** unless justified.

---

## 7. Compatibility constraints Phase 4 must honour

1. `domain/` must not import SQLAlchemy, psycopg, Alembic, or any session
   type. Currently `domain/` imports **zero** third-party packages.
2. `application/` must depend only on ports. It currently imports no
   infrastructure module.
3. Domain models are `frozen=True, slots=True` — ORM instances can never
   *be* domain objects. Explicit mappers are mandatory, which the brief
   already requires.
4. `Evidence.data` is a `MappingProxyType`; it must be converted to a
   plain dict before JSONB serialisation.
5. All datetimes are tz-aware and validated — columns must be
   `TIMESTAMPTZ`, never naive.
6. 704 tests must stay green.

---

## 8. Assumptions (stated, not hidden)

1. One `ScanCloudAccount.run()` = one `Scan` row.
2. `tenant_id` is supplied by the caller and is never derived from the
   cloud account (blueprint §8) — Phase 4 does not change this.
3. `account_id` may legitimately be `None` (denied STS). Phase 4 must
   store it nullable and must not let `None` become an identity
   collision.
4. Rule metadata is stable for a given `(rule_id, rule_version)`.
5. Scan volume assumed ≤ ~10⁵ resources and ≤ ~10⁶ findings per scan —
   enough to require bulk insert, not enough to require partitioning yet.

---

## 9. Risks

| # | Risk | Mitigation proposed for Phase 4 |
|---|---|---|
| R1 | Graph not wired (defect 1) | One-line fix + a regression test using the **real** catalog |
| R2 | `scan_id` collision (defect 2) | Phase 4 owns its own scan primary key; Phase 3's `scan_id` kept as a non-unique label |
| R3 | `logical_finding_id` collision (defect 3) | Store `(tenant, provider, account, resource, rule)` as columns; unique constraint on those, not on the string |
| R4 | Evidence may contain secrets | Evidence is built from collected attributes; no collector reads a secret value. Add an explicit test asserting no credential-shaped keys are persisted |
| R5 | Rule metadata bloat | `rule_versions` table + join (§4.2) |
| R6 | Long-running scans stuck in RUNNING | Explicit terminal-state transition on failure; `started_at`/`heartbeat` column for future reaping |
| R7 | Bulk insert performance | `executemany` / COPY-style batching, measured not assumed |
| R8 | Cross-tenant leakage | `tenant_id` on every table + mandatory tenant argument on every repository method + explicit isolation tests |

---

## 10. Missing information (needs a decision before implementation)

1. **May Phase 4 fix the three Phase 3 defects?** The brief says "do not
   redesign Phase 3". These are one-line correctness fixes, not
   redesigns, but they touch Phase 3 files.
2. **Scan primary key strategy** — see R2. Deterministic composite vs
   Phase-4-owned surrogate.
3. **Retention/partitioning** — Part 17 says design for it, do not
   implement destructive deletion. Confirmed as documentation-only.

---

## 11. Environment capability (so no claim later is fabricated)

Verified in this container:

| Component | Status |
|---|---|
| PostgreSQL server | **16.13 installed and running**, verified via `SELECT version()` |
| SQLAlchemy | 2.0.52 installed |
| psycopg | 3.3.4 installed |
| Alembic | 1.19.1 installed |
| Docker daemon | binary present, **daemon not usable** in this sandbox |
| Cloud credentials (AWS/Azure) | **absent** — the 60 integration tests remain skipped |

Phase 4 integration tests can therefore run against a **real PostgreSQL
instance**, and any result reported will be a real one. Docker Compose
will be provided as configuration for developers but **cannot be executed
here**, and will be labelled accordingly.
