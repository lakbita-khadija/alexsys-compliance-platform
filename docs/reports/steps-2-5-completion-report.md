# STEPS 2–5 — Completion Report

> Scope: identity→resource access edges, the flagship attack path,
> attack path persistence, and the attack path API. STEP 1
> (workload→identity) shipped previously and is referenced where the
> chain depends on it.

---

## 1. What was actually built

The chain a CSPM exists to find:

```
Internet ──▶ Public Workload ──▶ IAM Identity ──▶ Sensitive Resource
    │              │                   │                  │
 STEP 0         existing            STEP 1             STEP 2
(collector    (public_ip +        (ASSUMES from      (ACCESSES from
 registered)   open ingress)    GetInstanceProfile)   policy grants)
                                        │
                                     STEP 3  ── the scenario that reads it
                                        │
                                     STEP 4  ── it survives the scan
                                        │
                                     STEP 5  ── someone can see it
```

Before STEP 2 the second half had no producer, so the chain could not be
traversed end to end and the analyzer's own documentation said so.
Before STEP 4 every path was computed and then discarded at the
persistence boundary; only the derived *risk* survived, via
`Finding.related_attack_path_ids`. Before STEP 5 nothing exposed them.

---

## 2. Metrics

| Metric | Value |
|---|---|
| Tests passing | **1493** (was 1348 at the STEP 0 audit) |
| Tests skipped | 60 — all cloud-credential gated, unchanged |
| Tests failing | 0 |
| Tests deleted or weakened | **0** |
| `ruff check .` | clean |
| `mypy` (production packages) | clean, 181 source files |
| New production modules | 4 (654 lines) |
| Files changed | 35 (+3787 / −40) |
| New migration | `0004_attack_paths` |
| New endpoints | 2 |

### New test files

| File | Tests | Covers |
|---|---|---|
| `tests/unit/domain/test_identity_access.py` | 33 | Pattern classification, Deny precedence, `NotResource`, conditions |
| `tests/unit/application/test_flagship_attack_path.py` | 19 | The chain end to end, and every way it could be reported without being real |
| `tests/api/test_attack_paths.py` | 25 | HTTP contract, filters, summary consistency, tenant isolation |
| `tests/integration/persistence/test_attack_path_persistence.py` | 23 | Real PostgreSQL: JSONB round trip, CHECK enforcement, idempotence, CASCADE, rollback |

Existing suites extended rather than replaced: `test_security.py` (the
two new endpoints added to the anonymous-caller parametrization),
`test_migrations.py` (`attack_paths` added to `EXPECTED_TABLES`, which
subjects it to the tenant-first index audit), `test_persist_scan.py`.

---

## 3. The decisions that carried the most weight

### 3.1 A `*` grant produces no edges

An `AdministratorAccess` role is allowed `*` on `*`. Drawing one edge per
resource it *could* reach turns one role into |resources| edges, every
downstream query into a scan of the estate, and every attack path report
into noise.

So each resource pattern is classified **before** any edge is drawn:

| Pattern | Class | Edges |
|---|---|---|
| `arn:aws:s3:::acme-reports` | `EXACT` | one |
| `arn:aws:s3:::acme-*` | `BROAD` | one per literal-prefix match |
| `*` | `POTENTIAL` | **none** |

`POTENTIAL` is dropped rather than recorded at low confidence. "This
identity can reach everything" is true and useful, but it is a property
of the *identity*, not a set of |resources| relationships. §5 records it
as a deliberate false negative.

### 3.2 Three IAM semantics a naive ARN match gets wrong

- **Explicit `Deny` wins**, evaluated across all grants before any edge
  is emitted — matching IAM's evaluation order rather than emitting an
  edge and hoping a consumer subtracts it later.
- **`NotResource` inverts the match.** An inverted grant never produces
  an edge: "everything except these" is a `POTENTIAL` set by definition.
- **A `Condition` downgrades confidence** one step rather than
  suppressing the edge. The access may well be real; we cannot evaluate
  `aws:SourceIp` against a request that has not happened.

### 3.3 The flagship scenario refuses a shortcut

`internet_to_workload_to_identity_to_data` requires `ASSUMES` **then**
`ACCESSES`. A workload with a *direct* `ACCESSES` edge to data is a real
risk, but reporting it here would name a privilege hop that never
happened. A true risk stated in a false sentence is still a false
positive — the same defect class as the data-bearing/identity bug found
earlier in this project. Pinned by a test.

### 3.4 Composite primary key on `(attack_path_id, scan_key)`

Path ids are deterministic composites, so the same path recurs across
scans **by design**. Keying on the id alone would make each scan
overwrite the last and destroy exactly the history the fingerprint exists
to track.

### 3.5 Reads return plain mappings, not rebuilt aggregates

`AttackPath`'s invariants — path integrity, tenant match on every node,
blocked-implies-score-zero — are construction-time guarantees over live
`GraphNode`/`GraphEdge` objects. Reconstituting one from JSONB would
either re-validate against a graph that no longer exists, or force the
invariants to be relaxed. An aggregate relaxed so it can be read back has
stopped meaning anything.

---

## 4. What running the code caught that reading it did not

Consistent with every previous phase of this project, the defects lived
in seams.

1. **`find_resources_using_identity` returned a role when asked which
   resources use a bucket.** `ACCESSES` began serving double duty at
   STEP 2 — identity→resource *and* the pre-existing resource→resource
   sense. Fixed with an explicit optional `identity_types` parameter
   rather than a hardcoded identity-type list, which would have invented
   a vocabulary ahead of the Entra ID collectors. Pinned by a deliberate
   test.

2. **The migration/ORM schema-parity test rejected a `server_default`
   declared in one place and not the other.** Fixed by declaring it in
   both — the default is real, because a `NOT NULL` column added to a
   populated table during a rolling deploy needs one.

3. **`test_scan_cloud_account.py` asserted `attack_paths == ()`.** That
   assertion encoded the old placeholder, not intent — the fixture is a
   `public: True` bucket, which *should* produce a path. One assertion
   became four, asserting real discovery and real risk enrichment.

---

## 5. Limitations, stated plainly

These are properties of what shipped, not a to-do list disguised as one.

1. **Over-permissioned roles are invisible to the flagship scenario.**
   §3.1's trade. The exposure is still reported by
   `public_identity_with_privilege` and by the IAM rules; only the
   *composite* path is suppressed.
2. **Access derivation is AWS-only.** Azure role assignments have no
   equivalent producer, so the flagship chain cannot be found in an Azure
   estate.
3. **Identity-based policies only.** A bucket policy granting access to a
   principal produces no edge, so a path existing solely through a
   resource-based policy is a false negative.
4. **Cross-account grants produce no edge**, because the target resource
   is not in the graph. Correct, and still a gap.
5. **`blocked` is never set `True` by any collector.** The plumbing
   honours it; the input is always `False`.
6. **No live cloud validation.** Every scenario is exercised against
   fakes modelled on documented response shapes. No test uses a real
   cloud account, by requirement.
7. **Zero of 68 rules target `iam_role`.** Registering the collector made
   its output reachable; no rule consumes it yet.

---

## 6. Verification

```
$ python -m pytest tests/ -q
1493 passed, 60 skipped, 13 warnings

$ ruff check .
All checks passed!

$ mypy domain application infrastructure presentation contracts composition.py
Success: no issues found in 181 source files
```

The 60 skips are the cloud-credential-gated AWS and Azure integration
suites. A skip count of 131 means PostgreSQL is not running and the
persistence suites did not execute — worth checking before trusting a
green run.

---

## 7. Not done

- **STEP 6** — finding graph context is persisted but not exposed
  through the API.
- **STEP 7 onward** — compliance catalog, additional collectors,
  cross-resource rules, E2E, performance.

Both are unstarted, not partially done.
