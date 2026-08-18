# Post-Study-Guide Current State Audit

> **STEP 0. Audit only — no code was modified.**
>
> Every classification below was obtained by reading the current code or
> executing a query against it. Previous reports and the study guide were
> treated as **unverified claims**. That policy immediately paid for
> itself: §2 documents a blocker that no prior report mentions, and §3.1
> corrects a count the study guide states.

---

## 1. Verified baseline

Re-run at audit time:

```
Tests:    1408 collected
Passed:   1348
Skipped:     60   (AWS/Azure integration — need real credentials)
Failed:       0

ruff:     All checks passed!
mypy:     Success — no issues in 175 source files
```

Matches the previously reported figures.

---

## 2. 🔴 BLOCKER — `IamRoleCollector` is not registered

**This is the most important finding in the audit, and it is new.**

`AwsCollector.__init__` (`infrastructure/cloud/aws/collector.py:77-85`)
builds its default sub-collector tuple from **seven** collectors:

```
S3Collector · IamCollector · IamAccountCollector · Ec2Collector
SecurityGroupCollector · CloudTrailCollector · KmsCollector
```

`IamRoleCollector` is **not imported and not instantiated**. Verified:

```
$ grep -rn "IamRoleCollector(" --include=*.py .
infrastructure/cloud/aws/resource_collectors/iam_roles.py:67:class IamRoleCollector(...)
tests/unit/infrastructure/test_aws_iam_role_collector.py:160 / 315 / 343
```

**It is instantiated only inside its own unit tests.**

### Blast radius

| Consequence | Severity |
|---|---|
| No `iam_role` resource is collected in any real AWS scan | 🔴 |
| **No `PUBLICLY_EXPOSED` edge is ever produced** — `IamRoleCollector` is the only producer | 🔴 |
| **Attack path Scenario 1 (`public_identity_with_privilege`) can never fire in production** — the highest-scoring scenario (80.0 CRITICAL) | 🔴 |
| `policy_analysis.py` — the semantic IAM engine, ~530 lines, the most sophisticated code in the repository — is **dead in production** | 🔴 |
| The resilience layer has **zero production users** (`IamRoleCollector` was its only adopter) | 🔴 |
| `internet_node_ids()` returns `()` on every real scan, so the exposure queries find nothing | 🟠 |

### Why every test still passes

The same seam-defect class the study guide documents, for the third time:

- `test_aws_iam_role_collector.py` instantiates the collector **directly**
  and asserts on its output. Correct, and blind to registration.
- `test_aws_collector.py` passes an explicit `sub_collectors` tuple,
  bypassing the default construction entirely.
- Attack path tests construct estates **by hand**, never through
  `AwsCollector`.
- The AWS integration tests that *would* catch it are **skipped** (no
  credentials) and never mention `iam_role`.

**Nothing exercises the default sub-collector tuple.**

### Compounding finding

```
$ rules scoped to applies_to_resource_type == "iam_role"   →   0
```

**Zero of the 68 rules target `iam_role`.** So even if registration were
fixed, the resource would produce no findings — it exists purely to feed
attack path Scenario 1 and the graph.

### Recommended action

Register `IamRoleCollector` in `AwsCollector`, and add a test asserting
the **default** tuple contains every implemented collector — the seam
nothing currently covers. This is **STEP 0.5**, ahead of STEP 1: adding a
workload→identity edge is pointless while the identity node is never
collected.

---

## 3. Capability classification

### 3.1 Collectors

| Capability | Status | Evidence |
|---|---|---|
| AWS collector classes implemented | **IMPLEMENTED + TESTED** | 8 classes in `resource_collectors/` |
| AWS collectors **registered** | **PARTIALLY IMPLEMENTED** | **7 of 8** — see §2 |
| Azure collectors | **IMPLEMENTED + INTEGRATED** | 5, all registered (`azure/collector.py:70-74`) |
| Resilience layer | **IMPLEMENTED + TESTED, NOT INTEGRATED** | `infrastructure/cloud/resilience.py`; **1 of 13** collectors imports it — and that one is unregistered, so **0 in production** |
| Semantic IAM analysis | **IMPLEMENTED + TESTED, NOT INTEGRATED** | `policy_analysis.py`; reachable only via `IamRoleCollector` |
| `UNKNOWN` tri-state | **IMPLEMENTED + INTEGRATED** | `domain/shared/unknown.py`; `__bool__` raises |

> ⚠️ **Correction to the study guide.** Phase 1 states "**7 AWS
> collectors**". There are **8 collector classes**; 7 are registered. The
> guide's count silently matched the registered set without noticing the
> eighth existed. Corrected here.

### 3.2 Resource Graph

| Capability | Status | Evidence |
|---|---|---|
| `ResourceGraph` + invariants | **IMPLEMENTED + TESTED** | `domain/graph/models.py`; 20 tests |
| Adjacency/type indexes | **IMPLEMENTED + TESTED** | `_out`/`_in`/`_by_type`, index/scan agreement tests |
| External nodes | **IMPLEMENTED + INTEGRATED** | `kind="external"`, confidence `medium` |
| Validation + fingerprint | **IMPLEMENTED + TESTED** | `domain/graph/validation.py` |
| Query layer (11 primitives) | **IMPLEMENTED + TESTED** | `domain/graph/queries.py`; 62 tests |
| Relationship types emitted | **PARTIALLY IMPLEMENTED** | **5 of 8**; `contains`/`connects_to`/`protects` never produced |
| Workload → identity edge | **MISSING** | `ec2.py` stores `instance_profile_arn` as an attribute; no edge |
| Identity → resource edge | **MISSING** | no collector emits it |

### 3.3 Rule engine and catalog

| Capability | Status |
|---|---|
| Condition DSL — 6 node types, 32 operators | **IMPLEMENTED + TESTED** |
| Kleene three-valued logic | **IMPLEMENTED + INTEGRATED** |
| `no_relationship` + coverage guard | **IMPLEMENTED + TESTED, UNUSED** — 0 shipped rules |
| 68 rules (41 AWS / 27 Azure) | **IMPLEMENTED + INTEGRATED** |
| 7 cross-resource rules | **IMPLEMENTED + INTEGRATED** |
| Conformance framework | **IMPLEMENTED + TESTED** |

### 3.4 Attack paths

| Capability | Status | Evidence |
|---|---|---|
| `AttackPath` domain model | **IMPLEMENTED + TESTED** | 12 fields; 14 tests |
| Analyzer, 4 scenarios | **IMPLEMENTED + INTEGRATED** | 40 tests |
| Classification | **IMPLEMENTED + TESTED** | 8/8 types classified — **but see §4** |
| Scoring (`apsm-1.0`) | **IMPLEMENTED + TESTED** | named constants, breakdown |
| Severity mapping | **IMPLEMENTED + TESTED** | 4-value enum, boundaries tested |
| Pipeline integration | **IMPLEMENTED + INTEGRATED** | 12 tests |
| Scenario 1 **in production** | **BLOCKED** | §2 — no `PUBLICLY_EXPOSED` producer runs |
| Flagship chain (internet→workload→identity→resource) | **MISSING** | two edges absent |
| **Persistence** | **MISSING** | no table/model/mapper; `PersistScanResult` drops them |
| **API** | **MISSING** | no router, no schema |

### 3.5 Findings and risk

| Capability | Status |
|---|---|
| `Finding` + logical/physical identity | **IMPLEMENTED + INTEGRATED** |
| Graph contextualization (`related_resources`, `graph_context`) | **IMPLEMENTED + PERSISTED, NOT EXPOSED** — migration `0003` exists; **no API schema references them** (verified) |
| `EnrichRisk` (CRSF-1.1) | **IMPLEMENTED + INTEGRATED** |
| Factor derivation (`rfd-1.0`) | **IMPLEMENTED + TESTED** |
| `related_attack_path_ids` | **IMPLEMENTED + PERSISTED, NOT EXPOSED** |
| `Finding.environment` | **MISSING** — no collector populates it; every risk score defaults it |

### 3.6 Persistence and API

| Capability | Status |
|---|---|
| PostgreSQL, 3 migrations, 74 real-DB tests | **IMPLEMENTED + TESTED** |
| Schema-parity test | **IMPLEMENTED + TESTED** |
| REST API + JWT/JWKS | **IMPLEMENTED + TESTED** |
| Routers | `findings`, `scans`, `scores`, `meta` — **no `attack_paths`** |

### 3.7 Compliance catalog

| Capability | Status |
|---|---|
| Primary attribution (68 rules → `iso_27001`, 7 controls) | **IMPLEMENTED** |
| `FrameworkMapping` + anti-fabrication default | **IMPLEMENTED + TESTED** |
| Mapping status | **PARTIAL** — 11 verified / 16 unresolved; **100% of `cis_azure` unverified** |
| `ComplianceFramework` / `ControlMapping` types | **IMPLEMENTED, ORPHANED** — referenced only by `domain/shared/errors.py` in a docstring |
| Framework registry / validation | **MISSING** — identifiers are unvalidated strings |
| Catalog structure (framework→version→control→mapping) | **MISSING** |

---

## 4. 🟠 Confirmed gap — no classification-completeness test

All 8 `RelationshipType` members are currently classified exactly once
(verified programmatically — 4 traversable, 4 informational, 0
unclassified, 0 in both).

**But no test enforces it.**

```
$ grep -rn "TRAVERSABLE_RELATIONSHIPS" tests/   →   no matches
```

`is_traversable()` checks *membership*, so an unclassified type returns
`False`: attack paths silently never route through it. No error, no
warning. This is exactly the failure §6.1 of the plan asks to prevent, and
the study guide already flagged it as P2.2.

**Recommended action:** the test in §6.1, before any new relationship type
is added in STEP 1/2.

---

## 5. STEP 1 & 2 feasibility

### STEP 1 — workload → identity

| Question | Answer |
|---|---|
| Is `instance_profile_arn` collected? | ✅ Yes — `ec2.py:52`, from `IamInstanceProfile.Arn` |
| Is an edge emitted? | ❌ No |
| Is `iam:GetInstanceProfile` called anywhere? | ❌ **No** — verified by grep |
| Can the role be derived without it? | ❌ **No.** An instance-profile ARN (`…:instance-profile/X`) is a *different resource* from a role ARN (`…:role/Y`). Name matching is a convention, not a fact |
| Vocabulary to reuse | `ASSUMES` — already traversable, already emitted by `IamRoleCollector` |

**Feasible**, and requires one new API call. **Blocked in practice by §2**
until `IamRoleCollector` is registered, otherwise the target node will not
exist and `add_edge` will materialize it as an *external* node — a
misleading result.

### STEP 2 — identity → resource access

Existing material in `policy_analysis.py` is **stronger than expected**:

| Available | Location |
|---|---|
| `Statement` with `resources`, `not_resources` | parsed at `:249-250` |
| `allows_action` / `denies_action` | `:182`, `:196` |
| `has_condition`, `constraining_condition_keys` | `:165`, `:169` |
| `has_wildcard_action` / `has_wildcard_resource` | `:204`, `:208` |
| `is_allow` / `is_deny`, explicit-Deny precedence | `:157`, `:161` |
| `action_matches` (wildcard-aware) | `:130` |

**Missing:** a **resource-ARN matcher**. There is `action_matches` but no
`resource_matches`. Verified by grep.

So STEP 2 needs: ARN pattern matching, an evidence-level model
(`EXACT`/`BROAD`/`POTENTIAL`/`UNKNOWN` per §4), and edge emission. The
semantics (Deny precedence, conditions, `NotResource`) are already
modelled.

⚠️ **Principal hazard, restated:** `Resource: "*"` with `Action: "s3:*"`
must **not** produce an edge to every bucket. That is the graph-explosion
and false-positive risk §4 warns about, and it needs an explicit,
documented policy before implementation.

---

## 6. Architectural blockers

**One, and it is not architectural.**

§2 is a **wiring defect**, not a design flaw — a single missing
registration. The architecture is sound: layering holds, mypy is clean,
the dependency-rule test passes, and every component involved is
implemented and tested.

**No blocker prevents proceeding**, provided §2 is fixed first.

---

## 7. Recommended execution order (adjusted)

The plan's order is sound. One insertion is required:

```
STEP 0.5  ← NEW, BLOCKING
   Register IamRoleCollector + add a default-tuple test
   Add the RelationshipType classification-completeness test (§4)
        ↓
STEP 1   Workload → identity (iam:GetInstanceProfile)
        ↓
STEP 2   Identity → resource access (resource-ARN matcher + evidence levels)
        ↓
STEP 3   Flagship attack path
        ↓
STEP 4   Persistence   →   STEP 5  API   →   STEP 6  Finding/API context
        ↓
STEP 7+  Catalog, collectors, rules, E2E, performance, docs
```

**Rationale for STEP 0.5 first:** STEP 1 adds an edge *to* an IAM role.
While `IamRoleCollector` is unregistered, no real scan contains one, so
the edge would point at a node that does not exist — materialized as an
**external** node, which is precisely the "points outside the scan" vs
"we failed to collect it" conflation the external-node design exists to
prevent. Fixing registration first makes STEP 1 meaningful rather than
misleading.

---

## 8. Summary table

| Area | Verdict |
|---|---|
| Test suite, gates | ✅ Healthy — 1348 passed, 0 failed, ruff + mypy clean |
| Architecture | ✅ Sound; no redesign needed |
| Graph core + queries | ✅ Solid |
| Attack path engine | ✅ Correct, ⚠️ Scenario 1 **dead in production** |
| Collector registration | 🔴 **BLOCKER** — 7 of 8 |
| Relationship coverage | ⚠️ 5 of 8 emitted; 2 key edges missing |
| Classification test | 🟠 Missing |
| Attack path persistence | ❌ Missing |
| Attack path API | ❌ Missing |
| Finding context in API | ❌ Persisted, not exposed |
| Compliance catalog | ⚠️ Partial; types orphaned; no registry |
| Live cloud validation | ❌ Never performed |

**Proceed to STEP 0.5.**

---

## 9. Resolution log (appended after STEPS 1–5)

The verdicts above are **left as written**. An audit that gets edited
once its findings are fixed stops being evidence of what was true, and
the value of §2 was precisely that it contradicted the prior reports.
What follows is what changed since, and what did not.

| Audit finding | Status | Where |
|---|---|---|
| 🔴 `IamRoleCollector` unregistered | ✅ Fixed | Registered in `AwsCollector`; pinned by a test that derives the expected set from the package rather than hardcoding a count |
| 🟠 No classification-completeness test | ✅ Fixed | Same test |
| ⚠️ No workload → identity edge | ✅ Fixed (STEP 1) | `resource-graph.md` §5 |
| ⚠️ No identity → resource edge | ✅ Fixed (STEP 2) | `resource-graph.md` §5 |
| ⚠️ Flagship chain unevidenced | ✅ Fixed (STEP 3) | `attack-path-analysis.md` §6 |
| ❌ Attack path persistence | ✅ Fixed (STEP 4) | Migration `0004`; `attack-path-analysis.md` §16 |
| ❌ Attack path API | ✅ Fixed (STEP 5) | `attack-path-analysis.md` §17 |
| ❌ Finding context persisted but not exposed | ✅ Fixed (STEP 6) | `resource-graph.md` §9d; `attack-path-analysis.md` §12 |
| ⚠️ Compliance catalog partial, no registry | ⬜ Open | STEP 7 |
| ❌ Live cloud validation never performed | ⬜ Open | Unchanged — every scenario is still exercised against fakes modelled on documented response shapes, and no test uses a real cloud account |
| ⚠️ Zero of 68 rules target `iam_role` | ⬜ Open | Registration made the collector's output reachable; no rule consumes it yet |

Two things the audit did **not** predict, both found by running the code
rather than reading it, and both now regression-tested:

1. A publicly assumable IAM role was reported twice, and the *wrongly
   worded* path outranked the correct one — `IDENTITY` was in the
   data-bearing set, so the narrative claimed the role "holds sensitive
   data". See `attack-path-analysis.md` §5.
2. `find_resources_using_identity` returned a role when asked which
   resources use a bucket, because `ACCESSES` serves double duty since
   STEP 2. Fixed with an explicit `identity_types` parameter rather than
   a hardcoded list, which would have invented a vocabulary ahead of the
   Entra ID collectors.
