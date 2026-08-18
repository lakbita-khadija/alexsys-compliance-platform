# Attack Path Analysis & Risk Integration — Implementation Report

> **Verification policy.** Every number was produced by executing a
> command in this repository. Work not done is listed as not done, with
> the reason.

Companions:
[current-state audit](../architecture/attack-path-current-state-audit.md) ·
[architecture](../architecture/attack-path-analysis.md) ·
[framework status](../architecture/framework-integration-status.md)

---

## 1. Before

| Component | State |
|---|---|
| `AnalyzeAttackPaths.analyze()` | **EXISTS BUT INCOMPLETE** — hardcoded `return ()` |
| `AttackPath` aggregate | **EXISTS BUT INCOMPLETE** — no confidence, evidence or scenario |
| Graph query layer | **EXISTS AND WORKS** — 11 primitives incl. `find_paths` |
| `EnrichRisk` | **EXISTS BUT NOT INTEGRATED** — correct, called by nothing |
| Pipeline integration | **EXISTS AND WORKS** — already called `analyze()` at `scan_cloud_account.py:100` |
| Attack path persistence / API | **MISSING** |
| Framework catalog | 68 rules, 7 ISO controls, 11 of 27 mappings verified |

**The audit's most useful finding inverted the task's premise.** The gap
was never pipeline wiring — `ScanCloudAccount` already invoked the
analyzer and already routed its output into `ScanResult`. The analyzer
itself was the placeholder. So the §14 risk of "integrating into a
dead-end service" did not apply, and implementing `analyze()` lit up the
whole chain with no pipeline surgery.

**Why `EnrichRisk` was uncalled** was structural, not an oversight: it
needs five pre-computed factors, and `attack_path_involvement` was
underivable by construction while the analyzer returned nothing.

---

## 2. After

### Attack path scenarios implemented — 4

| Scenario | Chain | Grounded in |
|---|---|---|
| `public_identity_with_privilege` | `internet → identity` | Real `PUBLICLY_EXPOSED` edge + IAM privilege attributes |
| `internet_to_sensitive_data` | `store` | The store's own public-access attributes |
| `internet_to_exposed_workload` | `network control → workload` | Public address **and** unrestricted ingress |
| `sensitive_data_flow_to_exposed_store` | `source → … → store` | Traversable edges into a publicly readable store |

### Scoring — implemented, `apsm-1.0`

Additive and explainable: exposure + privilege + sensitivity +
relationship − length discount − confidence penalty − incompleteness
penalty, clamped to `[0, 100]`. Every weight is a named module constant;
every path carries its own `score_factors` breakdown. Documented as a
product judgement, explicitly **not** mathematically authoritative.

### Severity — implemented

Maps onto the existing four-value `Severity`. 70+/40+/20+/0 →
CRITICAL/HIGH/MEDIUM/LOW. No prior attack-path threshold existed, so no
contract was overridden. Every boundary tested.

### Confidence — reused, not reinvented

Uses the **graph** vocabulary (`high`/`medium`/`low`/`unknown`). Three
confidence concepts already existed; a fourth would have been the error
§7 warns about. Path confidence is the weakest link across all nodes and
edges.

### Pipeline integration — complete

```
collect → normalize → build graph → evaluate rules
       → analyze attack paths → enrich risk → ScanResult
```

`resources` is now threaded through to the analyzer (graph nodes carry no
attributes). Risk enrichment runs **after** attack paths, because
CRSF-1.1 takes attack-path involvement as one of its five factors.

### Finding integration — zero schema change

Writes to `Finding.risk` and `Finding.related_attack_path_ids` — **both
declared in Phase 1, both already with columns and mappers, neither ever
populated**. Attack-path risk therefore reaches the database without a
migration. Paths are referenced by id, never embedded.

---

## 3. Exact metrics

```
Tests:                  1408 collected
Passed:                 1348
Skipped:                  60   (AWS/Azure integration; need real credentials)
Failed:                    0

Baseline entering task: 1296 passed / 60 skipped
Net new tests:            52   (40 analysis + 12 pipeline integration)

Attack Path scenarios:
Implemented:               4
Deliberately not built:    2   (workload→identity chain; identity→data reach)

Graph queries reused:      3   (edges_of, find_paths, internet_node_ids)
Graph queries written:     0

Collectors touched:        0
Rules touched:             0   (catalog unchanged at 41 AWS / 27 Azure)
Framework references touched: 0

Files changed:            14   (7 new, 7 modified)
Commits:                   2

ruff:                   clean
mypy:                   clean, 175 source files
Alembic revisions added:   0
```

### Files

**New (7)**
```
domain/attack_paths/classification.py
domain/attack_paths/scoring.py
application/risk/factors.py
application/risk/enrich_findings.py
tests/unit/application/test_attack_path_analysis.py
tests/unit/application/test_attack_path_pipeline_integration.py
docs/architecture/attack-path-analysis.md
```
*(plus the two audit documents, committed separately)*

**Modified (7)**
```
application/attack_paths/analyze_attack_paths.py   placeholder → implementation
application/scanning/scan_cloud_account.py         resources threaded; risk wired
domain/attack_paths/models.py                      +scenario, +confidence, +evidence
docs/architecture/resource-graph.md                §10 rewritten
tests/unit/application/test_scan_cloud_account.py  one assertion (see §5)
```

---

## 4. A false positive found by running the code

Not by review. The first end-to-end run reported a publicly assumable IAM
role **twice**:

```
85.0 critical  internet_to_sensitive_data     "holds sensitive data..."   ← wrong
80.0 critical  public_identity_with_privilege "trust policy admits..."    ← right
```

The bogus entry scored **higher** and ranked **above** the correct one.
Cause: `is_sensitive()` included `IDENTITY`, and `is_publicly_assumable`
is a public-exposure attribute — so a role satisfied the data-store
scenario.

Fixed by splitting **data-bearing** roles (storage, secrets, audit log)
from **sensitive** roles (those plus identity). Regression-tested.

The lesson worth keeping: **a true risk stated in a false sentence is
still a false positive.** The role genuinely was critical — but a
responder reading "holds sensitive data" goes looking for data that is
not there, and stops trusting the next finding.

---

## 5. Backward compatibility

| Check | Result |
|---|---|
| Existing YAML rules still load | 68/68 |
| Public interfaces broken | none |
| Pre-existing tests deleted | **0** |
| Pre-existing tests weakened | **0** |
| Pre-existing tests changed | **1** (strengthened — below) |
| Full suite | 1348 passed, 60 skipped, 0 failed |

The 3 existing `AnalyzeAttackPaths` tests and all 14 `AttackPath` domain
tests pass **unchanged** — the former because they use an empty graph,
the latter because every new field defaults.

### The one changed test

`test_returns_a_scan_result_with_all_pipeline_outputs_populated` asserted
`result.attack_paths == ()`. That encoded the **placeholder**, not an
intended behaviour: its fixture is a bucket with `public: True`, a
genuinely internet-readable store. Per §21 the smallest layer was
modified — one assertion — and it now asserts real discovery plus risk
enrichment. Net: one assertion became four. Documented inline.

---

## 6. What was NOT done — explicitly

### Scenarios not built

**Internet → workload → IAM role → data.** `normalizers/ec2.py` records
`instance_profile_arn` as an *attribute*; no collector emits a
workload-to-identity *edge*. Building it would mean inventing the
relationship. A test asserts the path is **not** produced even with all
four resources present.

**Overprivileged identity → sensitive resource** (Scenario C's second
half). No collector emits an edge from an identity to the data it can
reach. What ships is the publicly-assumable-identity case, which *is*
evidenced.

### Not built at all

- **Attack path persistence.** No table, no ORM model, no mapper.
  `PersistScanResult` still drops `ScanResult.attack_paths`. The
  findings' `risk` and `related_attack_path_ids` **are** persisted, so
  the risk survives a round trip; the path detail does not.
- **No API surface.** No router or schema exposes attack paths.
- **No collectors added, no rules added, no framework references
  touched.**
- **`AttackTechnique` is always empty** — MITRE mapping would need a
  catalog nobody has specified.
- **`blocked` is still never set `True` by any collector.** The analyzer
  honours it; the input is always `False`.

### Not verified

- **No collector was run against a real AWS or Azure API.** Scenarios are
  exercised against fakes modelled on documented response shapes, and
  against the real `ScanCloudAccount` pipeline with static collectors.
- No load testing of path discovery.

---

## 7. False-positive controls, as shipped

| Control | Mechanism | Tested |
|---|---|---|
| Connectivity ≠ reachability | `ATTACHED_TO`/`ALLOWS` not traversable | ✅ |
| Blocked edges | Excluded; score 0 if present | ✅ |
| `UNKNOWN` never becomes `True` | `_definitely_true` | ✅ |
| Denied policy enumeration | Incompleteness penalty, surfaced | ✅ |
| External nodes | Cap confidence; never a target | ✅ |
| Unclassified types | `OTHER` — never a target | ✅ |
| Both halves required | Public IP **and** open ingress | ✅ |
| Cycles | `find_paths` visits each node once | ✅ |
| Depth | `MAX_DEPTH = 4` | ✅ |
| Malformed candidate | Skipped per-path, scan survives | ✅ |
| Identity ≠ data store | Data-bearing/sensitive split | ✅ |

19 of the 40 analysis tests assert what is **not** reported.

---

## 8. Honest state

ComplianceIQ now produces its first real, explainable, deterministic
attack paths from the existing Resource Graph, and their risk reaches
findings through the real scanning pipeline. That was the goal.

It is **not** a complete attack-path product. The most valuable chain in
cloud security — internet to workload to identity to data — remains
unevidenced, and closing it needs one API call
(`iam:GetInstanceProfile`) plus identity→resource edges, not more
analyzer logic. Paths are computed and then discarded at the persistence
boundary.

### Recommended next order

1. **Instance-profile → role resolution** — one API call unlocks the
   workload→identity edge and with it the textbook chain.
2. **Persist attack paths** (table + mapper + migration) and expose them
   through the API, so the analysis survives the scan that produced it.
3. **VPC / Subnet / Route Table collectors** — real network reachability
   instead of inference from a public IP.
4. **Identity → resource edges** from policy resource ARNs, completing
   Scenario C.
5. **Set `blocked`** by evaluating whether a security group rule actually
   prevents a path.
