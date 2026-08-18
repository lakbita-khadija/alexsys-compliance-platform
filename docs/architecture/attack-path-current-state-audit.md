# Attack Path Analysis — Current State Audit

> **Audit only. No code was modified to produce this document.**
> Every classification below was obtained by reading the code and
> executing queries against the repository. Prior reports and prompts
> were treated as unverified claims, not as evidence.

---

## 1. Component classification

### domain/graph/

| Component | State | Notes |
|---|---|---|
| `ResourceGraph` aggregate | **EXISTS AND WORKS** | Tenant isolation at `add_node`, referential integrity at `add_edge` |
| `GraphNode` / `GraphEdge` | **EXISTS AND WORKS** | 10 and 7 fields incl. provenance, evidence, confidence |
| External nodes (`kind="external"`) | **EXISTS AND WORKS** | `is_external`; distinguishes "outside the scan" from "failed to collect" |
| Adjacency + type indexes | **EXISTS AND WORKS** | `_out`/`_in`/`_by_type`, maintained inside mutators |
| `outgoing_edges`/`incoming_edges`/`resource_ids_of_type` | **EXISTS AND WORKS** | Public index readers |
| `neighbors()` | **EXISTS AND WORKS** | One hop, index-backed |
| `validate_graph`, `graph_fingerprint`, `graph_context_for` | **EXISTS AND WORKS** | Diagnostic, deterministic |
| `domain/graph/queries.py` — 11 primitives | **EXISTS AND WORKS** | Incl. **`find_paths`** (bounded, cycle-free, `blocked`-aware) |

### application/graph/

| Component | State | Notes |
|---|---|---|
| `BuildResourceGraph` | **EXISTS AND WORKS** | Per-edge isolation, external materialization, `GraphBuildResult` |

### domain/attack_paths/

| Component | State | Notes |
|---|---|---|
| `AttackPath` | **EXISTS BUT INCOMPLETE** | Validates identity, tenant isolation, path integrity, bounded score, and *blocked ⇒ score 0*. Has **no** `confidence`, **no** `evidence`, **no** `scenario` field |
| `AttackTechnique` | **EXISTS AND WORKS** | Open value object, no invented catalog |
| Domain tests | **EXISTS AND WORKS** | 14 tests |

### application/attack_paths/

| Component | State | Notes |
|---|---|---|
| `AnalyzeAttackPaths.analyze()` | **EXISTS BUT INCOMPLETE** | **Hardcoded `return ()`.** Signature already receives `tenant_id`, `graph`, `findings` — everything a real implementation needs |
| Its 3 tests | **EXISTS AND WORKS** | All three use an **empty graph**, so they remain valid after implementation. No test needs weakening |

### Risk

| Component | State | Notes |
|---|---|---|
| `RiskScore` + CRSF-1.1 formula | **EXISTS AND WORKS** | Exact §13 weights; attack-path involvement is 15% of it |
| `ConfidenceScore` | **EXISTS AND WORKS** | 0–100 |
| `EnrichRisk` | **EXISTS BUT NOT INTEGRATED** | Correct as written. Called by **nothing** outside its own 4 tests |

**Why `EnrichRisk` is not invoked** (§13 asks): not a bug and not an
oversight. It requires five pre-computed 0–100 factors, and nothing in
the codebase derives them, because the blueprint specifies the *weights*
but never how a raw signal becomes a factor. `attack_path_involvement`
was underivable by construction — the analyzer that would supply it
returns `()`. Implementing the analyzer removes that blocker for exactly
one of the five factors.

### Pipeline

| Component | State | Notes |
|---|---|---|
| `ScanCloudAccount` | **EXISTS AND WORKS** | The real entry point, reached from `SubmitScan`, the AWS/Azure integration tests, and `scripts/dev_scan_aws.py` |
| Attack-path step in pipeline | **EXISTS AND WORKS** | `scan_cloud_account.py:100` already calls `analyze()` and puts the result in `ScanResult.attack_paths` |
| Risk step in pipeline | **MISSING** | An explicit comment marks where it is not called |

> **This is the audit's most useful finding.** The wiring is not the gap.
> `AnalyzeAttackPaths` is *already* invoked by the real pipeline and its
> output *already* flows into `ScanResult`. Implementing `analyze()` makes
> attack paths appear end-to-end with **no pipeline surgery** — the risk of
> "integrating into a dead-end service" (§14) does not apply here.

### Persistence and API

| Component | State | Notes |
|---|---|---|
| `attack_paths` table | **MISSING** | No table, no ORM model, no mapper. `PersistScanResult` silently drops `ScanResult.attack_paths` |
| `Finding.related_attack_path_ids` | **EXISTS BUT NOT INTEGRATED** | Field, column and mapper all exist; nothing ever populates it |
| API surface | **MISSING** | No router, schema or contract mentions attack paths |

---

## 2. The binding constraint: what the graph can actually evidence

§17 forbids inventing coverage, so this decides which scenarios are
implementable. Every edge any collector emits today:

| Edge | Emitted by |
|---|---|
| `ec2_instance --ATTACHED_TO--> security_group` | `normalizers/ec2.py` |
| `security_group --ALLOWS--> security_group` | `normalizers/security_group.py` |
| `cloudtrail --ACCESSES--> s3_bucket` | `normalizers/cloudtrail.py` |
| `iam_role --ASSUMES--> aws-account:… / aws-service:…` | `resource_collectors/iam_roles.py` |
| `iam_role --PUBLICLY_EXPOSED--> internet` | `resource_collectors/iam_roles.py` |
| `azure_virtual_machine --ATTACHED_TO--> azure_network_security_group` | `azure/normalizers/compute.py` |
| `azure_activity_log_setting --ACCESSES--> azure_storage_account` | `azure/normalizers/monitor.py` |

13 resource types are produced. `contains`, `connects_to`, `protects`
are defined and never emitted.

### Three consequences

**1. `PUBLICLY_EXPOSED` has exactly one producer.** Only a publicly
assumable IAM role points at `internet`. **No compute or storage resource
ever gets an internet edge**, even when its own attributes say it is
public — `normalizers/s3.py` sets `relationships=()` while its own
docstring describes a `PUBLICLY_EXPOSED` edge, and `normalizers/ec2.py`
records `public_ip` as an attribute and emits no edge.

**2. There is NO workload → identity edge.** `normalizers/ec2.py` stores
`instance_profile_arn` as an **attribute** and emits no `ASSUMES` edge.
So the *fact* is collected and the *edge* is not.

**3. Therefore Scenario B (§5) is currently unevidenced.** Internet →
workload → identity → resource requires two edges that do not exist. It
cannot be implemented against today's graph without fabricating them.

> The distinction that matters: **materializing an already-collected fact
> into an edge is not faking coverage; inventing the fact is.**
> `instance_profile_arn` and `public_ip` are already read from real AWS
> responses. Turning them into edges adds no fictional capability.
> Emitting an edge for a resource type no collector produces would.

---

## 3. Three confidence concepts already exist

§7 says do not invent a second confidence system. There are already
**three**, and they are genuinely distinct:

| Concept | Type | Means |
|---|---|---|
| `GraphNode.confidence` / `GraphEdge.confidence` | `str` ∈ {high, medium, low, unknown} | How sure we are this node/edge is real |
| `Confidence` enum (`domain.shared.enums`) | high/medium/low | How reliable a **rule's detection logic** is |
| `ConfidenceScore` (`domain.risk`) | float 0–100 | How trustworthy the **collected data** is |

An attack path is assembled from graph edges, so the **graph** confidence
vocabulary is the correct one to reuse. Introducing a fourth would be the
error §7 warns about.

---

## 4. Severity

`Severity` = critical / high / medium / low (**four values, no INFO**).
`AttackPath.severity` already requires a `Severity`. No new enum is
needed; only a documented, tested score→severity mapping.

The example thresholds in §9 (0–19 LOW … 70–100 CRITICAL) do **not**
contradict anything existing — no attack-path threshold is defined
anywhere today, so there is no prior contract to preserve.

---

## 5. Blockers and hazards

**No blockers.** Nothing prevents implementing the analyzer.

Hazards to respect:

| Hazard | Why it matters |
|---|---|
| `blocked` is never set `True` by any collector | Traversal treats every edge as walkable. The `blocked ⇒ score 0` invariant is enforceable but its input is always `False` |
| `AttackPath` has no `evidence` field | §10 requires explainability; the model must be extended additively |
| `find_paths` returns edge tuples, not nodes | `AttackPath` needs both; nodes must be derived from the edge chain |
| External nodes carry `medium` confidence | `internet` is external, so *every* internet-origin path inherits reduced confidence — correct, and must not be "fixed" |
| The 3 existing analyzer tests | All use an empty graph and must keep passing unchanged |
| 68 rules / 7 cross-resource rules | Must not shift. Attack paths are additive, not a rule change |

---

## 6. What this phase can honestly deliver

| Scenario | Verdict |
|---|---|
| **A** — Internet → exposed resource → sensitive target | Implementable **after** materializing exposure edges from already-collected attributes |
| **B** — Internet → workload → identity → resource | Implementable **after** materializing the instance-profile edge from the already-collected `instance_profile_arn` |
| **C** — Overprivileged identity → sensitive resource | Implementable today for the publicly-assumable-role case; the `iam_role → s3_bucket` half has no producing collector |

Scenario C's second half is the honest limit: no collector emits an edge
from an identity to the data it can reach. Reporting one would require
inventing the relationship, which §17 forbids. This phase will report
what the graph evidences and say plainly what it cannot.

---

## 7. Recommended order

1. Extend `AttackPath` additively (`confidence`, `evidence`, `scenario`).
2. Materialize the two missing edges from **already-collected**
   attributes — no new API calls, no new collectors.
3. Implement `AnalyzeAttackPaths.analyze()` on the existing `find_paths`.
4. Scoring + severity mapping, documented and tested.
5. Wire `EnrichRisk` using the now-derivable attack-path factor.
6. Link findings to paths by reference (`related_attack_path_ids`).
7. Integration test through the real `ScanCloudAccount`.

Persistence and API for attack paths are **out of scope** and will be
reported as remaining work: a scan produces them, and
`PersistScanResult` will still drop them.
