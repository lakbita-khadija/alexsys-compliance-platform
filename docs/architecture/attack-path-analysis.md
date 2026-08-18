# Attack Path Analysis

## 1. Why attack paths exist

Most CSPM findings are single-resource facts: *this bucket is public*,
*this role has AdministratorAccess*. Both are worth reporting. Neither
tells you whether you are actually in danger.

The danger is in combinations. A public bucket holding nothing is a
housekeeping item. A public bucket that CloudTrail delivers audit logs
into is an attacker reading your detection coverage before they act.
Same bucket, same rule, same severity — completely different urgency.

**No amount of per-resource checking finds that**, because the finding is
not a property of either resource. It is a property of the relationship
between them. That is what the graph is for, and attack path analysis is
what reads it.

## 2. Inputs

```
NormalizedResource[] ──▶ BuildResourceGraph ──▶ ResourceGraph ─┐
                     └──────── attributes ────────────────────┤
                                                              ▼
Finding[] ──────────────────────────────────▶ AnalyzeAttackPaths
                                                              │
                                                    AttackPath[]
                                                              │
                                            EnrichFindingsWithRisk
                                                              ▼
                                        Finding.risk, .related_attack_path_ids
```

The analyzer needs **both** the graph and the resources. Graph nodes
carry identity, provenance and confidence but **not attributes**, and
"is this bucket public" lives in the attributes. `resources` is an
optional parameter: omit it and the attribute-driven scenarios find
nothing — a smaller result, never a wrong one.

## 3. Traversal strategy

Reuses `domain/graph/queries.find_paths`: depth-bounded (`MAX_DEPTH = 4`),
cycle-free by construction, `blocked`-aware. No second traversal engine
was written.

Four hops covers every chain the current relationship vocabulary can
express and bounds the combinatorial cost. Raising it is not free — path
count grows combinatorially, and an unbounded search over a large
tenant's graph is a denial of service against our own scanner.

## 4. Security-relevant relationships

The single most consequential decision in this design:

> **Connectivity is not reachability.**

| Relationship | Traversable | Why |
|---|---|---|
| `ASSUMES` | ✅ | Taking on an identity is movement |
| `ACCESSES` | ✅ | Reading through a principal is movement |
| `PUBLICLY_EXPOSED` | ✅ | The entry point itself |
| `CONNECTS_TO` | ✅ | Network reachability |
| `ATTACHED_TO` | ❌ | Configuration. An attacker does not travel *into* a security group |
| `ALLOWS` | ❌ | A policy statement, not a step |
| `CONTAINS` | ❌ | Topology |
| `PROTECTS` | ❌ | A control, not a route |

Treating every edge as a step is exactly how a graph becomes a
false-positive generator. The informational set is written out explicitly
rather than defined as "everything else", so adding a relationship type
forces a decision instead of silently defaulting to traversable.

`ATTACHED_TO` does appear in one scenario as a **reachability witness** —
it names *which* security group admits the internet. It is evidence, not
a traversal step, and it remains non-traversable everywhere else.

## 5. Resource roles

Normalized across providers (§18), so the analyzer never asks "is this
AWS". Adding a provider means adding table rows, not branches.

| Role | AWS | Azure |
|---|---|---|
| `WORKLOAD` | `ec2_instance` | `azure_virtual_machine` |
| `STORAGE` | `s3_bucket` | `azure_storage_account` |
| `SECRETS` | `kms_key` | `azure_key_vault` |
| `IDENTITY` | `iam_role`, `iam_user` | — |
| `NETWORK_CONTROL` | `security_group` | `azure_network_security_group` |
| `AUDIT_LOG` | `cloudtrail` | `azure_activity_log_setting` |
| `EXTERNAL` | `internet`, `aws_account`, `aws_service` | `azure_tenant` |

Two overlapping subsets, and the difference between them matters:

- **Sensitive** = STORAGE, SECRETS, IDENTITY, AUDIT_LOG — worth reaching.
- **Data-bearing** = STORAGE, SECRETS, AUDIT_LOG — actually *stores*
  something.

An IAM role is a valuable target but holds no data. Collapsing the two
produced a real false positive: a publicly assumable role was reported as
*"holds sensitive data and is readable from the internet"* — a true risk
stated in a false sentence, ranked above the correctly-worded path for
the same resource. A responder reading "holds sensitive data" goes
looking for data. Regression-tested.

## 6. Scenarios

Five ship. Each is grounded in edges and attributes collectors genuinely
produce today.

| Scenario | Chain | Evidence |
|---|---|---|
| `internet_to_workload_to_identity_to_data` | `network control → workload → identity → store` | Public address + unrestricted ingress + instance profile + matched IAM grant |
| `public_identity_with_privilege` | `internet → identity` | Real `PUBLICLY_EXPOSED` edge + privilege attributes |
| `internet_to_sensitive_data` | `store` | The store's own public-access attributes |
| `internet_to_exposed_workload` | `network control → workload` | Public address **and** unrestricted ingress |
| `sensitive_data_flow_to_exposed_store` | `source → … → exposed store` | Traversable edges into a publicly readable store |

> **Reachability note on Scenario 1.** It depends entirely on
> `IamRoleCollector`, the only producer of `PUBLICLY_EXPOSED`. That
> collector was **not registered** in `AwsCollector` until the STEP 0
> audit, so the scenario could not fire in any real scan — only in tests
> that build estates by hand. Registration is fixed and pinned by a test
> that derives the expected collector set from the package rather than
> hardcoding a count. See
> `docs/audits/post-study-guide-current-state.md` §2.

### The flagship chain, and what still constrains it

The textbook chain **internet → workload → IAM role → data** is now
complete, built in two halves:

- **STEP 1** added `ec2_instance --ASSUMES--> iam_role`, resolved from
  `iam:GetInstanceProfile` — never from name conventions or ARN string
  surgery (see `resource-graph.md` §5).
- **STEP 2** added `iam_role --ACCESSES--> <resource>`, derived from the
  role's own policy documents (`resource-graph.md` §6).

`internet_to_workload_to_identity_to_data` requires `ASSUMES` **then**
`ACCESSES`, every hop traversable, and a data-bearing target. Three
negatives are load-bearing and each is pinned by a test:

- A `*` grant produces **no** edges, so an `AdministratorAccess` role
  does not manufacture a path to every bucket in the estate.
- An explicit `Deny` removes the chain even when a matching `Allow`
  exists.
- A workload with a **direct** `ACCESSES` edge to data is *not* reported
  under this scenario. It is a real risk, but naming a privilege hop
  that never happened is a true risk stated in a false sentence — the
  same defect class as the data-bearing/identity bug in §5.

The constraint that remains is the one worth stating plainly: a
`POTENTIAL` grant is **silently dropped**, not reported at low
confidence. A role that can reach everything therefore contributes
nothing to this scenario. That is a deliberate false-negative in
exchange for not generating |resources| paths per over-permissioned
role, and §14 records it as a limitation rather than a feature.

A fabricated attack path is worse than a missing one: it sends a security
team to investigate something that does not exist, with a confident
severity attached, and it teaches them to distrust every other finding.

## 7. Confidence

Reuses the **graph** confidence vocabulary (`high`/`medium`/`low`/
`unknown`). Three confidence concepts already existed in this codebase; a
fourth would have been the mistake.

Path confidence is the **weakest link** across every node and edge.
Averaging would let two confident edges launder one guess.

A consequence worth stating: `internet` is an external node carrying
`medium` confidence, so every internet-origin path is capped at `medium`.
That is correct, not a defect — we never enumerated the internet.

## 8. Risk scoring

**An explainable product risk score, not a mathematically authoritative
one.** The weights are a documented product judgement. They are not
derived from incident data and not calibrated against any published
model. What they are is deterministic, inspectable, and changeable in one
place. A CSPM that hands out a confident 87.4 it cannot explain teaches
its users to ignore the number.

```
risk = exposure + privilege + sensitivity + relationship
       - length discount - confidence penalty - incompleteness penalty
```

clamped to `[0, 100]`. Model version `apsm-1.0`.

| Contribution | Points |
|---|---|
| Internet reachable via graph edge | +40 |
| Publicly exposed by attribute | +35 |
| Network control allows unrestricted ingress | +15 |
| Administrator access | +30 |
| Privilege escalation path | +20 |
| Wildcard action | +10 |
| *(privilege capped at)* | *30* |
| Sensitive target: secrets / storage / identity / audit log | +25 / +20 / +20 / +15 |
| Traverses `assumes` / `accesses` | +10 / +5 |
| Each hop beyond the first | −5 (max −15) |
| Confidence medium / low / unknown | −10 / −25 / −40 |
| Incomplete evidence | −20 |

Three decisions inside that table:

- **Edge and attribute exposure are alternatives, not cumulative.** They
  are two ways of learning the same fact; adding both would double-count.
- **Privilege is capped.** Two routes to total control is still total
  control.
- **A blocked edge short-circuits to 0.** Not a scoring choice — it is
  the `AttackPath` aggregate's own invariant, enforced in the scorer so
  the two can never disagree.

Every path carries its `score_factors` breakdown, so the number can be
defended line by line.

## 9. Severity mapping

Uses the project's existing four-value `Severity`. No fifth value, no
parallel enum. No prior attack-path threshold existed, so there was no
contract to preserve.

| Score | Severity |
|---|---|
| 70–100 | `CRITICAL` |
| 40–69 | `HIGH` |
| 20–39 | `MEDIUM` |
| 0–19 | `LOW` |

## 10. False-positive controls

| Control | Mechanism |
|---|---|
| Connectivity ≠ reachability | Informational relationships are not traversable |
| Blocked edges | Excluded in `is_traversable`; score 0 if present |
| `UNKNOWN` never becomes `True` | `_definitely_true` — anything not literally `True` is not evidence |
| Denied policy enumeration | Incompleteness penalty, and the fact is surfaced |
| External nodes | Cap confidence; never a target |
| Unclassified resource types | `OTHER` — never a target, never an entry |
| Both halves required | Public IP *and* open ingress; neither alone |
| Cycles | `find_paths` visits each node once |
| Depth | `MAX_DEPTH = 4` |
| Malformed candidate | Skipped per-path; never aborts the scan |
| Wildcard IAM grants | `*` classifies `POTENTIAL` → **no** `ACCESSES` edges |
| Explicit `Deny` | Wins over any matching `Allow`, before edges are drawn |
| `NotResource` grants | Inverted resources never match; no edge |
| Conditioned grants | Edge drawn at reduced confidence, and the path with it |
| Identity hop asserted, not assumed | The flagship scenario requires `ASSUMES` **then** `ACCESSES`; a direct workload→data edge is reported under a different scenario |

## 11. Examples — real output

The flagship chain, from the estate in
`tests/integration/persistence/test_attack_path_persistence.py`:

```
100.0  critical  high    internet_to_workload_to_identity_to_data
       sg-1 -> i-web -> arn:aws:iam::111111111111:role/app-server-role -> acme-reports
         publicly_exposed_by_attribute(public_ip,has_unrestricted_ingress): +35.0
         privileged_identity(has_administrator_access): +30.0
         sensitive_target(storage): +20.0
         network_control_allows_unrestricted_ingress: +15.0
         traverses_assumes_relationship: +10.0
         path_length_discount: -5.0

 50.0  high      high    internet_to_exposed_workload
       sg-1 -> i-web
         publicly_exposed_by_attribute(public_ip,has_unrestricted_ingress): +35.0
         network_control_allows_unrestricted_ingress: +15.0
```

The partial scenario is still reported alongside the full one. It is a
real, separately actionable exposure — closing the security group fixes
it without touching the IAM policy — and the ordering puts the composite
risk first.

From the estate in `test_attack_path_pipeline_integration.py`:

```
 80.0  critical  medium  public_identity_with_privilege
       internet -> role/admin
       this identity's trust policy admits a principal outside the
       account, so it can be assumed from the internet
         internet_reachable_via_graph_edge: +40.0
         privileged_identity(has_administrator_access): +30.0
         sensitive_target(identity): +20.0
         confidence_penalty(medium): -10.0

 60.0  high      high    sensitive_data_flow_to_exposed_store
       trail-1 -> bucket-public
       this resource writes into a store that is readable from the internet

 55.0  high      high    internet_to_sensitive_data
       bucket-public

 50.0  high      high    internet_to_exposed_workload
       sg-open -> i-web
       this workload has a public address and an attached network
       control that admits unrestricted ingress
```

## 12. Risk enrichment

`EnrichFindingsWithRisk` joins findings to paths and **reuses**
`EnrichRisk` — that component was correct all along, it simply had no
caller, because `attack_path_involvement` (one of CRSF-1.1's five
factors) was underivable while the analyzer returned nothing.

It writes to `Finding.risk` and `Finding.related_attack_path_ids`. **Both
fields already existed** since Phase 1, with columns and mappers, and
were never populated — so attack-path risk reaches the database with no
schema change.

Paths are referenced **by id**, never embedded: a finding carrying full
`AttackPath` copies would duplicate graph nodes and edges into every row.

A path implicates **every resource along it**, not just the endpoint — a
responder who only sees the target cannot break the chain anywhere else.
External nodes are excluded; nobody can remediate the internet.

### The two directions are not inverses (STEP 6)

Both links are exposed, and they answer **different questions**:

| Field | On | Question | Status filter |
|---|---|---|---|
| `related_attack_path_ids` | `Finding` | *Is my resource on this path?* | none — any status |
| `contributing_finding_ids` | `AttackPath` | *Which misconfigurations create this risk?* | `fail` only |

So a **passing** finding on a resource that sits on a path appears in the
first and not the second. Verified by running the pipeline, not by
reading it:

```
PATH  -> findings:  acme-reports:s3-public

FINDING -> paths:
  acme-reports:s3-public      fail           -> 1 path   reciprocated=True
  acme-reports:s3-encrypted   pass           -> 1 path   reciprocated=False
  i-web:ec2-imdsv2            indeterminate  -> 2 paths  reciprocated=False
```

The asymmetry is deliberate and the "fix" is worse than the condition.
Making them mirror would either attribute a *passing* check to an attack
path, or hide the fact that a resource on a chain has other findings
against it. What matters is that a client is told, so the schema
description says it outright and a test asserts the description says it —
otherwise a dashboard round-tripping the two would show findings
vanishing and file a bug against the wrong subsystem.

### The environment assumption, declared

`Finding.environment` is optional and no collector populates it. A factor
cannot be omitted, so unknown environment resolves to a mid-scale 50 and
the finding records `risk_environment_defaulted: true`. Scoring
everything as production inflates the estate; scoring everything as
sandbox hides real risk. Neither is honest, so the assumption is made
visible instead of hidden.

## 13. Determinism

Same graph → same paths → same order → same scores → same severity.

- Path ids are deterministic composites (`tenant:scenario:entry:target`)
  — no `uuid4`, no clock, so a path is trackable across scans.
- Results sort by `(-risk_score, id)`.
- Traversal order is the graph's index order, which is sorted.
- Tested: five identical runs, and reversed resource input order.

## 14. Limitations

1. **Over-permissioned roles are invisible to the flagship scenario.**
   A `*` resource grant classifies `POTENTIAL` and produces no
   `ACCESSES` edges at all, so the role most likely to matter
   contributes nothing to `internet_to_workload_to_identity_to_data`.
   The alternative — one edge per candidate resource — turns a single
   `AdministratorAccess` role into |resources| attack paths, and a
   report nobody can read is worse than a report missing a row. The
   exposure is still reported by `public_identity_with_privilege` and by
   the IAM rules; only the *composite* path is suppressed.
2. **`blocked` is never set `True` by any collector.** The plumbing
   honours it; the input is always `False`.
3. **Access derivation is AWS-only.** `extract_access_grants` reads IAM
   policy documents; Azure role assignments have no equivalent producer,
   so the flagship chain cannot be found in an Azure estate.
4. **Cross-account grants are not resolved.** A policy naming a resource
   in another account produces no edge, because that resource is not in
   the graph — correct, but it means a real cross-account path is a
   false negative.
5. **Resource-based policies are not read.** A bucket policy granting
   access to a principal is invisible; only identity-based grants are
   analyzed, so a path that exists only via a bucket policy is missed.
6. **`AttackTechnique` is always empty.** Mapping to MITRE would require
   a catalog nobody has specified.
7. **No live validation.** Scenarios are exercised against fakes modelled
   on documented response shapes.

Resolved since the previous revision: attack paths **are** now persisted
(§16) and **are** exposed through the API (§17); the workload→identity
and identity→data edges both exist (§6).

## 15. Future extensions

1. **VPC / Subnet / Route Table collectors** — they emit `contains`,
   `connects_to`, `routes_to`, making true network reachability
   computable instead of inferred from a public IP.
2. **Resource-based policy analysis** — bucket policies, KMS key
   policies and trust policies as a second grant source, closing
   limitation 5.
3. **Cross-account resolution** — requires collecting more than one
   account into a single graph, which is a tenancy decision before it is
   a graph one.
4. **Set `blocked`** by evaluating whether a security group rule actually
   prevents a path.
5. **A bounded representation for `POTENTIAL` grants** — something that
   says "this role reaches everything" as *one* path rather than
   thousands, closing limitation 1 without the explosion.

## 16. Persistence (STEP 4)

The ResourceGraph is rebuilt every scan and never persisted, so a path
fetched tomorrow cannot be rediscovered — the graph that found it is
gone. Before STEP 4, `ScanCloudAccount` produced attack paths and
`PersistScanResult` silently dropped them; only their *risk* survived,
via `Finding.related_attack_path_ids`.

`attack_paths` (migration `0004`) stores them.

| Decision | Reasoning |
|---|---|
| Composite PK `(attack_path_id, scan_key)` | Path ids are deterministic, so the same path recurs across scans **by design**. Keying on the id alone would make each scan overwrite the last and destroy the history the fingerprint exists to track. |
| `nodes` / `edges` as JSONB, not child tables | A path is read as one unit — a partial path is meaningless — is never queried independently, and is never joined against. Two child tables buy normalization nobody uses and cost a join on every read. |
| `fingerprint` excludes score and provenance | So "is this the same path as last week" survives a re-scoring or a change to the weights. |
| CHECK constraints on severity, confidence and score bounds | An invariant enforced only in Python is enforced only by the code paths that go through Python — not by a backfill or an operator with `psql` open. |
| `ON CONFLICT DO NOTHING` | A retried persist must be a no-op, not a crash and not a second copy. |
| `created_at` is the **scan's** time | The row records when the cloud was in this state, not when the database happened to be written. |
| `ON DELETE CASCADE` from `scans` | A path without its scan is an orphan nobody can interpret. |

Evidence payloads pass through `redact()` on the way in, for the same
reason finding evidence does: the payload is assembled from collected
values, and "it cannot contain a secret" is an assumption a future
collector change can invalidate.

## 17. API surface (STEP 5)

| Endpoint | Returns |
|---|---|
| `GET /api/v1/scans/{scan_id}/attack-paths` | Every path from one scan, highest risk first, **plus** a severity summary |
| `GET /api/v1/attack-paths/{attack_path_id}` | One path: ordered chain, evidence, scoring breakdown, contributing findings |

The reverse direction lives on findings: `GET /api/v1/findings/{id}`
returns `related_attack_path_ids`, and the detail endpoint additionally
returns `graph_context`. See §12 for why the two directions do not
mirror each other.

Filters: `severity`, `scenario`, `min_confidence`. The summary is
computed **after** filtering, so the dashboard's count cannot contradict
the list beneath it.

Two decisions worth naming:

- **Paths and summary in one response.** The landing screen needs both,
  and two endpoints would guarantee they eventually disagree.
- **Reads return plain mappings, not rebuilt `AttackPath` aggregates.**
  The aggregate's invariants — path integrity, tenant match on every
  node, blocked-implies-score-zero — are construction-time guarantees
  over live `GraphNode`/`GraphEdge` objects. Reconstituting them from
  JSONB would either re-validate against a graph that no longer exists,
  or force the invariants to be relaxed. An aggregate relaxed so it can
  be read back has stopped meaning anything.

Tenancy comes from the verified JWT; there is no `tenant_id` parameter.
A foreign path id and a nonexistent one return **identical** 404 bodies
(modulo the per-request correlation id), because any difference is an
oracle for enumerating another tenant's attack paths. A foreign
`scan_id` returns an empty list rather than an error, for the same
reason.
