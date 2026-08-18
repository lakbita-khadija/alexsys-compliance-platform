# Phase 12 — Answers (capstone)

**1. The full trace.**

```
1. COLLECT   infrastructure/cloud/aws/resource_collectors/s3.py
             ListBuckets → "acme-reports"
             GetBucketAcl → grant to AllUsers
             + encryption / versioning / logging / policy / PAB calls
             (AccessDenied on any → UNKNOWN, never False)

             cloudtrail.py → trail-1, S3BucketName = "acme-reports"

2. NORMALIZE aws/normalizers/s3.py
             NormalizedResource(resource_type="s3_bucket",
                 attributes={"public": True, "encrypted": False, ...},
                 relationships=())                     ← S3 emits NO edges
             aws/normalizers/cloudtrail.py
             NormalizedResource(resource_type="cloudtrail",
                 relationships=(ACCESSES → "acme-reports",))

3. GRAPH     application/graph/build_resource_graph.py
             nodes first, then edges:
               GraphNode("acme-reports", s3_bucket, kind=collected, confidence=high)
               GraphNode("trail-1", cloudtrail, ...)
               GraphEdge(trail-1 → acme-reports, ACCESSES)
             indexes _out/_in/_by_type maintained inside add_node/add_edge

4. RULES     rules/aws/s3.yaml → s3-bucket-public
               {field: public, operator: equals, value: true} → MATCHED
             rules/aws/cloudtrail.yaml → cloudtrail-logs-to-public-bucket
               relationship: accesses, target_type: s3_bucket,
               where: {field: public, operator: is_true} → MATCHED
               (needs graph + resources_by_id, else RAISES)

5. FINDINGS  application/rules/evaluate_rules.py::_to_finding
             FAIL / CRITICAL / iso_27001 A.8.24
             logical_finding_id = "acme:111111111111:acme-reports:s3-bucket-public"
             finding_id         = logical + ":" + scan_id
             evidence           = attributes + rendered narrative
             RelationshipTrace → the cloudtrail finding gets
               related_resources = ("acme-reports",)
               graph_context     = the trail's neighbourhood

6. QUERIES   domain/graph/queries.py — edges_of, find_paths (max_depth=4)

7. PATHS     application/attack_paths/analyze_attack_paths.py
             _exposed_sensitive_data:
               public_exposure_evidence({"public": True}) → ("public",)
               nodes=(bucket,), edges=()
               35 (attribute) + 20 (storage) = 55.0 → HIGH
             _data_flows_into_exposed_stores:
               find_paths(trail-1 → acme-reports) → one edge
               all traversable (ACCESSES ✅)
               35 + 20 + 5 (accesses) = 60.0 → HIGH
             sorted: 60.0 then 55.0

8. RISK      application/risk/factors.py + enrich_findings.py
             both paths implicate acme-reports
             severity_factor           = 100.0  (CRITICAL)
             exposure_factor           = 60.0   (max path score)
             environment_factor        = 50.0   (DEFAULTED — flagged)
             confidence_factor         = 100.0  (both paths high)
             attack_path_involvement   = 60 + 10 (2 paths) = 70.0
             CRSF-1.1: 100(.40) + 60(.25) + 50(.10) + 100(.10) + 70(.15)
                     = 40 + 15 + 5 + 10 + 10.5 = 80.5
             Finding.risk = 80.5
             Finding.related_attack_path_ids = both, sorted
             evidence += risk_model_version, attack_path_count=2,
                         risk_environment_defaulted=True

9. PERSIST   finding_snapshots row — risk and path ids survive.
             The AttackPath objects are DROPPED (no table).

10. API      GET /findings → the finding with risk 80.5
             ⚠️ related_resources / graph_context are stored but not
             exposed by any response schema.
```

*(The CRSF arithmetic above is worked by hand from the documented weights;
the exact float depends on the estate. ⚠️ Verify by running the pipeline
if you need the precise number.)*

**2. "Why is this finding 62 and that one 41?"**

Same rule, same severity → identical `severity_factor`. The difference is
in the other four factors, and almost entirely two of them:

- **`exposure_factor`** = the highest-scoring attack path implicating the
  resource. The 62 bucket sits on a path; the 41 bucket does not (0.0).
- **`attack_path_involvement_factor`** = that same worst score plus 10 per
  extra path, capped at 3 extras.

Together those carry 25% + 15% = **40% of the CRSF weight**.

Concretely: *"This bucket is publicly readable AND CloudTrail delivers
your audit logs into it — an attacker reading it learns your detection
coverage. The other bucket is publicly readable and nothing flows into
it."*

Then show `Finding.evidence["attack_path_count"]` and the path's
`score_factors` breakdown. Every number is traceable to a named graph
fact — which is the entire reason the scoring model is additive and
explainable rather than a single opaque formula.

**3. Three reasons to refuse the "roles usually have S3 access" path.**

1. **No edge exists — the claim is not evidence-based.** No collector
   emits workload→identity or identity→data. "Usually" is a statistical
   prior about the industry, not an observation about *this* customer.
   The analyzer's governing constraint is *only what the graph
   evidences*.

2. **The instance profile is not the role.** Even the first hop is
   unavailable: `instance_profile_arn` names a *profile*, and resolving
   its role needs `iam:GetInstanceProfile`, which nothing calls. Matching
   `profile/app` to `role/app` is a naming convention, and a convention is
   not a fact.

3. **The cost asymmetry.** A fabricated CRITICAL path pages someone at
   2am for a chain that does not exist. They lose an hour, and — worse —
   discount every future critical alert. A fabricated path is worse than a
   missing one.

Supporting: `test_no_workload_to_identity_path_is_invented` already
asserts this, deliberately, with all four resources present. Changing the
behaviour means deleting a test written to prevent exactly this proposal.

**4. Design the extension.**

**API call:** `iam:GetInstanceProfile` (or
`iam:ListInstanceProfilesForRole`).

**Edge:** `ec2_instance --ASSUMES--> iam_role` — already traversable, so
traversal needs no change.

**Files:**
- `infrastructure/cloud/aws/resource_collectors/ec2.py` — resolve the
  profile → role ARN, via `call_with_retry`; it is an N+1 over instances
- `infrastructure/cloud/aws/normalizers/ec2.py` — emit the relationship
- `application/attack_paths/analyze_attack_paths.py` — either a new
  builder, or let `_data_flows_into_exposed_stores`' `find_paths` pick up
  the longer chain
- `domain/attack_paths/classification.py` — **no change**; both types are
  already mapped

**Tests to add:**
- Collector: profile → role resolution
- Collector: `AccessDenied` → **no edge**, attribute `UNKNOWN`
- Graph: the edge appears
- Analyzer: the full chain is found when all four resources exist
- Analyzer: **still no path** when the instance is not internet-facing
- Determinism

**Test to delete:** `test_no_workload_to_identity_path_is_invented` — and
only when the edge genuinely exists. Replace it with the positive
assertion, and keep a negative for the denied-resolution case.

**Must not infer:** the role from the profile name; a single role per
profile (AWS models it as a list); that the workload's exposure implies
the role's.

**5. Explain to a non-engineer.**

> Imagine a building inspector who is given keys to some rooms but not
> all of them.
>
> A bad inspector writes "no fire hazards found" for the rooms they could
> not enter. The report says the building is safe. It might be on fire.
>
> A good inspector writes three things: *rooms I checked and passed*,
> *rooms I checked and failed*, and *rooms I could not get into*.
>
> ComplianceIQ does the third. If it lacks permission to read a bucket's
> settings, it does **not** report "this bucket is fine". It reports "I
> could not check this bucket" — which tells you to fix the *scanner's*
> access, not the bucket.
>
> The alternative is worse than useless: it is a clean bill of health for
> something nobody looked at.

**6. Adding GCP — what changes?**

**Changes (infrastructure only):**
- `infrastructure/cloud/gcp/` — collectors, normalizers, credentials
- `GcpCollector` implementing the `BaseCollector` port
- `rules/gcp/*.yaml`
- `CloudProvider.GCP` enum member — `domain/shared/enums.py`
- Rows in `_ROLE_BY_RESOURCE_TYPE` mapping GCP types to `ResourceRole`
- Tests

**Does NOT change:**
- `ResourceGraph`, `queries.py` — provider-agnostic
- `conditions.py` — operates on attributes
- `classification.py` **logic** — only the table gains rows
- `scoring.py`, `AnalyzeAttackPaths` — reason about `ResourceRole`
- `ScanCloudAccount` — depends on the port
- Findings, risk, persistence, API

That asymmetry is the payoff of §18's "no `if aws: elif azure:`" rule, and
it is verified today by
`test_azure_produces_paths_through_the_same_code`.

**7. Persisting attack paths.**

**Table** `attack_paths`: `attack_path_id` (PK, the deterministic
composite), `scan_key` (FK → `scans`, `ON DELETE CASCADE`), `tenant_id`,
`scenario`, `severity`, `risk_score`, `confidence`, `algorithm_version`,
`scoring_model_version`, `nodes` (JSONB), `edges` (JSONB), `evidence`
(JSONB, through `redact()`), `contributing_finding_ids` (JSONB).

Constraints mirroring the aggregate: `risk_score` between 0 and 100;
severity in the four-value set. Indexes on `(tenant_id, scan_key)` and
`(tenant_id, severity)`.

**Mapper:** `attack_path_to_row` / `attack_path_to_domain` in
`mappers.py`. Node/edge reconstruction needs care — `GraphNode` and
`GraphEdge` are frozen dataclasses with validated fields.

**Migration `0004`:** purely additive, new table only.

**API:** `GET /scans/{id}/attack-paths`, `GET /attack-paths/{id}`, and
expanding `related_attack_path_ids` on a finding.

**What breaks if you embed instead of reference:**

- **Duplication.** A path touching four resources is copied into four
  finding rows. Nodes and edges are the heaviest part of the object.
- **Update anomalies.** Rescoring a path means rewriting every finding
  that mentions it — with no transactional guarantee they stay
  consistent.
- **Payload size.** The AI Service contract is a fixed 11 fields
  precisely to keep the boundary small; embedding graph fragments would
  blow that up.
- **Circularity.** `AttackPath.contributing_finding_ids` already points at
  findings. Embedding paths in findings creates a cycle that
  serialization has to break arbitrarily.

Reference is why `Finding.related_attack_path_ids` was designed as an id
list in Phase 1 — the storage was built for this and left empty.
