# Glossary

Every definition includes a **ComplianceIQ-specific** example — not a
generic one.

---

**Attack Path** — A chain of nodes and edges showing how an attacker could
move through an environment. Answers *"how could someone get in and
move?"*, as opposed to a Finding's *"what is misconfigured?"*
→ `domain/attack_paths/models.py`
*Example:* `internet → role/admin` — a role whose trust policy admits an
unconditional wildcard principal, carrying `AdministratorAccess`. Scores
80.0, CRITICAL.

**AttackTechnique** — A named technique (e.g. MITRE-style) contributing to
a path. Open value object, no built-in catalog.
*Example:* **Always empty today.** Mapping to MITRE would need a catalog
nobody has specified.

**Collector** — Infrastructure component calling cloud APIs and producing
`NormalizedResource`s. 7 AWS, 5 Azure.
*Example:* `IamRoleCollector` — the only collector using the resilience
layer, and the only producer of a `PUBLICLY_EXPOSED` edge.

**Condition** — The nested-dict expression a rule evaluates. Six node
types: `and`, `or`, `not`, leaf, `relationship`, `no_relationship`.
*Example:* `{"field": "public", "operator": "equals", "value": true}` —
the whole of rule `s3-bucket-public`.

**Confidence** — Three distinct concepts, deliberately not unified:
1. `GraphNode/GraphEdge.confidence` — `high`/`medium`/`low`/`unknown`;
   how sure we are the node or edge is real
2. `Confidence` enum — how reliable a **rule's own logic** is (metadata;
   no evaluator reads it)
3. `ConfidenceScore` — 0–100; how trustworthy the **collected data** is
*Example:* An `internet` external node is `medium`, so every
internet-origin attack path caps at `medium` and takes −10.

**Control** — A specific requirement in a compliance framework.
*Example:* `A.8.24` (ISO 27001), the primary control on 18 of the 68
rules.

**CSPM** — Cloud Security Posture Management: continuously assessing cloud
configuration against security and compliance expectations.
*Example:* ComplianceIQ collects 12 of 26 target services and evaluates 68
rules against them.

**Evidence** — The deterministic collected facts behind a finding or a
path. Never AI-generated prose.
*Example:* `Finding.evidence.data` = the resource's attributes plus a
narrative rendered from `evidence_template`.

**External Node** — A graph node for something that is **not a collectible
resource**: the internet, an AWS service principal, a foreign account.
`kind="external"`, `confidence="medium"`.
*Example:* `internet`. Introduced to fix a blocker where an IAM role's
trust policy edge aborted every scan.

**Finding** — One rule's verdict on one resource. `FAIL` / `PASS` /
`INDETERMINATE`.
*Example:* `s3-bucket-public` on `acme-reports` → FAIL, CRITICAL.

**Framework Mapping** — A secondary (framework, control) reference beyond
a rule's primary attribution. `status` defaults to `"unresolved"`.
*Example:* 27 mappings exist; **11 verified, 16 defaulted**. All 9
`cis_azure` are unverified.

**GraphEdge** — A directed relationship. Carries `blocked`, `evidence`,
`source_collector`, `confidence`. Its `identity` —
`(source, target, type)` — **excludes provenance**, so two collectors
observing the same relationship assert one edge.
*Example:* `trail-1 --ACCESSES--> acme-reports`.

**GraphNode** — A resource in the graph: identity, context, provenance,
`kind`. **Carries no attributes** — which is why the attack path analyzer
needs the resources too.
*Example:* `GraphNode("acme-reports", "s3_bucket", provider=AWS,
kind="collected", confidence="high")`.

**Graph Query** — One of the 11 primitives in `domain/graph/queries.py`.
Index-backed, deterministically sorted.
*Example:* `find_paths(graph, source=..., target=..., max_depth=4)` —
depth-bounded, cycle-free, blocked-aware.

**INDETERMINATE** — The third evaluation result: *the data needed to
decide was not collected*. Never silently becomes MATCHED or NOT_MATCHED.
*Example:* `GetBucketAcl` returns `AccessDenied` → `public` is `UNKNOWN` →
the rule returns INDETERMINATE → `FindingStatus.INDETERMINATE`. The
operator's action is to grant the scanner more permission.

**Multi-hop traversal** — Following two or more edges. What makes
composite claims expressible.
*Example:* `trail-1 → bucket-public` is one hop and already composite —
"CloudTrail delivers logs to a publicly readable bucket" is a fact about
neither resource alone.

**NormalizedResource** — The provider-agnostic resource type. Ten fields;
`attributes` holds the security facts, `relationships` become graph edges.
*Example:* An S3 bucket and an Azure storage account are both
`NormalizedResource`; downstream code never asks which cloud.

**Normalizer** — Converts a raw provider response into a
`NormalizedResource`. Reports facts; does **not** interpret policy.
*Example:* `normalize_security_group` reports
`unrestricted_ingress_ports: (22,)`; a *rule* decides port 22 matters.

**Operator** — One of 32 comparison/quantifier/temporal operators.
*Example:* `is_null` is a **comparison**, distinct from `not_exists` — an
absent field is not the same fact as a field collected with value `None`.

**Orchestrator** — `ScanCloudAccount`, the use case sequencing the whole
pipeline. Calls domain code; never reimplements a domain invariant.
*Example:* `application/scanning/scan_cloud_account.py::run()`.

**Relationship** — A member of the closed 8-value `RelationshipType`
vocabulary. **5 are emitted**, 3 (`contains`, `connects_to`, `protects`)
are not.
*Example:* `ATTACHED_TO` is emitted but **not traversable** — an attacker
does not travel into a security group.

**ResourceGraph** — Tenant-scoped, in-memory, directed graph. Built fresh
each scan, **never persisted**, never mutated after construction.
Maintains three indexes inside its mutators.
*Example:* At 999 resources, index-backed evaluation is 5.1 ms vs 88.5 ms
for a linear scan.

**Risk** — `RiskScore`, 0–100, CRSF-1.1: severity 40% + exposure 25% +
environment 10% + confidence 10% + attack-path involvement 15%.
Contextual, unlike Severity.
*Example:* Two identical CRITICAL findings; the one on an attack path
scores higher. That difference **is** the product value of Phases 7–8.

**Rule** — A YAML-declared check: condition, severity, metadata,
remediation. 68 in the catalog.
*Example:* `s3-bucket-public` — `applies_to_resource_type: s3_bucket`,
`severity: critical`, one leaf condition.

**Scan** — One tenant-scoped run producing a `ScanResult`.
*Example:* `scan_id = "acme:aws:111111111111:2026-01-01T00:00:00+00:00"`
— the **account** component is what makes it unique.

**Severity** — How serious a violation is *in the abstract*. Four values:
`critical`, `high`, `medium`, `low`. **No `INFO`.**
*Example:* Attack paths map onto the same enum: 70+ CRITICAL, 40+ HIGH,
20+ MEDIUM, else LOW.

**Tenant** — The isolation boundary. Checked at graph node insertion and
rule evaluation.
*Example:* A foreign-tenant resource raises `TenantIsolationViolation` and
**aborts the scan** — a leak in progress, not a data quality issue.

**UNKNOWN** — The sentinel meaning *"we looked and could not determine
this"*. `__bool__` **raises**, so the dangerous conversion cannot happen
by accident.
*Example:* When IAM policy enumeration is denied, all five privilege
attributes become `UNKNOWN` and `policy_analysis_confidence` becomes
`"unknown"` — a degraded but honest result.

---

## Three distinctions people get wrong

**Severity vs Risk vs Confidence** — *how bad in the abstract* / *how bad
here* / *how much we trust the data*. Never collapse them.

**`UNKNOWN` vs an absent key** — *"applies, could not determine"* vs
*"does not apply"*. `root_volume_encrypted` is absent on an
instance-store-backed EC2 instance; that is not a data gap.

**Connectivity vs reachability** — an edge existing is not an attacker
being able to move along it. `ATTACHED_TO` connects; it is not
traversable.
