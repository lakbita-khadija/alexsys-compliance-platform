# Phase 3B — The Security Policy Evaluation Engine

> The Rule Engine decides whether a resource is compliant. It never
> parses Terraform, never calls a cloud API, and never compares an
> expectation to a result — those are three other components' jobs.

---

## 1. Objective

Turn the Phase 1 rule condition evaluator (10 operators, single
resource, no metadata) into a production-grade CSPM policy engine:

* a **senior operator catalog** — 30 operators across 7 categories
* **arbitrarily nested logical composition** with three-valued logic
  preserved throughout
* **cross-resource evaluation** over the ResourceGraph
* **rule metadata** a real CSPM product needs: title, rationale,
  evidence template, remediation, framework mappings
* **deterministic finding identity** that is stable across scans

Every change is additive. No Phase 1 or Phase 2 call site was modified
to accommodate it.

---

## 2. What is in the engine

| Layer | Module | Responsibility |
|---|---|---|
| Domain | `domain/rules/conditions.py` | The condition evaluator — operators, Kleene logic, relationship traversal |
| Domain | `domain/rules/rule.py` | The `Rule` entity, its metadata, and `applies_to()` |
| Domain | `domain/graph/models.py` | `ResourceGraph.neighbors()` — the one-hop query relationship conditions use |
| Application | `application/rules/evaluate_rules.py` | Orchestration: catalog → findings, identity, evidence |
| Application | `application/rules/evidence.py` | Deterministic evidence narrative rendering |
| Application | `application/rules/composite_rule_catalog.py` | Combines the per-provider catalogs into one |
| Infrastructure | `infrastructure/rules/yaml_rule_catalog.py` | YAML → `Rule` (the only place YAML is parsed) |
| Catalog | `rules/aws/*.yaml`, `rules/azure/*.yaml` | The rules themselves — data, never code |

---

## 3. The condition DSL

A condition is a plain nested `dict`. There is **no `eval`, no `exec`,
no embedded Python** anywhere in the evaluation path — a rule file is
data, and a malicious rule file can at worst produce a wrong finding,
never execute code.

### 3.1 Five node types

```yaml
# 1. Leaf — compare one field
field: public
operator: equals
value: true

# 2. Logical composition — and / or / not, arbitrarily nested
and:
  - field: encrypted
    operator: equals
    value: false
  - or:
      - field: versioning_enabled
        operator: equals
        value: false
      - not:
          field: logging_enabled
          operator: is_true

# 3. Quantifier — any / all / none over a collection field
field: ingress_rules
operator: any
where:
  field: port
  operator: equals
  value: 22

# 4. Relationship — evaluate a condition against graph neighbours
relationship: attached_to
direction: outgoing
target_type: security_group
where:
  field: has_unrestricted_ingress
  operator: equals
  value: true

# 5. Graph function leaf (`source: graph`) — Phase 1 vestige, registry
#    deliberately empty; superseded by the relationship node above.
```

### 3.2 The operator catalog (30 operators, 7 categories)

| Category | Operators |
|---|---|
| Scalar | `equals`, `not_equals`, `contains`, `not_contains`, `starts_with`, `ends_with` |
| Boolean/null | `is_true`, `is_false`, `exists`, `not_exists`, `is_null`, `is_not_null` |
| Numeric | `greater_than`, `greater_than_or_equal`, `less_than`, `less_than_or_equal` |
| Collection | `in`, `not_in`, `contains_any`, `contains_all`, `any`, `all`, `none` |
| String | `matches_regex` |
| Network | `cidr_contains`, `cidr_is_public`, `cidr_is_private`, `port_equals`, `port_in_range` |
| Temporal | `age_gt_days`, `age_gte_days`, `age_lt_days` |

Three design decisions worth stating explicitly:

* **`is_null` is a comparison operator, not a presence operator.** An
  absent field yields `INDETERMINATE`; a field collected *with* the
  value `None` yields `MATCHED`. "We never looked" and "we looked and
  found nothing" are different facts, and a CSPM that conflates them
  reports compliance it has not verified.
* **`matches_regex` with an invalid pattern raises**, it does not
  return `INDETERMINATE`. A broken regex is a rule-authoring bug, and
  hiding it as a data gap would let a silently-never-matching rule ship.
* **Temporal operators require an explicit `as_of`.** There is no
  fallback to `datetime.now()` anywhere in the evaluator. `EvaluateRules`
  passes the scan's own `detected_at`.

### 3.3 Syntax decision (documented, deliberate)

The brief illustrated a syntax using inline `all:`/`any:` keys with the
operator embedded in the value. **That syntax was not adopted.** The
existing `and`/`or`/`not` + `field`/`operator`/`value` shape was kept
as canonical, because:

1. Phase 1 already shipped it, and 41 AWS rules plus every existing
   test already use it — changing it would be a rewrite, not an
   extension, in direct conflict with "extend the existing system
   safely."
2. The brief itself says to *"adapt the exact syntax to the existing
   architecture."*

The example was therefore read as specifying **required capability**
(nested boolean composition, quantifiers) rather than mandating exact
keywords. Every capability it illustrates is implemented.

---

## 4. Three-valued logic

`MATCHED` / `NOT_MATCHED` / `INDETERMINATE`, with the invariant that
**`INDETERMINATE` never silently becomes `NOT_MATCHED`**.

### Truth tables

`NOT`:

| operand | result |
|---|---|
| MATCHED | NOT_MATCHED |
| NOT_MATCHED | MATCHED |
| INDETERMINATE | INDETERMINATE |

`AND` (any NOT_MATCHED wins; otherwise any INDETERMINATE wins):

| | MATCHED | NOT_MATCHED | INDETERMINATE |
|---|---|---|---|
| **MATCHED** | MATCHED | NOT_MATCHED | INDETERMINATE |
| **NOT_MATCHED** | NOT_MATCHED | NOT_MATCHED | NOT_MATCHED |
| **INDETERMINATE** | INDETERMINATE | NOT_MATCHED | INDETERMINATE |

`OR` (any MATCHED wins; otherwise any INDETERMINATE wins):

| | MATCHED | NOT_MATCHED | INDETERMINATE |
|---|---|---|---|
| **MATCHED** | MATCHED | MATCHED | MATCHED |
| **NOT_MATCHED** | MATCHED | NOT_MATCHED | INDETERMINATE |
| **INDETERMINATE** | MATCHED | INDETERMINATE | INDETERMINATE |

`AND`/`NOT_MATCHED` and `OR`/`MATCHED` short-circuit **semantically**
(the absorbing value wins even when another operand is unknown) — this
is standard Kleene logic, and it is what lets a rule reach a definite
answer despite partial data.

### Empty-collection semantics (vacuous truth)

| Quantifier | Empty collection |
|---|---|
| `any` | NOT_MATCHED |
| `all` | MATCHED |
| `none` | MATCHED |

Implemented by `_existence_quantified_or` / `_quantified_and`, which
are deliberately *separate functions* from `_kleene_or`/`_kleene_and`:
an empty top-level `and:` in a rule's own condition tree is a rule bug
and raises, whereas an empty *collection* is a legitimate vacuous case.

---

## 5. Cross-resource evaluation

### How it works

1. `BuildResourceGraph` (Phase 2, unchanged) builds a `ResourceGraph`
   from the `ResourceRelationship`s the collectors emitted.
2. `EvaluateRules` threads that graph plus a `resources_by_id` lookup
   into `Rule.evaluate()`.
3. A `relationship` node calls `ResourceGraph.neighbors(...)`, filters
   by `target_type`, resolves each neighbour's full `NormalizedResource`,
   and evaluates its `where` clause against each — existence-quantified
   (OR) across neighbours.

### Deliberate constraints

* **One hop only.** `neighbors()` has no depth parameter and no
  path-finding. Multi-hop reachability is attack-path analysis, which
  the brief explicitly said not to build speculatively.
* **A missing graph is a wiring bug, not a data gap.** Using a
  `relationship` node without supplying `graph`/`resources_by_id`
  raises `InvalidRuleCondition` rather than returning `INDETERMINATE`,
  so a misconfigured caller fails loudly instead of silently reporting
  "unknown" for every cross-resource rule.
* **A neighbour whose full resource is missing contributes
  `INDETERMINATE`** — that genuinely is a data gap.

### Relationships actually wired

| Relationship | Provider | Emitted by |
|---|---|---|
| `ec2_instance` → `security_group` (ATTACHED_TO) | AWS | `normalizers/ec2.py` |
| `security_group` → `security_group` (ALLOWS) | AWS | `normalizers/security_group.py` |
| `cloudtrail` → `s3_bucket` (ACCESSES) | AWS | `normalizers/cloudtrail.py` |
| `azure_virtual_machine` → `azure_network_security_group` (ATTACHED_TO) | Azure | `normalizers/compute.py` |
| `azure_activity_log_setting` → `azure_storage_account` (ACCESSES) | Azure | `normalizers/monitor.py` |

**Not implemented, and why:** IAM-Role→EC2 and VPC/Subnet→EC2
relationships from the brief's list have no collector behind them (IAM
roles are still blueprint-FUTURE; VPC/subnet ids are captured as plain
attributes). Emitting graph edges to resources that are never collected
would raise `GraphIntegrityViolation` on every real scan. This is a
gap, stated rather than glossed over.

---

## 6. Rule metadata

```yaml
- id: s3-bucket-public
  applies_to_resource_type: s3_bucket
  framework: iso_27001
  control_id: A.8.24
  domain: storage
  service: s3
  severity: critical
  confidence: high
  version: "1.1.0"
  title: "S3 bucket ACL grants access to the public"
  description: >
    ...
  rationale: >
    ...
  condition: { ... }
  evidence_template: "Bucket {resource_id} has an ACL grant to a public group (region {region})."
  tags: [s3, exposure, data-protection]
  references:
    - "https://docs.aws.amazon.com/..."
  framework_mappings:
    - framework: cis_aws
      control: "2.1.5"
      status: verified      # or "unresolved" (the default)
  remediation:
    summary: "..."
    why_it_matters: "..."
    how_to_fix: "..."
    automation_example: "aws s3api put-public-access-block ..."
```

Every field beyond the original six is **optional with a default**, so
no existing `Rule(...)` call site broke.

### `framework` vs `framework_mappings`

`framework`/`control_id` (singular) stay the primary mapping because
they feed `Finding.framework`/`Finding.control_id`, which are exactly
the fields the AI Core's already-agreed external contract expects
(`contracts/ai_service/`). `framework_mappings` (plural) is *additional*
catalog detail for reporting; it does not feed the AI contract path.

### `status: verified` vs `unresolved`

`unresolved` is the **default**, deliberately. Fabricating an unverified
control mapping is the fastest way to lose an auditor's trust; only
mappings a maintainer has actually checked against the published
benchmark text are marked `verified`.

### `applies_to_resource_type` — found by the conformance framework

Attribute names are **not globally unique across resource types**. An
Azure Key Vault and an Azure storage account both carry
`network_default_action`, so before this field existed, the Key Vault
firewall rule genuinely fired against storage accounts.

This was **not found by inspection** — it was found by the conformance
framework's own `UNEXPECTED_FINDING` classification the first time
Azure scenarios were run (see `phase-3-conformance.md` §7). A rule that
does not apply produces **no finding at all**, deliberately *not*
`INDETERMINATE`: "this rule is not about this resource type" and "the
data needed to decide was missing" are different statements, and
conflating them would bury every real `INDETERMINATE` under thousands
of irrelevant ones.

`None` (the default) means "every resource type", preserving the
original behaviour for any rule that does not set it. A test asserts
that **every shipped rule** sets it.

---

## 7. Evidence

`application/rules/evidence.py` renders `evidence_template` with
`str.format_map` over the resource's own attributes plus
`resource_id`/`resource_type`/`region`/`account_id`.

* Pure function of (template, resource) — same input, same text, always.
* A placeholder for a field the resource lacks renders as the literal
  `{field_name}` rather than raising. Missing data is exactly the kind
  of thing evidence should be able to say plainly.
* The rendered narrative lands in `Finding.evidence.data["narrative"]`,
  alongside the raw attributes — never replacing them.

Evidence is a full sentence naming the resource and the actual values,
never "Rule failed":

> `Security group sg-0a1b2c allows unrestricted ingress on port 22 (open ports: (22, 3389)).`

---

## 8. Finding identity

Two-tier, both deterministic, no `uuid4()` anywhere:

```
logical_finding_id = "{tenant}:{account}:{resource}:{rule}"
finding_id         = "{logical_finding_id}:{scan_id}"
```

* **`logical_finding_id`** is stable across scans — it answers "is this
  the same underlying problem I saw last week?", which is what
  deduplication, ticket linking, and drift all need.
* **`Finding.id`** is scan-scoped and therefore deliberately *not*
  stable across scans — each scan produces a distinct record of an
  observation at a point in time.

Multi-account safety comes from including `account_id`, populated from
`sts:GetCallerIdentity` (AWS) or the subscription id (Azure).

**Known limitation:** `ResourceId` itself is still not
account-qualified, so two resources in different accounts sharing a
cloud-assigned id would collide as *graph nodes* even though their
findings would not. `ScanCloudAccount` scans one account per call, so
this cannot occur today — but a future multi-account single-scan
feature must address it.

---

## 9. The catalog

68 rules total, all loaded through one `YamlRuleCatalog` per provider,
combined by `CompositeRuleCatalog` (which rejects duplicate rule ids
across providers rather than silently resolving them by ordering).

| Provider | Service | Rules |
|---|---|---|
| AWS | IAM | 10 |
| AWS | S3 | 8 |
| AWS | Security Groups | 8 |
| AWS | CloudTrail | 6 |
| AWS | EC2 | 5 |
| AWS | KMS | 4 |
| Azure | Storage | 7 |
| Azure | Network (NSG) | 7 |
| Azure | Key Vault | 5 |
| Azure | Monitor | 5 |
| Azure | Compute | 3 |
| **Total** | | **68** |

By severity: 21 critical, 23 high, 14 medium, 10 low.
Cross-resource (relationship) rules: **7**.

---

## 10. Determinism

The engine is a pure function of (catalog, resources, graph,
`detected_at`, `scan_id`):

* No `datetime.now()`, `random()`, or `uuid4()` in any evaluation path.
* Temporal operators take `as_of` explicitly.
* Findings are produced in catalog × resource order, both of which are
  themselves deterministic (sorted file globs, collector order).
* Asserted directly by tests, not merely intended.

---

## 11. Known limitations

1. **IAM-Role and VPC/Subnet relationships are not wired** (§5) — no
   collector emits them.
2. **`ResourceId` is not account-qualified** (§8).
3. **Absence of a resource cannot be flagged.** A rule evaluates
   resources that exist; "this subscription has no Activity Log export
   at all" produces no resource and therefore no finding. Affects
   `rules/azure/monitor.yaml` specifically.
4. **`policy_analysis` is pattern-matching, not IAM simulation.** It
   detects an unconditional wildcard-principal `Allow`; it does not
   evaluate `NotPrincipal`, `Condition` semantics, SCPs, or permission
   boundaries. Any statement carrying a `Condition` is treated
   conservatively as *not* public.
5. **Security-group port ranges are not expanded.** A rule opening
   `20-25` to the internet sets `has_unrestricted_ingress` but adds no
   entries to `unrestricted_ingress_ports`, so the named-port rules do
   not fire — the catch-all rule covers it. Same on both providers.
6. **`Confidence` is metadata only.** No evaluator logic consumes it
   yet.

---

## 12. Architectural boundaries this engine respects

* The Rule Engine **never parses Terraform**. It has never seen a `.tf`
  file; it consumes `NormalizedResource`s only.
* The Rule Engine **never calls a cloud API**. Collection is
  Infrastructure's job, behind the `BaseCollector` port.
* The Rule Engine **never compares expected to actual**. That is the
  conformance framework's job, and it is a strictly downstream
  consumer.
* `domain/` contains **zero** boto3, azure-sdk, YAML, filesystem, or
  network imports — verified by an automated dependency audit.
