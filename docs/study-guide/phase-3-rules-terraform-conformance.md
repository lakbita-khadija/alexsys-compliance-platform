# Study Guide — Rules, Terraform, and Conformance: Zero to Hero

A 34-concept learning path through ComplianceIQ's Phase 3B: the Rule
Engine, the Terraform Security Scenario Laboratory, and the
Expected-vs-Actual Conformance Framework — now across two clouds.

Each concept follows the same shape: **what it is · why it exists · how
it works here · which files · a concrete example · common mistakes ·
what a senior engineer should understand.**

Read in order. Concepts 1–8 are foundations, 9–16 the DSL, 17–22
cross-resource and multi-cloud, 23–28 Terraform, 29–33 conformance,
34 the road ahead.

---

## Part A — Foundations (1–8)

### 1. What a CSPM Rule Engine is

**What.** The component that decides whether a cloud resource's
*configuration* violates a policy. Not a vulnerability scanner (which
looks at software versions), not a runtime monitor (which watches
behaviour) — a configuration judge.

**Why.** Cloud misconfiguration, not software exploitation, is the
dominant cause of cloud data breaches. A public S3 bucket needs no CVE.

**How here.** `Rule.evaluate()` runs a declarative condition against a
`NormalizedResource` and returns one of three values. `EvaluateRules`
turns that into a `Finding`.

**Files.** `domain/rules/rule.py`, `domain/rules/conditions.py`,
`application/rules/evaluate_rules.py`.

**Example.** "A bucket whose ACL grants `AllUsers` READ is a critical
finding" becomes eight lines of YAML — no Python.

**Common mistakes.** Building the engine around *specific* rules, so
that adding a rule means writing code. The engine should never know
what S3 is.

**Senior takeaway.** The engine is a small interpreter over a data
format. Its quality is measured by what it *cannot* express (arbitrary
code) as much as what it can.

---

### 2. Declarative rules vs code rules

**What.** Rules as data (YAML) rather than functions (Python).

**Why.** Three reasons that all matter in production: rules can be
reviewed by security people who don't write Python; rules can be
shipped, versioned, and hot-loaded without a deployment; and a rule
file **cannot execute code**, so an untrusted or third-party catalog is
a data-integrity problem rather than a remote-code-execution one.

**How here.** `YamlRuleCatalog` parses YAML into `Rule` objects.
`evaluate_condition` interprets the condition dict. There is **no
`eval`, no `exec`, no `import`** in the evaluation path.

**Files.** `infrastructure/rules/yaml_rule_catalog.py`,
`rules/aws/*.yaml`, `rules/azure/*.yaml`.

**Example.**
```yaml
condition:
  field: public
  operator: equals
  value: true
```

**Common mistakes.** Adding an `expression:` field that gets `eval`'d
"just for the complex cases". That single escape hatch destroys every
benefit above.

**Senior takeaway.** Every DSL faces pressure to grow an escape hatch.
Resisting it is the design.

---

### 3. `NormalizedResource` — the provider-neutral currency

**What.** One shape every cloud resource is translated into before
anything else sees it: id, type, provider, tenant, region, attributes,
tags, relationships, timestamp, account.

**Why.** It is the seam that makes multi-cloud possible. Without it,
every rule, every graph operation, and every report would need a branch
per provider.

**How here.** Each normalizer builds one. Nothing downstream knows
which cloud it came from except by reading `cloud_provider`.

**Files.** `domain/resources/models.py`,
`infrastructure/cloud/{aws,azure}/normalizers/`.

**Example.** An S3 bucket and an Azure storage account arrive at the
Rule Engine as the same Python type with different `resource_type` and
different attribute keys.

**Common mistakes.** Force-mapping one provider's vocabulary onto
another's (calling Azure's `https_only` "encrypted" because S3 has
`encrypted`). It produces rules that lie.

**Senior takeaway.** Normalize the *shape*, not the *semantics*. Shared
structure, honest per-provider names.

---

### 4. Three-valued (Kleene) logic

**What.** `MATCHED` / `NOT_MATCHED` / `INDETERMINATE`, rather than
true/false.

**Why.** A scanner that lacked permission to read a setting must not
report the resource as compliant. "We don't know" is a real answer, and
suppressing it is how a CSPM silently lies.

**How here.** Every operator returns one of three values; the
combinators implement the Kleene truth tables; `INDETERMINATE` maps to
`FindingStatus.INDETERMINATE`, never to PASS.

**Files.** `domain/rules/conditions.py` (`_kleene_and`, `_kleene_or`,
`_kleene_not`).

**Example.** Encryption unreadable → `INDETERMINATE` → the report says
"unknown", and an operator goes and checks.

**Common mistakes.** `if not resource.attributes.get("encrypted")` —
which turns "absent" into "insecure" or, worse, "absent" into "fine".

**Senior takeaway.** Absorbing values still work: `NOT_MATCHED AND
INDETERMINATE` is `NOT_MATCHED`, because one false operand settles an
AND regardless of what is unknown.

---

### 5. Absent vs collected-null

**What.** A field that was never collected differs from a field
collected with the value `None`.

**Why.** They mean opposite things. "We never looked" is a coverage
gap; "we looked, and the setting doesn't apply" is a determinate fact.

**How here.** An absent field yields `INDETERMINATE` for every
comparison operator. A present-but-`None` field is compared normally —
so `is_null` matches it, and `equals: false` does not.

**Files.** `domain/rules/conditions.py` (`_lookup_field`),
`rules/aws/kms.yaml` (the canonical worked example).

**Example.** An AWS-managed KMS key has `rotation_enabled: None`
because rotation status doesn't apply. The rotation rule compares
`None == False` → not equal → PASS. Correct: AWS rotates those keys
itself.

**Common mistakes.** `dict.get(key)` returning `None` for both cases,
collapsing the distinction at the lowest level of the stack.

**Senior takeaway.** This distinction has to be preserved by the
*collector* first. A normalizer that writes `False` on a failed API
call has already destroyed it.

---

### 6. Determinism

**What.** The same inputs always produce byte-identical outputs.

**Why.** Non-deterministic findings can't be diffed, so drift detection
is impossible; tests become flaky; and an auditor cannot reproduce a
report.

**How here.** No `datetime.now()`, `random()`, or `uuid4()` anywhere in
domain or application logic. Timestamps are explicit parameters
(`detected_at`, `as_of`, `collected_at`). Ordering comes from sorted
globs and preserved iteration order, never from sets or dict hashing.

**Files.** `application/rules/evaluate_rules.py`,
`application/conformance/runner.py` (`CONFORMANCE_DETECTED_AT`).

**Example.** Temporal operators *require* an explicit `as_of` and raise
without one, rather than quietly reading the clock.

**Common mistakes.** A "harmless" `datetime.now()` default. It makes
every test that touches the value time-dependent.

**Senior takeaway.** Determinism is a property of the whole call graph.
One impure leaf poisons every caller.

---

### 7. Ports and adapters

**What.** The application depends on interfaces (`BaseCollector`,
`LoadRuleCatalog`); concrete implementations live in infrastructure.

**Why.** It is what let Azure be added without touching the
application layer, and what lets every collector be unit-tested with no
credentials.

**How here.** `BaseCollector` has one method. `AwsCollector` and
`AzureCollector` both satisfy it. `ScanCloudAccount` cannot tell them
apart.

**Files.** `application/scanning/collector.py`,
`infrastructure/cloud/{aws,azure}/collector.py`.

**Example.**
```python
assert issubclass(AwsCollector, BaseCollector)
assert issubclass(AzureCollector, BaseCollector)
```

**Common mistakes.** Putting a `provider` enum check inside the
application layer. The moment that appears, the port has failed.

**Senior takeaway.** The test of a port is whether adding an
implementation changes anything above it. Azure changed nothing.

---

### 8. Tenant isolation

**What.** Every resource and finding carries a `TenantId`, and crossing
tenants raises.

**Why.** In multi-tenant SaaS, a cross-tenant data leak is the
existential bug.

**How here.** `ensure_same_tenant` is called at every boundary.
`ResourceGraph` enforces it on `add_node`.

**Files.** `domain/tenants/isolation.py`,
`application/rules/evaluate_rules.py`, `domain/graph/models.py`.

**Common mistakes.** Deriving tenant from the cloud account. The AWS
account is *not* the tenant — the caller supplies tenant identity, and
Terraform's `tenant_id` variable is a traceability tag only.

**Senior takeaway.** Isolation must be enforced at construction, not
checked at query time. By the time you're filtering, the mistake has
already been made.

---

## Part B — The DSL (9–16)

### 9. Condition trees

**What.** A rule condition is a nested dict interpreted recursively.

**Why.** Real policies are compound: "unencrypted AND unversioned",
"public via ACL OR via policy".

**How here.** Five node types: leaf, `and`/`or`/`not`, quantifier,
`relationship`, and the vestigial `source: graph`.

**Files.** `domain/rules/conditions.py` (`evaluate_condition`).

**Example.** See `s3-bucket-publicly-exposed` — an `or` over three
distinct exposure mechanisms.

**Common mistakes.** Flattening nesting into a rule-per-combination.
The combinatorics explode and the catalog becomes unreviewable.

**Senior takeaway.** Recursion here is depth-first and side-effect
free, which is why it's trivially testable at any depth.

---

### 10. The operator catalog

**What.** 30 operators across scalar, boolean/null, numeric,
collection, string, network, and temporal categories.

**Why.** Coverage: without `cidr_is_public` you cannot express network
exposure; without `age_gt_days` you cannot express credential rotation.

**How here.** A flat registry mapping name → `(value, expected) ->
EvaluationResult`. Presence, quantifier, and temporal operators are
handled separately because they need more than a value comparison.

**Files.** `domain/rules/conditions.py` (`_COMPARISON_OPERATORS`).

**Example.** `port_in_range: [22, 25]`, `cidr_is_public`,
`matches_regex`.

**Common mistakes.** Adding an operator for one rule's convenience. Each
one is permanent API surface every future rule author must learn.

**Senior takeaway.** Operators must be **total** — defined for every
input, including wrong-typed ones. Here, a `TypeError` becomes
`INDETERMINATE`, never a crash mid-scan.

---

### 11. Quantifiers and vacuous truth

**What.** `any` / `all` / `none` over a collection field, each taking a
`where` sub-condition.

**Why.** Resources contain lists — ingress rules, policy statements,
attached policies — and policies are often about *some* or *every*
element.

**How here.** `_evaluate_quantifier` iterates and combines. Empty
collections follow standard vacuous truth: `any`→NOT_MATCHED,
`all`→MATCHED, `none`→MATCHED.

**Files.** `domain/rules/conditions.py` (`_existence_quantified_or`,
`_quantified_and`).

**Example.** "any ingress rule whose port is 22" over a list of rule
dicts.

**Common mistakes.** Treating an empty collection as an error, or as
`False` for `all`. "Every element of the empty set satisfies P" is
`True`, and getting it wrong makes empty resources report violations.

**Senior takeaway.** The vacuous-truth helpers are deliberately
*separate functions* from the Kleene combinators — an empty `and:` in a
rule's own tree is an authoring bug that raises, while an empty
collection is legitimate. Same truth table, different error semantics.

---

### 12. Presence operators

**What.** `exists` / `not_exists`, which test whether a field is there
at all rather than what it holds.

**Why.** They're the only way to *interrogate* the absent case rather
than propagating `INDETERMINATE` through it.

**How here.** Handled before the absence check in
`_evaluate_leaf_against_data`, so they return MATCHED/NOT_MATCHED
rather than INDETERMINATE.

**Files.** `domain/rules/conditions.py`.

**Common mistakes.** Assuming `is_null` is a presence operator. It is
not — it's a comparison, and an absent field makes it INDETERMINATE.
This trips people constantly; it is documented at the operator table.

**Senior takeaway.** `exists` is the deliberate escape from three-valued
propagation. Everything else preserves it.

---

### 13. Network operators

**What.** `cidr_contains`, `cidr_is_public`, `cidr_is_private`,
`port_equals`, `port_in_range`.

**Why.** "Open to the internet" is the single most important CSPM
question, and it is a network-semantics question, not a string
comparison.

**How here.** Python's standard `ipaddress` module — never regex on
CIDR strings. "Public" means not private, loopback, link-local,
reserved, multicast, or unspecified.

**Files.** `domain/rules/conditions.py` (`_is_public_network`).

**Example.** `0.0.0.0/0` is public; `10.0.0.0/8` is not; `100.64.0.0/10`
(CGNAT) is correctly not public.

**Common mistakes.** `if cidr == "0.0.0.0/0"`. It misses `::/0`, misses
`0.0.0.0/1`, and misses every equivalent notation.

**Senior takeaway.** Use the standard library for anything with a
specification. Hand-rolled network parsing is always subtly wrong.

---

### 14. Temporal operators

**What.** `age_gt_days`, `age_gte_days`, `age_lt_days`.

**Why.** Credential-age and key-rotation policies are inherently
time-relative.

**How here.** They require an explicit `as_of` and **raise** without
one. `EvaluateRules` supplies the scan's `detected_at`.

**Files.** `domain/rules/conditions.py` (`_evaluate_temporal`).

**Common mistakes.** Defaulting `as_of` to `datetime.now()`. It's one
line, it looks harmless, and it makes the entire engine
non-deterministic.

**Senior takeaway.** Making the clock an explicit parameter is the
cheapest determinism guarantee available, and it must be enforced by
raising, not by convention.

---

### 15. Evidence rendering

**What.** Turning a finding into a sentence a human can act on.

**Why.** "Rule s3-bucket-public failed" tells an operator nothing.
"Bucket `acme-prod-data` has an ACL grant to a public group (region
us-east-1)" tells them what to open and what to look at.

**How here.** `str.format_map` over the resource's own attributes plus
standard identity fields, with a `__missing__` that renders unknown
placeholders literally rather than raising.

**Files.** `application/rules/evidence.py`.

**Example.**
```yaml
evidence_template: "Security group {resource_id} allows unrestricted ingress on port 22 (open ports: {unrestricted_ingress_ports})."
```

**Common mistakes.** Building evidence with f-strings inside rule code
— which requires rules to *be* code. Or letting a missing key raise
mid-scan.

**Senior takeaway.** Evidence is a pure function of (template,
resource). Same finding, same words, every time — which is what makes
it diffable.

---

### 16. Remediation

**What.** Structured fix guidance: summary, why it matters, how to fix,
optional automation example.

**Why.** A finding without remediation is a complaint. The three-part
split forces the rule author to justify the rule.

**How here.** A frozen `Remediation` dataclass requiring all three
prose fields; `automation_example` is optional plain text that this
codebase **never executes**.

**Files.** `domain/rules/rule.py`.

**Common mistakes.** Destructive automation examples (`aws s3 rb
--force`). Remediation snippets get copy-pasted by tired people at 2am.

**Senior takeaway.** "Why it matters" is the field that keeps a catalog
honest. A rule whose impact can't be stated in one sentence probably
shouldn't fire at severity high.

---

## Part C — Cross-resource and multi-cloud (17–22)

### 17. The Resource Graph

**What.** A tenant-scoped, in-memory directed graph of resources and
their relationships, rebuilt every scan and never persisted.

**Why.** Security is relational. A permissive security group attached
to nothing is harmless; attached to a public instance it's an incident.

**How here.** `BuildResourceGraph` turns the `ResourceRelationship`s
normalizers emitted into `GraphNode`s and `GraphEdge`s, enforcing
referential integrity (an edge can never reference a missing node).

**Files.** `domain/graph/models.py`,
`application/graph/build_resource_graph.py`.

**Common mistakes.** Emitting an edge to a resource the scan doesn't
collect — which raises `GraphIntegrityViolation` on every real scan.

**Senior takeaway.** Referential integrity enforced at `add_edge` is
what makes every downstream traversal safe without null checks.

---

### 18. The closed relationship vocabulary

**What.** Eight `RelationshipType` values, extended only when a real
collection capability justifies one.

**Why.** An open vocabulary becomes a junk drawer, and rules written
against invented types silently never match.

**How here.** `ATTACHED_TO`, `ALLOWS`, `ACCESSES` and five others,
reused unchanged across both providers.

**Files.** `domain/shared/enums.py`.

**Example.** `ATTACHED_TO` covers both EC2→SecurityGroup and Azure
VM→NSG. No `AZURE_VM_ATTACHED_TO_NSG` was invented.

**Common mistakes.** Adding a provider-specific relationship type. It
immediately makes the graph provider-aware.

**Senior takeaway.** The vocabulary's job is to be *semantic*, not
*syntactic*. If two clouds mean the same thing, they share the value.

---

### 19. Cross-resource rules

**What.** The `relationship` condition node — evaluating a sub-condition
against a resource's graph neighbours.

**Why.** It is the difference between a checklist and a security tool.

**How here.** `ResourceGraph.neighbors()` (one hop, no path-finding),
filtered by `target_type`, each neighbour's full resource resolved via
`resources_by_id`, combined existence-quantified.

**Files.** `domain/rules/conditions.py` (`_evaluate_relationship`),
`rules/aws/ec2.yaml`, `rules/azure/compute.yaml`.

**Example.** "This VM is attached to an NSG that is open to the
internet" — neither resource alone is a finding.

**Common mistakes.** Returning `INDETERMINATE` when the graph wasn't
supplied. That hides a caller wiring bug as a data gap; here it raises.

**Senior takeaway.** One hop is a deliberate ceiling. Multi-hop
reachability is attack-path analysis — a different problem with
different performance and correctness characteristics, and it was
explicitly not built speculatively.

---

### 20. Multi-cloud without provider branching

**What.** Adding Azure changed nothing in `domain/` or `application/`.

**Why.** Because the seam (`NormalizedResource`) and the port
(`BaseCollector`) were designed for it in Phase 1/2.

**How here.** `AzureCollector` satisfies the same port; Azure
normalizers produce the same type; the same DSL, graph, and `Finding`
handle both.

**Files.** `infrastructure/cloud/azure/`, `rules/azure/`.

**Common mistakes.** `if provider == AWS: ... elif provider == AZURE:`
anywhere above infrastructure. Grep for it; it should return nothing.

**Senior takeaway.** The measure of an abstraction is what a second
implementation costs. Here it cost zero changes above the adapter.

---

### 21. Resource-type scoping

**What.** `Rule.applies_to_resource_type` — a rule declares which
resource type it judges.

**Why.** Attribute names are not globally unique. An Azure Key Vault
and a storage account both have `network_default_action`, so without
scoping the Key Vault rule fired against storage accounts.

**How here.** `Rule.applies_to()` gates evaluation; a non-matching rule
produces **no finding**, deliberately not `INDETERMINATE`.

**Files.** `domain/rules/rule.py`,
`application/rules/evaluate_rules.py`.

**Common mistakes.** Making the skip produce `INDETERMINATE`. With 68
rules and thousands of resources, that buries every genuine unknown
under noise.

**Senior takeaway.** This bug was found by the conformance framework's
`UNEXPECTED_FINDING` classification, not by review — see concept 33.
Per-rule unit tests could not have caught it, because every rule was
individually correct.

---

### 22. Composite catalogs

**What.** `CompositeRuleCatalog` presents several catalogs as one.

**Why.** One catalog per provider keeps each reviewable; a scan wants a
single catalog.

**How here.** Composes the *port*, not the storage format — so a
future database-backed catalog composes identically. Duplicate rule ids
across catalogs **raise** rather than being resolved by ordering,
because a duplicate id makes `Finding.rule_id` ambiguous.

**Files.** `application/rules/composite_rule_catalog.py`.

**Common mistakes.** Last-wins or first-wins on duplicate ids. Both
silently change which rule ran.

**Senior takeaway.** Compose at the interface, and make ambiguity an
error rather than a policy.

---

## Part D — The Terraform Scenario Laboratory (23–28)

### 23. Why a real cloud environment

**What.** Deployable AWS and Azure environments provisioning both
compliant and non-compliant resources.

**Why.** Mocks encode what you *think* the API returns. Only real
infrastructure proves the collector reads what the cloud actually
sends.

**How here.** `terraform/aws/` and `terraform/azure/`, each with
per-resource-type modules and a deployable `environments/test/` root.

**Files.** `terraform/{aws,azure}/`.

**Common mistakes.** Only provisioning broken resources — then a
scanner that flags everything passes every test.

**Senior takeaway.** Compliant/non-compliant *pairs* are what make the
environment a test rather than a demo.

---

### 24. Terraform is not a rule engine

**What.** The lab contains no rule ids, no expected findings, no
severities.

**Why.** If Terraform declared the expected finding, the test would be
asserting that a file agrees with itself.

**How here.** Enforced by a test scanning every `.tf` for forbidden
tokens.

**Files.** `tests/conformance/test_rule_catalog_conformance.py`
(`test_terraform_contains_no_rule_engine_metadata`).

**Common mistakes.** A helpful `tags = { expected_rule = "..." }`. It
looks like documentation and quietly turns the whole suite tautological.

**Senior takeaway.** When separation matters, assert it in a test. Prose
in a README is not a boundary.

---

### 25. Safety guards on intentionally-insecure infrastructure

**What.** `environment == "test"` hard validation, dedicated resource
groups, `Purpose` tags, no real data, no generated credentials.

**Why.** This code *deliberately* creates public buckets and
internet-open SSH. Pointed at production it is an attack.

**How here.** Terraform refuses to plan with any other `environment`
value. AWS never creates an access key; Azure takes only a public SSH
key with password auth disabled.

**Files.** `terraform/{aws,azure}/variables.tf`, both READMEs.

**Common mistakes.** A `production` value that "just warns".

**Senior takeaway.** The guard must be at the earliest possible layer —
variable validation runs before any plan is computed.

---

### 26. Cost awareness

**What.** Every resource chosen for cheapness; per-resource cost tables
in both READMEs; documented destroy procedure.

**Why.** A test environment nobody tears down becomes a recurring bill
and a permanent attack surface.

**How here.** `t3.micro`/`Standard_B1s`, empty buckets, KMS deletion
windows at the 7-day minimum. Explicitly avoided: RDS, NAT gateways,
load balancers, instance fleets.

**Files.** `terraform/{aws,azure}/README.md`.

**Common mistakes.** A NAT gateway "for realism" — ~$32/month for
nothing the scanner reads.

**Senior takeaway.** Cost is a design constraint on test infrastructure,
not an afterthought.

---

### 27. Provider-specific realities

**What.** Azure needed a VNet and subnets AWS gets for free; Azure NSGs
have Deny rules AWS security groups don't; Azure VM→NSG is indirect.

**Why.** Two clouds are not the same cloud, and pretending otherwise
produces collectors that are wrong in one of them.

**How here.** The Azure network module provisions minimal networking;
the NSG normalizer ignores Deny rules; the VM *collector* resolves the
NIC→subnet→NSG chain before normalization.

**Files.** `terraform/azure/modules/network_test_resource/main.tf`,
`infrastructure/cloud/azure/normalizers/network.py`,
`infrastructure/cloud/azure/resource_collectors/compute.py`.

**Example.** The lab deliberately includes a wildcard-source **Deny**
rule that must *not* count as unrestricted ingress — a case AWS's
allow-only model can never exercise.

**Common mistakes.** Copying the AWS collector and renaming types.

**Senior takeaway.** Resolve provider-specific indirection in the
collector; keep the normalizer a pure shape translation.

---

### 28. Documented limitations over silent gaps

**What.** Every thing the lab *can't* provision is written down: no
MFA-enabled IAM user, singleton password policy, no second CloudTrail
trail, Key Vault purge protection off.

**Why.** An undocumented gap looks like coverage. A documented one is a
known risk.

**How here.** Both READMEs and both architecture docs carry explicit
limitation sections; the failing branches are covered by unit and
conformance tests instead.

**Files.** `terraform/{aws,azure}/README.md`,
`docs/architecture/phase-3-terraform.md` §9.

**Senior takeaway.** "We couldn't test this, here's why, here's what we
did instead" is a stronger engineering statement than silence.

---

## Part E — Conformance (29–33)

### 29. Expected vs actual testing

**What.** Declare what a scan *should* find; compare against what it
*did* find; classify every difference.

**Why.** It moves rule correctness from "someone wrote an assertion" to
"the whole catalog is checked against declared behaviour, every run".

**How here.** `Scenario` (expectations, in YAML) → `RunConformanceScenario`
(runs the real engine) → `ConformanceComparator` (classifies) →
`ConformanceReport`.

**Files.** `application/conformance/`,
`tests/conformance/scenarios/*.yaml`.

**Common mistakes.** Asserting `expected == actual`. It collapses ten
distinguishable failure modes into one unhelpful boolean.

**Senior takeaway.** The classification vocabulary *is* the product
here. A boolean comparator would be a day's work and worth far less.

---

### 30. The outcome taxonomy

**What.** Ten outcomes: PASS, MISSING_FINDING, UNEXPECTED_FINDING,
WRONG_RULE, WRONG_RESOURCE, WRONG_STATUS, WRONG_SEVERITY,
WRONG_EVIDENCE, FALSE_POSITIVE, FALSE_NEGATIVE.

**Why.** Different failures need different responses. A false negative
is a security hole; a wrong severity is a triage annoyance.

**How here.** `ConformanceOutcome`, a closed enum, each value produced
by exactly one comparator branch.

**Files.** `application/conformance/models.py`,
`application/conformance/comparator.py`.

**Example.** Expected PASS, got FAIL → `FALSE_POSITIVE`, distinct from
a PASS↔INDETERMINATE difference which is `WRONG_STATUS`.

**Common mistakes.** Lumping false positives and negatives into
"status mismatch". They are the two outcomes a security reviewer must
see first.

**Senior takeaway.** Taxonomies earn their keep when they change what
someone does next. These do.

---

### 31. Three-pass deterministic comparison

**What.** Canonicalize → match by stable key → classify leftovers.

**Why.** Determinism and order-independence. A comparator whose result
depends on finding order is unusable in CI.

**How here.** A dict keyed by `rule_id`, then classification, then
sorted output.

**Files.** `application/conformance/comparator.py`.

**Common mistakes.** Nested loops matching by position. It works until
the catalog is reordered.

**Senior takeaway.** "Canonicalize first" is the general answer to
comparing two unordered collections meaningfully.

---

### 32. Running the whole catalog

**What.** Every scenario runs all 68 rules, not just the ones it
mentions.

**Why.** `UNEXPECTED_FINDING` is only reachable this way — and it is
the outcome that finds bugs nobody predicted.

**How here.** `RunConformanceScenario` never filters by `rule_ids`.
Unclaimed FAILs are reported; unclaimed PASS/INDETERMINATE are not.

**Files.** `application/conformance/runner.py`.

**Common mistakes.** Optimizing by evaluating only expected rules. It
makes the suite faster and blind.

**Senior takeaway.** The expensive path is the one that finds the
surprises. 54 scenarios × 68 rules still runs in 0.4 seconds.

---

### 33. The meta-test — testing the tester

**What.** Tests that deliberately corrupt a known-good scenario and
assert the comparator reports the specific fault.

**Why.** "Everything conforms" is worthless unless non-conformance
would be caught. A comparator hardwired to return PASS satisfies every
scenario.

**How here.** `TestComparatorActuallyDetectsFaults` flips statuses,
breaks severities, drops expectations, and asserts each produces the
right outcome.

**Files.** `tests/conformance/test_rule_catalog_conformance.py`.

**Example.** Assert PASS on a genuinely-failing rule → must be
classified `FALSE_POSITIVE`, and the report must be non-conformant.

**Common mistakes.** Trusting a green suite without ever having seen it
go red.

**Senior takeaway.** This framework proved itself twice during
construction: it caught an incomplete fixture, and then caught a real
architectural bug (concept 21) that no per-rule test could have found.
That is the return on building the classification instead of a boolean.

---

## Part F — What comes next (34)

### 34. Future evolution

**What's built.** 68 rules across two clouds, 30 operators,
cross-resource evaluation, deterministic identity, a scenario lab per
cloud, and a self-verifying conformance framework. 704 tests.

**What's honestly not.**

* **Entra ID identity rules** — needs Microsoft Graph, a different SDK
  and permission model. There is no Azure counterpart to the 10 AWS IAM
  rules.
* **Account-qualified `ResourceId`** — findings are multi-account safe;
  graph nodes are not yet. Blocks multi-account single-scan.
* **Attack-path analysis** — the graph supports one hop deliberately.
  Multi-hop reachability is a separate engine with separate
  correctness and performance problems.
* **Absence detection** — "this subscription has no audit log export"
  cannot be expressed by a per-resource rule engine. Needs an
  account-level assertion concept.
* **Real IAM policy simulation** — `policy_analysis` is deliberate
  pattern matching, not an evaluator for `NotPrincipal`, `Condition`,
  SCPs, or permission boundaries.
* **Real-cloud execution** — the integration suites are written and
  gated but have **never run against a real AWS account or Azure
  subscription** in this environment, and `terraform validate` has not
  run (provider download is blocked by egress policy).

**Senior takeaway.** The last bullet is the one that matters most for
professional judgement. Knowing precisely which parts are *verified*
and which are merely *prepared* — and saying so without being asked —
is the difference between an engineer a team can trust with production
and one they cannot.
