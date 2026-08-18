# Phase 2 — Application Layer

Status: **implemented**. This document records what Phase 2 built on top
of Phase 1, the ports it defines, and — honestly — what it deliberately
does not do yet. It does not restate the blueprint; see
`ComplianceIQ_Senior_Architecture_Blueprint.md` (§4 primarily) and
`docs/architecture/phase-1-domain.md` for what came before.

---

## 1. Objective

Formalize the orchestration layer the blueprint calls `application/`
(§4, DESIGNED): the layer that *uses* the Phase 1 Domain to run a scan,
without becoming a second Domain and without importing any cloud SDK,
web framework, or database driver. Blueprint §4's own words: the
migration from the informal `ScanService.run()` "formalise, elle ne
redessine pas" — formalizes, does not redesign.

## 2. Scope

Built: `ScanCloudAccount` (the central use case) and all seven other
components blueprint §4 names for `application/`: `BuildResourceGraph`,
`EvaluateRules` + `LoadRuleCatalog`, `QueryFindings` +
`FindingRepositoryPort`, `EnrichRisk`, `AnalyzeAttackPaths`,
`DetectDrift`, `ManageTenant`. Also formalized `BaseCollector`, the port
the blueprint has referred to as "already abstract" since §6 but never
actually defined as code (§25: "port non formalisé... à confirmer après
Phase 2" — this is that confirmation).

Not built, on purpose: any concrete adapter (no AWS/Azure collector, no
YAML rule loader, no database-backed finding repository), FastAPI,
JWT, the AI Core HTTP client, Terraform, persistence. See §12.

## 3. Architecture

```
presentation/   [FUTURE — not built]
      ↓
application/    [THIS PHASE]
      ↓
domain/         [Phase 1 — untouched]
```

`infrastructure/` (not built) will later provide concrete
implementations of the three ports defined in this phase. Verified
one-directional: `application/` imports only `domain/` and the Python
standard library; `domain/` has zero awareness `application/` exists
(§7, dependency audit below).

## 4. Application components

| Path | Component | Blueprint ref |
|---|---|---|
| `application/scanning/scan_cloud_account.py` | `ScanCloudAccount` | §4 |
| `application/scanning/collector.py` | `BaseCollector` (port) | §6, §7, §25, §27 |
| `application/scanning/dtos.py` | `ScanConfiguration`, `ScanResult` | §4 |
| `application/graph/build_resource_graph.py` | `BuildResourceGraph` | §4, §10 |
| `application/rules/evaluate_rules.py` | `EvaluateRules` | §4, §9 |
| `application/rules/rule_catalog.py` | `LoadRuleCatalog` (port) | §4, §5 |
| `application/findings/query_findings.py` | `QueryFindings` | §4 |
| `application/findings/finding_repository.py` | `FindingRepositoryPort` (port) | §4, §5 |
| `application/risk/enrich_risk.py` | `EnrichRisk`, `RiskFactors` | §4, §13 |
| `application/attack_paths/analyze_attack_paths.py` | `AnalyzeAttackPaths` | §4, §11 |
| `application/drift/detect_drift.py` | `DetectDrift` | §4, §12 |
| `application/tenants/manage_tenant.py` | `ManageTenant` | §4 |
| `application/errors.py` | `ApplicationError`, `ResourceCollectionError` | — |

## 5. Ports

| Port | Purpose | Implemented by later layer | Blueprint reference |
|---|---|---|---|
| `BaseCollector` | Collect `NormalizedResource`s for one cloud account | `infrastructure/cloud/aws`, `azure` (Phase 3+) | §6, §7, §25, §27 Q2/Q10 |
| `LoadRuleCatalog` | Obtain the `Rule` catalog | `infrastructure/rules/` yaml loader (Phase 3+) | §4, §9 |
| `FindingRepositoryPort` | Query persisted `Finding`s | `infrastructure/persistence/` (FUTURE) | §4, §5 |

**`ResourceGraphPort` (§5, ADR-005) was considered and explicitly not
created.** Its purpose is swapping the graph's storage backend; nothing
in Phase 2 persists a graph, so there is nothing to swap. ADR-005 itself
gates building it on "si le volume le justifie un jour, mesuré" — Phase
2 has no measurement suggesting that need exists yet. Creating it now
would be exactly the speculative port Section 5 of this phase's brief
forbids.

## 6. Use cases

### `ScanCloudAccount` (the central use case)

Input: `tenant_id`, `provider`, `credentials_reference`,
`scan_configuration`, plus `scanned_at` (explicit, for determinism —
see §10) and an optional `previous_snapshot` (for drift). Output:
`ScanResult`.

Pipeline actually implemented:

```
collect()                     -- via BaseCollector
  -> verify tenant + provider integrity (defense in depth)
  -> BuildResourceGraph.build()
  -> EvaluateRules.evaluate()  -- produces Finding tuple
  -> AnalyzeAttackPaths.analyze()  -- always () this phase, see §12
  -> [[ EnrichRisk not invoked here — see §12 ]]
  -> DetectDrift.detect()      -- only if previous_snapshot given
  -> ScanResult
```

Ordering note: blueprint §4's prose sequence lists "calculate risk"
*before* "discover attack paths", but its own architectural note
overrides that explicitly — "Attack Path avant Risk final" — because
the CRSF-1.1 formula (§13) needs attack-path involvement as an input
factor. This implementation follows the note. In practice this phase
never calls risk enrichment automatically (§12), so the ordering
constraint currently only matters for whoever wires it in next.

"Correlate findings" (also in §4's prose) has no other specification
anywhere in the blueprint; it's satisfied by `EvaluateRules` simply
returning the full set of findings it produced — no separate
correlation algorithm exists or was invented.

### The other seven

* **`BuildResourceGraph`** — `build(tenant_id, resources) -> ResourceGraph`. Two-pass (all nodes, then all edges) so relationship order in the input never matters; every invariant check is the Domain's own (`add_node`/`add_edge`), none duplicated.
* **`EvaluateRules`** — `evaluate(tenant_id, resources, detected_at, scan_id=None, rule_ids=None) -> tuple[Finding, ...]`. One `Finding` per `(rule, resource)` pair — see §13 for why.
* **`QueryFindings`** — `execute(tenant_id) -> tuple[Finding, ...]`, backed by `FindingRepositoryPort`. Re-checks tenant scoping on every result before returning it.
* **`EnrichRisk`** — `enrich(RiskFactors) -> RiskScore`. A pure wrapper; see §12 for what it deliberately does not do.
* **`AnalyzeAttackPaths`** — `analyze(tenant_id, graph, findings) -> tuple[AttackPath, ...]`. Always returns `()`; see §12.
* **`DetectDrift`** — `detect(tenant_id, previous, current, detected_at) -> tuple[DriftEvent, ...]`. Direct delegation to `DiffEngine.compare()`.
* **`ManageTenant`** — `register(tenant_id, name) -> Tenant`. Pure delegation to `Tenant()`; nothing beyond registration exists (§13).

## 7. Dependency direction

Verified by the same exhaustive-grep method Phase 1 used:

```
grep -rEn "^\s*(import|from)\s+(boto3|azure|fastapi|flask|sqlalchemy|
  psycopg2|redis|requests|httpx|kubernetes|openai|anthropic|langchain)" application/
  →  no matches
grep -rn "import contracts\|from contracts\|import infrastructure\|from infrastructure" application/
  →  no matches
grep -rn "import application\|from application" domain/
  →  no matches (Domain still has zero awareness Application exists)
grep -rn "provider ==\|provider==" application/
  →  no matches (no if-provider branching anywhere)
grep -rn "eval(\|exec(" application/
  →  no matches
```

## 8. Tenant isolation

Preserved at three points, not just relied upon downstream:

1. **`ScanCloudAccount._verify_collected_resources`** — every resource the injected `BaseCollector` returns is checked against the requested `tenant_id` (via `domain.tenants.isolation.ensure_same_tenant`, reused rather than reimplemented) *before* the graph is built, so a misbehaving collector fails fast with a clear error instead of partially building a cross-tenant graph.
2. **`BuildResourceGraph`** — inherits the check for free via `ResourceGraph.add_node`, since it never duplicates that invariant.
3. **`QueryFindings`** — re-verifies every `Finding` returned by `FindingRepositoryPort` actually belongs to the requested tenant, so a buggy repository adapter can't leak cross-tenant findings (tested explicitly: `test_defense_in_depth_rejects_a_leaking_adapter`).

All three raise the Domain's own `TenantIsolationViolation` — no
application-specific isolation exception was invented; the invariant
information Phase 1 attached to that exception is preserved unchanged.

## 9. Error handling

Two categories, kept deliberately separate:

* **Domain exceptions propagate unmodified.** `TenantIsolationViolation`, `GraphIntegrityViolation`, `InvalidRuleCondition`, `InvalidScoreValue`, etc. are never caught and rewrapped — they carry precise invariant information a generic `ApplicationError` would destroy.
* **`ResourceCollectionError`** (new this phase, `application/errors.py`) is raised for exactly two situations, both genuinely new failure modes at this layer: the injected `BaseCollector` raising (wrapped via `raise ... from cause`, cause preserved and tested) and a collector returning a resource tagged with a different `CloudProvider` than the scan declared (a port-contract violation, not a Domain concept).

No bare `except Exception: raise ApplicationError("something went wrong")` exists anywhere in `application/`.

## 10. Determinism

No hidden `datetime.now()`, `random()`, or `uuid4()` anywhere in
`application/`:

* `ScanCloudAccount.run()` requires an explicit, timezone-aware `scanned_at` (validated, rejects naive datetimes — same rule Phase 1 applies to `NormalizedResource.collected_at` etc.).
* `Finding.id` is derived deterministically: `f"{tenant_id}:{resource_id}:{rule_id}"`.
* `ScanResult.scan_id` is derived deterministically: `f"{tenant_id}:{provider.value}:{scanned_at.isoformat()}"`.
* `DetectDrift`/`DiffEngine.compare()` takes `detected_at` explicitly (inherited from Phase 1's own determinism invariant).

Tested directly: `test_scan_id_is_deterministic`,
`test_identical_inputs_produce_identical_findings`, and a determinism
test in every other Phase 2 test file.

## 11. Testing

55 new tests, all using in-memory fakes — no AWS/Azure credentials, no
database, no network, no Docker:

| File | Tests |
|---|---|
| `test_manage_tenant.py` | 3 |
| `test_build_resource_graph.py` | 7 |
| `test_evaluate_rules.py` | 12 |
| `test_query_findings.py` | 4 |
| `test_enrich_risk.py` | 4 |
| `test_analyze_attack_paths.py` | 3 |
| `test_detect_drift.py` | 3 |
| `test_scan_cloud_account.py` | 19 |

Every port (`BaseCollector`, `LoadRuleCatalog`, `FindingRepositoryPort`)
is exercised only through a fake subclass defined in the test file
itself (`FakeCollector`, `FailingCollector`, `FakeRuleCatalog`,
`FakeFindingRepository`, `TenantLeakingFakeRepository`) — never a real
adapter, because no real adapter exists yet.

```
Phase 1 tests: 188 passed
Phase 2 tests:  55 passed
Total:         243 passed
```

Run with: `python3 -m pytest tests/ -q`

## 12. Known limitations (explicit, not silent)

* **`EnrichRisk` is never automatically invoked by `ScanCloudAccount`.** The blueprint gives the CRSF-1.1 *weights* (§13) but nowhere specifies how a raw signal (a `Severity`, "is this resource exposed", an environment label, `ConfidenceScore`, attack-path involvement) becomes a `[0, 100]` factor. `EnrichRisk.enrich(RiskFactors)` exists and is fully tested, but nothing in this phase derives `RiskFactors` from a `Finding` — every `Finding.risk` produced by a scan is `None`. Inventing that mapping was explicitly disallowed this phase.
* **`AnalyzeAttackPaths` always returns `()`.** Blueprint §11 names five components (`PathDiscovery`, `PathConstraintEvaluator`, `AttackPathScorer`, `AttackTechniqueMapper`, `AttackPathAnalyzer`) with no traversal algorithm, no constraint model, and no scoring formula specified anywhere — the same gap the Phase 1 audit already flagged. None were fabricated.
* **`ScanConfiguration` only supports filtering by `rule_ids`.** The blueprint names the field but never describes its shape; a rule-id filter is the only extension groundable in an already-fully-specified Domain concept without guessing.
* **`ManageTenant` only registers.** No update, deactivation, or lookup — the blueprint gives this component a name and nothing else.
* **No concrete port implementations.** `BaseCollector`, `LoadRuleCatalog`, and `FindingRepositoryPort` have zero real adapters — by design, this is Phase 3+ (AWS/Azure collectors, rule catalog loader, persistence).
* **No `application/compliance/`.** Your Section 4 brief sketched a "perform compliance assessment" pipeline step, but neither blueprint §4's `application/` tree nor `ScanCloudAccount`'s declared sequence include one — the blueprint (the stated authority) doesn't support adding it, so it wasn't added. `domain.compliance.ComplianceAssessment.from_findings()` remains available, unused by this phase's pipeline.
* **The six Phase 1 audit gaps are all still open**, and none were touched: attack-path algorithm (above), the 33-rule catalog (still doesn't exist — `LoadRuleCatalog` is the abstraction that would load it, not the data itself), `CloudProvider` placement, `RuleCondition` naming, `DiffEngine` signature, `ResourceRelationship` evidence/provenance. None of them blocked Phase 2, so none were "fixed" as a side effect — see §13.

## 13. Blueprint decisions

Every deviation/addition, and why:

* **`EvaluationResult → FindingStatus` mapping is now enforced in code** (`MATCHED→FAIL`, `NOT_MATCHED→PASS`, `INDETERMINATE→INDETERMINATE`, in `EvaluateRules._to_finding`). Phase 1's own docs already anticipated this exact mapping as "1:1 by convention, not enforced by the Domain" — Phase 2 is precisely where that convention becomes real code, not a new invention.
* **A `Finding` is created for every `(rule, resource)` pair**, including passes. `Rule` has no resource-type targeting field, so there's no non-inventing way to skip irrelevant pairs; the condition evaluator's missing-field→`INDETERMINATE` behavior absorbs them instead. This also matches blueprint §17's own testing philosophy (a rule must be provably able to produce both PASS and FAIL, not just "always finds something").
* **`Finding.evidence` is a snapshot of `resource.attributes`** at evaluation time — the only deterministic, already-collected fact available without inventing a mechanism to record which specific field a condition inspected.
* **Deterministic ID generation** (`Finding.id`, `ScanResult.scan_id`) via composite string keys instead of `uuid4()` — an explicit, justified default consistent with the "no hidden randomness" instruction, not a blueprint-specified format (none exists).
* **Provider-integrity check added** (`ScanCloudAccount._verify_collected_resources` rejecting a resource whose `cloud_provider` doesn't match the declared scan `provider`) — not blueprint-specified, but a direct consequence of treating `BaseCollector` as a real port: a port's contract can be violated by a buggy implementation, and Section 17 ("never hide... invalid identifiers") argues for catching that immediately rather than passing bad data downstream.

## 14. What Phase 3 will consume

* **`BaseCollector`** — implement `AwsCollector`/`AzureCollector` against it (blueprint Phase 3/4). `ScanCloudAccount` needs no changes to accept either.
* **`LoadRuleCatalog`** — implement the YAML loader for the (still-missing) 33-rule catalog against it.
* **`FindingRepositoryPort`** — implement against real persistence (blueprint Phase 8's snapshot persistence, or a general findings store) once `infrastructure/persistence/` exists.
* **`RiskFactors`/`EnrichRisk`** — once an authoritative raw-signal-to-factor mapping is specified (not before), wire it into `ScanCloudAccount` between attack-path discovery and `ScanResult` construction — the ordering is already correct.
* **`AnalyzeAttackPaths`** — once a discovery/scoring algorithm is specified, this is the one file to change; its signature already receives everything a real implementation needs.
* **`ScanResult`** — ready to be handed to a future `presentation/` layer (FastAPI, Phase 11) or to `contracts.ai_service.translation.finding_to_contract()` (already built, Phase 1) for each finding it contains.

---

# Phase 2 Study Guide — Zero to Hero

This guide assumes you know Python but have never built a layered
architecture before. Every example below uses real code from this
repository — nothing is invented for illustration. Read it in order;
each part builds on the last.

## Part A — Fundamentals

**1. What is the Application layer?**
It's the layer that knows *how to run a scan* without knowing *what a
compliant S3 bucket looks like* (that's Domain) or *how to call the AWS
API* (that's Infrastructure). It's the "orchestra conductor" — it
doesn't play any instrument itself, it tells the right instrument to
play at the right time.

**2. Why does it exist?**
Without it, `ScanCloudAccount`'s logic ("collect resources, then build a
graph, then run rules, then...") would have to live either inside the
Domain (which would force the Domain to know about collectors and
ports — contaminating it) or inside a concrete AWS adapter (which would
mean rewriting the whole orchestration for Azure). Application is the
one place that sequence lives, written once, reusable for any cloud.

**3. Domain vs Application vs Infrastructure — one sentence each:**
- Domain: the *rules of the business* (a bucket with `acl: public-read` is non-compliant, and that fact is true no matter what language or database you use).
- Application: the *sequence of steps* to apply those rules to real data (collect, build graph, evaluate, produce findings).
- Infrastructure: the *plumbing* (an actual `boto3.client("s3").list_buckets()` call).

**4. What is orchestration?**
Calling other things in the right order and passing their outputs to
each other's inputs. Look at `ScanCloudAccount.run()` — it never
computes anything itself (no `if attributes["public"]:`); it just calls
`self._collector.collect()`, then `self._build_graph.build(...)`, then
`self._evaluate_rules.evaluate(...)`, in that order. That's the entire
job.

**5. What is a use case?**
One named, complete unit of "something a user wants done." "Scan this
cloud account" is a use case → `ScanCloudAccount`. "Show me my
findings" is a different use case → `QueryFindings`. Each use case is
one class with one main method (`run`, `execute`, `evaluate`,
`analyze`, `detect` — the name varies, the shape doesn't).

**6. What is dependency inversion?**
Normally, "high-level" code calls "low-level" code directly (your scan
logic calls `boto3` directly). Dependency inversion flips this: the
high-level code (`ScanCloudAccount`) defines an *interface* it needs
(`BaseCollector`), and the low-level code (a future `AwsCollector`)
implements that interface. `ScanCloudAccount` depends on an abstraction
it owns, not a concrete thing owned by AWS's SDK.

**7. What is a port?**
The abstraction itself — an `ABC` (Abstract Base Class) with
`@abstractmethod`s and no implementation. Example, verbatim from this
repo (`application/scanning/collector.py`):

```python
class BaseCollector(ABC):
    @abstractmethod
    def collect(self) -> tuple[NormalizedResource, ...]:
        ...
```

This says: "I need *something* that can give me normalized resources. I
don't care how." That's a port.

**8. What is an adapter?**
A concrete class that implements a port. `AwsCollector` (not built yet
— that's Phase 3) would be an adapter: `class AwsCollector(BaseCollector): def collect(self): # call boto3, return NormalizedResource tuples`.
In this phase's tests, `FakeCollector` (in `test_scan_cloud_account.py`)
is also an adapter — a fake one, built purely for testing.

**9. Why should Application not import boto3?**
Two reasons. First, testability: if `ScanCloudAccount` called `boto3`
directly, every test would need real AWS credentials — impossible to
run in CI, impossible to run offline. Second, replaceability: the day
you add Azure, if Application imported `boto3` directly, you'd have to
rewrite `ScanCloudAccount` to also import the Azure SDK and branch on
provider. Because it only knows `BaseCollector`, adding Azure means
writing one new adapter class — zero changes to `ScanCloudAccount`.

**10. Why should business rules remain in Domain?**
Because business rules (what counts as a violation, how three-valued
logic combines, what makes a risk score) don't change based on *how*
you scan — they're true whether the data came from AWS, Azure, or a
CSV file someone typed by hand. Putting them in Application would mean
duplicating them differently for every use case that touches findings.
Putting them in Domain means one implementation, tested once
(`domain/rules/conditions.py`), reused everywhere.

## Part B — Connect to Phase 1

Phase 1 built the *nouns*: `Tenant`, `NormalizedResource`,
`ResourceGraph`, `Rule`, `Finding`, `RiskScore`, `ComplianceAssessment`,
`DriftEvent`, `AttackPath`. Each one knows how to validate itself and
enforce its own invariants (a `ResourceGraph` refuses a node from the
wrong tenant; a `Finding` requires a `tenant_id`; a `RiskScore` can't
exceed 100). But none of them know how to *get used together*. You
could construct a `Rule` and a `NormalizedResource` by hand in a Python
shell and call `rule.evaluate(resource)` — Phase 1 proved that works,
with 188 tests. What was missing was: who constructs the resource in
the first place? Who decides which rules to run against which
resources? Who takes the results and assembles them into something a
user actually receives back?

That's what was missing after Phase 1: **orchestration**. Nothing was
wrong with Phase 1 — it just doesn't answer "how does a scan actually
happen, end to end." Application is the next layer specifically because
that question needs an answer that isn't a business rule (so it doesn't
belong in Domain) and isn't a cloud API call (so it doesn't belong in
Infrastructure either).

## Part C — Trace one complete scan

Walk through `ScanCloudAccount.run()` from `application/scanning/scan_cloud_account.py`
step by step, using a hypothetical S3 bucket scan.

**Step 0 — User request.** Someone (a future CLI, a future FastAPI
endpoint) decides to scan tenant `acme`'s AWS account. They call:
```python
scan_cloud_account.run(
    tenant_id=TenantId("acme"),
    provider=CloudProvider.AWS,
    credentials_reference="acme-prod-role",
    scan_configuration=ScanConfiguration(),
    scanned_at=datetime.now(timezone.utc),
)
```
*What enters:* four blueprint-specified inputs plus an explicit
timestamp. *Layer:* whoever calls this (future Presentation) owns
constructing these inputs.

**Step 1 — Validate inputs.** `_validate_inputs` checks
`credentials_reference` isn't blank and `scanned_at` is timezone-aware.
*Why it's here, not Domain:* these aren't business invariants about a
resource or a rule — they're this use case's own preconditions.

**Step 2 — Collect.** `self._collector.collect()` is called — a
`BaseCollector` was injected into `ScanCloudAccount.__init__` when it
was constructed (dependency injection — see Part E). It returns a tuple
of `NormalizedResource`. *What leaves:* raw-but-normalized resource data
— Phase 1's `NormalizedResource`, not a `boto3` object. *Who owns this
responsibility:* the concrete `BaseCollector` implementation
(Infrastructure, not built yet); `ScanCloudAccount` never sees a
`boto3.Session`.

**Step 3 — Verify.** `_verify_collected_resources` checks every
returned resource actually belongs to `tenant_id` and actually reports
`provider`. *Why:* defense in depth — if the collector has a bug, this
catches it before a graph gets built with wrong data.

**Step 4 — Build graph.** `BuildResourceGraph().build(tenant_id, resources)`
constructs a `ResourceGraph`, adding one `GraphNode` per resource and one
`GraphEdge` per `ResourceRelationship`. *What leaves:* a
tenant-scoped `ResourceGraph` — Phase 1's aggregate, unmodified.

**Step 5 — Evaluate rules.** `EvaluateRules.evaluate(...)` loads the
rule catalog (via `LoadRuleCatalog`, another port), and for every
`(rule, resource)` pair calls Phase 1's `rule.evaluate(resource)` — the
exact three-valued Kleene evaluator from `domain/rules/conditions.py`.
Each result becomes a `Finding` (`MATCHED→FAIL`, `NOT_MATCHED→PASS`,
`INDETERMINATE→INDETERMINATE`). *What leaves:* a tuple of `Finding`.

**Step 6 — Discover attack paths.** `AnalyzeAttackPaths.analyze(...)` is
called — and returns `()`, always, this phase (see §12 above for why).

**Step 7 — Risk.** Not called automatically this phase — see §12.

**Step 8 — Drift.** If a caller supplied `previous_snapshot`,
`DetectDrift.detect(...)` runs (delegating to Phase 1's `DiffEngine`).
Otherwise skipped — `drift_events = ()`.

**Step 9 — Scan result.** Everything gets assembled into a `ScanResult`
dataclass and returned. *Who owns this:* `ScanCloudAccount` itself — the
one place the whole pipeline's shape is visible.

## Part D — Code walkthrough

**`application/scanning/collector.py` — `BaseCollector`**
Why it exists: to let `ScanCloudAccount` depend on an abstraction
instead of a concrete cloud SDK. One abstract method, `collect()`, no
arguments (the concrete adapter is constructed with its credentials
already resolved — see the module docstring for why). No invariants of
its own; it's a pure interface.

**`application/graph/build_resource_graph.py` — `BuildResourceGraph`**
Important method: `build(tenant_id, resources) -> ResourceGraph`. Two
passes: all nodes first, then all edges — this means if resource B
appears *before* resource A in the input list, but B has a relationship
pointing at A, it still works, because by the time edges are added,
every node already exists. Try reading `test_relationship_order_does_not_matter_nodes_added_before_edges`
in `tests/unit/application/test_build_resource_graph.py` — it proves
exactly this.

**`application/rules/evaluate_rules.py` — `EvaluateRules`**
Important method: `evaluate(tenant_id, resources, detected_at, scan_id=None, rule_ids=None) -> tuple[Finding, ...]`.
Invariant worth noticing: `ensure_same_tenant` is called for *every*
resource before it's evaluated — meaning even if `BuildResourceGraph`
were skipped entirely, `EvaluateRules` would still refuse a foreign
tenant's resource. That's intentional redundancy, not sloppiness — each
component that touches tenant-scoped data checks it itself, so no
single missing call anywhere in a future caller can create a leak.

**`application/scanning/scan_cloud_account.py` — `ScanCloudAccount`**
Its constructor takes `collector: BaseCollector` and
`rule_catalog: LoadRuleCatalog` — both *ports*, not concrete classes.
This is dependency injection: the caller decides which concrete
adapter to hand in. In production that'll eventually be
`ScanCloudAccount(collector=AwsCollector(session), rule_catalog=YamlRuleCatalog(path))`.
In tests, it's `ScanCloudAccount(collector=FakeCollector([...]), rule_catalog=FakeRuleCatalog([...]))`.
Same class, zero code changes, completely different behavior — that's
the entire point of a port.

**`application/scanning/dtos.py` — `ScanConfiguration`, `ScanResult`**
Both are plain frozen dataclasses. `ScanResult` is the single object
that carries everything a scan produced — a future presentation layer
would take a `ScanResult` and turn it into JSON, or a future AI Core
integration would take `result.findings` and run each through
`contracts.ai_service.translation.finding_to_contract()` (already built
in Phase 1).

## Part E — Ports and Adapters

```
Application (ScanCloudAccount)
         ↓  depends on the abstraction
   BaseCollector  (ABC, defined in application/)
         ↑  implemented by
   FakeCollector          AwsCollectorAdapter
   (tests, this phase)    (Phase 3, not built yet)
```

Both `FakeCollector` and a future `AwsCollectorAdapter` satisfy the same
contract: "give me a tuple of `NormalizedResource` when `collect()` is
called." `ScanCloudAccount` cannot tell them apart — it just calls
`self._collector.collect()`. This is why testing is possible without
AWS credentials: the test constructs `ScanCloudAccount` with a
`FakeCollector` that returns pre-built `NormalizedResource` objects
in-memory, and every line of orchestration logic runs exactly as it
would in production, with zero network calls.

**Dependency Injection** is simply: *how* the adapter gets handed to the
class that needs it. Here, it's constructor injection —
`ScanCloudAccount(collector=..., rule_catalog=...)`. Nothing fancier
than passing arguments to `__init__`.

## Part F — Testing

**Unit tests** (Domain, Phase 1): test one class in complete isolation
— e.g. does `RiskScore.calculate()` apply the right weights.

**Application tests** (this phase): test orchestration — does
`ScanCloudAccount` call things in the right order, with the right data,
and handle failures correctly. They still don't touch a network or a
disk — every port is a fake.

**Fake adapters**: minimal, in-memory classes that implement a port
just enough to test with. `FakeCollector` in
`test_scan_cloud_account.py` is ~5 lines — it just returns whatever
list of resources the test constructed.

**GIVEN / WHEN / THEN**, for three real tests:

*`test_indeterminate_finding_when_data_is_missing`*
- GIVEN a rule checking `attributes["public"] == True`, and a resource with an empty `attributes` dict
- WHEN `ScanCloudAccount.run(...)` executes
- THEN the resulting `Finding.status` is `FindingStatus.INDETERMINATE` — not `PASS`, not `FAIL`

*`test_collector_returning_a_foreign_tenant_resource_is_rejected`*
- GIVEN a `FakeCollector` that returns a resource tagged `tenant_id=TENANT_B`
- WHEN the scan is run requesting `tenant_id=TENANT_A`
- THEN `TenantIsolationViolation` is raised before any graph or finding is built

*`test_collector_failure_is_wrapped_not_swallowed`*
- GIVEN a `FailingCollector` whose `collect()` raises `ConnectionError`
- WHEN the scan is run
- THEN `ResourceCollectionError` is raised, and its `__cause__` is the original `ConnectionError` — nothing was silently discarded

## Part G — Security

* **Tenant isolation**: enforced three separate times in this phase (§8) — not because one check isn't "enough" in theory, but because in a real system, every place tenant-scoped data crosses a boundary is a place a bug could leak it. Redundant checks are the point, not an oversight.
* **Cloud credential boundaries**: `ScanCloudAccount` never sees a raw credential — it receives `credentials_reference` (an opaque string) and a pre-constructed `BaseCollector`. Resolving `credentials_reference` into an actual session is Infrastructure's job, kept entirely out of Application's reach.
* **Least privilege**: because Application never imports `boto3`, it's structurally incapable of making an unintended AWS call — there's no SDK object anywhere in this layer to misuse.
* **Data isolation**: see tenant isolation above — the same mechanism.
* **Deterministic scanning**: `scanned_at` is explicit, IDs are derived not randomly generated — meaning if a scan is re-run with the exact same inputs, you get the exact same outputs. For compliance evidence, this matters: you can prove a scan's result wasn't influenced by hidden clock or randomness behavior.
* **Compliance evidence integrity**: `Finding.evidence` is a literal snapshot of the resource's attributes at scan time (`Evidence(data=resource.attributes)`) — not a summary, not an AI-generated description. It's exactly what Phase 1 called "deterministic, collected facts... authoritative."
* **Preventing cross-tenant findings**: `EvaluateRules` calls `ensure_same_tenant` per-resource before evaluating; `QueryFindings` re-checks every result. Two independent chances to catch a leak.
* **Preventing fabricated graph relationships**: `BuildResourceGraph` only ever builds edges from `ResourceRelationship`s that were actually present on a collected `NormalizedResource` — it invents nothing; a resource collector claiming a relationship it didn't actually observe would be an Infrastructure-layer bug, not something Application could introduce.

## Part H — Architecture interview questions

1. **Why does ComplianceIQ need an Application layer?**
   Because "how to run a scan" (sequence, coordination) is a different
   kind of knowledge than "what makes a bucket compliant" (business
   rule) or "how to call the AWS API" (technical detail) — mixing them
   makes each one harder to test and change independently.

2. **Why can't `ScanCloudAccount` live inside Domain?**
   Because it depends on `BaseCollector`, a port whose real
   implementations touch the network — and the Domain rule is "nothing
   in `domain/` may depend on infrastructure, even indirectly through a
   port." Domain must be usable with zero I/O.

3. **Why can't Application import boto3?**
   Because doing so would tie the orchestration logic to one specific
   cloud provider's SDK, making Azure support require rewriting
   `ScanCloudAccount` instead of just adding an adapter — and it would
   make every test require real AWS credentials.

4. **What is a port?**
   An abstract interface (in Python, typically an `ABC`) that describes
   a capability the Application layer needs, without specifying how
   it's fulfilled.

5. **What is an adapter?**
   A concrete class implementing a port — could be a real integration
   (`AwsCollector`) or a test double (`FakeCollector`).

6. **Why use dependency inversion?**
   So the direction of source-code dependency (`Application → port`)
   doesn't force a direction of *control* dependency onto a specific
   technology. It lets Infrastructure depend on Application's ports,
   instead of Application depending on Infrastructure.

7. **How is tenant isolation preserved?**
   By enforcing it at every layer independently — Domain
   (`ResourceGraph.add_node`), and Application (`EvaluateRules`,
   `ScanCloudAccount._verify_collected_resources`, `QueryFindings`) —
   rather than trusting a single earlier check.

8. **Why are normalized resources important?**
   Because they're the one shape every downstream component (graph,
   rules, findings) can rely on, regardless of which cloud they came
   from — without them, every component would need provider-specific
   logic.

9. **Why should `Finding` remain a Domain entity?**
   Because "what a finding is" (its required fields, its invariants —
   must have a `tenant_id`, a bounded risk score) is a business fact, not
   an orchestration detail. Application constructs `Finding`s but never
   redefines what a valid one looks like.

10. **What happens when a rule returns `INDETERMINATE`?**
    The resulting `Finding.status` is `FindingStatus.INDETERMINATE` —
    never silently converted to `PASS` or `FAIL`. This is tested
    explicitly (`test_indeterminate_is_never_silently_converted`).

11. **How can Phase 2 be tested without AWS?**
    By injecting `FakeCollector` (and `FakeRuleCatalog`,
    `FakeFindingRepository`) instead of real adapters — every test in
    `tests/unit/application/` does exactly this.

12. **What happens if the collector fails?**
    `ScanCloudAccount` catches the exception and re-raises it as
    `ResourceCollectionError`, preserving the original as `__cause__` —
    it's surfaced clearly, not swallowed.

13. **Why should infrastructure be replaceable?**
    Because cloud providers, databases, and external services change
    far more often than business rules do — isolating that volatility
    behind ports means a provider or database migration doesn't touch
    Domain or Application code at all.

14. **What is orchestration vs business logic?**
    Orchestration is *sequencing and coordinating* calls (Application);
    business logic is *deciding what's true or valid* (Domain).
    `ScanCloudAccount` orchestrates; `Rule.evaluate()` decides.

15. **Where should risk calculation live?**
    The *formula* (`RiskScore.calculate`, exact CRSF-1.1 weights) lives
    in Domain, because it's a business rule. *Deriving the input
    factors* from a `Finding` is orchestration-adjacent and would live
    in Application (`EnrichRisk`) — once that mapping is actually
    specified (it isn't yet).

16. **Why shouldn't Application duplicate Domain invariants?**
    Because two implementations of the same rule will eventually
    disagree — one gets updated, the other doesn't. `BuildResourceGraph`
    never re-checks referential integrity itself; it just calls
    `add_edge` and lets the one true implementation raise.

17. **How would Azure support be added?**
    Write `AzureCollector(BaseCollector)` implementing `collect()`
    against the Azure SDK, returning `NormalizedResource`s with
    `cloud_provider=CloudProvider.AZURE`. Zero changes to
    `ScanCloudAccount`, `BuildResourceGraph`, or any Domain code.

18. **How would persistence be introduced later?**
    Implement `FindingRepositoryPort` (and eventually
    `ResourceGraphPort`, if volume ever justifies it) against a real
    database. `QueryFindings` doesn't change at all.

19. **How would the AI Service boundary be integrated?**
    `ScanResult.findings` already exist as Phase-1 `Finding` entities;
    each can already be passed through
    `contracts.ai_service.translation.finding_to_contract()` (built in
    Phase 1) to get the exact external DTO. The remaining work is
    purely transport (HTTP client, JWT) — explicitly out of scope for
    both Phase 1 and Phase 2.

20. **How would you explain this architecture to a senior engineer?**
    "Domain holds the rules that don't change based on deployment
    details. Application holds the one true sequence for running a scan,
    depending only on abstractions it defines itself. Infrastructure
    will plug concrete technology into those abstractions later. Nothing
    outer ever leaks into something inner — verified by grep, not just
    convention."

## Part I — Practical exercises

**Level 1 — Understand the classes.**
Open `application/scanning/scan_cloud_account.py` and
`application/scanning/collector.py`. Without running anything, write
down: what does `ScanCloudAccount.__init__` require? What's the one
method `BaseCollector` demands? *Hint: look at the `@abstractmethod`.*

**Level 2 — Trace a scan.**
Using `tests/unit/application/test_scan_cloud_account.py`'s
`TestSuccessfulScan.test_returns_a_scan_result_with_all_pipeline_outputs_populated`,
manually list every method call `ScanCloudAccount.run()` makes, in
order, along with what each one returns. *Hint: Part C above already
did this — try it yourself first, then check.*

**Level 3 — Write a fake collector.**
Write a `FakeCollector` (or reuse the one in the tests) that returns
three `NormalizedResource`s, two of which have a `PROTECTS` relationship
to the third. Build a `ScanCloudAccount` with it and a rule catalog
containing zero rules, and inspect `result.graph.edges`.
*Hint: `ResourceRelationship(target_resource_id=..., relationship_type=RelationshipType.PROTECTS)`.*

**Level 4 — Add a new application port.**
Design (don't need to fully implement) a port for "notify someone when
a scan finds a CRITICAL severity finding." What's the one abstract
method? What would a `FakeNotifier` look like for testing? *Hint: think
about what `ScanCloudAccount` would need to call, and when in the
pipeline.*

**Level 5 — Test tenant isolation.**
Write a new test (don't need to add it permanently) where
`FakeFindingRepository` returns findings for three different tenants,
and assert `QueryFindings` only ever returns the requested one.
*Hint: look at `test_query_findings.py`'s existing tests for the
pattern.*

**Level 6 — Simulate a collector failure.**
Write a `FlakyCollector(BaseCollector)` whose `collect()` raises
`TimeoutError` the first time it's called. Run it through
`ScanCloudAccount` and confirm the exception you get is
`ResourceCollectionError`, and that `str(exc.__cause__)` mentions the
timeout. *Hint: `FailingCollector` in `test_scan_cloud_account.py` is
almost this already.*

**Level 7 — Add a new cloud provider adapter WITHOUT modifying Domain.**
Sketch (in comments, no need to fully implement) a fictional
`GcpCollector(BaseCollector)`. What would stop you from actually wiring
it in today, given the current `domain.shared.enums.CloudProvider`?
*Hint: re-read Phase 1's docs on why `CloudProvider` intentionally has
only `aws`/`azure` — this is the "Phase 1 gap, handle carefully"
exercise made concrete.*

**Level 8 — Explain the entire architecture verbally.**
In under two minutes, explain to an imaginary colleague: what Domain
is, what Application is, why `ScanCloudAccount` doesn't import `boto3`,
and what happens when a rule can't be evaluated because data is
missing. *Hint: Parts A, C, and G above give you everything you need —
the exercise is compressing it, not learning new material.*

## Part J — Zero to Hero final checklist

```
[ ] I understand Domain
[ ] I understand Application
[ ] I understand Infrastructure
[ ] I understand ports
[ ] I understand adapters
[ ] I understand dependency inversion
[ ] I can trace ScanCloudAccount
[ ] I can explain tenant isolation
[ ] I can write a fake adapter
[ ] I can write an application unit test
[ ] I understand why boto3 is not in Application
[ ] I understand why Domain remains pure
[ ] I understand what Phase 3 will add
```
