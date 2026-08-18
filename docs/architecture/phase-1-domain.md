# Phase 1 — Domain Foundation

Status: **implemented**. This document records what Phase 1 built, the
boundaries it enforces, and what is intentionally left for later phases.
It does not restate the blueprint — see
`ComplianceIQ_Senior_Architecture_Blueprint.md` for the target
architecture this phase implements.

## 1. Objective

Build the pure Domain layer described in blueprint §3 as a **greenfield
implementation** — the repository contained no code before this phase,
only the architectural blueprint. Every module below is written from
scratch against the blueprint's CURRENT-labeled sections (§8–§13), which
this project treats as the specification for what must be built, not as
evidence of pre-existing code.

## 2. Implemented components

| Module | Contents |
|---|---|
| `domain/shared/` | `TenantId`, `ResourceId`, `RuleId`, `FindingId`, `AttackPathId` (typed identifiers); `CloudProvider`, `RelationshipType`, `Severity` enums; `DomainError` and all domain exceptions |
| `domain/tenants/` | `Tenant` entity; `ensure_same_tenant()` — the single canonical tenant-isolation check reused by `graph/` and `attack_paths/` |
| `domain/resources/` | `NormalizedResource`, `ResourceRelationship` |
| `domain/rules/` | `Rule`; `evaluate_condition()` — deterministic, three-valued (Kleene) recursive evaluator; AND/OR/NOT; 10 leaf operators; `source: graph` extension point |
| `domain/graph/` | `ResourceGraph`, `GraphNode`, `GraphEdge` |
| `domain/findings/` | `Finding`, `Evidence`, `FindingStatus` |
| `domain/risk/` | `RiskScore` (CRSF-1.1 weighted formula), `ConfidenceScore` |
| `domain/attack_paths/` | `AttackPath`, `AttackTechnique` |
| `domain/drift/` | `DriftEvent`, `DriftType`, `canonicalize()`, `DiffEngine` |
| `domain/compliance/` | `ComplianceFramework`, `ControlMapping`, `ComplianceAssessment`, `ComplianceStatus` |
| `contracts/ai_service/` | `FindingContract`, `NormalizedResourceContract` (external DTOs); `Framework`, `RiskDomain`, `ExternalFindingStatus` (contract-only closed vocabularies); `finding_to_contract()`, `resource_to_contract()` (deterministic translation) |

Not implemented, and not touched: `application/`, `infrastructure/`,
`presentation/`, `terraform/` — out of scope for Phase 1 by explicit
instruction. `contracts/` is implemented, but scoped narrowly — see
§10 below: only the boundary DTOs and translation exist, not the HTTP
client, JWT issuance, or `/ai/enrich` call itself.

## 3. Domain boundaries

* `resources/`, `rules/`, `graph/`, `attack_paths/`, `drift/`, `risk/`
  know nothing of any cloud SDK, ORM, web framework, or AI/LLM client —
  verified by exhaustive grep (§9 below), matching the blueprint's own
  verification method.
* `findings/` is a **pure domain entity** — it is not modeled around, and
  contains no reference to, the AI Core's 11-field external contract
  (blueprint §26.5). The projection from `Finding` to that contract lives
  entirely in `contracts/ai_service/`, one layer outside the Domain —
  `domain/findings/models.py` has no import of, and no knowledge of,
  `contracts/` (verified the same way as the SDK-purity check in §5:
  `grep -rn "import contracts\|from contracts" domain/` → no matches).
  The full Anti-Corruption Layer (HTTP client, JWT, retry — blueprint
  §26.12) still does not exist; only the translation/DTO half does — see
  §10.
* `compliance/` depends on `findings/` (for `FindingStatus`) but has no
  notion of the AI Core contract, matching the blueprint's requirement
  that `compliance/` never cross that boundary.
* `RelationshipType` lives in `shared/`, not duplicated between
  `resources/` and `graph/`, so neither module depends on the other for
  a shared vocabulary.
* Within `domain/`, the only inter-module dependencies are:
  `graph → tenants` (isolation check), `attack_paths → graph, tenants,
  shared`, `compliance → findings, shared`, `rules → resources, shared`.
  No cycles.

## 4. Domain invariants (enforced in code, verified by tests)

1. **Tenant isolation** — `ResourceGraph.add_node` and `AttackPath`
   construction both reject any node whose `tenant_id` differs from the
   aggregate's own, via the shared `ensure_same_tenant()` check.
2. **Graph referential integrity** — `ResourceGraph.add_edge` raises
   `GraphIntegrityViolation` if either endpoint is not a node already in
   the graph; duplicate nodes are rejected the same way.
3. **Attack path integrity** — every `AttackPath` edge must reference a
   node present in that same path; every node must belong to the path's
   tenant.
4. **Finding integrity** — `Finding` always carries a `tenant_id` and a
   `resource_id`; both are required constructor arguments of validated
   identifier types.
5. **Determinism** — `Rule.evaluate()`, `RiskScore.calculate()`,
   `DiffEngine.compare()`, and `ComplianceAssessment.from_findings()` are
   pure functions of their inputs (no randomness, no internal wall-clock
   reads — `DiffEngine.compare` takes `detected_at` as an explicit
   argument for this reason). Verified by repeated-call tests in every
   module.
6. **No hidden compliance** — applied at two layers: a rule condition
   leaf whose field was not collected evaluates to `INDETERMINATE`, never
   `MATCHED`/`NOT_MATCHED`; and `ComplianceAssessment.from_findings([])`
   (no evidence at all) resolves to `UNKNOWN`, never `COMPLIANT`.
7. **Blocked attack path invariant** — an `AttackPath` with any blocked
   edge must have `risk_score == 0`; enforced at construction.
8. **Bounded scores** — `RiskScore`, `ConfidenceScore`, and `Finding`'s
   internal `risk`/`confidence` annotations are always in `[0, 100]`.
9. **Timezone-aware timestamps** — `NormalizedResource.collected_at`,
   `Finding.detected_at`, `DriftEvent.detected_at`, and
   `ComplianceAssessment.evaluated_at` all reject naive datetimes.
10. **The AI Service never sees an INDETERMINATE finding** —
    `finding_to_contract()` raises `ContractTranslationError` rather than
    coercing an indeterminate result into `pass` or `fail`.

## 5. Dependency rules

`domain/` depends on the Python standard library only. Verified for this
phase by:

```
grep -rEn "^\s*(import|from)\s+(boto3|azure|fastapi|flask|sqlalchemy|
  psycopg2|redis|requests|httpx|kubernetes|openai|anthropic|langchain)" domain/
  →  no matches
grep -rn "eval(\|exec(" domain/
  →  no matches
```

Pydantic was considered (the blueprint notes the pre-existing reference
implementation's only external dependency is `pydantic`) but not used:
this phase uses `dataclasses` (`frozen=True, slots=True`) with explicit
`__post_init__` validation instead, so every validation failure raises an
exact, intentional domain exception under our own control rather than a
library-owned `ValidationError`. This keeps the zero-dependency
guarantee trivially true rather than merely intended.

`contracts/` (the AI Service boundary layer, §10) is held to the same
zero-external-dependency standard and depends on `domain/` in one
direction only — `domain/` has no knowledge of `contracts/` at all, verified
the same way:

```
grep -rn "import contracts\|from contracts" domain/   →  no matches
grep -rEn "^\s*(import|from)\s+(boto3|...)" contracts/  →  no matches
```

## 6. Test coverage

188 tests, all passing:

| Module | Tests |
|---|---|
| `tests/unit/domain/test_shared.py` | 12 |
| `tests/unit/domain/test_tenants.py` | 6 |
| `tests/unit/domain/test_resources.py` | 13 |
| `tests/unit/domain/test_rules.py` | 44 |
| `tests/unit/domain/test_graph.py` | 13 |
| `tests/unit/domain/test_findings.py` | 20 |
| `tests/unit/domain/test_risk.py` | 17 |
| `tests/unit/domain/test_attack_paths.py` | 14 |
| `tests/unit/domain/test_drift.py` | 14 |
| `tests/unit/domain/test_compliance.py` | 13 |
| `tests/unit/contracts/test_ai_service_contract.py` | 22 |

Run with: `python3 -m pytest tests/ -q`

## 7. Architectural decisions

* **`resource_type` stays a free provider-specific string** (blueprint
  §8) — no canonical category abstraction introduced before a second
  provider exists to prove the mapping is needed.
* **`NormalizedResource.region` is optional** — IAM users (a
  blueprint-listed, currently-collected AWS resource) are global and have
  no region; forcing a region would misrepresent real data.
* **`source: graph` condition leaves use an intentionally empty function
  registry** — the blueprint confirms this capability exists structurally
  but "no real rule uses it yet" (§9); inventing function names now would
  be speculative. Using an unregistered function raises
  `InvalidRuleCondition`.
* **Missing field in a rule condition → `INDETERMINATE`**, not
  `NOT_MATCHED`, for every operator except `exists`/`not_exists` — this
  applies the no-hidden-compliance principle at the evaluator itself, not
  only at the compliance-aggregation layer.
* **`FindingStatus` mirrors the rule engine's three-valued result**
  (`FAIL`/`PASS`/`INDETERMINATE`) since a `Finding` is produced directly
  from a rule evaluation outcome.
* **`Finding.risk`/`Finding.confidence` are plain bounded floats**, not
  `RiskScore`/`ConfidenceScore` instances — this keeps `findings/`
  decoupled from `risk/` (no import either direction); attaching a full
  `RiskScore` to a `Finding` is an application-layer concern.
* **`AttackPath.risk_score` is an accepted, validated input, not a
  computed output** — see Known Limitations below (correction from
  review: no scoring formula is specified by the blueprint, so none was
  invented).
* **`RiskScore.calculate()` implements only the weighting formula**
  explicitly given in blueprint §13, over five already-computed `[0,100]`
  factor scores — the mapping from a raw signal (e.g. a `Severity` enum
  member) to a `[0,100]` factor is *not* implemented, because the
  blueprint does not specify it (see Known Limitations).
* **Duplicate `ResourceGraph` nodes are rejected**, not silently
  overwritten — a resource can only be represented once per graph;
  silent overwrite would hide a collector bug.
* **`DriftEvent` volatile-field stripping covers exactly `collected_at`**
  — the only field the blueprint identifies as collection-time metadata
  (§8); no other field is assumed volatile without similar evidence.
* **`DiffEngine.compare()` takes `detected_at` as an explicit parameter**
  rather than reading the wall clock internally, to keep it a pure,
  deterministic function (invariant 5 above).
* **Typed identifiers share one internal base dataclass** (`_Identifier`
  in `shared/identifiers.py`) to avoid duplicating validation logic five
  times, while remaining five distinct, mutually-incompatible types.
* **`Severity` was narrowed from 5 values to the 4 the Core↔AI Service
  handoff confirmed** (`critical`/`high`/`medium`/`low`, no `info`) — this
  replaces a Phase 1 placeholder that was explicitly flagged as an open
  ambiguity (blueprint §13 specifies no severity enumeration at all); the
  handoff resolved it with authoritative information rather than this
  phase inventing one, so the placeholder was updated in place.
* **`Finding.framework`/`Finding.domain` stay free strings inside the
  Domain**, even though the handoff specifies closed `Framework`/
  `RiskDomain` vocabularies for its own contract. The Domain already
  applies this exact reasoning to `resource_type` (§8: no canonical
  category before it's proven necessary) — the closed vocabulary is
  enforced only at the `contracts/ai_service/` boundary, on translation,
  never inside `Rule`/`Finding` themselves.
* **`CloudProvider` stays `{aws, azure}`** — the handoff's contract text
  additionally listed `gcp`, which appears nowhere in the blueprint (a
  document that discusses AWS and Azure exhaustively and a third
  provider not at all). Treated as out of scope pending an explicit
  blueprint update, not silently absorbed.
* **The AI Service contract boundary (`contracts/ai_service/`) was built
  in this phase, but scoped to DTOs + translation only** — no HTTP
  client, JWT, or `/ai/enrich` call (still correctly deferred, per
  blueprint §26.12/Phase 12). It lives outside `domain/`, one-directional
  dependency (`contracts → domain`), so the Domain's AI-Core-independence
  invariant (§3, §5) is unaffected.

## 8. Known limitations (explicit, not silent)

* **No attack-path discovery algorithm.** `PathDiscovery` (graph
  traversal from `__internet__`) and `AttackPathScorer` (blueprint §11)
  are not implemented. `AttackPath.risk_score` is accepted as a
  pre-computed value and only validated (bounds, and the
  blocked-path-must-score-zero invariant) — nothing in this phase
  computes it. The blueprint gives no formula for this (unlike
  `RiskScore`), so none was invented per explicit instruction.
* **No mapping from raw signals to `RiskScore` factors.** The blueprint
  specifies the five factor *weights* but not how a `Severity`, an
  exposure state, an environment label, a `ConfidenceScore`, or attack
  path involvement become a `[0,100]` number. That mapping is real
  business logic the blueprint does not define — implementing it here
  would mean inventing rules, which was explicitly disallowed.
* **Graph-context rule functions are unimplemented.** The `source: graph`
  leaf mechanism exists and is tested (rejects unregistered functions),
  but the registry itself is empty — matching the blueprint's own
  observation that this capability is unexploited by any real rule today.
* **No `resource_type → canonical_category` mapping.** Deferred until
  Azure produces a real second provider to map against (blueprint §8
  recommendation).
* **No persistence, no application orchestration.** `ResourceGraph`,
  `Finding`, `DriftEvent`, etc. are all in-memory-only, as required —
  nothing here reads or writes any store.
* **No `resource_type → (service, type)` decomposition.** The handoff's
  `NormalizedResourceContract` splits a resource into `service` (e.g.
  `"s3"`) and `type` (e.g. `"bucket"`); the Domain's `resource_type` is
  one opaque provider-specific string (e.g. `"s3_bucket"`,
  `"security_group"`) with no specified splitting rule, and no rule can
  be safely inferred (`"security_group"` does not decompose into a
  correct AWS service name by any string convention). `resource_to_contract()`
  therefore requires the caller to supply `service` explicitly and maps
  `type` directly from `resource_type` as-is — a real mapping table is a
  Phase 2+ concern once it can be validated against more than one
  resource type.
* **No AI Service HTTP integration.** `contracts/ai_service/` produces
  payload dicts (`to_payload()`); nothing sends them anywhere. The client,
  authentication, retry/circuit-breaker, and the endpoints themselves
  (`/ai/enrich`, etc.) are unbuilt, per blueprint §26.12/Phase 12.

## 9. Core ↔ AI Service handoff review

Mid-Phase-1, an AI Service integration handoff was received, specifying
the exact external `Finding`/`NormalizedResource` contracts. It was
reviewed field-by-field against the implementation already built; the
findings and the decisions made from them:

| Area | Resolution |
|---|---|
| `Severity` vocabulary | Adopted as-is (`critical`/`high`/`medium`/`low`) — resolved an open ambiguity the blueprint itself left unspecified. |
| Timezone-aware timestamps | Adopted as a Domain-wide invariant (§4.9), not just an external-contract concern. |
| External `Finding.status` (`pass`/`fail`, no `INDETERMINATE`) | Enforced only at the `contracts/` boundary (`finding_to_contract` rejects `INDETERMINATE`); the Domain's three-valued `FindingStatus` is untouched. |
| `Framework`/`RiskDomain` closed vocabularies | Modeled in `contracts/ai_service/enums.py`, **not** in `domain/shared/enums.py` — the Domain's `framework`/`domain` fields stay free strings, matching the blueprint's own anti-premature-abstraction stance on `resource_type`. |
| `CloudProvider` including `gcp` | **Rejected for now** — contradicts the blueprint's exhaustive AWS/Azure-only scope; no third provider is designed anywhere in this project. Flagged rather than silently added. |
| `NormalizedResource` external field names (`id`, `cloud`, `service`, `type`, `config`) | Modeled as a separate `NormalizedResourceContract` DTO in `contracts/ai_service/`; the Domain's own `NormalizedResource` field names (`resource_id`, `cloud_provider`, `resource_type`, `attributes`) are unchanged. |
| Internal-only `Finding` fields (`risk`, `confidence`, `scan_id`, ...) | Confirmed excluded from `FindingContract.to_payload()` (tested explicitly) — the AI Service's "reject unknown fields" requirement is satisfied by construction, since `FindingContract` has no way to carry them in the first place. |

Net effect: the AI Service boundary now exists as a typed, tested
translation layer rather than an unimplemented gap — but only the
translation. The HTTP call itself remains future work (§8, Known
Limitations).

## 10. What Phase 2 will consume

Phase 2 (formalizing `application/`, starting with `ScanCloudAccount` per
blueprint §4) will consume this Domain as-is:

* `NormalizedResource` / `ResourceRelationship` as the collector output
  shape.
* `Rule.evaluate()` as the deterministic evaluation entry point.
* `ResourceGraph`/`GraphBuilder`-equivalent construction using
  `add_node`/`add_edge`.
* `Finding` construction from a `(Rule, NormalizedResource,
  EvaluationResult)` triple — the application layer decides how
  `EvaluationResult` maps to `FindingStatus` (currently 1:1 by
  convention, not enforced by the Domain itself).
* `RiskScore.calculate()` once the application layer defines how it
  derives the five `[0,100]` factors from a `Finding` and its graph
  context — the open mapping noted in §8 above.
* `ComplianceAssessment.from_findings()` for the compliance
  query/reporting use case.
* `AttackPath` construction once a discovery/scoring algorithm is
  designed and explicitly specified (not before — see §8).
* `contracts.ai_service.translation.finding_to_contract()` /
  `resource_to_contract()` as the ready-made ACL for whichever phase
  builds the actual `/ai/enrich` HTTP call — Phase 2 (or later) supplies
  the transport, not the translation, which already exists and is
  tested.
