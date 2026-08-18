# Compliance Catalog — Current State Audit

> **STEP 7, audit phase. No code was modified.**
>
> Every number below was computed by executing against the repository,
> not read from a previous report. Prior documents were treated as
> unverified claims.

---

## 1. The headline

The repository already contains **more mapping machinery than expected**
and **less framework coverage than the product tier list assumes**.

| Question | Answer |
|---|---|
| Frameworks in Platform code | **4** — `iso_27001`, `cis_aws`, `cis_azure`, `nist_800_53` |
| Frameworks in an AI corpus | **none — `corpus/` does not exist in this repository** |
| Framework **versions** anywhere | **zero.** No version field exists on any framework reference |
| Rules | 68 |
| Distinct primary control ids | 7 |
| Secondary mappings | 27, across 26 rules |
| Mappings marked `verified` | 11 |
| Provenance on those 11 | **none — the field does not exist** |
| Tier-1 frameworks (ISO, DNSSI, Loi 05-20) present | **1 of 3** |
| Tier-2 (NIST CSF) present | **0** — see §4.2 |
| Tier-3 (SOC 2) present | **0** |

---

## 2. What exists, precisely

### 2.1 Primary mapping — every rule has exactly one

```
TOTAL RULES: 68
framework values: {'iso_27001': 68}
rules with no framework:  0
rules with no control_id: 0
distinct control_ids: 7
```

| Control id | Rules |
|---|---|
| `A.8.20` | 23 |
| `A.8.24` | 18 |
| `A.5.17` | 8 |
| `A.8.13` | 7 |
| `A.8.15` | 7 |
| `A.5.15` | 4 |
| `A.8.5` | 1 |

`Rule.framework` and `Rule.control_id` are **singular and required**.
They feed `Finding.framework` / `Finding.control_id`, which are the
fields `contracts.ai_service` expects — a received external contract, so
they are not ours to reshape.

Consequence: the *primary* mapping is exactly the
`rule → one framework → one control` model §8 forbids as the whole
design. It is not, however, the whole design — see §2.2.

### 2.2 Secondary mapping — `FrameworkMapping` already exists

`domain/rules/rule.py` defines:

```python
@dataclass(frozen=True, slots=True)
class FrameworkMapping:
    framework: str
    control: str
    status: str = "unresolved"
```

Measured usage:

```
rules WITH framework_mappings: 26 of 68
mapping counts per rule: {0: 42, 1: 25, 2: 1}
statuses: {'verified': 11, 'unresolved': 16}
secondary frameworks: {'cis_aws': 17, 'cis_azure': 9, 'nist_800_53': 1}
```

So **many-to-many is already partially real**: one rule carries two
secondary mappings, and the loader (`YamlRuleCatalog._parse_framework_mappings`)
parses a list. This is the abstraction STEP 7 should extend rather than
replace — §7's instruction to reuse existing abstractions applies
directly.

Its docstring already states the anti-fabrication principle:

> *`status` defaults to `"unresolved"` deliberately — fabricating an
> unverified control mapping is the single fastest way to lose
> credibility with an actual auditor.*

### 2.3 Compliance domain

`domain/compliance/models.py` (130 lines) has:

- `ComplianceStatus` — `compliant` / `non_compliant` / `unknown`
- `ComplianceFramework(id, name, version)` — **has a `version` field**
- `ControlMapping(framework, control_id, rule_ids)` — control → many rules
- `ComplianceAssessment` — aggregates `FindingStatus` per control, with
  the no-hidden-compliance rule (no evidence → `UNKNOWN`, never
  `COMPLIANT`)

`ControlMapping` is the *inverse* direction of `FrameworkMapping` and is
the natural home for "which rules provide evidence for this control"
(§17). **Nothing constructs either from the rule catalog today** — they
are used only in unit tests.

### 2.4 Scoring — framework scope already exists

`ScoreScope` is a closed enum: `TENANT`, `FRAMEWORK`, `DOMAIN`, `SCAN`.
`ComputeScoresForScan` already emits one score per framework touched,
and `GET /api/v1/scores?scope=framework&scope_value=iso_27001` already
works.

Framework scoring is therefore **IMPLEMENTED**, and §13's fallback
("document as follow-up") does not apply. What it scores is
`Finding.framework` — the primary mapping only. Secondary mappings
contribute nothing to any score.

---

## 3. The gaps

### 3.1 🔴 `verified` without provenance

Eleven mappings are marked `verified` and the word `provenance` does not
appear anywhere in the rule model, the YAML schema, or the loader.

This is the most serious finding. A `verified` status that cannot say
*verified against what* is an assertion, not evidence — and §6 requires
every `VERIFIED` mapping to carry provenance. Until it does, those
eleven are indistinguishable from a maintainer's confident guess.

Note what this does **not** mean: the mappings are probably fine. CIS AWS
Foundations control numbers are public and checkable. The defect is that
nothing records who checked, against which document, at which version.

### 3.2 🔴 No framework versions

`ComplianceFramework` has a `version` field and **nothing populates it**.
Rule YAML has no version key. `Finding.framework` is a bare string.

Without a version, `cis_aws 1.20` is ambiguous: CIS AWS Foundations
v1.4.0 and v3.0.0 renumber controls. A mapping without a version is not
auditable.

### 3.3 🟠 No `proposed` status

`_VALID_MAPPING_STATUSES = frozenset({"verified", "unresolved"})`.

§6 requires three. The missing one matters: `unresolved` currently
absorbs both *"we think this is right but haven't checked"* and *"this is
a deliberate technical proposal"*, which are different claims to an
auditor.

### 3.4 🟠 42 of 68 rules have no secondary mapping

Not a defect — a coverage fact. Reported in the matrices.

### 3.5 No catalog assembly, validation, or reporting

There is no component that:

- builds a framework/control registry from the rules
- validates that a mapping's framework and control exist
- detects duplicate `(rule, framework, version, control)` tuples
- detects orphan controls or unmapped rules
- computes coverage

`ControlMapping` exists as a *shape* with no producer.

---

## 4. Framework coverage against the product tiers

### 4.1 Tier 1

| Framework | Present | Notes |
|---|---|---|
| **ISO/IEC 27001:2022** | ✅ as `iso_27001` | 68 rules, 7 controls. Version not recorded, but the `A.5.x`/`A.8.x` numbering is unambiguously the **2022** revision — the 2013 revision used `A.5`–`A.18` with different numbering. That inference is defensible; it is still an inference, and is recorded as such |
| **DNSSI** | ❌ **absent** | Zero occurrences anywhere in the repository |
| **Loi 05-20** | ❌ **absent** | Zero occurrences anywhere |

### 4.2 Tier 2 — a naming trap worth flagging

| Framework | Present |
|---|---|
| **NIST CSF** | ❌ **absent** |

The repository contains `nist_800_53` on exactly one rule. **NIST SP
800-53 is not the NIST Cybersecurity Framework.** They are different
documents with different structures — 800-53 has control identifiers
like `AC-3`, CSF has functions/categories like `PR.AC-4`. Counting
`nist_800_53` as NIST CSF coverage would be a fabricated claim, and the
coverage matrix must not do it.

### 4.3 Tier 3

| Framework | Present |
|---|---|
| **SOC 2** | ❌ **absent** |

`ScoreScope.FRAMEWORK`'s docstring gives `soc_2` as an *example* value.
That is illustrative prose, not data.

---

## 5. The AI corpus boundary

**`corpus/` does not exist in this repository.** No `dnssi.json`, no
`iso_27001.json`, nothing. Verified by directory listing.

So the ownership boundary §2 asks about is currently preserved by
absence rather than by design. That is not the same as being safe: when
the AI team's corpus does land, nothing in this codebase would stop a
future contributor from reading a corpus `control_id` and promoting a
mapping to `verified` on the strength of it.

**The boundary therefore needs an explicit, tested rule now**, while it
costs nothing — not after the corpus arrives and the temptation is
concrete.

---

## 6. Finding integration

`Finding` already carries `framework` and `control_id` (singular,
required, populated from the rule). Per §12 these should be **reused,
not duplicated**. They are also part of the frozen 11-field
`AiFindingContract`, so adding fields there would be a breaking change to
another team's client.

The right integration is therefore **validation, not extension**: a
finding's `(framework, control_id)` should resolve against the catalog,
and a mismatch should be detectable. No new Finding field is needed.

---

## 7. Security posture

The catalog is **global reference data**, not tenant data:

- Rules load from `rules/*.yaml` on disk, read-only, at startup
- No API writes rules or mappings
- `Finding.framework`/`control_id` are set by the rule engine from the
  rule, never from request input
- No route accepts a `framework` or `control_id` in a request body

So a tenant cannot mutate mappings today. That property is currently
**incidental** — it holds because no write path exists — and should be
made explicit and tested before any catalog API is added.

---

## 8. Answers to §3's twelve questions

| # | Question | Answer |
|---|---|---|
| 1 | Frameworks in Platform code | `iso_27001`, `cis_aws`, `cis_azure`, `nist_800_53` |
| 2 | Frameworks only in the AI corpus | None — no corpus exists here |
| 3 | Framework versions represented | **Zero.** No version is recorded anywhere |
| 4 | Control ids referenced by rules | 7 primary (ISO), plus 27 secondary references |
| 5 | Mappings actually verified | 11 claim `verified`; **0 carry provenance**, so none is verifiable |
| 6 | Unresolved | 16 |
| 7 | Proposed | **0 — the status does not exist** |
| 8 | Rules with no framework mapping | 0 primary; **42 have no secondary mapping** |
| 9 | Controls with no rule | 0 among the 7 primary — every catalogued control is reachable. Unmeasurable for frameworks with no control registry |
| 10 | Framework-level scoring | **Yes, implemented** — `ScoreScope.FRAMEWORK`, computed per scan, queryable |
| 11 | Domain-level mapping model to reuse | **Yes** — `FrameworkMapping` (rule → controls) and `ControlMapping` (control → rules). Extend, do not replace |
| 12 | Where mapping metadata is expected | On the **Rule**, flowing into the Finding as two singular fields. The Finding must not embed control records |

---

## 9. Recommended scope for the implementation phase

1. Add `version`, `provenance` and a `proposed` status to the existing
   `FrameworkMapping` — additive, defaulted, backward compatible.
2. Enforce **`verified` requires provenance**. The 11 existing
   `verified` mappings must either gain provenance or be downgraded.
   Downgrading is the honest default: they were never verifiable.
3. Build a **framework/control registry** with version, jurisdiction and
   authority, assembled from the rules rather than hand-maintained.
4. Add validation: existence, duplicates, orphans.
5. Compute both matrices from repository data, never by hand.
6. Add the corpus-boundary test now, before the corpus exists.
7. Do **not** add a catalog write API. Do not touch scoring.

Explicitly out of scope: inventing DNSSI, Loi 05-20, NIST CSF or SOC 2
content. Their coverage is zero and the matrices must say so.
