# The Compliance Catalog

> The technical mapping layer between what ComplianceIQ **checks** and
> what a framework **requires**.
>
> Generated artifacts:
> [coverage](../reports/compliance-catalog-coverage.md) ·
> [rule mapping matrix](../reports/compliance-rule-mapping-matrix.md).
> Audit that preceded it:
> [current-state](../audits/compliance-catalog-current-state.md).

---

## 1. Why it exists

A CSPM finding says *this bucket is public*. A compliance officer needs
*which control does that violate, and can you prove the link*. The
catalog is what turns the first into the second, and it answers two
questions in both directions:

```
Which control does this rule assess?     →  rule → controls
Which rules evidence this control?       →  control → rules
```

Without it, `Finding.framework = "iso_27001"` is a string nobody can
audit: it names a framework but not a version, and nothing records
whether a human ever checked that the rule actually assesses the control
it claims.

---

## 2. Catalog vs AI corpus — the ownership boundary

This is the most important distinction in the design, and it decides
what may live here.

| Platform Catalog (this) | AI / RAG corpus (other team) |
|---|---|
| rule → control mapping | control text, summaries, references |
| mapping status and provenance | retrieval, citation, explanation |
| coverage arithmetic | regulatory interpretation |
| **a technical claim** | **knowledge** |

The shared vocabulary is exactly three fields — `framework`, `version`,
`control_id` — used as **reference keys**.

**A corpus entry never creates a mapping here.** Knowing that
`DNSSI-ACC` exists and is called "Access management" is knowledge; that
*rule X technically assesses it* is a different claim, and only the
second is the Platform's to make. Promoting a mapping to `verified`
because a corpus row exists would be exactly the fabrication the whole
catalog exists to prevent.

The corpus does **not** currently exist in this repository. That is
precisely why the boundary is enforced by test now — when it lands, the
shared keys will make the shortcut tempting, and by then the temptation
is concrete:

```python
# tests/unit/domain/test_compliance_catalog.py
def test_the_catalog_module_can_read_nothing(self):
    # AST, not grep: the module's docstring discusses the corpus at
    # length. What matters is that the CODE imports no json, pathlib,
    # os, io, csv, yaml or requests, and calls no open().
```

The catalog is built from `Rule` objects and nothing else. It *cannot*
read a corpus file even by accident.

### Deliberate consequence: no control titles

`Control.title` exists and is always `None`. Regulatory text is the
corpus's domain; reproducing it here would fork it, and typing titles
from memory would be inventing official language. The field is there so
a future integration can populate it from an authoritative source.

---

## 3. The hierarchy

```
Framework            iso_27001 · cis_aws · cis_azure · nist_800_53
   ↓
Version              2022 · unversioned
   ↓
Control              A.8.24 · 2.1.5 · AC-3
   ↓
CatalogEntry         rule → control, with status + provenance
   ↓
Finding              framework + control_id (references, not copies)
   ↓
ComplianceScore      ScoreScope.FRAMEWORK
```

### Versions, and why most say `unversioned`

A mapping without a version is not auditable: CIS AWS Foundations v1.4.0
and v3.0.0 renumber controls, so `cis_aws 1.20` names different
requirements depending on an edition nobody recorded.

Only `iso_27001` carries a version — **2022** — and it is an
**inference**, recorded as such in the source: the rule catalog's control
ids use the `A.5.x`/`A.8.x` structure, which is unambiguously the 2022
revision, because the 2013 revision numbered Annex A `A.5`–`A.18`
differently.

Everything else is `UNVERSIONED`, a spelled-out sentinel rather than
`None` so it survives sorting and renders as a visible fact. Guessing a
CIS edition from control numbering would be fabrication.

---

## 4. Many-to-many

Not theoretical — the shipped catalog exercises it. `s3-bucket-public`:

```
s3-bucket-public
  ├── iso_27001@2022:A.8.24          (primary)
  ├── cis_aws@unversioned:2.1.5      (secondary)
  └── nist_800_53@unversioned:AC-3   (secondary)
```

and in the other direction, `iso_27001@2022:A.8.24` is evidenced by
**18** rules.

Measured: **26 of 68** rules map to more than one framework; 95 mappings
across 31 controls.

The model reuses what already existed rather than replacing it:

| Direction | Type | Since |
|---|---|---|
| rule → controls | `Rule.framework_mappings` (`FrameworkMapping`) | Phase 3B |
| control → rules | `Control.rule_ids` | STEP 7 |

`Rule.framework`/`control_id` stay **singular and required**. They feed
`Finding.framework`/`control_id`, which are part of the frozen
`AiFindingContract` — a received external contract, not ours to reshape.

---

## 5. Statuses and provenance

```
VERIFIED     authoritative evidence supports it — REQUIRES provenance
PROPOSED     a deliberate technical proposal, not authoritative
UNRESOLVED   plausible, but nobody established it
```

`proposed` was added in STEP 7. Before it, `unresolved` absorbed two
different statements — *"we think so but nobody checked"* and *"this is a
deliberate proposal"* — which an auditor treats differently.

### `verified` requires provenance, and what that cost

Enforced in two places: `FrameworkMapping.__post_init__` and
`CatalogEntry.__post_init__`, because an entry is constructible from
sources other than a `Rule`.

The audit found **11 mappings claiming `verified`** while the word
`provenance` appeared nowhere in the model. They were **downgraded to
`unresolved`**, not grandfathered — grandfathering would have preserved
exactly the unfalsifiable claim the field exists to prevent.

Each downgraded mapping records what is actually known, as a *rationale*
rather than provenance:

> Control numbering is consistent with CIS AWS Foundations Benchmark
> v1.5.0 or later (networking moved to section 5). That is an inference
> from the numbering, not a verification against the published benchmark
> text, so this mapping stays unresolved until a maintainer checks it and
> records provenance.

**This lowered reported coverage to 0%.** That is the correct direction
when the evidence does not exist.

### The primary mapping is never auto-verified

Every rule *must* fill in `framework`/`control_id`, so its presence
proves a maintainer typed something — not that anyone checked it against
the standard. Treating a required field as evidence would hand the
product 100% coverage for free. Pinned by
`test_the_primary_mapping_is_never_auto_verified`.

---

## 6. Coverage

```
coverage = controls with ≥ 1 VERIFIED mapping
           / controls represented in the Platform Catalog
```

One definition, documented once, computed in one place
(`FrameworkCoverage.coverage`).

**The denominator is controls** — not rules, not findings. 68 rules
pointing at 7 controls is *7 controls* of coverage. Counting rules would
let coverage rise by adding rules that assess something already assessed.

**Only `verified` counts.** Including `unresolved` would let the number
rise by asserting things nobody checked, which is how a compliance
product ends up selling coverage it cannot defend. A 0% is honest and
actionable; an inflated 80% is neither.

Current state, computed:

| Framework | Version | Controls | Verified | Coverage |
|---|---|---:|---:|---:|
| `iso_27001` | 2022 | 7 | 0 | 0.0% |
| `cis_aws` | unversioned | 14 | 0 | 0.0% |
| `cis_azure` | unversioned | 9 | 0 | 0.0% |
| `nist_800_53` | unversioned | 1 | 0 | 0.0% |

### Product tiers, including the zeros

| Tier | Framework | Present |
|---|---|---|
| 1 | ISO/IEC 27001:2022 | ✅ |
| 1 | **DNSSI** | ❌ absent |
| 1 | **Loi 05-20** | ❌ absent |
| 2 | **NIST CSF** | ❌ absent |
| 3 | **SOC 2** | ❌ absent |

The absent rows are reported rather than omitted: a matrix that leaves
them out reads as *not asked*, when the truth is *asked, and the answer
is zero*.

**On NIST.** The catalog contains `nist_800_53`, which is **not** the
NIST Cybersecurity Framework. Different documents, different structures
(`AC-3` versus `PR.AC-4`). Counting one as the other would be a
fabricated coverage claim, so the tier table reports NIST CSF absent
while `nist_800_53` keeps its own row.

---

## 7. Validation

| Check | Behaviour |
|---|---|
| Framework/control referenced by a mapping | Exists by construction — the catalog is built *from* the mappings |
| `verified` without provenance | **Raises** at rule load |
| Duplicate `(rule, framework, version, control)` | **Reported** in `catalog.duplicates`, and deduplicated so arithmetic stays correct |
| Same control in two versions | **Not** a duplicate — different editions are different controls |
| Rules with no mapping | `catalog.unmapped_rule_ids` |
| Orphan controls | `catalog.orphan_controls()` |

Duplicates are reported rather than raised on purpose: catalog hygiene
is a documentation defect, and aborting rule loading over one would take
the product down for it. An unprovenanced `verified` *does* raise,
because that one is a false compliance claim.

---

## 8. Finding integration

**Validate, do not duplicate.** `Finding` already carries `framework`
and `control_id`; STEP 7 adds no field. A test asserts every shipped
rule's `(framework, control_id)` resolves in the catalog, which is what
makes those strings references rather than free text.

A Finding never embeds a control record. The AI contract stays at
exactly 11 fields.

---

## 9. Score integration

Framework scoring **already exists** and predates this step:
`ScoreScope.FRAMEWORK`, computed per scan, queryable at
`GET /api/v1/scores?scope=framework&scope_value=iso_27001`.

What it scores is `Finding.framework` — the **primary** mapping only.
Secondary mappings contribute to *coverage* but to no score. That is why
`CatalogEntry.primary` exists: without it, a reader would reasonably
assume a `cis_aws` mapping moves a `cis_aws` score, and nothing does.

Wiring secondary mappings into scoring is a deliberate follow-up, not a
gap this step left by accident — it would change what every existing
framework score means.

---

## 10. Security

The catalog is **global shared reference data**, not tenant data.

- No `tenant_id` anywhere in it. It cannot be used to smuggle data
  across a tenant boundary, and no tenant can hold a private version of
  a control.
- Rules load read-only from `rules/**/*.yaml` at startup. There is no
  write path.
- `Finding.framework`/`control_id` are set by the rule engine from the
  rule, never from request input.
- No request body accepts a `framework` or `control_id` — asserted
  structurally.

Before STEP 7 these properties held *incidentally*, because no write
path existed. They are now tested.

---

## 11. End-to-end, with real repository data

```
S3 bucket with public access
        ↓  collector → NormalizedResource(resource_type="s3_bucket",
                                          attributes={"public": True})
        ↓
rules/aws/s3.yaml  ·  s3-bucket-public
        condition: {field: public, operator: equals, value: true}
        severity: critical · domain: storage
        ↓
Finding(rule_id="s3-bucket-public",
        framework="iso_27001", control_id="A.8.24",
        status=FAIL, severity=CRITICAL)
        ↓
Compliance Catalog
   ├── iso_27001@2022:A.8.24        unresolved  (primary)
   ├── cis_aws@unversioned:2.1.5    unresolved
   └── nist_800_53@unversioned:AC-3 unresolved
        ↓
Control iso_27001@2022:A.8.24 ← evidenced by 18 rules
        ↓
Coverage matrix: iso_27001 · 7 controls · 0 verified · 0.0%
```

Every value above is from the repository. The three `unresolved`
statuses are the honest state: the mappings are plausible and nobody has
recorded checking them.

---

## 12. Limitations

1. **Coverage is 0% across every framework.** Nothing carries
   provenance. This is the true state, not a bug.
2. **Three of five product-priority frameworks are absent** — DNSSI, Loi
   05-20, SOC 2 — plus NIST CSF. Adding them means adding rules that
   genuinely assess their controls, not adding rows to a table.
3. **Versions are unrecorded** for every framework but ISO, and ISO's is
   inferred rather than declared.
4. **Secondary mappings do not affect any score** (§9).
5. **No catalog API.** Deliberate: §21 asks for one only if the product
   genuinely needs it, and nothing consumes it yet. The data is
   available through the generated reports.
6. **No persistence.** The catalog is rebuilt from rules on demand. It is
   derived data with a single source of truth, so storing it would
   create a second one.
7. **Control titles are always `None`** (§2).

## 13. What would raise coverage honestly

For each mapping a maintainer intends to claim:

1. Open the published framework text at a specific edition.
2. Confirm the rule's condition actually assesses that control.
3. Record `version`, `provenance` (document and section), and set
   `status: verified`.
4. Regenerate the reports.

That is the only path. There is no shortcut through the corpus, and the
tests are built to keep it that way.
