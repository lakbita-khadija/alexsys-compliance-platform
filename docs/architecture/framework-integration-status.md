# Framework Integration — Status Audit

> **Documentation only.** No framework reference, control ID, mapping or
> status was added, removed or changed while producing this document.
> Every number below came from parsing `rules/**/*.yaml` and reading the
> domain model, not from a previous report.
>
> Per the task brief §20: this exists so the Attack Path work does not
> silently entangle itself with framework ownership. It records the
> boundary; it does not move it.

---

## 1. What exists

### Two independent mechanisms

**1. Primary attribution — every rule has exactly one.**

```yaml
framework: iso_27001
control_id: A.8.20
```

Required by `Rule`, present on all **68** rules.

**2. Secondary mappings — optional, many per rule.**

```python
FrameworkMapping(framework: str, control: str, status: str = "unresolved")
```

`status` ∈ {`verified`, `unresolved`}, defaulting to `unresolved`. The
default is deliberate and documented in the model: *"fabricating an
unverified control mapping is the single fastest way to lose credibility
with an actual auditor."*

### A third mechanism exists and is unused

`domain/compliance/models.py` defines `ComplianceFramework`,
`ControlMapping` and `ComplianceAssessment`. **Nothing outside that module
and its own tests references them.** The rule catalog uses plain strings,
not these types. This is a real structural gap, but it belongs to the
framework owner, not to this task.

---

## 2. Frameworks in use

| Framework | Role | Rules |
|---|---|---|
| `iso_27001` | **Primary on all 68 rules** | 68 |
| `cis_aws` | Secondary mapping | 17 |
| `cis_azure` | Secondary mapping | 9 |
| `nist_800_53` | Secondary mapping | 1 |

No framework catalog module exists — these four identifiers are
conventions carried in YAML strings, with no central registry validating
them. A typo (`iso27001`) would load without complaint.

---

## 3. Control IDs

### Primary (ISO 27001) — 7 distinct controls across 68 rules

| Control | Rules |
|---|---|
| `A.8.20` | 23 |
| `A.8.24` | 18 |
| `A.5.17` | 8 |
| `A.8.13` | 7 |
| `A.8.15` | 7 |
| `A.5.15` | 4 |
| `A.8.5` | 1 |

The concentration is worth noting for the owner: two controls carry 60%
of the catalog. Whether that reflects ISO's actual structure or an
under-differentiated mapping is a framework question, not one this audit
can answer.

### Secondary mapping status — 27 mappings, 11 verified

| Framework | verified | unresolved (defaulted) |
|---|---|---|
| `cis_aws` | 11 | 6 |
| `cis_azure` | 0 | 9 |
| `nist_800_53` | 0 | 1 |
| **Total** | **11** | **16** |

**All 16 unresolved mappings omit `status` entirely** and inherit the
`"unresolved"` default. None was explicitly marked unresolved. The
system is behaving exactly as designed — the default is doing its job.

**Every `cis_azure` mapping is unverified.** Azure framework attribution
currently rests on no checked source.

---

## 4. Ownership boundaries

| Area | Owner | This task |
|---|---|---|
| Which framework a rule attributes to | Framework owner | Do not touch |
| Control IDs | Framework owner | Do not invent, rename or reassign |
| `status` verified/unresolved | Framework owner | Do not promote to `verified` |
| `FrameworkMapping` model shape | Domain | Unchanged |
| Attack path severity | **This task** | Uses `Severity`, not framework controls |

**Attack paths deliberately carry no framework mapping.** An attack path
is a composite graph observation, not a control assessment. Attributing
one to an ISO control would be inventing a mapping — precisely what the
`"unresolved"` default exists to prevent. If a framework owner later
decides attack paths map to a control, that is their call to make with
published text in hand.

---

## 5. Observations for the framework owner

Findings, not instructions — no action was taken on any of them.

1. **No framework registry.** Identifiers are unvalidated strings; a typo
   silently produces a new framework.
2. **`ComplianceFramework`/`ControlMapping` are orphaned.** A typed model
   exists and the catalog does not use it.
3. **16 of 27 secondary mappings are unverified**, including 100% of
   Azure. Resolving them requires the published benchmark text.
4. **Seven ISO controls for 68 rules**, with 41 rules on two controls.
5. **`ComplianceScore`** (`domain/compliance/scoring.py`) computes posture
   from findings and is **independent of this catalog** — it scores by
   framework string, so an unresolved mapping does not corrupt it.

---

## 6. Conclusion

The framework layer is **coherent and honest within its limits**: one
primary attribution per rule, secondary mappings that default to
unverified rather than claiming accuracy they lack, and a domain model
whose docstring states the anti-fabrication rationale.

Its gaps — no registry, an orphaned typed model, 16 unresolved mappings —
are **real but not blocking**, and none of them affects Attack Path
analysis, which uses `Severity` and graph evidence rather than framework
controls.

**No framework change is required by, or was made during, the Attack Path
work.**
