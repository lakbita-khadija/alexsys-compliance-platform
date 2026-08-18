# Compliance Catalog — Coverage

> **Generated from the rule catalog.** Do not edit by hand —
> run `python scripts/generate_compliance_reports.py`. Every number
> below is computed from `rules/**/*.yaml`; none is typed.

## Coverage metric

```
coverage = controls with >= 1 VERIFIED mapping
           / controls represented in the Platform Catalog
```

Deliberately strict, and worth stating why. Counting `unresolved`
mappings would let the number rise by asserting things nobody
checked — which is how a compliance product ends up selling
coverage it cannot defend in an audit. A 0% here is honest and
actionable; an inflated 80% is neither.

Note the denominator: **controls**, not rules and not findings.
Sixty-eight rules mapping to seven controls is seven controls of
coverage, not sixty-eight.

## Frameworks referenced by the rule catalog

| Framework | Version | Controls | Verified | Unresolved | Proposed | Rules mapped | Coverage |
|---|---|---:|---:|---:|---:|---:|---:|
| `cis_aws` | unversioned | 18 | 0 | 25 | 0 | 25 | 0.0% |
| `cis_azure` | unversioned | 10 | 0 | 10 | 0 | 10 | 0.0% |
| `iso_27001` | 2022 | 8 | 0 | 77 | 0 | 77 | 0.0% |
| `nist_800_53` | unversioned | 1 | 0 | 1 | 0 | 1 | 0.0% |

## Product framework priority

The tiers as asked for, including the ones with no coverage — a
matrix that omitted them would read as *not asked* rather than
*asked, answer zero*.

| Tier | Framework | Present in Platform | Controls | Coverage |
|---|---|---|---:|---:|
| Tier 1 | ISO/IEC 27001:2022 | ✅ `iso_27001` | 8 | 0.0% |
| Tier 1 | DNSSI | ❌ **absent** | 0 | 0% |
| Tier 1 | Loi 05-20 | ❌ **absent** | 0 | 0% |
| Tier 2 | NIST CSF | ❌ **absent** | 0 | 0% |
| Tier 3 | SOC 2 | ❌ **absent** | 0 | 0% |

**On NIST.** The catalog contains `nist_800_53`, which is **not**
the NIST Cybersecurity Framework. NIST SP 800-53 and NIST CSF are
different documents with different structures (`AC-3` versus
`PR.AC-4`). Counting one as the other would be a fabricated
coverage claim, so the tier table above reports NIST CSF as absent
while the framework table reports `nist_800_53` on its own row.

## Catalog totals

- Rules in catalog: **77**
- Mappings (rule → control): **113**
- Distinct controls: **37**
- Distinct (framework, version) pairs: **4**
- Rules mapping to more than one framework: **35**
- Rules with no mapping at all: **0**
- Orphan controls (no rule): **0**
- Duplicate mappings: **0**

## Frameworks

| Id | Name | Version | Jurisdiction | Authority |
|---|---|---|---|---|
| `cis_aws` | CIS Amazon Web Services Foundations Benchmark | unversioned | International | Center for Internet Security |
| `cis_azure` | CIS Microsoft Azure Foundations Benchmark | unversioned | International | Center for Internet Security |
| `iso_27001` | ISO/IEC 27001 | 2022 | International | ISO/IEC |
| `nist_800_53` | NIST SP 800-53 | unversioned | United States | NIST |

## Controls and the rules that assess them

| Framework | Version | Control | Rules |
|---|---|---|---:|
| `cis_aws` | unversioned | `1.10` | 1 |
| `cis_aws` | unversioned | `1.16` | 1 |
| `cis_aws` | unversioned | `1.5` | 1 |
| `cis_aws` | unversioned | `1.8` | 2 |
| `cis_aws` | unversioned | `2.1.1` | 1 |
| `cis_aws` | unversioned | `2.1.3` | 1 |
| `cis_aws` | unversioned | `2.1.5` | 3 |
| `cis_aws` | unversioned | `2.2.1` | 1 |
| `cis_aws` | unversioned | `2.3.1` | 1 |
| `cis_aws` | unversioned | `2.3.2` | 1 |
| `cis_aws` | unversioned | `2.3.3` | 2 |
| `cis_aws` | unversioned | `3.1` | 1 |
| `cis_aws` | unversioned | `3.2` | 1 |
| `cis_aws` | unversioned | `3.8` | 1 |
| `cis_aws` | unversioned | `5.1` | 4 |
| `cis_aws` | unversioned | `5.2` | 1 |
| `cis_aws` | unversioned | `5.3` | 1 |
| `cis_aws` | unversioned | `5.6` | 1 |
| `cis_azure` | unversioned | `1.23` | 1 |
| `cis_azure` | unversioned | `3.1` | 1 |
| `cis_azure` | unversioned | `3.15` | 1 |
| `cis_azure` | unversioned | `3.7` | 1 |
| `cis_azure` | unversioned | `3.8` | 1 |
| `cis_azure` | unversioned | `5.1.2` | 1 |
| `cis_azure` | unversioned | `6.1` | 1 |
| `cis_azure` | unversioned | `6.2` | 1 |
| `cis_azure` | unversioned | `8.4` | 1 |
| `cis_azure` | unversioned | `8.5` | 1 |
| `iso_27001` | 2022 | `A.5.15` | 4 |
| `iso_27001` | 2022 | `A.5.17` | 8 |
| `iso_27001` | 2022 | `A.8.13` | 8 |
| `iso_27001` | 2022 | `A.8.15` | 7 |
| `iso_27001` | 2022 | `A.8.2` | 1 |
| `iso_27001` | 2022 | `A.8.20` | 29 |
| `iso_27001` | 2022 | `A.8.24` | 19 |
| `iso_27001` | 2022 | `A.8.5` | 1 |
| `nist_800_53` | unversioned | `AC-3` | 1 |
