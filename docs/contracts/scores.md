# Compliance score contract

```json
{
  "tenant_id": "acme",
  "scope": "framework",
  "scope_value": "iso_27001",
  "score": 82.35,
  "coverage": 94.12,
  "counts": {"passed": 14, "failed": 3, "indeterminate": 1,
             "critical": 1, "high": 1, "medium": 1, "low": 0},
  "computed_at": "2026-06-01T12:00:00+00:00",
  "scan_key": "…"
}
```

## Scopes

| `scope` | `scope_value` | Meaning |
|---|---|---|
| `tenant` | `null` | Everything known for the tenant |
| `framework` | framework id | One compliance framework |
| `domain` | domain name | One risk domain |
| `scan` | scan key | One scan execution |

`tenant` is the only scope whose `scope_value` is null — the tenant is
already identified. Every other scope requires one: a framework score
that does not say which framework is a number, not a score.

## `score` can be `null`

`null` means **nothing determinate was evaluated** in that scope.

Render it as "no data". Coercing it to 0 or 100 states something false
about the tenant's posture in one direction or the other.

## `score` excludes INDETERMINATE

```
score = 100 × passed / (passed + failed)
```

Indeterminate checks are excluded from the denominator, never counted as
passes. An averaging formula that rounded unknowns up to compliant would
reintroduce hidden compliance one layer above the rule engine.

## Always read `coverage` alongside it

```
coverage = 100 × (passed + failed) / (passed + failed + indeterminate)
```

A 100% score computed over 4 determinate checks out of 900 is not a good
posture — it is an absent one, and only `coverage` reveals that.

## `counts` is stored, not derived on read

A bare "73.5%" is unfalsifiable. "203 passed, 73 failed, 12 could not be
evaluated" can be checked against the findings themselves, which is what
makes the number auditable — and lets a client render a breakdown without
another request.

## Scores are immutable

Computed once when a scan completes. Re-scoring the same scan replaces
the row by identity (idempotent retry); a new scan writes new rows. Last
quarter's score never silently changes.

## Dashboard queries

| Need | Query |
|---|---|
| Current posture | `/scores/current?scope=tenant` |
| By framework | `/scores?scope=framework` |
| By domain | `/scores?scope=domain` |
| Evolution | `/scores?scope=framework&scope_value=iso_27001&computed_after=…` |
| Scan comparison | two `/scores?scan_key=…` calls |
