# Pagination contract

Every list endpoint returns the same envelope:

```json
{ "items": [...], "total": 1284, "limit": 50, "offset": 0, "has_more": true }
```

| Field | Meaning |
|---|---|
| `items` | This page only |
| `total` | Everything matching the filter, across all pages |
| `limit` | Page size actually applied |
| `offset` | Zero-based index of the first item |
| `has_more` | Whether further pages exist |

## Bounds

- `limit` default **50**, maximum **100**, minimum 1
- `offset` minimum 0

Exceeding the maximum is a **422, not a silent clamp**. A client asking
for 1000 should learn it cannot have it, rather than believing it
received everything when it received 100.

## Ordering is deterministic

Sort orders are a closed enum (`detected_at_desc`, `detected_at_asc`,
`severity_desc`) — arbitrary sort fields are both an injection surface
and a performance trap. Every order ends with a **unique tiebreaker**.

Without one, rows sharing a timestamp can be returned in a different
order on each query, so a row appears on two pages or none. That bug is
invisible in small datasets and corrupts every export in large ones.
Tested with fixtures that deliberately share `detected_at`.

## The AI contract view

`GET /api/v1/findings/ai-contract` omits findings the 11-field contract
cannot represent (INDETERMINATE, or a framework/domain outside its closed
vocabulary). `total` still reflects the unfiltered match count, so
`len(items)` may be smaller than `limit`.

**Page until `items` is empty** rather than computing page count from
`total`.

## Offset vs cursor

Offset paging, matching the required contract. Its known weakness — a row
inserted during traversal shifts later pages — is mitigated by
deterministic ordering. Cursor paging can be added later as an additive
alternative without changing this shape.
