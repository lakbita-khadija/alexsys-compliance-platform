# Scan contract

## Submission is asynchronous

```
POST /api/v1/scans        →  202 Accepted
{"provider": "aws", "account_id": "111111111111"}
{"scan_key": "…", "status": "queued", "tenant_id": "acme", "submitted_at": "…"}
```

**The scan has not run when this returns.** A real scan is hundreds of
throttled cloud API calls; a synchronous endpoint would hold the
connection open for minutes and time out behind any load balancer.

The response deliberately contains no findings — that would imply
completion.

Requires the **`scanner`** role, separate from `reader`: triggering a
scan spends money and calls real cloud APIs.

There is no `tenant_id` in the body. Sending one is a 422, not a silently
ignored field.

## Polling

`GET /api/v1/scans/{scan_key}` until `status` is terminal.

| Status | Terminal | Meaning |
|---|---|---|
| `queued` | no | Accepted, not started |
| `running` | no | In progress |
| `completed` | yes | Everything enumerated and evaluated |
| `partial` | yes | **Ran, but could not enumerate everything** |
| `failed` | yes | Did not produce usable results |
| `cancelled` | yes | Stopped before completion |

## `partial` is not success

It means a service could not be enumerated — typically a permission
denial. Anything that service would have covered was **not verified**.

Reporting it as completed would tell an auditor that the unreachable
service was checked and found compliant. Check `errors[]`, and never
present a partial scan as a clean bill of health.

## Conflicts

Scan keys are deterministic — the same target at the same instant derives
the same key. A duplicate submission while one is still running returns
**409**, rather than starting a second concurrent scan of the same
account.

## Known limitation

In the default production profile, submission returns **503** until an
operator configures a cloud credentials reference and rule catalog path.
The pipeline is implemented and tested; its configuration is
deployment-specific.
