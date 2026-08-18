# Authentication Test Matrix

> Legend: `PASS` · `PARTIAL` · `NOT TESTED` · `LIVE VERIFICATION REQUIRED`
>
> **`LIVE PASS` is never claimed.** No cloud authentication code in this
> repository has executed against a real AWS account or Azure
> subscription. Every cloud row's live column reads
> `LIVE VERIFICATION REQUIRED` for that reason and no other.
>
> Suite at time of writing: **1644 passed, 60 skipped, 0 failed.**
> The 60 skips are the opt-in AWS and Azure integration suites.

---

## Scenario matrix

| Scenario | AWS | Azure | Local Test | Live Test |
|---|---|---|---|---|
| Correct credentials | PASS | PASS | PASS | LIVE VERIFICATION REQUIRED |
| Invalid credentials | PASS | PASS | PASS | LIVE VERIFICATION REQUIRED |
| Missing credentials | PASS | PASS | PASS | LIVE VERIFICATION REQUIRED |
| Expired credentials | PASS | PASS | PASS | LIVE VERIFICATION REQUIRED |
| **Wrong tenant/account** | PASS | PASS | PASS | LIVE VERIFICATION REQUIRED |
| **Wrong subscription** | n/a | PASS | PASS | LIVE VERIFICATION REQUIRED |
| **Wrong Entra directory** | n/a | PASS | PASS | LIVE VERIFICATION REQUIRED |
| Missing account binding | PASS | PASS | PASS | n/a — config only |
| Malformed identity response | PASS | PASS | PASS | LIVE VERIFICATION REQUIRED |
| Identity call fails (STS / token) | PASS | PASS | PASS | LIVE VERIFICATION REQUIRED |
| AccessDenied on a resource → UNKNOWN | PASS | PASS | PASS | LIVE VERIFICATION REQUIRED |
| Token expiry mid-scan | NOT TESTED | PARTIAL | NOT TESTED | LIVE VERIFICATION REQUIRED |
| Throttling | PARTIAL | NOT TESTED | PARTIAL | LIVE VERIFICATION REQUIRED |
| AssumeRole + ExternalId | PASS | n/a | PASS | LIVE VERIFICATION REQUIRED |
| Audit event emitted | PASS | PASS | PASS | n/a — local behaviour |
| Secret redaction | PASS | PASS | PASS | PARTIAL — see note 3 |
| Cross-tenant binding isolation | PASS | PASS | PASS | n/a |
| Collector unreached on rejection | PASS | PASS | PASS | n/a |

### Notes

1. **Token expiry mid-scan (AWS) is genuinely NOT TESTED.** Assumed-role
   sessions are minted once per scan and never refreshed; a scan longer
   than the session lifetime will fail partway with a non-retryable
   error. Open P1, unchanged by STEP 6.5.
2. **Throttling (Azure) is NOT TESTED.** `resilience.py` is AWS-shaped
   and is not applied to the Azure path. Open P1.
3. **Secret redaction live column is PARTIAL** because the one open
   question — whether real Azure SDK error text can carry a credential —
   needs a real 403/429 to answer. The gate already records exception
   *types* rather than messages, so the exposure is bounded regardless.

---

## Component coverage

| Component | Code | Unit | Integration | Security | Local status |
|---|---|---|---|---|---|
| `CloudAccountBinding` | YES | YES (25) | n/a | YES | PASS |
| `verify_cloud_identity` | YES | YES (25) | n/a | YES | PASS |
| `VerifyCloudIdentity` gate | YES | YES (23) | n/a | YES | PASS |
| `AwsIdentityProvider` | YES | YES (17) | opt-in, skipped | YES | PASS |
| `AzureIdentityProvider` | YES | YES (18) | opt-in, skipped | YES | PASS |
| `StaticCloudAccountDirectory` | YES | YES | n/a | YES | PASS |
| `EnvCloudAccountDirectory` | YES | YES | n/a | YES | PASS |
| `external_id` on AssumeRole | YES | YES (11) | opt-in, skipped | YES | PASS |
| Gate inside `ScanCloudAccount` (AWS) | YES | YES (11) | n/a | YES | PASS |
| Gate inside `ScanCloudAccount` (Azure) | YES | YES (12) | n/a | YES | PASS |
| `AUTHENTICATION_FAILED` emission | YES | YES | n/a | YES | PASS |
| `AUTHORIZATION_FAILED` emission | **NO** | — | — | — | **NOT IMPLEMENTED** |
| `TENANT_ISOLATION_VIOLATION` emission | **NO** | — | — | — | **NOT IMPLEMENTED** |
| JWT verification | YES | via API suite | YES | YES (32) | PASS |
| JWT issuance | YES | via API suite | YES | PARTIAL | PARTIAL |
| RBAC | YES | via API suite | YES | YES | PARTIAL |
| Tenant isolation (API→DB) | YES | YES | YES (real DB) | YES | PASS |
| Secret redaction | YES | YES | YES (real DB) | YES | PASS |

**New in STEP 6.5: 132 tests**, across six files:

| File | Tests |
|---|---|
| `tests/unit/domain/test_cloud_account_binding.py` | 25 |
| `tests/unit/application/test_verify_cloud_identity.py` | 23 |
| `tests/unit/application/test_scan_identity_gate.py` | 11 |
| `tests/unit/application/test_azure_identity_gate.py` | 12 |
| `tests/unit/infrastructure/test_cloud_identity_providers.py` | 35 |
| `tests/unit/infrastructure/test_external_id_and_directory.py` | 26 |

---

## The semantic distinction, tested in both directions

| Situation | Required outcome | Test |
|---|---|---|
| `expected 111111111111`, `actual 222222222222` | **SCAN REJECTED**, collector never called | `test_nothing_is_collected` |
| Correct account, `DescribeSecurityGroups → AccessDenied` | attribute = `UNKNOWN`, scan continues | `test_unknown_attributes_do_not_stop_a_correctly_authenticated_scan` |
| Wrong account | must **not** degrade to `UNKNOWN` | `test_a_wrong_account_is_not_degraded_to_unknown` |
| Correct directory, denied resource (Azure) | `UNKNOWN`, scan continues | `test_access_denied_on_a_resource_does_not_reject_the_scan` |

Both directions are pinned because either reversal is a serious defect:
treating a denied API call as an identity failure would abort scans over
a single unreadable security group, and treating an identity failure as
resource uncertainty would silently collect the wrong estate.

---

## Security regressions — all still passing, none weakened

| Test | Status |
|---|---|
| JWT `alg=none` | PASS |
| JWT RS256→HS256 confusion | PASS |
| Wrong issuer / wrong audience | PASS |
| Expired token | PASS |
| Missing / blank `tenant_id` | PASS |
| Foreign-tenant finding → 404 | PASS |
| Foreign-tenant attack path → 404 | PASS |
| Graph tenant isolation | PASS |
| Only one module imports `jwt` | PASS — and it **caught a real design smell** during this step |
| No route declares a `tenant_id` parameter | PASS |
| Every non-unique index leads with `tenant_id` | PASS |

The architecture test is worth singling out. A first draft of
`AzureIdentityProvider` used PyJWT to read the `tid` claim; the test
failed, correctly. Rather than widen the rule, the adapter was rewritten
to decode base64 directly — which is better, because it makes "we are not
verifying" structural instead of a comment.
