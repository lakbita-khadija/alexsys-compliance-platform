# Compliance Catalog — Rule → Framework Mapping Matrix

> **Generated from the rule catalog.** Do not edit by hand —
> run `python scripts/generate_compliance_reports.py`.

A cell shows the strongest status that rule holds for that
framework; `—` means no mapping. `VERIFIED` requires provenance,
so a cell can only reach it when a maintainer recorded what the
mapping was checked against.

| Rule | `cis_aws` | `cis_azure` | `iso_27001` | `nist_800_53` |
|---|---|---|---|---|
| `azure-activity-log-administrative-category-disabled` | — | — | UNRESOLVED | — |
| `azure-activity-log-exports-to-publicly-exposed-storage` | — | — | UNRESOLVED | — |
| `azure-activity-log-exports-to-storage-without-soft-delete` | — | — | UNRESOLVED | — |
| `azure-activity-log-no-destination` | — | — | UNRESOLVED | — |
| `azure-activity-log-retention-too-short` | — | UNRESOLVED | UNRESOLVED | — |
| `azure-key-vault-network-default-allow` | — | — | UNRESOLVED | — |
| `azure-key-vault-public-network-access-enabled` | — | — | UNRESOLVED | — |
| `azure-key-vault-purge-protection-disabled` | — | UNRESOLVED | UNRESOLVED | — |
| `azure-key-vault-rbac-authorization-disabled` | — | — | UNRESOLVED | — |
| `azure-key-vault-soft-delete-disabled` | — | UNRESOLVED | UNRESOLVED | — |
| `azure-nsg-mysql-open-to-internet` | — | — | UNRESOLVED | — |
| `azure-nsg-postgres-open-to-internet` | — | — | UNRESOLVED | — |
| `azure-nsg-rdp-open-to-internet` | — | UNRESOLVED | UNRESOLVED | — |
| `azure-nsg-sql-open-to-internet` | — | — | UNRESOLVED | — |
| `azure-nsg-ssh-open-to-internet` | — | UNRESOLVED | UNRESOLVED | — |
| `azure-nsg-unrestricted-ingress-any-port` | — | — | UNRESOLVED | — |
| `azure-nsg-winrm-open-to-internet` | — | — | UNRESOLVED | — |
| `azure-privileged-role-assigned-at-subscription-scope` | — | UNRESOLVED | UNRESOLVED | — |
| `azure-storage-account-allows-blob-public-access` | — | UNRESOLVED | UNRESOLVED | — |
| `azure-storage-account-blob-soft-delete-disabled` | — | — | UNRESOLVED | — |
| `azure-storage-account-https-not-enforced` | — | UNRESOLVED | UNRESOLVED | — |
| `azure-storage-account-infrastructure-encryption-disabled` | — | — | UNRESOLVED | — |
| `azure-storage-account-network-default-allow` | — | UNRESOLVED | UNRESOLVED | — |
| `azure-storage-account-publicly-reachable` | — | — | UNRESOLVED | — |
| `azure-storage-account-weak-tls-version` | — | UNRESOLVED | UNRESOLVED | — |
| `azure-vm-attached-to-open-network-security-group` | — | — | UNRESOLVED | — |
| `azure-vm-no-managed-identity` | — | — | UNRESOLVED | — |
| `azure-vm-public-ip-assigned` | — | — | UNRESOLVED | — |
| `cloudtrail-log-validation-disabled` | UNRESOLVED | — | UNRESOLVED | — |
| `cloudtrail-logging-disabled` | — | — | UNRESOLVED | — |
| `cloudtrail-logs-to-non-versioned-bucket` | — | — | UNRESOLVED | — |
| `cloudtrail-logs-to-public-bucket` | — | — | UNRESOLVED | — |
| `cloudtrail-not-encrypted-with-kms` | — | — | UNRESOLVED | — |
| `cloudtrail-not-multi-region` | UNRESOLVED | — | UNRESOLVED | — |
| `ec2-instance-attached-to-open-security-group` | — | — | UNRESOLVED | — |
| `ec2-instance-imds-v1-allowed` | UNRESOLVED | — | UNRESOLVED | — |
| `ec2-instance-in-internet-routed-subnet-with-public-ip` | UNRESOLVED | — | UNRESOLVED | — |
| `ec2-instance-no-iam-instance-profile` | — | — | UNRESOLVED | — |
| `ec2-instance-public-ip-assigned` | — | — | UNRESOLVED | — |
| `ec2-instance-root-volume-not-encrypted` | UNRESOLVED | — | UNRESOLVED | — |
| `iam-account-password-max-age-too-long` | — | — | UNRESOLVED | — |
| `iam-account-password-policy-missing` | UNRESOLVED | — | UNRESOLVED | — |
| `iam-account-password-policy-no-numbers-required` | — | — | UNRESOLVED | — |
| `iam-account-password-policy-no-symbols-required` | — | — | UNRESOLVED | — |
| `iam-account-password-policy-too-short` | UNRESOLVED | — | UNRESOLVED | — |
| `iam-root-account-mfa-disabled` | UNRESOLVED | — | UNRESOLVED | — |
| `iam-user-access-key-without-mfa` | — | — | UNRESOLVED | — |
| `iam-user-full-admin-policy-attached` | UNRESOLVED | — | UNRESOLVED | — |
| `iam-user-mfa-disabled` | UNRESOLVED | — | UNRESOLVED | — |
| `iam-user-multiple-active-access-keys` | — | — | UNRESOLVED | — |
| `kms-key-not-customer-managed` | — | — | UNRESOLVED | — |
| `kms-key-pending-deletion` | — | — | UNRESOLVED | — |
| `kms-key-policy-allows-public-access` | — | — | UNRESOLVED | — |
| `kms-key-rotation-disabled` | UNRESOLVED | — | UNRESOLVED | — |
| `nacl-allows-unrestricted-ingress` | UNRESOLVED | — | UNRESOLVED | — |
| `rds-automated-backups-disabled` | UNRESOLVED | — | UNRESOLVED | — |
| `rds-public-endpoint-configured` | UNRESOLVED | — | UNRESOLVED | — |
| `rds-reachable-from-internet` | UNRESOLVED | — | UNRESOLVED | — |
| `rds-storage-not-encrypted` | UNRESOLVED | — | UNRESOLVED | — |
| `route-table-has-internet-route` | UNRESOLVED | — | UNRESOLVED | — |
| `s3-bucket-encryption-and-versioning-both-disabled` | — | — | UNRESOLVED | — |
| `s3-bucket-logging-disabled` | — | — | UNRESOLVED | — |
| `s3-bucket-not-encrypted` | UNRESOLVED | — | UNRESOLVED | — |
| `s3-bucket-policy-allows-public-access` | UNRESOLVED | — | UNRESOLVED | — |
| `s3-bucket-public` | UNRESOLVED | — | UNRESOLVED | UNRESOLVED |
| `s3-bucket-public-access-block-disabled` | UNRESOLVED | — | UNRESOLVED | — |
| `s3-bucket-publicly-exposed` | — | — | UNRESOLVED | — |
| `s3-bucket-versioning-disabled` | UNRESOLVED | — | UNRESOLVED | — |
| `security-group-allows-another-open-security-group` | — | — | UNRESOLVED | — |
| `security-group-ftp-open-to-world` | — | — | UNRESOLVED | — |
| `security-group-mysql-open-to-world` | — | — | UNRESOLVED | — |
| `security-group-postgres-open-to-world` | — | — | UNRESOLVED | — |
| `security-group-rdp-open-to-world` | UNRESOLVED | — | UNRESOLVED | — |
| `security-group-ssh-open-to-world` | UNRESOLVED | — | UNRESOLVED | — |
| `security-group-telnet-open-to-world` | — | — | UNRESOLVED | — |
| `security-group-unrestricted-ingress-any-port` | — | — | UNRESOLVED | — |
| `subnet-auto-assigns-public-ip-with-internet-route` | UNRESOLVED | — | UNRESOLVED | — |

## Gaps this matrix reveals

- **Rules with no mapping at all:** 0
- **Rules covering more than one framework:** 35
- **Rules with only their primary (ISO) mapping:** 42

The last figure is the honest read of this matrix: every rule has
an ISO reference because the field is required, and fewer than half
carry a second framework. A single-framework rule is not a defect —
it is a coverage gap, and naming it is the point of generating this
table rather than asserting a number.
