#!/usr/bin/env python3
"""Development/test scan runner — NOT the ComplianceIQ product CLI or
API.

Presentation (blueprint §4/§5, FUTURE) does not exist yet. This script
exists solely so Phase 3 can be exercised end-to-end against a real AWS
account from a terminal, wiring the exact same production components an
eventual CLI or FastAPI endpoint would: ``AwsSessionFactory`` ->
``AwsCollector`` -> ``YamlRuleCatalog`` -> ``ScanCloudAccount``. It is
deliberately thin — argument parsing and printing only, no business
logic — and lives in ``scripts/``, outside every architectural layer
(domain/application/infrastructure), because it is not part of the
product.

Usage:

    python3 scripts/dev_scan_aws.py --tenant-id acme --region us-east-1
    python3 scripts/dev_scan_aws.py --tenant-id acme --region us-east-1 --profile my-aws-profile
    python3 scripts/dev_scan_aws.py --tenant-id acme --region us-east-1 --role-arn arn:aws:iam::123456789012:role/scan-role

AWS credentials are resolved entirely via the normal AWS credential
chain (env vars / profile / assumed role) — nothing here ever accepts
or prints a raw access key or secret.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from application.scanning.dtos import ScanConfiguration  # noqa: E402
from application.scanning.scan_cloud_account import ScanCloudAccount  # noqa: E402
from application.errors import ResourceCollectionError  # noqa: E402
from domain.findings.models import FindingStatus  # noqa: E402
from domain.shared.enums import CloudProvider  # noqa: E402
from domain.shared.identifiers import TenantId  # noqa: E402
from infrastructure.cloud.aws.collector import AwsCollector  # noqa: E402
from infrastructure.cloud.aws.credentials import AwsCredentialConfig  # noqa: E402
from infrastructure.cloud.aws.errors import AwsError  # noqa: E402
from infrastructure.cloud.aws.session import AwsSessionFactory  # noqa: E402
from infrastructure.rules.errors import RuleCatalogError  # noqa: E402
from infrastructure.rules.yaml_rule_catalog import YamlRuleCatalog  # noqa: E402

DEFAULT_RULES_DIR = Path(__file__).resolve().parent.parent / "rules" / "aws"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--tenant-id", required=True, help="ComplianceIQ tenant identifier for this scan.")
    parser.add_argument("--region", required=True, help="AWS region to scan.")
    parser.add_argument("--profile", default=None, help="Named AWS profile (optional; default credential chain otherwise).")
    parser.add_argument("--role-arn", default=None, help="IAM role to assume before scanning (optional).")
    parser.add_argument("--rules-dir", default=str(DEFAULT_RULES_DIR), help=f"Rule catalog directory (default: {DEFAULT_RULES_DIR}).")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    credential_config = AwsCredentialConfig(region=args.region, profile=args.profile, role_arn=args.role_arn)
    session = AwsSessionFactory().create(credential_config)

    tenant_id = TenantId(args.tenant_id)
    collector = AwsCollector(session=session, tenant_id=tenant_id)
    rule_catalog = YamlRuleCatalog(args.rules_dir)

    use_case = ScanCloudAccount(collector=collector, rule_catalog=rule_catalog)

    try:
        result = use_case.run(
            tenant_id=tenant_id,
            provider=CloudProvider.AWS,
            credentials_reference=args.profile or "default-credential-chain",
            scan_configuration=ScanConfiguration(),
            scanned_at=datetime.now(timezone.utc),
        )
    except ResourceCollectionError as exc:
        print(f"Scan failed: resource collection error: {exc}", file=sys.stderr)
        if isinstance(exc.__cause__, AwsError):
            print(f"  caused by: {type(exc.__cause__).__name__}: {exc.__cause__}", file=sys.stderr)
        return 1
    except RuleCatalogError as exc:
        print(f"Scan failed: rule catalog error: {exc}", file=sys.stderr)
        return 1

    _print_summary(result)
    return 0


def _print_summary(result) -> None:
    print(f"Scan {result.scan_id}")
    print(f"  tenant: {result.tenant_id}")
    print(f"  provider: {result.provider.value}")
    print(f"  scanned at: {result.scanned_at.isoformat()}")
    print(f"  resources collected: {len(result.resources)}")

    by_type: dict[str, int] = {}
    for resource in result.resources:
        by_type[resource.resource_type] = by_type.get(resource.resource_type, 0) + 1
    for resource_type, count in sorted(by_type.items()):
        print(f"    {resource_type}: {count}")

    by_status: dict[FindingStatus, int] = {}
    for finding in result.findings:
        by_status[finding.status] = by_status.get(finding.status, 0) + 1
    print(f"  findings: {len(result.findings)}")
    for status in (FindingStatus.FAIL, FindingStatus.PASS, FindingStatus.INDETERMINATE):
        print(f"    {status.value}: {by_status.get(status, 0)}")

    fail_findings = [f for f in result.findings if f.status is FindingStatus.FAIL]
    if fail_findings:
        print("\n  FAIL findings:")
        for finding in fail_findings:
            print(f"    [{finding.severity.value}] {finding.rule_id} on {finding.resource_id} ({finding.control_id})")


if __name__ == "__main__":
    raise SystemExit(main())
