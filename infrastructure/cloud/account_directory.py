"""Which cloud accounts each tenant may scan (STEP 6.5).

Provider-neutral, so it lives beside `resilience.py` rather than inside
`aws/` or `azure/`.

Two adapters, and the difference between them is deployment posture:

* :class:`StaticCloudAccountDirectory` — bindings supplied in process.
  What tests use, and what a single-tenant or config-file deployment
  uses.
* :class:`EnvCloudAccountDirectory` — bindings parsed from one
  environment variable, for a container deployment with no database
  table for this yet.

Both are deliberately **read-only**. Nothing in the running application
may add a binding: a control that the application can extend at runtime
is a control an application bug can widen. Bindings are operator
configuration, changed by redeploying.

There is no PostgreSQL-backed adapter, and that is a considered gap
rather than an omission — see `docs/architecture/cloud-authentication.md`
on why a table for this needs a tenant-administration API to be worth
having, and what would have to exist first.
"""

from __future__ import annotations

import json
import os
from typing import Iterable

from application.ports.cloud_identity import CloudAccountDirectory
from domain.shared.enums import CloudProvider
from domain.shared.identifiers import TenantId
from domain.tenants.cloud_accounts import CloudAccountBinding

#: Environment variable holding a JSON array of binding objects.
ENV_VAR = "COMPLIANCEIQ_CLOUD_ACCOUNT_BINDINGS"


class StaticCloudAccountDirectory(CloudAccountDirectory):
    """Bindings held in memory, fixed at construction."""

    def __init__(self, bindings: Iterable[CloudAccountBinding] = ()) -> None:
        self._bindings = tuple(bindings)

    def bindings_for(
        self, *, tenant_id: TenantId, provider: CloudProvider
    ) -> tuple[CloudAccountBinding, ...]:
        return tuple(
            b for b in self._bindings if b.tenant_id == tenant_id and b.provider is provider
        )


class EnvCloudAccountDirectory(StaticCloudAccountDirectory):
    """Bindings parsed from ``COMPLIANCEIQ_CLOUD_ACCOUNT_BINDINGS``.

    Expected shape — a JSON array, validated by
    :class:`CloudAccountBinding`'s own constructor so a malformed entry
    is rejected at startup rather than at scan time:

    .. code-block:: json

        [
          {"tenant_id": "acme",  "provider": "aws",
           "account_id": "111111111111"},
          {"tenant_id": "acme",  "provider": "azure",
           "account_id": "0000-sub", "directory_id": "0000-tenant"}
        ]

    An unset or empty variable yields **no bindings**, which means no
    tenant may scan anything. That is the correct failure direction: a
    deployment that forgot to configure this refuses to scan, rather
    than scanning whatever it happens to authenticate as.
    """

    def __init__(self, raw: str | None = None) -> None:
        super().__init__(_parse(raw if raw is not None else os.environ.get(ENV_VAR, "")))


def _parse(raw: str) -> tuple[CloudAccountBinding, ...]:
    if not raw.strip():
        return ()

    try:
        entries = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{ENV_VAR} is not valid JSON: {exc}") from exc

    if not isinstance(entries, list):
        raise ValueError(f"{ENV_VAR} must be a JSON array of binding objects")

    bindings: list[CloudAccountBinding] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"{ENV_VAR}[{index}] must be an object")
        try:
            bindings.append(
                CloudAccountBinding(
                    tenant_id=TenantId(str(entry["tenant_id"])),
                    provider=CloudProvider(str(entry["provider"])),
                    account_id=str(entry["account_id"]),
                    directory_id=(
                        str(entry["directory_id"])
                        if entry.get("directory_id") is not None
                        else None
                    ),
                )
            )
        except KeyError as exc:
            raise ValueError(f"{ENV_VAR}[{index}] is missing {exc.args[0]!r}") from exc
        except ValueError as exc:
            # Covers an unknown provider string from CloudProvider(...).
            raise ValueError(f"{ENV_VAR}[{index}]: {exc}") from exc

    # Sorted, so two processes reading the same configuration hold it in
    # the same order — the determinism discipline the rest of the
    # codebase keeps at every boundary.
    return tuple(
        sorted(bindings, key=lambda b: (str(b.tenant_id), b.provider.value, b.account_id))
    )


__all__ = ["ENV_VAR", "EnvCloudAccountDirectory", "StaticCloudAccountDirectory"]
