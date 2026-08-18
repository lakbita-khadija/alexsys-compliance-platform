"""``BaseCollector`` (blueprint §6, §7, §25, §27).

The blueprint repeatedly refers to ``BaseCollector`` as "already
abstract" in its reference implementation, used to argue AWS is
"replaceable without modifying the Domain," but also notes (§25) that
the port itself is "not yet formalized... to confirm after Phase 2."
This is that formalization.

A concrete collector (``infrastructure/cloud/aws.AwsCollector``,
future ``infrastructure/cloud/azure.AzureCollector`` — not built in this
phase) is constructed with its cloud session already resolved and
injected (blueprint §6: "reçoit une boto3.Session injectée, jamais
construite en interne") — so ``collect()`` itself takes no per-call
credentials. ``ScanCloudAccount`` depends only on this abstraction,
never on a concrete collector or any cloud SDK.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from domain.resources.models import NormalizedResource


class BaseCollector(ABC):
    """Port: collect normalized resources for one cloud account."""

    @abstractmethod
    def collect(self) -> tuple[NormalizedResource, ...]:
        """Discover and normalize every resource this collector is
        responsible for. Concrete collectors are expected to isolate
        per-service failures internally (blueprint §6: ``_safe()`` — a
        failure collecting one resource type must not prevent collecting
        the others); a raised exception here is treated as the whole
        collection having failed.
        """
