"""Canonicalization for drift comparison (blueprint §12).

Strips fields that are volatile by nature of *when* data was collected,
not by nature of the resource's actual state — comparing them would
report drift on every single scan even when nothing changed. The
blueprint identifies exactly one such field on ``NormalizedResource``:
``collected_at`` (§8). No other field is assumed volatile without
similar evidence — inventing more would risk silently hiding real drift.
"""

from __future__ import annotations

from typing import Any, Mapping

_VOLATILE_FIELDS = frozenset({"collected_at"})


def canonicalize(data: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return a copy of ``data`` with volatile fields removed. Pure —
    never mutates its input.
    """

    return {key: value for key, value in data.items() if key not in _VOLATILE_FIELDS}
