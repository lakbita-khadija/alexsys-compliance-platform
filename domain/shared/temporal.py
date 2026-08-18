"""Shared datetime validation.

A single, reused check rather than four copies of the same logic
(``resources``, ``findings``, ``drift``, ``compliance`` each carry a
timestamp field). Naive datetimes are ambiguous across tenants/regions
and reused here as a general Domain invariant — sharpened by the
Core↔AI Service handoff's explicit requirement that external timestamps
be timezone-aware.
"""

from __future__ import annotations

from datetime import datetime


def is_timezone_aware(value: datetime) -> bool:
    return value.tzinfo is not None and value.tzinfo.utcoffset(value) is not None
