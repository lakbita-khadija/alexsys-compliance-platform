"""The ``UNKNOWN`` sentinel — "we looked and could not determine this".

Audit gap G3, and §34 of the upgrade brief, which calls this critical.
It is worth being precise about why.

## The problem

The rule engine already reasons in three values (MATCHED / NOT_MATCHED /
INDETERMINATE). The **collectors** did not. A normalizer that could not
determine a value had two options, and both were wrong:

* **omit the key** — most operators then return INDETERMINATE, which is
  accidentally correct but indistinguishable from "this resource type
  has no such attribute"
* **emit ``False``** — the engine says "definitely non-compliant", which
  is a **false positive**

The second is the damaging one, and it is the natural thing to write:

```python
mfa_enabled = bool(response.get("MFADevices"))   # WRONG when the call was denied
```

If the credential lacks ``iam:ListMFADevices``, that expression yields
``False``, and the platform tells a customer their administrator has no
MFA. That is not a minor inaccuracy — it is a false accusation that
destroys trust in every other finding, and it is indistinguishable from
a true positive in the output.

## The distinction

| Situation | Correct value | Meaning |
|---|---|---|
| MFA device list returned, empty | ``False`` | No MFA. A real finding. |
| MFA device list returned, non-empty | ``True`` | Compliant. |
| ``AccessDenied`` on the call | ``UNKNOWN`` | **Scan configuration problem**, not a customer problem. |
| Attribute absent from this resource type | key omitted | Rule does not apply. |

"We could not check" is an operational signal that the scanner needs
more permission. Reporting it as a violation sends a security team to
investigate their own configuration for a problem that does not exist.

## How it behaves

``UNKNOWN`` is a singleton sentinel, not ``None`` — ``None`` already
means "explicitly null" in collected cloud data and conflating the two
would lose exactly the distinction this module exists to make.

It is deliberately **falsy-resistant**: ``bool(UNKNOWN)`` raises rather
than silently returning ``False``. That converts the single most likely
misuse — ``if resource.attributes["mfa_enabled"]:`` — from a silent
false positive into a loud error at the call site.
"""

from __future__ import annotations

from typing import Any, Final


class UnknownType:
    """Type of the ``UNKNOWN`` singleton.

    Comparison is identity-based and total: ``UNKNOWN == UNKNOWN`` is
    True, and ``UNKNOWN == anything_else`` is False. It is hashable and
    JSON-representable so it survives persistence, and immutable so it
    cannot be corrupted by a caller.
    """

    _instance: "UnknownType | None" = None

    def __new__(cls) -> "UnknownType":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "UNKNOWN"

    def __str__(self) -> str:
        return "unknown"

    def __bool__(self) -> bool:
        """Refuse to collapse into a boolean.

        This is the whole safety mechanism. ``if value:`` on an unknown
        value is almost always a bug that would silently report a
        violation, so it raises instead of quietly evaluating False.

        Use ``is_unknown(value)`` or compare explicitly against ``True``
        / ``False``.
        """

        raise TypeError(
            "UNKNOWN has no truth value — it means 'could not be determined', "
            "which is neither True nor False. Use is_unknown(value), or compare "
            "explicitly (value is True / value is False)."
        )

    def __eq__(self, other: object) -> bool:
        return other is self

    def __ne__(self, other: object) -> bool:
        return other is not self

    def __hash__(self) -> int:
        return hash("complianceiq.UNKNOWN")

    def __copy__(self) -> "UnknownType":
        return self

    def __deepcopy__(self, memo: dict) -> "UnknownType":
        return self

    def __reduce__(self) -> tuple:
        # Survives pickling as the same singleton.
        return (_get_unknown, ())


def _get_unknown() -> "UnknownType":
    return UNKNOWN


#: The singleton. Import this, never construct ``UnknownType()``.
UNKNOWN: Final[UnknownType] = UnknownType()

#: How UNKNOWN is stored in JSONB and rendered on the wire. A string
#: rather than SQL NULL because NULL already means "explicitly absent",
#: and the whole point is that these are different facts.
UNKNOWN_WIRE_VALUE: Final[str] = "unknown"


def is_unknown(value: Any) -> bool:
    """Whether ``value`` is the UNKNOWN sentinel.

    The safe way to test — unlike ``if value:``, which raises, and unlike
    ``value == UNKNOWN``, which works but reads less clearly at call
    sites.
    """

    return value is UNKNOWN


def is_known(value: Any) -> bool:
    """Whether ``value`` carries a determined answer."""

    return value is not UNKNOWN


def unknown_if_none(value: Any) -> Any:
    """Map ``None`` to ``UNKNOWN``.

    For SDK responses where an absent field genuinely means "not
    retrievable" rather than "explicitly null". Use it deliberately —
    many cloud APIs return ``None`` to mean a real, known absence, and
    converting those to UNKNOWN would suppress true findings, which is
    the opposite error and just as bad.
    """

    return UNKNOWN if value is None else value


def to_wire(value: Any) -> Any:
    """Render for JSON/persistence: UNKNOWN becomes ``"unknown"``.

    Recurses through mappings and sequences so a whole attribute bag can
    be serialized in one call.
    """

    if is_unknown(value):
        return UNKNOWN_WIRE_VALUE
    if isinstance(value, dict):
        return {k: to_wire(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_wire(v) for v in value]
    return value


def tri_state(
    *,
    determined: bool,
    value: bool,
) -> "bool | UnknownType":
    """Build a tri-state boolean from a determination and a value.

    Reads better than a conditional expression at collector call sites
    and makes the intent explicit:

    ```python
    mfa_enabled=tri_state(determined=mfa_call_succeeded, value=bool(devices))
    ```

    versus the version that quietly produces a false positive when the
    call failed.
    """

    return value if determined else UNKNOWN
