"""Secret redaction guard (Phase 4, Part 20).

Part 20 is absolute: cloud credentials, access keys, secret keys, tokens,
passwords and private keys must NEVER be persisted.

Phase 3's collectors are already designed not to read secret VALUES —
they read configuration metadata. So this module is not a
band-aid over a known leak; it is a **defense-in-depth backstop** for a
future collector that adds a field without thinking, or a rule whose
evidence template interpolates something it shouldn't.

Deliberately conservative in both directions:

* It matches on KEY NAMES, not value heuristics. Scanning values for
  "things that look like a secret" produces false positives on ordinary
  ARNs and resource ids, and false negatives on anything unusual.
* It REDACTS rather than raises. A scan that discovers one suspicious
  key should still persist its other 10,000 findings — dropping the
  entire scan would turn a hygiene issue into an outage. The redaction
  is visible in the stored data, so it is auditable.
"""

from __future__ import annotations

from typing import Any, Mapping

#: Substrings that mark a key as credential-bearing. Matched
#: case-insensitively against the key name.
_SECRET_KEY_MARKERS = (
    "secret",
    "password",
    "passwd",
    "token",
    "credential",
    "private_key",
    "privatekey",
    "access_key",
    "accesskey",
    "api_key",
    "apikey",
    "session_key",
    "client_secret",
    "connection_string",
    "sas_token",
    "shared_key",
)

#: Keys that CONTAIN a marker but are safe: they name a credential
#: without carrying one. `access_key_count` is a number; `key_manager`
#: is "AWS" or "CUSTOMER"; `kms_key_id` is an ARN, not key material.
_ALLOWLIST = (
    "access_key_count",
    "active_access_key_count",
    "key_manager",
    "key_state",
    "kms_key_id",
    "key_policy_allows_public_access",
    "has_full_admin_policy",
    "ssh_public_key",
    "public_key",
)

REDACTED = "[REDACTED]"


def is_secret_key(key: str) -> bool:
    """Whether a key name suggests it carries credential material."""

    lowered = key.lower()
    if lowered in _ALLOWLIST:
        return False
    return any(marker in lowered for marker in _SECRET_KEY_MARKERS)


def redact(data: Mapping[str, Any]) -> dict[str, Any]:
    """Return a copy with credential-shaped values replaced.

    Recurses into nested mappings and lists, because evidence and
    resource attributes both nest (an IAM policy document, a list of
    ingress rules).
    """

    result: dict[str, Any] = {}
    for key, value in data.items():
        if isinstance(key, str) and is_secret_key(key):
            result[key] = REDACTED
        elif isinstance(value, Mapping):
            result[key] = redact(value)
        elif isinstance(value, (list, tuple)):
            result[key] = [redact(v) if isinstance(v, Mapping) else v for v in value]
        else:
            result[key] = value
    return result
