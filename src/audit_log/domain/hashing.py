"""Canonical serialization and SHA-256 hashing for the audit hash chain.

This module is the single source of truth for how records are hashed. It uses only the
standard library so operator and verification scripts (e.g. ``scripts/verify_bundle.py``)
can reuse it without the service, database, or third-party packages.

Content hash
    SHA-256 over the canonical JSON of::

        {
          "eventType", "actorId", "resourceType", "resourceId", "timestamp",
          "payload",       # payload with sensitive keys removed
          "fieldHashes",   # {sensitive key: field hash}
          "previousHash"
        }

    ``archived`` and ``fieldSalts`` are deliberately excluded: both change after write
    (retention, redaction) and hashing them would break the chain.

Field hash (sensitive payload keys)
    SHA-256(salt bytes + UTF-8 canonical JSON of the value), with a random 32-byte salt per
    field per record. The content hash covers the field hash instead of the raw value, so
    the raw value and salt can later be removed without changing the content hash.

Canonical JSON
    Sorted keys, no whitespace (``","`` and ``":"`` separators), non-ASCII kept as UTF-8,
    NaN/Infinity rejected.
"""

import hashlib
import json
import secrets
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

HASH_ALGORITHM = "SHA-256"
SALT_BYTES = 32

# First 32 bits of the fractional parts of the square roots of the first 8 primes
# (2, 3, 5, 7, 11, 13, 17, 19): a "nothing-up-my-sleeve" value for the first record's link.
GENESIS_HASH = "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19"

_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def canonical_json(value: Any) -> str:
    """Serialize ``value`` deterministically: sorted keys, no whitespace."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def sha256_hex(data: bytes) -> str:
    """Return the lowercase hex SHA-256 digest of ``data``."""
    return hashlib.sha256(data).hexdigest()


def format_timestamp(moment: datetime) -> str:
    """Render a timezone-aware datetime as canonical UTC ISO 8601 with ``Z``."""
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return moment.astimezone(UTC).strftime(_TIMESTAMP_FORMAT)


def generate_salt() -> str:
    """Return a new random 32-byte salt, hex encoded."""
    return secrets.token_hex(SALT_BYTES)


def compute_field_hash(salt: str, value: Any) -> str:
    """Return SHA-256(salt + canonical value) for a sensitive payload field.

    ``salt`` is hex encoded; its raw bytes are prepended to the UTF-8 canonical JSON of
    ``value``.
    """
    salt_bytes = bytes.fromhex(salt)
    if len(salt_bytes) != SALT_BYTES:
        raise ValueError(f"salt must be {SALT_BYTES} bytes")
    return sha256_hex(salt_bytes + canonical_json(value).encode("utf-8"))


def field_hash_matches(salt: str, value: Any, field_hash: str) -> bool:
    """Return whether ``value`` with ``salt`` reproduces ``field_hash``; False for a bad salt."""
    try:
        return compute_field_hash(salt, value) == field_hash
    except ValueError:  # salt edited to invalid hex or the wrong length
        return False


@dataclass(frozen=True)
class ProtectedFields:
    """Field hashes and salts produced for a payload's sensitive keys."""

    field_hashes: dict[str, str]
    field_salts: dict[str, str]


def protect_sensitive_fields(
    payload: Mapping[str, Any], sensitive_fields: Iterable[str]
) -> ProtectedFields:
    """Salt and hash every top-level payload key listed in ``sensitive_fields``."""
    field_hashes: dict[str, str] = {}
    field_salts: dict[str, str] = {}
    for key in sorted(set(sensitive_fields) & payload.keys()):
        salt = generate_salt()
        field_salts[key] = salt
        field_hashes[key] = compute_field_hash(salt, payload[key])
    return ProtectedFields(field_hashes=field_hashes, field_salts=field_salts)


def hashable_payload(payload: Mapping[str, Any], field_hashes: Mapping[str, str]) -> dict[str, Any]:
    """Return the payload with sensitive keys removed; their field hashes stand in for them."""
    return {key: value for key, value in payload.items() if key not in field_hashes}


def compute_content_hash(
    *,
    event_type: str,
    actor_id: str,
    resource_type: str,
    resource_id: str,
    timestamp: str,
    payload: Mapping[str, Any],
    field_hashes: Mapping[str, str],
    previous_hash: str,
) -> str:
    """Return the record's content hash, linking it to ``previous_hash``."""
    content = {
        "eventType": event_type,
        "actorId": actor_id,
        "resourceType": resource_type,
        "resourceId": resource_id,
        "timestamp": timestamp,
        "payload": hashable_payload(payload, field_hashes),
        "fieldHashes": dict(field_hashes),
        "previousHash": previous_hash,
    }
    return sha256_hex(canonical_json(content).encode("utf-8"))
