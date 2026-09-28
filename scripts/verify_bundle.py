"""Verify an exported audit bundle offline: ``python verify_bundle.py bundle.json``.

Standard library only and self-contained, so a recipient can run this single file with any
Python 3.13 without the service, its database or third-party packages. It hashes exactly
like ``audit_log.domain.hashing`` (the tests check both agree on the same inputs):

- canonical JSON: sorted keys, no whitespace, non-ASCII kept as UTF-8, NaN/Infinity rejected
- content hash: SHA-256 over the canonical JSON of the event fields, the payload without
  its sensitive keys, ``fieldHashes`` and ``previousHash``
- field hash: SHA-256(salt bytes + UTF-8 canonical JSON of the value)
- bundle hash: SHA-256 over the canonical JSON array of content hashes, in id order

Checks, stopping at the first failure:

1. the bundle is well formed and uses SHA-256
2. record ids are strictly increasing
3. every record matches the export filter in the metadata
4. every record's recomputed content hash equals its ``contentHash``
5. every sensitive field with a salt matches its field hash; one without a salt must be
   shown as ``[REDACTED]``
6. consecutive ids (N, N+1) link: ``previousHash`` of N+1 is ``contentHash`` of N
7. ``recordCount`` and ``bundleHash`` match the records, so an added, removed or reordered
   record is detected

Exit status: 0 intact, 1 verification failed, 2 file unreadable or not JSON.
"""

import argparse
import hashlib
import json
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

HASH_ALGORITHM = "SHA-256"
SALT_BYTES = 32
REDACTED = "[REDACTED]"

_EVENT_FIELDS = ("eventType", "actorId", "resourceType", "resourceId", "timestamp")
_HASH_FIELDS = ("contentHash", "previousHash")
# Metadata filter keys and the record fields they must equal.
_FILTER_FIELDS = ("actorId", "resourceType", "resourceId")


class BundleError(Exception):
    """The bundle failed a check; ``record_id`` is set when one record is at fault."""

    def __init__(self, message: str, record_id: int | None = None) -> None:
        super().__init__(message)
        self.record_id = record_id


def canonical_json(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_field_hash(salt: str, value: Any) -> str:
    salt_bytes = bytes.fromhex(salt)
    if len(salt_bytes) != SALT_BYTES:
        raise ValueError(f"salt must be {SALT_BYTES} bytes")
    return sha256_hex(salt_bytes + canonical_json(value).encode("utf-8"))


def compute_content_hash(record: Mapping[str, Any]) -> str:
    field_hashes = record["fieldHashes"]
    content = {
        "eventType": record["eventType"],
        "actorId": record["actorId"],
        "resourceType": record["resourceType"],
        "resourceId": record["resourceId"],
        "timestamp": record["timestamp"],
        "payload": {k: v for k, v in record["payload"].items() if k not in field_hashes},
        "fieldHashes": dict(field_hashes),
        "previousHash": record["previousHash"],
    }
    return sha256_hex(canonical_json(content).encode("utf-8"))


def compute_bundle_hash(content_hashes: Sequence[str]) -> str:
    return sha256_hex(canonical_json(list(content_hashes)).encode("utf-8"))


@dataclass(frozen=True)
class Result:
    record_count: int
    error: BundleError | None = None

    @property
    def intact(self) -> bool:
        return self.error is None


def verify_bundle(bundle: Any) -> Result:
    """Run every check on a parsed bundle; report the first failure."""
    try:
        records = _check_bundle(bundle)
    except BundleError as exc:
        return Result(record_count=0, error=exc)
    return Result(record_count=len(records))


def _check_bundle(bundle: Any) -> list[Mapping[str, Any]]:
    if not isinstance(bundle, dict):
        raise BundleError("bundle must be a JSON object")
    metadata = _require(bundle, "metadata", dict)
    records: list[Mapping[str, Any]] = _require(bundle, "records", list)
    bundle_hash = _require(bundle, "bundleHash", str)
    if metadata.get("hashAlgorithm") != HASH_ALGORITHM:
        raise BundleError(f"unsupported hashAlgorithm: {metadata.get('hashAlgorithm')!r}")
    export_filter = _require(metadata, "filter", dict)
    if not export_filter or not set(export_filter) <= set(_FILTER_FIELDS):
        raise BundleError(f"metadata filter must use {', '.join(_FILTER_FIELDS)}")

    previous: Mapping[str, Any] | None = None
    for index, record in enumerate(records):
        _check_shape(record, index)
        record_id = record["id"]
        if previous is not None and record_id <= previous["id"]:
            raise BundleError("record ids are not strictly increasing", record_id)
        for key, expected in export_filter.items():
            if record[key] != expected:
                raise BundleError(f"{key} does not match the export filter", record_id)
        _check_content(record)
        if (
            previous is not None
            and record_id == previous["id"] + 1
            and record["previousHash"] != previous["contentHash"]
        ):
            raise BundleError("previousHash does not match the preceding record", record_id)
        previous = record

    if metadata.get("recordCount") != len(records):
        raise BundleError(f"recordCount does not match the {len(records)} record(s) present")
    if compute_bundle_hash([record["contentHash"] for record in records]) != bundle_hash:
        raise BundleError("bundleHash does not match the records (added, removed or reordered)")
    return records


def _require(container: Mapping[str, Any], key: str, kind: type) -> Any:
    value = container.get(key)
    if not isinstance(value, kind):
        raise BundleError(f"{key} is missing or not a {kind.__name__}")
    return value


def _check_shape(record: Any, index: int) -> None:
    where = f"record at index {index}"
    if not isinstance(record, dict):
        raise BundleError(f"{where} is not an object")
    record_id = record.get("id")
    if not isinstance(record_id, int) or isinstance(record_id, bool):
        raise BundleError(f"{where} has no integer id")
    for key in (*_EVENT_FIELDS, *_HASH_FIELDS):
        if not isinstance(record.get(key), str):
            raise BundleError(f"{key} is missing or not a string", record_id)
    for key in ("payload", "fieldHashes", "fieldSalts"):
        if not isinstance(record.get(key), dict):
            raise BundleError(f"{key} is missing or not an object", record_id)


def _check_content(record: Mapping[str, Any]) -> None:
    record_id = record["id"]
    try:
        recomputed = compute_content_hash(record)
    except ValueError as exc:  # NaN/Infinity are not canonical JSON
        raise BundleError(f"content cannot be canonically serialized: {exc}", record_id) from exc
    if recomputed != record["contentHash"]:
        raise BundleError("contentHash does not match recomputed hash", record_id)
    payload, field_hashes, field_salts = (
        record["payload"],
        record["fieldHashes"],
        record["fieldSalts"],
    )
    for key in sorted(field_salts):
        if key not in field_hashes:
            raise BundleError(f"salt for {key!r} has no field hash", record_id)
    for key in sorted(field_hashes):
        if key not in field_salts:
            if payload.get(key) != REDACTED:
                raise BundleError(
                    f"sensitive field {key!r} has no salt but is not {REDACTED}", record_id
                )
            continue
        if key not in payload or not _field_matches(
            field_salts[key], payload[key], field_hashes[key]
        ):
            raise BundleError(
                f"value of sensitive field {key!r} does not match its field hash", record_id
            )


def _field_matches(salt: str, value: Any, field_hash: str) -> bool:
    try:
        return compute_field_hash(salt, value) == field_hash
    except (TypeError, ValueError):  # salt edited to non-text, invalid hex or wrong length
        return False


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="verify_bundle", description="Verify an exported audit bundle offline."
    )
    parser.add_argument("bundle", help="path to the bundle JSON file")
    args = parser.parse_args(argv)
    try:
        with open(args.bundle, encoding="utf-8") as file:
            bundle = json.load(file)
    except (OSError, ValueError) as exc:
        print(f"verify_bundle: cannot read {args.bundle}: {exc}", file=sys.stderr)
        return 2
    result = verify_bundle(bundle)
    if result.error is None:
        print(f"verify_bundle: intact ({result.record_count} record(s))")
        return 0
    where = f"record {result.error.record_id}: " if result.error.record_id is not None else ""
    print(f"verify_bundle: FAILED: {where}{result.error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
