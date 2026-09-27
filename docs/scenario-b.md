# Scenario B — Extend Your Own System: Retention and Redaction

## 1. Requirement understanding

- **Retention policy:** Records older than configurable window should be archieved or soft-deletable
- **Redaction:** Sensitive fields within records payload must be redactable to satisfy data privacy
- **Export:** Export all records for an actor or resource as a bundle anyone can verify offline, proving no record was changed, added, or removed since export.

Done when:

- Records older than a configurable window can be archived; verify reports no false break
- Sensitive payload fields can be redacted; verify still passes
- Records for an actorId or resourceType + resourceId export as a bundle that verify_bundle.py confirms intact, and rejects if altered

## 2. Fields and Table changes

| Name             | Type                          | Used by   | Description                                                                                              |
| ---------------- | ----------------------------- | --------- | -------------------------------------------------------------------------------------------------------- |
| BEFORE           | make parameter (ISO 8601 UTC) | Retention | Records with timestamp earlier than this are archived                                                    |
| archived         | boolean                       | Retention | Table: audit_events; True once archived; not hashed                                                      |
| SENSITIVE_FIELDS | config (list)                 | Redaction | Top-level payload keys to protect                                                                        |
| fieldHashes      | object                        | Redaction | Table: audit_events; audit_eventsSHA-256(salt + value) per sensitive field; kept after redaction; hashed |
| fieldSalts       | object                        | Redaction | Table: audit_events; Random 32-byte salt per sensitive field; deleted on redaction; not hashed           |

## 3. API Examples

GET /audit/export?resourceType=ACCOUNT&resourceId=acct-88731

```json
{
  "metadata": {
    "exportedAt": "2026-09-27T10:00:00Z",
    "filter": { "resourceType": "ACCOUNT", "resourceId": "acct-88731" },
    "hashAlgorithm": "SHA-256",
    "serialization": "canonical JSON (sorted keys, no whitespace)",
    "sensitiveFields": ["accountNumber"],
    "recordCount": 2
  },
  "records": [
    {
      "id": 3,
      "eventType": "RECORD_UPDATED",
      "actorId": "user-1042",
      "resourceType": "ACCOUNT",
      "resourceId": "acct-88731",
      "payload": { "accountNumber": "[REDACTED]", "field": "mailingAddress" },
      "timestamp": "2026-09-24T14:32:10Z",
      "fieldHashes": { "accountNumber": "c3a9…" },
      "previousHash": "41b8…",
      "contentHash": "9f2c…"
    }
  ],
  "bundleHash": "e71d…"
}
```

## 4. Questions and decisions

| Question                                           | Decision                                                                                                          | Why                                                                                |
| -------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| How is the retention window set?                   | Operator passes a cutoff time per run: make retention BEFORE=…                                                    | Explicit and predictable; the window is chosen per run rather than fixed in config |
| Cutoff rules?                                      | Required, ISO 8601 UTC, not in the future, strictly earlier than                                                  | Prevents mistakes; matches the exclusive "to" in queries                           |
| What does archiving do?                            | Sets archived = true; clear event content; keep only id, timestamp, contentHash, previousHash                     | Data removed per policy only chain link stays linkable                             |
| Is archived flag hashed?                           | No                                                                                                                | It changes after write; hashing it would break the chain                           |
| How does verify detect misuse of archived flag?    | Archived records must be a continuous block from the first record; otherwise INVALID_ARCHIVE                      | Retention always archives oldest-first, so any gap means tampering                 |
| Are archived records returned by queries?          | No                                                                                                                | Their content has been removed                                                     |
| What is redaction scheme?                          | Salted fields hashes                                                                                              | Chain statys verifiable after redaction; standard and simple approach              |
| Which fields can be redacted?                      | Top-level payload keys listed in SENSITIVE_FIELDS config                                                          | Operator controls policy; consistent across callers; must be known at write time   |
| How is a field hash computed?                      | SHA-256(salt + canonical value), with a random 32-byte salt per field per record                                  | Salt prevents guessing short values like account numbers by brute force            |
| What goes into the record's content hash?          | Field hash in place of the raw value for sensitive fields; raw values for all others                              | Removing the raw value later doesn't change the content hash                       |
| How does verify check sensitive fields?            | If value and salt are present, checks SHA-256(salt + value) matches the field hash; if redacted, skips that check | Detects edits to a sensitive value, which the content hash alone wouldn't catch    |
| How is redaction triggered?                        | Script (make redact ID=… FIELD=…)                                                                                 | Operator-only; public API stays write-and-read only; consistent with retention     |
| Isn't redaction an "update"?                       | It removes a value and its salt without changing any stored hash; not exposed via the API                         | Tamper evidence is preserved, and the API remains append-only                      |
| What does a redacted field look like in responses? | "[REDACTED]"                                                                                                      | Clear to readers that a value existed and was removed                              |
| Which requests does the script refuse?             | Fields not in SENSITIVE_FIELDS, archived records, already-redacted fields                                         | Prevents misuse and no-op redactions                                               |
| Export endpoint?                                   | GET /audit/export?actorId=… or ?resourceType=…&resourceId=…                                                       | Read-only; resourceType required with resourceId, same as queries                  |
| Bundle contents?                                   | Metadata, records with all hashed fields + fieldHashes, bundleHash                                                | Enough to recompute every hash offline                                             |
| Salts included?                                    | Yes, for unredacted fields                                                                                        | Needed to check values against field hashes                                        |
| bundleHash?                                        | SHA-256 over contentHashes in id order                                                                            | Detects added, removed, or reordered records                                       |
| Archived / redacted?                               | Archived excluded; redacted included as "[REDACTED]"                                                              | Only verifiable content is exported                                                |
| Recipient verification?                            | scripts/verify_bundle.py, standard library only                                                                   | No service or database needed                                                      |

## 5. Tasks

| #   | Task                               | Needs  | Done when                                                                                                                  |
| --- | ---------------------------------- | ------ | -------------------------------------------------------------------------------------------------------------------------- |
| B1  | Archive columns + retention script | A      | make retention BEFORE=… archives records earlier than BEFORE and clears their content                                       |
| B2  | Verify handles archived records    | B1     | Archived records cause no false break; an archived record after a non-archived one reports INVALID_ARCHIVE                 |
| B3  | Field hashes                       | A2     | Sensitive values stored with salt and field hash; content hash uses the field hash; verify checks value against field hash |
| B4  | Redaction script                   | B3     | make redact removes value and salt; response shows "[REDACTED]"; verify still passes                                       |
| B5  | Combined test                      | B2, B4 | A chain with archived and redacted records verifies; tampering is still detected                                           |
| B6  | Export endpoint                    | A5, B3 | Returns bundle for actorId or resourceType + resourceId                                                                    |
| B7  | Bundle verifier                    | B6     | Passes untouched bundle; fails on edited or removed record                                                                 |
| B8  | Update docs                        | B1–B7  | Docs match the code                                                                                                        |

## 7. Execution notes

| #   | Task | Area      | Notes                                                                                                                                                                                                              |
| --- | ---- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1   | B1   | Storage   | `archived`, `field_hashes`, `field_salts` columns and the "content required unless archived" check constraint already existed from A1; no schema change needed                                                     |
| 2   | B1   | Config    | `--before` argument (was `RETENTION_DAYS`, now removed): required, ISO 8601 UTC with `Z`, whole seconds, not in the future; parsed by `parse_cutoff` in `operations/retention.py` |
| 3   | B1   | Retention | `archive_before` in `storage/repository.py`: records with timestamp strictly earlier than the cutoff are archived; archives the id prefix up to the newest expired record |
| 4   | B1   | Retention | Sets `archived = true`, clears event fields, payload, `field_hashes`, `field_salts`; keeps `id`, `timestamp`, `contentHash`, `previousHash`; one transaction under the write lock                                  |
| 5   | B1   | Script    | `operations/retention.py` (`parse_cutoff`, `run_retention`, `main`), thin `scripts/run_retention.py`; `make retention BEFORE=…` passes `--before` and `--env-file .env` when `.env` exists; exit `2` if `--before` missing, invalid or in the future |
| 6   | B2   | Verify    | Reused unchanged `verify_chain`: archived records get the link check only; archived after non-archived is `INVALID_ARCHIVE` (both already built in A6)                                                             |
| 7   | B2   | Tests     | Unit `test_retention.py` and integration `test_retention_script.py` (runs the real script): verify intact after retention at several windows, new appends still link, out-of-order archive gives `INVALID_ARCHIVE` |
| 8   | B1   | Change    | Replaced `RETENTION_DAYS` config with required `make retention BEFORE=…` cutoff per §4; removed `config.retention_days()` and its tests; unit + integration tests cover missing, invalid, non-`Z`, fractional and future values |
| 9   | B3   | Hashing   | Already built in A2/A6: `protect_sensitive_fields` salts + field-hashes `SENSITIVE_FIELDS` keys on append, content hash uses the field hash, verify checks value against field hash; only change: value check extracted to shared `field_hash_matches` in `domain/hashing.py` |
| 10  | B4   | Redaction | `redact_field` in `storage/repository.py`: removes the payload key and its salt, keeps `fieldHashes` and every stored hash; one transaction under the write lock; responses show `"[REDACTED]"` (existing `EventRecord.from_record`) |
| 11  | B4   | Refusals  | Field not in `SENSITIVE_FIELDS`, unknown or archived record, record without that field hash, already redacted, and (added) value not matching its field hash, so redaction can't erase evidence of an edit; nothing changes on refusal |
| 12  | B4   | Script    | `operations/redaction.py` (`run_redaction`, `main`), thin `scripts/redact.py`; `make redact ID=… FIELD=…` passes `--id`/`--field` and `--env-file .env` when present; exit `0` done, `1` refused, `2` missing/invalid arguments |
| 13  | B4   | Tests     | Unit `test_redaction.py` (hashes unchanged, verify intact, `[REDACTED]` response, every refusal leaves the row untouched, CLI args) and integration `test_redact_script.py` (runs the real script; verify intact, new appends link, refusals) |

## 8. Validation

{Filled after build.}
