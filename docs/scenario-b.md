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

| Name             | Type             | Used by   | Description                                                                                              |
| ---------------- | ---------------- | --------- | -------------------------------------------------------------------------------------------------------- |
| RETENTION_DAYS   | config (integer) | Retention | Age in days after which records are archived                                                             |
| archived         | boolean          | Retention | Table: audit_events; True once archived; not hashed                                                      |
| SENSITIVE_FIELDS | config (list)    | Redaction | Top-level payload keys to protect                                                                        |
| fieldHashes      | object           | Redaction | Table: audit_events; audit_eventsSHA-256(salt + value) per sensitive field; kept after redaction; hashed |
| fieldSalts       | object           | Redaction | Table: audit_events; Random 32-byte salt per sensitive field; deleted on redaction; not hashed           |

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

| Question                                           | Decision                                                                                                          | Why                                                                              |
| -------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| How does retention get triggered?                  | Script (make retention); use window form RETENTION_DAYS .env config file                                          | Operation task only; no public endpoint to prevent misuse                        |
| What does archiving do?                            | Sets archived = true; clear event content; keep only id, timestamp, contentHash, previousHash                     | Data removed per policy only chain link stays linkable                           |
| Is archived flag hashed?                           | No                                                                                                                | It changes after write; hashing it would break the chain                         |
| How does verify detect misuse of archived flag?    | Archived records must be a continuous block from the first record; otherwise INVALID_ARCHIVE                      | Retention always archives oldest-first, so any gap means tampering               |
| Are archived records returned by queries?          | No                                                                                                                | Their content has been removed                                                   |
| What is redaction scheme?                          | Salted fields hashes                                                                                              | Chain statys verifiable after redaction; standard and simple approach            |
| Which fields can be redacted?                      | Top-level payload keys listed in SENSITIVE_FIELDS config                                                          | Operator controls policy; consistent across callers; must be known at write time |
| How is a field hash computed?                      | SHA-256(salt + canonical value), with a random 32-byte salt per field per record                                  | Salt prevents guessing short values like account numbers by brute force          |
| What goes into the record's content hash?          | Field hash in place of the raw value for sensitive fields; raw values for all others                              | Removing the raw value later doesn't change the content hash                     |
| How does verify check sensitive fields?            | If value and salt are present, checks SHA-256(salt + value) matches the field hash; if redacted, skips that check | Detects edits to a sensitive value, which the content hash alone wouldn't catch  |
| How is redaction triggered?                        | Script (make redact ID=… FIELD=…)                                                                                 | Operator-only; public API stays write-and-read only; consistent with retention   |
| Isn't redaction an "update"?                       | It removes a value and its salt without changing any stored hash; not exposed via the API                         | Tamper evidence is preserved, and the API remains append-only                    |
| What does a redacted field look like in responses? | "[REDACTED]"                                                                                                      | Clear to readers that a value existed and was removed                            |
| Which requests does the script refuse?             | Fields not in SENSITIVE_FIELDS, archived records, already-redacted fields                                         | Prevents misuse and no-op redactions                                             |
| Export endpoint?                                   | GET /audit/export?actorId=… or ?resourceType=…&resourceId=…                                                       | Read-only; resourceType required with resourceId, same as queries                |
| Bundle contents?                                   | Metadata, records with all hashed fields + fieldHashes, bundleHash                                                | Enough to recompute every hash offline                                           |
| Salts included?                                    | Yes, for unredacted fields                                                                                        | Needed to check values against field hashes                                      |
| bundleHash?                                        | SHA-256 over contentHashes in id order                                                                            | Detects added, removed, or reordered records                                     |
| Archived / redacted?                               | Archived excluded; redacted included as "[REDACTED]"                                                              | Only verifiable content is exported                                              |
| Recipient verification?                            | scripts/verify_bundle.py, standard library only                                                                   | No service or database needed                                                    |

## 5. Tasks

| #   | Task                               | Needs  | Done when                                                                                                                  |
| --- | ---------------------------------- | ------ | -------------------------------------------------------------------------------------------------------------------------- |
| B1  | Archive columns + retention script | A      | make retention archives records older than RETENTION_DAYS and clears their content                                         |
| B2  | Verify handles archived records    | B1     | Archived records cause no false break; an archived record after a non-archived one reports INVALID_ARCHIVE                 |
| B3  | Field hashes                       | A2     | Sensitive values stored with salt and field hash; content hash uses the field hash; verify checks value against field hash |
| B4  | Redaction script                   | B3     | make redact removes value and salt; response shows "[REDACTED]"; verify still passes                                       |
| B5  | Combined test                      | B2, B4 | A chain with archived and redacted records verifies; tampering is still detected                                           |
| B6  | Export endpoint                    | A5, B3 | Returns bundle for actorId or resourceType + resourceId                                                                    |
| B7  | Bundle verifier                    | B6     | Passes untouched bundle; fails on edited or removed record                                                                 |
| B8  | Update docs                        | B1–B7  | Docs match the code                                                                                                        |

## 7. Execution notes

{Filled during build.}

## 8. Validation

{Filled after build.}
