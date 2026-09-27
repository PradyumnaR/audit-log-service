# Scenario A — Greenfield: Core Audit Log Service

## 1. Requirement understanding

Build a service that records events(who did what, to which resource, when) as an append only-history. Caller can write and query events but never changes or remove them. Each record is linked to previous one by hashes, so any change to stored data can be detected by a verification endpoint that reports first broken record and why.

Done when:

- Events can be written with: eventType, actorId, resourceType, resourceId, payload, timestamp
- Events can be queried by actorId, resourceType + resourceId, eventType, and time range, with pagination
- Verify reports an intact chain, then detects tampering after a record is directly modified in the database
- If broken: Which record is the first inconsistency and what type of violation was detected.

## 2. Fields and Query Parameters

### Event Fields

| Field        | Type                   | Required        | Description                                                                                |
| ------------ | ---------------------- | --------------- | ------------------------------------------------------------------------------------------ |
| eventType    | string                 | Yes             | What happened, e.g. USER_LOGIN, RECORD_UPDATED                                             |
| actorId      | string                 | Yes             | Who or what caused the event                                                               |
| resourceType | string                 | Yes             | Type of resource affected, e.g. ACCOUNT, USER                                              |
| resourceId   | string                 | Yes             | The specific resource affected                                                             |
| payload      | object                 | Yes             | Event-specific details                                                                     |
| timestamp    | string (ISO 8601, UTC) | server-assigned | When the event occured. Set by server when event comes in. Included in the return response |

### Query Parameters

| Field        | Type                   | Description                                    |
| ------------ | ---------------------- | ---------------------------------------------- |
| eventType    | string                 | What happened, e.g. USER_LOGIN, RECORD_UPDATED |
| actorId      | string                 | Who or what caused the event                   |
| resourceType | string                 | Type of resource affected, e.g. ACCOUNT, USER  |
| resourceId   | string                 | The specific resource affected                 |
| from         | string (ISO 8601, UTC) | Start time, inclusive                          |
| to           | string (ISO 8601, UTC) | End time, exclusive                            |
| limit        | number                 | number of records to include in the reponse    |
| cursor       | string (optional)      | last record's ID                               |

## 3. API Examples

### POST /audit/events:

Sample request:

```json
{
  "eventType": "RECORD_UPDATED",
  "actorId": "user-1042",
  "resourceType": "ACCOUNT",
  "resourceId": "acct-88731",
  "payload": {
    "field": "mailingAddress",
    "oldValue": "12 Oak St",
    "newValue": "48 Pine Ave"
  },
  "timestamp": "2026-09-24T14:32:10Z"
}
```

Sample response:

```json
{
  "id": 1,
  "eventType": "RECORD_UPDATED",
  "actorId": "user-1042",
  "resourceType": "ACCOUNT",
  "resourceId": "acct-88731",
  "payload": {
    "field": "mailingAddress",
    "oldValue": "12 Oak St",
    "newValue": "48 Pine Ave"
  },
  "timestamp": "2026-09-24T14:32:10Z"
}
```

### GET /audit/events?resourceType=ACCOUNT&resourceId=acct-88731&limit=2

Sample response:

```json
{
  "items": [
    {
      "id": 3,
      "eventType": "RECORD_UPDATED",
      "actorId": "user-1042",
      "resourceType": "ACCOUNT",
      "resourceId": "acct-88731",
      "payload": {
        "field": "mailingAddress",
        "oldValue": "12 Oak St",
        "newValue": "48 Pine Ave"
      },
      "timestamp": "2026-09-24T14:32:10Z",
      "contentHash": "9f2c…e1a7",
      "previousHash": "41b8…0c3d"
    }
  ],
  "nextCursor": null
}
```

### Verify chain (GET /audit/verify)

Sample request:

```
GET /audit/verify
```

Intact:

```json
{ "intact": true, "recordsChecked": 120 }
```

Tampered:

```json
{
  "intact": false,
  "recordsChecked": 42,
  "firstBrokenRecordId": 42,
  "violationType": "CONTENT_HASH_MISMATCH",
  "detail": "Stored contentHash does not match recomputed hash"
}
```

Violation types: CONTENT_HASH_MISMATCH, BROKEN_LINK

## 4. Questions and decisions

| Quesiton                                           | Decision                                                                                                                       | Why                                                                                                                                                                                                         |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Who sets timestamp: Caller or server?              | Server                                                                                                                         | Single source of truth for all the systems. Avoids user bypassing time-clock and unfair ordering                                                                                                            |
| Timestamp format?                                  | UTC ISO 8601 with Z                                                                                                            | Standard format                                                                                                                                                                                             |
| eventType / resourceType: fixed list or free text? | Free text matching UPPER_SNAKE_CASE, max 64 chars; Conventional values documented                                              | Service must accept events from many systems without code changes; format rule still reject bad input                                                                                                       |
| Which hash algorithm?                              | SHA-256                                                                                                                        | Widely used secure standard that generates a 256-bit code. Commenly used in Blockchain systems                                                                                                              |
| What exactly goes into a record's hash             | event fields + previous hash;sensitive payload fields use their salted field hash instead of the raw value (see scenario-b.md) | Together these form a hash chain: any modification to a past record invalidates its own hash and every hash that follows it, making tampering detectable; Allows later redaction without breaking the chain |
| Serialization before hashing?                      | Canonical JSON (sorted keys, fixed format)                                                                                     | Same record must always produce same hash                                                                                                                                                                   |
| Genesis Value                                      | Square root of the first 8 prime numbers (2, 3, 5, 7, 11, 13, 17 and 19)                                                       | Using square roots of primes creates "nothing-up-my-sleeve" numbers to prove                                                                                                                                |
| How are simultaneous writes kept in order          | Database write lock                                                                                                            | Writed to database are queued up. Helps to process one request at a time                                                                                                                                    |
| Pagination type for the api                        | Cursor-based pagination + limit                                                                                                | Fast for largere datasets, infinite scroll feeds                                                                                                                                                            |
| Can resourceId be used without resourceType?       | No: resourceId needs resourceType. resourceType can be used alone.                                                             | ID's may repeat across types, so an ID alone is ambiguous                                                                                                                                                   |
| What inputs are rejected                           | Missing fields,bad formats, unknown fields, invalid timestamps, oversized payload, unknown fields                              | Bad data cannot be fixed later in an append-only log                                                                                                                                                        |
| What does audit/verify endpoint report?            | Content hash mismatch, Broken link                                                                                             | Content hash mismatch: Record data was edited; Broken link: PreviousHash doesn't match the preceding record iteself, Covers for deleted records                                                             |

## 5. Tasks

| #   | Task                 | Needs    | Done when                                                                                                      |
| --- | -------------------- | -------- | -------------------------------------------------------------------------------------------------------------- |
| A1  | Database Table       | -        | Table name: audit_events; Store all event fields, both hashes, and an order number                             |
| A2  | Hashing              | -        | Same data always gives the same hash; sensitive fields hashed via salted field hash                            |
| A3  | Save with chain link | A1, A2   | Eash record link to its previous hash, first links to genesis;parallel writes still produce one unbroken chain |
| A4  | POST /audit/events   | A3       | Saves valid events into database, rejects bad inputs, no update/delete                                         |
| A5  | GET /audit/events    | A1       | Filters and Pagination work                                                                                    |
| A6  | Verify logic         | A2       | Finds each problem type                                                                                        |
| A7  | GET /audit/verify    | A6       | Returns intact or first bad record + problem type (CONTENT_HASH_MISMATCH, BROKEN_LINK)                         |
| A8  | Tamper test + demo   | A4, A7   | Direct DB edit is detected                                                                                     |
| A9  | Update docs          | A1 to A8 | Docs match the code built                                                                                      |

## 6. Execution notes

| #   | Task | Area            | Notes                                                                                                                                                                  |
| --- | ---- | --------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | A1   | Storage         | `audit_events` in `storage/models.py`; `id` is SQLite `AUTOINCREMENT` (chain order, never reused); `timestamp` stored as the exact hashed string `YYYY-MM-DDTHH:MM:SSZ` |
| 2   | A1   | Storage         | Also holds `content_hash`, `previous_hash`, `archived`, `field_hashes`, `field_salts`; content columns nullable only for retention, check constraint on non-archived rows |
| 3   | A2   | Hashing         | All in `domain/hashing.py`, stdlib only; canonical JSON = `sort_keys=True`, `separators=(",", ":")`, `ensure_ascii=False`, `allow_nan=False`, UTF-8                     |
| 4   | A2   | Hashing         | Content hash covers event fields, timestamp, payload (sensitive keys removed), `fieldHashes`, `previousHash`; `archived` and `fieldSalts` excluded                      |
| 5   | A2   | Hashing         | Field hash = SHA-256(32-byte salt + canonical value); genesis `6a09e667...5be0cd19` from square roots of first 8 primes                                                  |
| 6   | A3   | Append          | `append_event` in one transaction: read last `content_hash` (or genesis), set server timestamp, hash `SENSITIVE_FIELDS`, compute content hash, insert                    |
| 7   | A3   | Write lock      | `make_engine` issues `BEGIN IMMEDIATE`, so parallel appends run one at a time and timestamps never decrease in `id` order                                                |
| 8   | A4   | POST validation | `EventCreate` rejects missing/unknown/server-owned fields, coerced types, bad UPPER_SNAKE_CASE, IDs over 255 chars or with whitespace, payload over 16 KiB or NaN (`422`) |
| 9   | A4   | API             | Returns `201`; `422` body omits `input`; `PUT`/`PATCH`/`DELETE` give `405`, `/audit/events/{id}` gives `404`; `create_app` wires engine and per-request `Session`        |
| 10  | A4   | Config          | `config.py`: `SENSITIVE_FIELDS` (comma-separated, empty default), `DATABASE_URL` (default `sqlite:///./audit_log.db`)                                                     |
| 11  | A5   | Query           | `query_events` in `storage/repository.py`: non-archived records in `id` order; keyset pagination (`id > cursor`), fetches `limit + 1` to set `nextCursor` (string id, `null` on last page) |
| 12  | A5   | GET validation  | `EventQuery` rejects unknown params, bad filter formats, `resourceId` without `resourceType`, `from >= to`, `limit` outside 1–200 (default 50), bad cursors (`422`) |
| 13  | A5   | Time range      | `from`/`to` need ISO 8601 with `Z` or offset (epochs/naive refused); normalized to stored UTC string, fractional seconds rounded up so `>= from` / `< to` stay exact |
| 14  | A5   | API             | Items add `contentHash`, `previousHash`; salts never returned; sensitive key with field hash but no salt shown as `"[REDACTED]"` (scenario B)                               |
| 15  | A6   | Verify logic    | `verify_chain` in `domain/verification.py`, stdlib only, reuses `domain/hashing.py`; reads records via a `ChainRecord` protocol, so no DB types in the domain; stops at first violation |
| 16  | A6   | Violation types | Per record in `id` order: `INVALID_ARCHIVE` (archived after non-archived, scenario B), `BROKEN_LINK` (previousHash ≠ prior contentHash or genesis), `CONTENT_HASH_MISMATCH` (recomputed hash differs) |
| 17  | A6   | Archived/fields | Archived records: link check only (content cleared); sensitive value with salt checked against its field hash (`CONTENT_HASH_MISMATCH`), redacted fields skipped; deleting newest records is not detectable |
| 18  | A7   | API             | `GET /audit/verify` in `api/verify.py` only wires `iter_chain` → `verify_chain` → `VerifyResponse`; always `200`; intact omits violation fields; `recordsChecked` includes the broken record |
| 19  | A7   | Storage read    | `iter_chain` streams all records (including archived) in batches of 500 under the SQLite write lock, so appends wait and verify sees one consistent chain                   |

## 7. Validation

{Filled after build.}
