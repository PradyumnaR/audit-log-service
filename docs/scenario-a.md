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

{Filled during build.}

## 7. Validation

{Filled after build.}
