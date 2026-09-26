# Architecture

## Summary

The Audit Log Service is a tamper-evident, append-only audit log built with Python 3.13, FastAPI, Pydantic, SQLAlchemy and SQLite. Callers write events (who did what, to which resource, when) and query them, but can never update or delete them. Each record is linked to the previous one by a SHA-256 hash over canonically serialized content, forming a hash chain. A verification endpoint walks the chain and reports the first broken record and the type of violation.

## Architecture

| Scenarios  | Summary |
| ---------- | ------- |
| scenario-a | • **Append-only:** events can be written and queried, never updated or deleted.<br>• **Timestamps:** set by the server in UTC ISO 8601 with `Z`, so there is one source of truth for ordering.<br>• **Hash chain:** each record's SHA-256 hash covers its event fields plus the previous hash, serialized as canonical JSON (sorted keys, fixed format). The first record links to a genesis value derived from the square roots of the first 8 primes.<br>• **Write ordering:** a database write lock handles simultaneous writes one at a time, keeping the chain in order.<br>• **Input validation:** missing fields, bad formats, unknown fields, invalid timestamps and oversized payloads are rejected. `eventType` and `resourceType` are free text in UPPER_SNAKE_CASE, max 64 chars.<br>• **Querying:** filter by actorId, eventType, resourceType (+ optional resourceId, which requires resourceType) and time range, with cursor-based pagination plus limit.<br>• **Verification:** reports whether the chain is intact, or the first broken record with `CONTENT_HASH_MISMATCH` (record data was edited) or `BROKEN_LINK` (previousHash doesn't match the preceding record, e.g. a deleted record). |
