# Scenario C — Compliance Reporting

## 1. Requirement understanding

Product: "Regulators need to be able to audit access to client account data." It doesn't define access, which data counts, or how regulators get the data.

## 2. Questions for Product

1. What counts as "access": views, updates, exports?
2. Which data is "client account data"?
3. How do regulators receive the data?
4. How are regulators authenticated?

## 3. Assumptions

| Question         | Assumption                         |
| ---------------- | ---------------------------------- |
| Access           | Views, updates, and exports        |
| Account data     | resourceType ACCOUNT               |
| Delivery         | A report API                       |
| Source of events | Calling systems send access events |
| Authentication   | Out of scope                       |

## 4. Clarified requirement

Provide a read-only report showing who viewed, updated, or exported client account data in a time range, filterable by account or actor.

## 5. Design decisions

| Question                          | Decision                                                                                              | Why                                    |
| --------------------------------- | ----------------------------------------------------------------------------------------------------- | -------------------------------------- |
| How are access events identified? | resourceType ACCOUNT + eventType ACCOUNT_VIEWED, ACCOUNT_UPDATED, ACCOUNT_EXPORTED                    | Reuses existing fields                 |
| Report endpoint?                  | GET /audit/reports/account-access?from&to[&resourceId or actorId]; resourceType is implicitly ACCOUNT | Read-only, matches regulator questions |

### Access event convention

Calling systems record each access to client account data by sending `POST /audit/events` with:

| Field          | Value                                                                  |
| -------------- | ---------------------------------------------------------------------- |
| `resourceType` | `ACCOUNT`                                                              |
| `resourceId`   | The account id                                                         |
| `actorId`      | Who accessed it                                                        |
| `eventType`    | `ACCOUNT_VIEWED` (read), `ACCOUNT_UPDATED` (change), `ACCOUNT_EXPORTED` (data taken out) |
| `payload`      | Optional context, e.g. channel or changed field; no raw account data   |

Sample `ACCOUNT_VIEWED` event:

```json
{
  "eventType": "ACCOUNT_VIEWED",
  "actorId": "user-1042",
  "resourceType": "ACCOUNT",
  "resourceId": "acct-88731",
  "payload": { "channel": "web", "view": "account-summary" }
}
```

Report request, for one account in September 2026 (`resourceId` and `actorId` are optional and combine with AND):

```http
GET /audit/reports/account-access?from=2026-09-01T00:00:00Z&to=2026-10-01T00:00:00Z&resourceId=acct-88731
```

The response has the same shape as `GET /audit/events`: `{"items": [...], "nextCursor": ...}`.

## 6. Scope

| In scope                                                                    | Out of scope                                    | Why out                                                        |
| --------------------------------------------------------------------------- | ----------------------------------------------- | -------------------------------------------------------------- |
| Access event convention (ACCOUNT_VIEWED, ACCOUNT_UPDATED, ACCOUNT_EXPORTED) | Authentication and regulator roles              | No auth system exists yet; needs product and security input    |
| Report endpoint: GET /audit/reports/account-access                          | Capturing reads in other systems                | This service only records events other systems send            |
| Required from/to; optional resourceId or actorId                            | Client data beyond ACCOUNT (statements, trades) | Needs Product to define which resources count                  |
| Same pagination and archived/redacted handling as GET /audit/events         | Failed or denied access attempts                | Not confirmed as "access"; can be added as an event type later |
| Tests for the report endpoint                                               | CSV/PDF formats, dashboards                     | Not needed to answer the core question                         |

## 7. Tasks

| #   | Task                             | Needs  | Done when                                                                |
| --- | -------------------------------- | ------ | ------------------------------------------------------------------------ |
| C1  | Document access event convention | A4     | Convention and a sample ACCOUNT_VIEWED event in scenario-c.md and README |
| C2  | Report endpoint                  | A5     | Returns account access events for the range and filters                  |
| C3  | Update docs                      | C1, C2 | Docs match the code                                                      |

## 8. Execution notes

| #   | Task | Area     | Notes |
| --- | ---- | -------- | ----- |
| 1   | C1   | Docs     | Access event convention and sample `ACCOUNT_VIEWED` event in §5 and README; constants `ACCOUNT_RESOURCE_TYPE` and `ACCOUNT_ACCESS_EVENT_TYPES` in `schema/reports.py` |
| 2   | C2   | Storage  | `EventFilter.event_types` (any of a set, SQL `IN`) added to shared `_live_matching`; `GET /audit/events` behaviour unchanged |
| 3   | C2   | Endpoint | `GET /audit/reports/account-access` (`api/reports.py`, `schema/reports.py`): fixed `resourceType` ACCOUNT and the three event types; `from`/`to` required (`from` < `to`, same ISO 8601 rules); optional `resourceId`, `actorId` (both may be given, AND); `limit`/`cursor` as events; unknown params (incl. `resourceType`, `eventType`) → 422; other methods 405 |
| 4   | C2   | Reuse    | Runs `query_events`, so pagination, `[from, to)` range, archived exclusion and `[REDACTED]` masking match `GET /audit/events`; response is `EventList`, built by new shared `EventList.from_page` (also used by `/audit/events`) |
| 5   | C2   | Tests    | Unit `test_account_access_query.py`, `test_repository.py` (`event_types` cases); integration `test_account_access_report.py` (type filtering, filters, range, pagination, archived, redacted, 422s, 405) |
| 6   | C3   | Docs     | scenario-c.md and README updated; docs/architecture.md not changed |

## 9. Validation

{Filled after build.}
