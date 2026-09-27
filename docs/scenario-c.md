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

| Question                          | Decision                                                                           | Why                                    |
| --------------------------------- | ---------------------------------------------------------------------------------- | -------------------------------------- |
| How are access events identified? | resourceType ACCOUNT + eventType ACCOUNT_VIEWED, ACCOUNT_UPDATED, ACCOUNT_EXPORTED | Reuses existing fields                 |
| Report endpoint?                  | GET /audit/reports/account-access?from&to[&resourceId or actorId]                  | Read-only, matches regulator questions |

## 6. Tasks

| #   | Task                             | Needs  | Done when                                               |
| --- | -------------------------------- | ------ | ------------------------------------------------------- |
| C1  | Document access event convention | A      | Convention in docs                                      |
| C2  | Report endpoint                  | A5     | Returns account access events for the range and filters |
| C3  | Update docs                      | C1, C2 | Docs match the code                                     |

## 7. Execution notes

{Filled during build.}

## 8. Validation

{Filled after build.}
