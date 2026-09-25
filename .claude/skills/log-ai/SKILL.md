---
name: log-ai
description: Draft a new AI usage log entry in docs/ai-usage-log.md. Use only when the engineer runs /log-ai.
argument-hint: <category> <title>
allowed-tools: Read, Edit
disable-model-invocation: true
---

Append one entry to docs/ai-usage-log.md for this session's work. Arguments: $ARGUMENTS

Rules:

- Use the next sequential number. Append only; never edit existing entries.
- Fill only: title, date, Category, and Prompt (factual, no self-evaluation).
- Leave Decision, Rationale, and Commit as "TODO (engineer)". Do not suggest values.

Categories: Implementation, Debugging, Refactoring, Test generation, Documentation, Review preparation, Analysis/Design.

Format:

## #{n} — {title} ({date})

- **Category:** {category}
- **Prompt:** {what you asked for, 1–2 sentences}
- **Decision:** TODO (engineer)
- **Rationale:** TODO (engineer)
- **Commit:** TODO (engineer)
