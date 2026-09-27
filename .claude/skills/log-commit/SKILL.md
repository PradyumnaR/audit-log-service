---
name: log-commit
description: Fill the Commit field of the latest AI usage log entry with the latest commit hash. Use only when the engineer runs /log-commit.
allowed-tools: Read, Edit, Bash(git log:*)
disable-model-invocation: true
---

1. Run `git log --oneline -1` to get the latest short commit hash.
2. Read docs/ai-usage-log.md and find the last entry.
3. In that entry only, replace the Commit value "TODO (engineer)" with the hash.
4. If the last entry's Commit is already filled, stop and report it; do not change anything.
5. Do not edit any other part of the file.
