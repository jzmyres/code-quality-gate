# QF5: a tracked file deleted from the working tree is a deletion, not a file

Repository: `~/code-quality-gate`. Work only in the clone `/home/work/code-quality-gate/.worktrees/qg1`. Read
`quality_gate/files.py` (enumeration, inventory, hygiene), its tests, and README's enumeration paragraph first.

Why: agents now work with a read-only `.git` (safe-agent-harness SH7), so they cannot stage deletions; the runner
stages and commits after the gate. When an agent deletes tracked files as its spec says (HA1 deleted
`inventory.tsv` and three test files), the gate still enumerates them from the index and fails inventory and hygiene
with "cannot inspect: No such file or directory". The gate must evaluate the working tree as it would be committed.

## Change

Enumeration excludes tracked entries that are deleted from the working tree (`git ls-files --deleted -z`): they are
not inspected, sized or classified, and a rule that now matches no file still fails as stale (that is a real
inventory change the agent must make). A tracked path whose worktree entry was replaced by something else (for
example a directory) is not "deleted" and keeps today's handling. README's enumeration paragraph says so.

## Tests

A fixture repository with a tracked file deleted from the working tree (not staged): inventory and hygiene pass and
do not mention it; its now-unmatched rule fails as stale; a staged deletion behaves the same. Behaviour label
`behaviour change (enumeration ignores worktree deletions)`.

ACCEPT: make -k check
