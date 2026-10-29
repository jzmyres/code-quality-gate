# QF13: the ratchet docs match the implementation, and test-only parsers are removed

TIER: trivial

Repository: `~/code-quality-gate`. Work only in the clone `~/code-quality-gate/.worktrees/qg1`. Read
`CLAUDE.md`, `docs/SCHEMA.md` (around the ratchet rules), README (the ratchet section), `quality_gate/ratchet.py`,
`quality_gate/python_tests.py`, its tests, and findings 9 and 10 of `plans/review-astra-gate-2026-10-26.md` first.

## Change

1. `docs/SCHEMA.md` and README state the three rules as the code implements them. A maximum metric without an
   entry passes at or below its threshold. A maximum entry resolves once the value is at or below the threshold. A
   minimum metric needs an entry. The zero-default statement applies only to verification metrics.
2. Remove `parse_test_summary` and `parse_test_count`, which only tests use, and test `regexrun` and
   `summarize_matches` directly.

## Docs

As above. Commit label `docs (ratchet rules) and dead code removal`.

ACCEPT: make -k check
