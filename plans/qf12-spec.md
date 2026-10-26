# QF12: _run_python_tests meets the CRAP threshold

Repository: `~/code-quality-gate`. Work only in the clone `/home/work/code-quality-gate/.worktrees/qg1`. Read
`CLAUDE.md` (cohesive abstractions, never fragmenting), `quality_gate/checks.py` (`_run_python_tests` and its
callers), `quality-gate-crap.toml`, and finding 4 of `plans/review-astra-gate-2026-10-26.md` first.

Why (Astra's batched review, 2026-10-26, finding 4): M2c changed `_run_python_tests`, whose cyclomatic complexity is
13, so it cannot reach CRAP 6. Only its baseline entry lets it pass.

## Change

A behaviour-preserving refactor. Split it into cohesive functions with meaningful names and independent tests, for
example setup, interpreting the execution result, and finalizing evidence. Each scores at or below 6, and the
baseline entry for `_run_python_tests` is removed. Error messages, result fields and evidence records stay
byte-identical; existing tests pass unchanged.

## Docs

None beyond the baseline. Commit label `refactor (python tests check: setup, outcome, evidence)`.

ACCEPT: make -k check
