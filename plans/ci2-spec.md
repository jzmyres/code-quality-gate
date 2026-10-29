# CI2: re-derive the CI timeout from the measured job time

TIER: trivial

Repository: `~/code-quality-gate`. Work only in the clone `~/code-quality-gate/.worktrees/qg1`.

The workflow's own rule (the comment above `timeout-minutes` in `.github/workflows/check.yml`) is the smallest
multiple of 5 minutes at least three times the measured time. The latest CI run (40188680325, after QF4) measured
the slower job at 101 s (debian:13; ubuntu:24.04 took 90 s): 3 x 101 s = 303 s, above 5 minutes. Set
`timeout-minutes: 10` and update the comment to state the CI measurement (101 s, run 40188680325) instead of the old
local one. Nothing else changes. `make -k check` passes. Commit label `fix`.

ACCEPT: make -k check
