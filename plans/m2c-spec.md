# M2c: verification loss is measured — a ratchet on executed tests, skips and exclusions

Repository: `~/code-quality-gate`. Work only in the clone `~/code-quality-gate/.worktrees/qg1`. Read
`CLAUDE.md`, `README.md`, `docs/SCHEMA.md`, `docs/TRUST.md`, the generic baseline/ratchet code, the `python_tests`
adapter, `quality_gate/trust.py` (baseline merge) and the tests first, then `plans/review-fable-tiered-design-2026-10-24.md`
(M2 row: "a verification-loss detector (deleted tests, added skips, lowered budgets, grown pragma counts)") and
`plans/review-sol-gate-2026-10-25.md` (finding 26).

Why: M2a authenticates the tools and M2b protects the policy and baselines, but an implementer can still make the
gate easier by weakening what the tests verify: deleting tests, adding skips, or excluding code from coverage
(`pragma: no cover`) or from lint (`noqa`). Each of these is a number that can move, so the gate can ratchet it.

## Changes

1. **Metric direction.** A check's metric declares `direction = "max"` (today's meaning: value must not exceed the
   bound; tightening lowers it) or `"min"` (value must not fall below the bound; tightening raises it). The ratchet,
   `--prune`, and M2b's baseline merge under `--policy-from` all respect it: for a `min` metric a candidate's raised
   bound is applied and a lowered one is ignored. Existing checks are `max`; the SCHEMA documents the field.
2. **A `verification` adapter.** For each `python_tests` check it measures `tests:CHECK:executed` (min: executed
   tests, `ran - skipped`) and `tests:CHECK:skipped` (max); for every measured Python file it measures
   `exclusions:FILE:no-cover` (max: lines carrying the coverage exclusion the gate's coverage configuration honours)
   and `exclusions:FILE:noqa` (max: `# noqa` comments). It reuses the test check's recorded counts (requires that
   check; no second test run) and reads source files once. Subjects and metrics follow the existing reasoned
   baseline format in `quality-gate-verification.toml`; a missing baseline entry means bound 0 for `max` metrics
   and makes a `min` metric `unmeasured` until a baseline entry exists (no plausible default).
3. **This repository adopts it.** `quality-gate.toml` enables the check; the baseline is measured from the current
   tree with reason "measured at adoption (M2c, 2026-10-25)". This spec authorises exactly those entries.

## Tests

Deleting a test lowers `executed` below its floor and fails; adding a skip raises `skipped` and fails; adding a
`pragma: no cover` or a `noqa` line fails; adding a test or removing an exclusion passes, and `--prune` records it
(floor raised, ceiling lowered); under `--policy-from`, a candidate that lowers a floor or raises a ceiling in the
baseline has it ignored, and one that tightens it has it applied; a `min` metric without a baseline entry is
`unmeasured`, never a pass.

Every new or changed function stays at CRAP 6 or below; the CRAP baseline may only shrink. Commit label
`behaviour change (verification-loss ratchet)`.

ACCEPT: make -k check
