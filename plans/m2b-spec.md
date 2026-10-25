# M2b: the trust root — `qg check --policy-from REV`

Repository: `~/code-quality-gate`. Work only in the clone `/home/work/code-quality-gate/.worktrees/qg1`. Read
`CLAUDE.md`, `README.md`, `docs/SCHEMA.md`, `qg.py`, `quality_gate/` (policy loading, checks, baselines, the result
document, prune) and the tests first, then `plans/review-astra-gate-2026-10-25.md` (finding 2),
`plans/review-sol-gate-2026-10-25.md` (finding 26) and `plans/review-fable-tiered-design-2026-10-24.md` (M2 row).

Why: the gate reads its policy, baselines and tool lock from the working tree it is checking, so an implementing
agent can weaken what measures it: add a baseline exception or raise a bound, raise a threshold, remove a check,
add an exemption, narrow test discovery, weaken Ruff's configuration, change a tool pin, or edit the scripts the
checks run. Claude's landing checklist catches some of this by hand (QF1 added nine entries and sixteen raised
bounds before it was caught). M2's acceptance: a working-tree baseline edit is ignored under `--policy-from`; a
reviewed replacement passes.

## The contract (write it into `docs/TRUST.md`, linked from README and SCHEMA)

- **Parties.** The *candidate* is the working tree being checked (untrusted). The *trusted revision* REV is a commit
  chosen by the caller outside the candidate (a runner passes the batch's base commit; a person passes the commit
  they reviewed). The *gate program* is trusted only when it runs from a copy the candidate cannot modify.
- **Protected inputs** are, in REV: the policy file, every baseline file the policy names, the tools lock, and every
  path or glob listed in REV's policy under a new `[protect] paths = [...]` (for example `ruff.toml`, `Makefile`,
  CI workflows, test runners such as `tests/run_tests.py`). The protected list itself always comes from REV, so a
  candidate cannot unprotect a path. The gate reads REV's versions from Git objects, never from the working tree.
- **Effective inputs.** For each protected input whose candidate content differs from REV:
  - *Baseline files:* entries the candidate removes or whose bound it lowers are applied (tightening is always
    allowed); entries it adds, bounds it raises and reasons it changes are ignored and REV's entry is used.
  - *Authorized paths:* when the caller passes `--allow-protected PATH` (repeatable; a reviewed spec authorizes
    it), the candidate's version is used and reported as an authorized change.
  - *The policy file and tools lock, unauthorized:* REV's version is used.
  - *Any other protected path, unauthorized:* the decision is `blocked` (exit 1) with the path, because the gate
    cannot run REV's version of a file another program reads or executes; the checks still run and are reported.
- **Prune under `--policy-from`** writes REV's baseline lowered by the measurement: it never adds an entry, raises a
  bound or keeps a candidate-only entry.
- **Identity.** Before any check runs the gate records REV's commit id, each protected input's REV and candidate
  sha256, each pinned tool's payload digest (M2a) and a digest of the gate program's own files; after the checks
  it records them again. Any protected input, tool payload or gate file that changed during the run makes the
  decision `error` naming it.
- **Trusted invocation.** With `--policy-from`, the gate refuses (exit 2) when its own program files lie inside the
  candidate root, naming both paths: the caller must run a trusted copy (for a consumer, REV's pinned submodule
  commit extracted outside the candidate; for this repository, REV itself). Without `--policy-from` nothing changes
  (a developer checking their own tree trusts it).
- **Out of scope.** CI trust (the workflow file is part of the candidate; branch protection and review cover it)
  and verification loss inside test code (M2c: deleted tests, added skips, grown pragmas).

## Result document

A `trust` object (schema bump, documented in `docs/SCHEMA.md`): `policy_from` (REV id or null), `protected`
(one entry per protected input: `path`, `rev_sha256`, `candidate_sha256`, `status` one of `unchanged`, `tightened`,
`ignored`, `authorized`, `blocked`, plus `ignored_entries` for baselines), `identity_before`, `identity_after`.
`decision` gains `blocked`.

## Tests

Under `--policy-from`: an added baseline entry and a raised bound are ignored (the function fails as under REV) and
reported; a removed entry and a lowered bound take effect; a raised policy threshold and a removed check are
ignored; an unauthorized `ruff.toml` change is `blocked` while `--allow-protected ruff.toml` makes it pass and
reported as authorized; a candidate that deletes a path from `[protect]` still has it protected; prune never adds
or raises; a protected file modified by a check during the run is `error`; the gate refuses to run from inside the
candidate; a missing REV exits 2. Without `--policy-from`, existing behaviour and tests are unchanged. Build the
repositories in temporary directories with `git init`.

Every new or changed function stays at CRAP 6 or below; the baseline may only shrink. Commit label
`behaviour change (trust root: --policy-from)`.

ACCEPT: make -k check
