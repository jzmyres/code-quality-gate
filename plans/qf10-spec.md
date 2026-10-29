# QF10: the trust root closes its remaining gaps (prune exemption, lint configuration, git invocation)

Repository: `~/code-quality-gate`. Work only in the clone `~/code-quality-gate/.worktrees/qg1`. Read
`CLAUDE.md`, `docs/TRUST.md`, README (the trust root, `--prune`), `quality_gate/trust.py`, `quality_gate/files.py`,
`quality_gate/gate_result.py`, `quality-gate.toml`, `tests/test_trust.py`, and findings 2, 7 and 8 of
`plans/review-astra-gate-2026-10-26.md` first.

Why (Astra's batched review, 2026-10-26): three gaps remain after QF9.
- **Finding 2.** A successful prune exempts every change to that baseline path from identity validation
  (`_prune_exemption`). A check can weaken an authorized live baseline during the run, and pruning then keeps the
  weakened value. Astra reproduced it in memory: a test floor went from 371 to 1, one test was measured, and the
  result said `accepted`.
- **Finding 7.** `ruff.toml` is outside the protected scope, so `--policy-from` still lets a candidate weaken lint.
- **Finding 8.** Only `trust.py` disables candidate-configured git callbacks. Astra confirmed that `ls-files -s`
  in `files.py` runs a configured `core.fsmonitor` program.

## Changes

1. **Identity before pruning.** Validate identities after the checks and before pruning. After pruning, a
   pruned baseline path may differ from its pre-prune content only by exactly the bytes the gate generated. Any
   other difference fails the run, naming the path.
2. **The lint configuration is protected.** The repository's own policy protects `ruff.toml`, and the Ruff check
   passes it explicitly (`--config ruff.toml`), so a discovered configuration file elsewhere cannot change lint
   policy. Document this in the policy example for adopters.
3. **One git invocation.** One helper builds every git command the gate runs on a candidate repository
   (`files.py`, `trust.py`, `gate_result.py`), with `--no-replace-objects`, `core.fsmonitor=false` and the existing
   `safe.directory`. No module builds its own git argument list.

## Tests

Write each test failing first: a check that rewrites an authorized floor during the run, then a successful prune,
must fail; a candidate `ruff.toml` that disables a rule must be ignored under `--policy-from`; a candidate repository
with `core.fsmonitor` set must not run that program from any gate command (record it with a marker file).

## Docs

`docs/TRUST.md`, README (pruning, protected scope). Commit label `fix (the trust root closes its remaining gaps)`.

ACCEPT: make -k check
