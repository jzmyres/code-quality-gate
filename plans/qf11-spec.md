# QF11: the coverage runner verifies the effective coverage install without importing the gate

Repository: `~/code-quality-gate`. Work only in the clone `/home/work/code-quality-gate/.worktrees/qg1`. Read
`CLAUDE.md` (every subprocess goes through `runner.py`), `quality_gate/covrun.py`, `quality_gate/tools.py`
(`verify_tool_directory`, the payload digest), `quality_gate/coverage_tool.py`, the trust root's lock override, the
tests for covrun and tools, and finding 3 of `plans/review-astra-gate-2026-10-26.md` first.

Why (Astra's batched review, 2026-10-26, finding 3, with timings): `covrun.py` verifies the coverage install by
starting another interpreter, which loads the bundled `tools.lock.toml`. It does not use the effective lock
(`--policy-from` or an authorized lock), so parent and child can disagree, and an authorized coverage upgrade fails
against the bundled pin. The extra interpreter costs about 44 ms per coverage invocation, against about 1 ms for the
digest itself. It also calls `subprocess.run` directly, which CLAUDE.md forbids.

## Changes

1. The parent passes the effective coverage descriptor (version and `payload_sha256`) to `covrun` explicitly.
2. A small standard-library verifier module computes the payload digest exactly as `tools.py` does. `tools.py` and
   `covrun.py` both use it, so the measured interpreter never imports `quality_gate`, and covrun starts no extra
   interpreter.
3. The direct `subprocess.run` in `covrun.py` is gone.

## Tests

The parent and covrun agree under an authorized lock that differs from the bundled one (failing first). A tampered
coverage payload still fails in covrun with a message naming the tool and path. The fixed digest oracle from QF9
covers the shared verifier.

## Docs

README (coverage runner) and `docs/TRUST.md` where tool verification is described. Commit label `fix (covrun
verifies the effective coverage install)`.

ACCEPT: make -k check
