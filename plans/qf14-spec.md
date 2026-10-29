# QF14: payload errors are handled at installation, and the docs say when a minimum entry resolves

Repository: `~/code-quality-gate`. Work only in the clone `~/code-quality-gate/.worktrees/qg1`. Read
`CLAUDE.md`, `quality_gate/payload.py`, `quality_gate/tools.py` (`_build_install`, `command_tools_fetch`),
`quality_gate/ratchet.py` (`_record_unmeasured`), `docs/SCHEMA.md` (near line 250), README (near line 607), their
tests, and `plans/review-astra-gate-2026-10-26b.md` first.

Why (Astra's second gate review, 2026-10-26):
- **Finding 2.** QF11 made `PayloadError` independent of `GateError`, but installation still relies on the old
  inheritance. A payload read failure in `_build_install()` now escapes `command_tools_fetch()` as a traceback,
  where it used to give a handled diagnostic.
- **Finding 4.** The docs say a `min` entry never resolves. `_record_unmeasured()` resolves any subject absent from
  a completely measured domain whatever its direction, and pruning then removes the entry.

## Changes

1. At the installation boundary, catch `PayloadError` and raise a `GateError` that names the tool and the path.
   Test it by injecting a read failure during installation: a handled diagnostic, exit 2, no traceback.
2. `docs/SCHEMA.md` and README say that a measured minimum subject never resolves by itself, and that any subject
   absent from a completely measured domain resolves and is pruned, whatever its direction.

## Docs

As above. Commit label `fix (payload errors at installation; when a minimum entry resolves)`.

ACCEPT: make -k check
