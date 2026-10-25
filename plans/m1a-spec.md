# M1a: split qg.py into a package (behaviour-preserving)

Repository: `~/code-quality-gate`. Work only in the clone `/home/work/code-quality-gate/.worktrees/qg1`. Read
`CLAUDE.md`, `README.md`, `qg.py`, `quality-gate.toml`, `Makefile` and `tests/support.py` first, then
`plans/review-fable-tiered-design-2026-10-24.md` sections 3 and 5 (the approved architecture; M1 is split into
M1a, M1b and M1c, and this is M1a).

Why (user approval 2026-10-24 of the tiered-gate plan): `qg.py` is 1,285 lines in one module. M1b adds a policy
`[checks]` layer, a generic ratchet and a JSON result, and M1c adds Python test and CRAP adapters; the core and
the adapters need separate homes first. This commit only moves code.

## Change

- A package `quality_gate/` next to `qg.py`, with one module per concern:
  - `policy.py`: the error classes, the configuration dataclasses, the TOML value helpers and `load_config`;
  - `files.py`: repository resolution, git enumeration, code detection, inventory and hygiene;
  - `tools.py`: the tool lock, fetch, extraction, checksum verification and `tools path`;
  - `clones.py`: jscpd invocation, SARIF parsing, the clone baseline and the `clones` command;
  - `cli.py`: the argument parser, `check` and `main`.
  Put a function where its concern is; if one does not fit, say where it went and why in the commit message.
- `qg.py` stays the entry point and the only documented command, `python3 -I qg.py`. `-I` leaves the script's
  directory off `sys.path`, so `qg.py` puts its own resolved directory first on `sys.path`, imports
  `quality_gate.cli` and exits with `main()`'s status. No other code stays in it.
- No behaviour change: every message, exit code, output stream and file written stays byte-identical. The
  existing tests must pass unchanged; do not edit them.
- `quality-gate.toml`: classify `quality_gate/*.py` as `python` with a reason, and keep `qg.py`'s rule
  (reason: the entry point). The Makefile's lint already takes its file list from the inventory.
- README: the layout paragraph names the package and its modules; `CLAUDE.md`: one orientation line.

## Done when

- `make -k check` passes (lint, all tests, the self-check including clones).
- `git diff --stat HEAD -- tests` is empty.
- No module exceeds 400 lines.

ACCEPT: make -k check && test -z "$(git diff --stat HEAD -- tests)"
