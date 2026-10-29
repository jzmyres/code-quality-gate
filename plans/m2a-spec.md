# M2a: installed tools are authenticated by their whole payload, at every use

Repository: `~/code-quality-gate`. Work only in the clone `~/code-quality-gate/.worktrees/qg1`. Read
`CLAUDE.md`, `README.md` (tools, `qg tools fetch`), `docs/SCHEMA.md`, `quality_gate/tools.py`,
`quality_gate/covrun.py`, `quality_gate/coverage_tool.py`, `tools.lock.toml` and the tool tests first, then
`plans/review-sol-gate-2026-10-25.md` (finding 26) and `plans/review-astra-gate-2026-10-25.md` (finding 2).

Why: M2 is the integrity milestone. Today `qg tools fetch` verifies the downloaded archive's sha256, but every
later use accepts an installed tool by the presence of one file (`binary` in the lock); a replaced or extra file in
the install tree, for example an exit-zero stub for Ruff or a modified coverage module, is executed and trusted.
Hashing one file would not help: coverage is a whole package of modules. Also, importing the installed coverage
writes `__pycache__/*.pyc` into its install tree (82 files exist today, from Python 3.12 and 3.13), and a `.pyc`
whose recorded source timestamp matches is loaded instead of the source.

## Changes

1. **Payload digest.** Define one canonical digest of an install tree: every entry under the tool's install
   directory in sorted relative-path order, each contributing its relative path, its type (file, directory,
   symlink), for files the executable bit and the sha256 of the content, and for symlinks the target text; any
   other file type makes the tree invalid. Document the exact encoding in `docs/SCHEMA.md` (it is a contract).
2. **The lock pins it.** Each tool in `tools.lock.toml` gains `payload_sha256`, written from a fresh install and
   reviewed like the archive digest. `qg tools fetch` installs into a temporary directory, verifies the archive
   digest, computes the payload digest, refuses (installing nothing) when it differs from the lock, and only then
   moves the tree into place. A lock entry without `payload_sha256` is a lock error.
3. **Verified at every use.** Before any gate step executes or imports a tool (Ruff, jscpd, the coverage package
   for `covrun` and for analysis), the gate recomputes the install's payload digest and compares it with the lock;
   a mismatch or an invalid tree is `unsupported` with a message naming the tool, the install directory, and the
   expected and actual digests, and nothing from that install runs.
4. **No bytecode in payloads.** Every import of the installed coverage package (in the gate process, `covrun.py`
   and the children it starts) runs with bytecode writing off (`sys.dont_write_bytecode` before the import, and
   `PYTHONDONTWRITEBYTECODE=1` in children's environment), so a verified tree stays byte-identical after use.
   Existing installs with `__pycache__` fail verification and must be reinstalled with `qg tools fetch` (no
   exclusion rule, no compatibility path); README says so.

## Tests

The digest is stable across runs and changes for: one changed byte, a flipped executable bit, an added file, a
removed file, a retargeted symlink; a FIFO in the tree is invalid. Fetch refuses a payload mismatch and leaves no
install; a tampered Ruff stub and a modified coverage module are each `unsupported` before they run; a full gate run
leaves the coverage install byte-identical (no `__pycache__`). Use small fixture "tools" built in temporary
directories; never download in tests.

## Docs

README (tools: payload digest, verification at use, reinstall after upgrading), `docs/SCHEMA.md` (the encoding).
Every new or changed function stays at CRAP 6 or below; the baseline may only shrink (`--prune`). Commit label
`behaviour change (installed tools are authenticated by payload)`.

ACCEPT: make -k check
