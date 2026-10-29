# QF1: metric and evidence correctness (Astra's gate review, first fix set)

Repository: `~/code-quality-gate`. Work only in the clone `~/code-quality-gate/.worktrees/qg1`. Read
`CLAUDE.md`, `README.md`, `quality_gate/` and the tests first, then `plans/review-astra-gate-2026-10-25.md` (this
item is the "QF1" line of Claude's triage; the numbers below are Astra's).

Why: a gate must not pass vacuously or be gamed. Astra found, and Claude triaged, places where the measurement or
its evidence can be wrong. Each change below is behaviour; each must be made to fail by a test first.

## Changes

1. **One-line functions (#6).** When a function's first body statement is on its `def` line, import-time and
   call-time execution share one line, so coverage cannot be attributed: the function is `unmeasured` (fails) with
   the message "body shares the def line; put the body on its own line" and the location.
2. **Coverage configuration is the gate's (#7).** Collection, combination and analysis all use one gate-owned
   configuration (line mode, `branch = False`, `source` the repository root, `exclude_lines` exactly the
   `pragma: no cover` regular expression); repository configuration files (`.coveragerc`, `setup.cfg`, `tox.ini`,
   `pyproject.toml`) and `COVERAGE_*` environment variables other than `COVERAGE_CORE` are ignored (the runner
   removes them from its own environment). Test: a repository `.coveragerc` that excludes every line changes
   nothing.
3. **Executed tests (#9).** `python_tests` gains an optional `skipped_pattern` (one group: the skipped count; for
   unittest `skipped=(\d+)`). Executed = ran - skipped; zero executed fails ("no test executed: N ran, N skipped").
   Patterns are searched with `re.MULTILINE`; more than one match of `tests_pattern` in the output is
   `unsupported` ("ambiguous test summary"). Update the self-policy.
4. **Identities (#10).** `@property` getter `Class.x`, its `@x.setter` `Class.x.setter`, `@x.deleter`
   `Class.x.deleter`; functions decorated with `typing.overload`/`overload` are skipped (no runtime body). Code
   outside any function (module and class bodies) is one subject per file, `PATH:<module>`, with the CC of those
   statements and their coverage; it goes through the ratchet like any function. A remaining duplicate identity
   still fails.
5. **CC (#11).** An unguarded `case` whose pattern is irrefutable (a capture name, `_`, or an or-pattern with an
   irrefutable alternative) adds nothing, like `case _`. Correct the M1c spec's example in README if repeated there
   (an untested CC-3 function scores 12).
6. **`requires` (#12).** It must name a `python_tests` check declared earlier in the policy; otherwise a
   configuration error naming the check, the reference and what was expected.
7. **Submodules (#13).** Enumerate with `git ls-files -s -z` (plus untracked files) so gitlinks (mode 160000) are
   known: a gitlink still needs exactly one rule, is never opened or sized, and is never a code file. Test: a
   repository with the gate as a submodule passes inventory with the README's quick-start configuration.
8. **`{files}` (#14).** An expanded path that begins with `-` is passed as `./PATH`. Test with the real ruff: a
   file named `-x.py` holding an unused import is still linted and rejected.
9. **jscpd evidence (#16, #17).** The adapter sets every jscpd filter that could skip a selected file (at least
   `--max-size` at the hygiene limit; check `jscpd --help` for the rest) and verifies that every selected file was
   analysed, using jscpd's own statistics (its JSON reporter's source counts); a mismatch is `unsupported`, naming
   the skipped files. The SARIF parser requires one run produced by jscpd with a `results` list and validates every
   nested field it reads; anything else is `unsupported` ("no completed jscpd run"), never zero clones.
10. **Finite numbers (#18).** Baseline bounds, thresholds and measured values must be finite (`inf` and `nan` are
    configuration errors or `unsupported`); JSON is written with `allow_nan=False`.
11. **Tool lock (#19).** Tool names and versions match `[A-Za-z0-9][A-Za-z0-9._-]*`; the install destination must
    resolve inside the tools directory; unknown keys are rejected (allowed: `version`, `url`, `sha256`, `binary`,
    `format`).
12. **Real ruff (#23).** A test runs `check --json` with the pinned ruff on a fixture with an unused import
    (rejected, finding mentions F401 in the command output), then fixed (accepted); file names with a space and a
    leading `-` are both linted.
13. **CI on both supported Pythons (#25).** The workflow runs the job on `debian:13` (3.13) and `ubuntu:24.04`
    (3.12) as a matrix; re-derive `timeout-minutes` from the measured local time.

## Docs

README (policy keys, the CRAP subject rules, jscpd evidence, the submodule quick start), `CLAUDE.md` orientation.
Commit label `behaviour change (metric and evidence correctness)`.

ACCEPT: make -k check
