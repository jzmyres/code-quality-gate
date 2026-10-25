# QF7: the coverage runner never shadows the measured program's imports

Repository: `~/code-quality-gate`. Work only in the clone `/home/work/code-quality-gate/.worktrees/qg1`. Read
`CLAUDE.md`, `README.md` (python_tests), `quality_gate/covrun.py`, `quality_gate/coverage_tool.py`, the
`python_tests` adapter that builds the `{python}` prefix, and `tests/test_python_tests.py` first.

Why: Claude smoke-tested M2b by running the landed gate (a trusted copy outside the candidate) with
`--policy-from HEAD` against a disposable clone of this repository. The tests passed (354), but CRAP reported zero
coverage for most of `quality_gate/` (for example `CheckResult.is_satisfied` 20.0, `_check_command` 156.0).
Cause: `covrun.py` puts its own repository at `sys.path[0]` and imports `quality_gate.coverage_tool` before
running the program, so when the measured program is this repository's test suite, its `import quality_gate`
returns the trusted copy's already-loaded package from `sys.modules`: the candidate's tests exercise the trusted
copy's code and the candidate's own code is never run. A runner that changes what the measured program imports
breaks the measurement for any consumer whose modules share a name with the gate's.

## Change

`covrun.py` imports nothing from `quality_gate` and leaves `sys.path` and `sys.modules` as the program would see them
when started as `python -I PROGRAM`: the adapter passes the coverage configuration path and the registry directory
as explicit arguments (it already computes both), and `covrun.py` uses only the standard library plus the pinned
coverage install. Update the `{python}` prefix, README and SCHEMA's description of the prefix.

## Tests

A fixture program whose own package is named `quality_gate` (with a function only it defines), run through the real
`covrun.py` from another directory, imports its own package and its function is covered; the existing covrun tests
keep passing with the new arguments. Claude repeats the smoke test after landing.

Every new or changed function stays at CRAP 6 or below; the baseline may only shrink. Commit label
`behaviour change (the coverage runner never shadows the program's imports)`.

ACCEPT: make -k check
