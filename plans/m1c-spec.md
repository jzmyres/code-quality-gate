# M1c: Python tests under coverage and Python CRAP, applied to the gate itself

Repository: `~/code-quality-gate`. Work only in the clone `~/code-quality-gate/.worktrees/qg1`. Read
`CLAUDE.md`, `README.md`, the package `quality_gate/` (M1a, M1b), `quality-gate.toml`, `tools.lock.toml`,
`tests/support.py`, and `plans/review-fable-tiered-design-2026-10-24.md` first.

Why (user approval 2026-10-24, including coverage.py as the one pinned non-standard-library dependency): tier 1
for Python needs two measurements the core then judges with the M1b ratchet: did the consumer's own tests run
(and how many), and how risky is each function (CRAP = CC² × (1 − cov)³ + CC, threshold 6, the same formula and
threshold as the editor's gate). The gate applies both to itself first.

## coverage.py, pinned

- `tools.lock.toml` gains `[coverage]`: version `7.16.2`, url
  `https://files.pythonhosted.org/packages/3f/0c/7a64e1ac90541a8edf50daef0914848011fb057a5bf55284a4811e21939a/coverage-7.16.2-py3-none-any.whl`,
  sha256 `11d28e9123a9156cb405d8d27b44256c9a58fb5decc2073a8f17862057e3aa0f`, `format = "wheel"`,
  `binary = "coverage/__init__.py"` (the file that proves the install). A wheel is a zip: `tools fetch` extracts
  it with `zipfile` under the same safety rules as tar members (no absolute paths, no `..`, no links). The
  install directory `<tools>/coverage-7.16.2` is what goes on `sys.path`. Archives without `format` stay tar.
- Claude has already installed exactly this layout in the tools cache (verified by sha256), so you can run it;
  you have no network. `tools fetch` must see it as installed.
- The pure-Python wheel has no C tracer: run coverage with `COVERAGE_CORE=sysmon` (Python 3.12+), line coverage
  only (`branch = False`). The metric is `python-lines/1`.

## Adapter `python_tests` (tier 1)

`[checks.ID]` keys: `run` (argument list, required), `tests_pattern` (required regular expression with one group:
the number of tests that ran), `budget_seconds` (default 900).
- The gate makes a fresh data directory and runs `run` from the repository root. The token `{python}` in `run`
  expands, in place, to a prefix that starts Python under coverage: the current interpreter, `-I`, and a small
  runner module of the gate (for example `quality_gate/covrun.py`) with the data directory and source root,
  which puts the coverage install on `sys.path`, sets `COVERAGE_CORE=sysmon` and calls coverage's own command
  line (`run --parallel-mode --data-file=... --source=ROOT`) on the rest of the arguments (a script, or `-m
  MODULE`).
- Tests that start the consumer's Python programs as subprocesses need the same prefix: the gate exports it as
  `QG_PYTHON`, a JSON array of strings, in the test command's environment. Document this contract in README: a
  test launcher that starts Python programs uses `json.loads(os.environ["QG_PYTHON"])` instead of
  `[sys.executable, "-I"]` when the variable is set, and passes it through to the child's environment.
- Outcome: `fail` when the command exits non-zero, times out (termination `budget`) or reports zero tests;
  `unsupported` when `tests_pattern` does not match (the count was not measured) or coverage is not installed
  (naming `qg.py tools fetch`). On `pass`, the adapter combines the data files; the combined data is the
  evidence for the checks that require it.

## Adapter `python_crap` (tier 1)

`[checks.ID]` keys: `requires` (the id of one `python_tests` check, required), `threshold` (default 6),
`baseline` (path; may not exist yet, meaning no entries). It measures the files of the classes listing it.
- If the required tests check did not pass, the outcome is `unsupported` with "coverage unreliable: check ID
  did not pass"; nothing is scored.
- **Functions**: every `def` and `async def` that is not inside another function: module level, and methods of
  classes at any depth that are not inside a function. Nested functions and lambdas belong to their enclosing
  function. Identity: `PATH:Qualified.name` with the repository-relative path (for example
  `quality_gate/policy.py:load_config`, `quality_gate/files.py:Rule.matches`). Two functions with the same
  identity in one file fail the check, naming both lines.
- **CC** (counted from `ast`, as a data table in one place): 1, plus one for each `if` (an `elif` is a nested
  `if`), conditional expression, `for`, `async for`, `while`, comprehension `for` clause and comprehension
  `if`, `except` handler (including `except*`), `match` case other than an unguarded `case _`, and each operand
  of `and`/`or` after the first. Nested function and lambda bodies add to the enclosing function.
- **cov**: from coverage's own analysis (`Coverage.analysis2` on the combined data, which also reports files the
  tests never imported, with every statement missing): the function's statements are those whose line falls
  between its first decorator or `def` line and its `end_lineno`; cov = executed ÷ statements. A function with no
  statements is `unmeasured` and fails; it is never scored as covered.
- Lines excluded by `# pragma: no cover` are reported per function in the finding's measurement
  (`excluded_lines`), so an added pragma is visible in the JSON result.
- Findings go through the M1b ratchet: `subject` is the identity, `value` the unrounded CRAP. The report rounds
  to one decimal only for display.

## The gate gates itself

- `quality-gate.toml`: a `tests` check (`python_tests`, `run = ["{python}", "-m", "unittest", "discover", "-s",
  "tests"]`, `tests_pattern = "^Ran (\\d+) tests? in"`) for the `test` class, and a `crap` check (`python_crap`,
  requires `tests`, baseline `quality-gate-crap.toml`) for the `python` class.
- `tests/support.py`'s launcher uses `QG_PYTHON` when set (the contract above), so the gate's own subprocess
  tests are measured.
- The baseline lists each current function above 6, measured by this commit, with reason "above 6 at adoption
  (M1c, 2026-10-24); worklist". Nothing else enters it.
- `make check` becomes `python3 -I qg.py check` plus nothing that duplicates a policy check: remove the
  Makefile's separate lint and test recipes if the policy now runs them (removal symmetry). Keep `make check`
  as the one entry point.
- `CLAUDE.md`'s "standard-library Python only" rule becomes: the core is standard library; the Python adapters
  load the pinned coverage wheel from the tools cache.

## Tests (each failure mode must be made to fail)

Fixture repositories with tiny Python packages and unittest suites, through the real command:
- tests pass with N tests; zero tests fails; a failing test fails; a timeout reports `budget`; an unmatched
  `tests_pattern` is `unsupported`; coverage missing is `unsupported`;
- a subprocess launched through `QG_PYTHON` is measured (its function's cov is above 0);
- CC table: one fixture function per construct, asserting the exact CC;
- an untested new function at CC 3 fails (CRAP 30 > 6); a fully covered CC-6 function passes; a baselined
  function exactly at its mark passes and one whose CRAP rises 0.1 above fails; a never-imported file's
  functions score at cov 0; a function's `# pragma: no cover` line appears in `excluded_lines`;
- `python_crap` whose tests check failed is `unsupported` and the decision is `rejected`;
- duplicate identity fails;
- `tools fetch` of a wheel: verifies the checksum and refuses an unsafe member (build the fixture wheel in the
  test; no network).

Commit label `behaviour change (Python tests and CRAP adapters)`.

ACCEPT: make -k check
