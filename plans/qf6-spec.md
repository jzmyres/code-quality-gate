# QF6: a coverage dataset counts when coverage saved it, however the program ended

Repository: `~/code-quality-gate`. Work only in the clone `/home/work/code-quality-gate/.worktrees/qg1`. Read
`CLAUDE.md`, `README.md` (the `python_tests` section on children and the registry), `docs/SCHEMA.md`,
`quality_gate/covrun.py`, `quality_gate/coverage_tool.py`, the adapter that calls them, and
`tests/test_python_tests.py` first.

Why: `covrun.py` writes `INVOCATION.started`, runs `coverage run`, and writes the completion record
`INVOCATION.json` only if `coverage_main` returns. When the wrapped program ends with an uncaught
`KeyboardInterrupt` (a SIGINT that lands outside the program's own handler), coverage still saves the dataset in its
own `finally`, but the exception propagates out of `coverage_main`, the completion record is never written, and the
gate reports `coverage invocation X did not finalize` and makes the tests evidence `unsupported` although the data
exists. Reproduced by Claude on 2026-10-25: `x = 1` then `raise KeyboardInterrupt`, run through `covrun.py` with
the pinned coverage, leaves the dataset on disk and `.started` without `.json`. A Python program stopped by SIGTERM
(default action) saves nothing at all. In a consumer's suite, whether a stop signal lands inside or outside the
program's handler is timing, so the same tree passes and fails: safe-agent-harness's gate failed 1 run in 4 on one
tree (HA2, 2026-10-25) and passed on the runner's retry.

## Changes

1. **Register the dataset up front.** `covrun.py` writes one registration record per invocation before the run,
   naming the dataset file it will use and the program it runs (the script path, or `-m MODULE`; not the remaining
   arguments, which may carry values a consumer would not want in gate output). The record is written atomically
   (temporary file, then rename). The separate completion record goes away (removal symmetry: code, docs, tests);
   nothing runs in `covrun.py` after `coverage_main`, so the wrapped program's exit status, signal death and
   traceback stay exactly as they are today.
2. **Complete means saved.** At combination, every registered invocation's named dataset must exist and load. A
   missing dataset (the process was killed before coverage could save, for example SIGKILL or `os._exit`) or an
   unloadable one stays `unsupported`, with a message naming the invocation, its program and its dataset. A record
   that is unreadable or names an unsafe dataset (not a plain file name) stays `unsupported` as today.
3. **SIGTERM saves.** The gate-owned coverage configuration sets `[run] sigterm = true`, so a Python child stopped by
   SIGTERM saves its dataset; coverage then re-delivers SIGTERM, so the child's exit status is unchanged.

## Tests (write each failing test first; real `covrun.py` with the pinned coverage, no mocks of coverage)

- A program that raises `KeyboardInterrupt` at top level: its dataset counts, combination succeeds, and the
  process still dies by SIGINT (as today).
- A program that prints a ready line and sleeps without a SIGTERM handler, stopped with SIGTERM after the test reads
  that line (no sleeps as synchronisation): its dataset counts and the process status is death by SIGTERM.
- The same program stopped with SIGKILL after the ready line: `unsupported`, and the message names the invocation,
  the program and the dataset.
- A registration record naming `../x` or an absolute path, and a truncated record: `unsupported` with the record's
  path, as today.

## Docs

README (the `python_tests` children paragraph: registration names the dataset; complete means saved; SIGTERM saves),
`docs/SCHEMA.md` if it describes the registry. Every new or changed function stays at CRAP 6 or below; the baseline
may only shrink (`--prune`), never gain an entry or a raised bound. Commit label
`behaviour change (coverage datasets count when saved)`.

ACCEPT: make -k check
