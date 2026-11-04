---
name: time-limits
description: Checklist for changing the gate's run limit, per-check deadline, subprocess budgets or step names.
verified: 2026-11-04
commit: 3169f1d6d9a2
paths: quality_gate/runner.py, quality_gate/checks.py, quality_gate/cli.py, quality_gate/worklist.py, quality_gate/python_tests.py, quality_gate/clones.py, quality_gate/verification.py, tests/test_check.py, tests/test_worklist.py, tests/test_runner.py, tests/test_command_checks.py, tests/test_python_tests.py, README.md, docs/SCHEMA.md
---

# Changing time limits

QF118 replaced supervised analysis workers with one run limit; there is no worker registry, cancellation or
`analysis_step` left. `checks` owns the run limit and the per-check context; `runner` owns each subprocess.

1. **Keep exactly two budgets.** The run limit is `checks._run_limit(selected_checks)`: the sum of
   `_check_budget(check)` over the checks that run plus `RUN_ALLOWANCE_SECONDS = 300`; `_run_policy_checks`
   passes every configured check for a full run and the selected ids for `check --only`. A subprocess gets
   `runner.remaining_budget(seconds)`, the smaller of its own seconds and the current check's remaining time,
   and `runner._run_budget` sets its grace to 0 inside a check. The allowance is required: the timer starts
   before every subprocess, so a limit equal to the budgets makes the run win over a hanging last check, and that
   check must report `execution = "budget"` instead. Do not shrink or remove the allowance to make a test faster.
2. **Arm once, disarm last.** `checks._run_policy_checks` calls `_arm_run_limit` (saves the previous
   `SIGALRM` handler, sets `ITIMER_REAL`) before its loop and `_disarm_run_limit` (zero timer, restore handler)
   in the outer `finally`. The loop removes its one `qg-run-` directory in an inner `except`/`else` before that
   `finally`: a failed removal on a normal end raises `checks.RunCleanupError` (a `UsageError`, exit 2), while
   a run that already raised prints the removal message and keeps its own exception. The handler raises
   `runner.RunTimeout`, a `policy.UsageError` (exit 2); `cli._main` already prints it and writes the JSON error
   document. Its message names the limit, the allowance, the check and the step from `runner._check_deadline`,
   whose default is None.
3. **Name every in-process phase.** `checks.run_check` enters `runner.check_deadline(check.id, start,
   _check_budget(check))` for the check, so the step starts as "check setup"; call `runner.mark_step("...")`
   before analysis work. Every phase now calls `mark_step` (44 call sites); a missing mark reports the previous
   step. Give each new phase a distinct name that a user can act on.
4. **The interrupt must kill the child.** `runner.run` starts the child with `start_new_session=True`, wraps
   `_capture_process` in `except BaseException`, calls `_kill_and_wait` (SIGKILL to the process group, then
   `wait`) and re-raises. A new exception path must leave that handler intact; the timer's handler can fire in
   the middle of any in-process call, including a regular-expression match.
5. **Do not move the subprocess-budget tests.** `tests/test_python_tests.py:test_timeout_reports_budget` and
   `tests/test_command_checks.py:test_continuous_output_is_stopped_at_the_check_deadline` (the 3.0 s bound)
   pass unchanged. If a limit change forces one wider, the limit is wrong. Add `RunLimitTests` cases in
   `tests/test_check.py` instead: a registered stub adapter, `cli.main` called in-process, and
   `mock.patch.object(checks, "RUN_ALLOWANCE_SECONDS", ...)` with 0 and 1; assert exit 2, the limit and check
   names in stderr, the JSON error document, and after both a passing run and a timeout that
   `signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)` and `signal.getsignal(signal.SIGALRM)` is the
   handler installed before the run. Add a `--only` case whose selected sleep has budget 1 and whose
   unselected sleep has budget 100: the run limit message must name `1 s limit`, so the limit sums only the
   checks that run. When the loop changes, also point `TMPDIR` at a fresh directory and assert no `qg-run-`
   entry remains after a pass, a failure and a stopped run; `RunLimitTests` and `WorklistRunLimitTests` do
   this.
6. **Probe the kill with the liveness test, not `killpg`.** `tests/test_runner.py:RunInterruptTests` arms a
   real `ITIMER_REAL` at 1 s whose handler raises, runs `sh -c 'echo $$ > PIDFILE; sleep 30 & wait'` with
   `budget_seconds=60`, and asserts the run raises, the timer is disarmed and `runner._group_alive(pid)` is
   False. Do not assert that `os.killpg(pid, 0)` raises `ProcessLookupError`: a killed child can stay a
   zombie in the group, so `killpg` still succeeds; the QF120 spec reports CI failing on exactly that.
   `_group_alive` asks `killpg` first (`ProcessLookupError` is dead, another `OSError` alive) and then, on
   Linux, scans `/proc/*/stat` with `_proc_group_member` for a member of the group whose state is not `Z` or
   `X`; `_process_finished` uses it, so a finished command whose orphan a container's PID 1 never reaps
   completes instead of failing at its budget. `GroupAliveTests` covers a zombie group, a running group and an
   unreaped orphan through a child that sets `PR_SET_CHILD_SUBREAPER` and never reaps, and
   `ProcGroupMemberTests` covers the stat-line cases on files it writes.
7. **Run the focused tests and the lint.** `python3 -I -m unittest discover -s tests -p test_runner.py`, the
   same for `test_check.py`, `test_worklist.py`, `test_command_checks.py` and `test_python_tests.py`, then the
   Ruff command from CLAUDE.md on the changed Python files. Before finishing, `grep -rnw` outside `.agents`
   for `analysis_step`, `StepTimeout`, `WorkerError`, `check_time`, `record_diagnostics`,
   `install_worker_measurement`, `WorkerMeasurement`, `process_setup`, `setup_process` and
   `_register_session`; the owner runs the gate.
