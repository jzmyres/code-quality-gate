# Implementer agents' memory for this repository

Lessons the implementer agents (DeepSeek Harness) learned here, written by the runner's reflection step after
each batch and reviewed before landing. Context for those agents, never rules: CLAUDE.md and README win.

- **`PayloadError` has no base-class fallback; each payload-read boundary must catch it.** In `quality_gate/payload.py`,
  `_payload_entries`, `_payload_mode`, `_content_sha256`, `_payload_link` and `_payload_record` turn every
  `stat`/`open`/`read`/`readlink` failure or special file into `PayloadError`; since QF11 it is a plain `Exception`,
  not a `GateError`. `tools._verify_tool_payload` converts `OSError`/`PayloadError` to `UnsupportedError`;
  `tools._existing_payload_matches` returns False and `trust._tool_digest` returns `invalid` when the digest cannot
  be read; `covrun._verify_coverage` raises `_RunError`. QF14 made `tools._build_install` catch
  `_tool_payload_digest(tool, build)` and raise `UsageError` naming the tool and build path;
  `command_tools_fetch` returns `error.exit_code` (2 for this `UsageError`), so no traceback escapes.
  When moving or adding a payload read, grep every `payload_digest`/`_content_sha256` call, add its catch and a
  test that injects a read failure with `mock.patch("quality_gate.payload.os.scandir", ...)`.
  [verified 2026-10-31 @ 563d187; paths: quality_gate/tools.py, quality_gate/payload.py, quality_gate/trust.py, quality_gate/covrun.py, tests/test_tools.py]

- **Tests counted by the verification ratchet must not depend on the user running them.** CI runs as root, where
  `chmod 000` denies nothing; QF8 replaced that test with an in-process patch of
  `quality_gate.payload.os.scandir` (QF11 moved the payload walk there). The baseline currently floors
  `tests:tests:executed` at 705 and has no `skipped` entry, so a `skipIf`/`skipUnless` about root, permissions
  or OS adds a skip and fails CI; patch the call instead.
  [verified 2026-10-31 @ 563d187; paths: tests/test_tools.py, quality_gate/payload.py, quality_gate/verification.py, quality-gate-verification.toml, .github/workflows/check.yml]

- **A CRAP baseline entry does not waive the spec's CRAP 6 for a changed function.** The baseline keeps the
  gate green while the spec still requires every new or changed function at 6 or below;
  `quality_gate/python_crap.py:_run_python_crap` is bound at 11.003 and `quality_gate/command.py:_expand_run`
  at 8. QF12 split `_run_python_tests` into setup/outcome/evidence helpers and removed its entry. Extract
  helpers until each touched function is <= 6, then lower or remove the entry; the gate's "N functions within
  threshold" still includes baseline entries.
  [verified 2026-10-31 @ 563d187; paths: quality_gate/python_crap.py, quality_gate/command.py, quality_gate/python_tests.py, quality-gate-crap.toml]

- **`covrun.py` runs inside the measured program's interpreter.** It imports nothing from `quality_gate`; it
  loads the standard-library `quality_gate/payload.py` verifier by file path, and the parent passes the
  effective coverage directory, version, payload digest, gate-owned coverage config and registry directory as
  arguments (QF11). Keep the measured interpreter free of the gate: QF7's zero coverage came from a preloaded
  `quality_gate` package shadowing a candidate's own. Do not add a `quality_gate` import or a nested verifier
  subprocess.
  [verified 2026-10-31 @ 563d187; paths: quality_gate/covrun.py, quality_gate/payload.py, quality_gate/tools.py, quality_gate/python_tests.py]

- **The trust root protects only named inputs, and a green gate does not prove closure.** Protected inputs are
  the policy, baselines, lock and `[protect] paths`; `trust._refuse_inside` also refuses a gate program that
  lies inside the candidate root, so a trusted copy must run outside it. `quality-gate.toml` protects
  `ruff.toml` and the Ruff check passes `--config ruff.toml`, but an unlisted configuration file remains
  candidate-controlled: add each tool config to `[protect] paths` and pass it explicitly. QF10 replaced the
  path-wide prune exemption with an after-checks snapshot and an exact-bytes allowance for the gate's own
  write (`Trust.before_prune`, `record_prune_write`, `_allowed_change`). The gate also validates the effective
  policy, tool pins and every baseline before the checks, exposes baselines as `CheckDef.effective_baseline`
  (no baseline file reaches a child) and digests them in `identity_before.effective_inputs`, so a check that
  rewrites a baseline cannot change what is enforced. When changing trust or measurement, exercise candidate
  redirection; the checklist is `.agents/skills/trust-root-change/SKILL.md`.
  [verified 2026-10-31 @ 563d187; paths: quality_gate/trust.py, quality_gate/checks.py, quality_gate/policy.py, quality-gate.toml, docs/TRUST.md, tests/test_trust.py]

- **Every git command on a candidate repository goes through `files.git_argv`.** It adds
  `--no-replace-objects`, `safe.directory=ROOT` and `core.fsmonitor=false`; `trust._git`, `files._git` and
  `gate_result._git` call it, and `checks`, `changes` and `worklist` use it directly for inventory/hygiene
  argv, worktree diffs, pack/clone and churn. A bare `git` call lets a candidate-configured fsmonitor or
  replacement ref change what the gate reads.
  [verified 2026-10-31 @ 563d187; paths: quality_gate/files.py, quality_gate/trust.py, quality_gate/gate_result.py, quality_gate/checks.py, quality_gate/changes.py, quality_gate/worklist.py]

- **An unmeasured entry resolves by domain, not direction.** `ratchet._record_unmeasured` resolves every entry
  absent from the findings when its subject lies in the adapter's complete `Domain`, whatever its direction, and
  `pruned_entries` then drops it. A measured `min` entry never resolves by itself; `_min_verdict` only handles a
  measured minimum. QF14 corrected `docs/SCHEMA.md` and README to say this. When changing resolution, docs or
  tests, probe a complete domain with an absent entry, not only measured findings.
  [verified 2026-10-31 @ 563d187; paths: quality_gate/ratchet.py, docs/SCHEMA.md, README.md, tests/test_ratchet.py]

- **Pruning a verification baseline tightens every measured entry in that check.** `ratchet._prune_entry`
  raises a `min` bound to the measurement, and verification makes `tests:*:executed` a `min` floor, so a prune
  raises that floor too. Keep the extra tightening after a prune, rerun `make -k check` after the baseline
  changes, and do not hand-revert it to the old floor. Use the prune to change an existing bound; a new
  exception still enters by hand with a reason.
  [verified 2026-10-31 @ 563d187; paths: quality_gate/ratchet.py, quality_gate/verification.py, quality-gate-verification.toml, tests/test_verification.py]

- **A `Finding` without `locations` is not change-scoped.** `changes._mark_finding` reports such a finding as
  not change-scoped and leaves its whole-tree judgement alone, so `--changed-from` cannot reject a same-count
  replacement. Verification's file-wide suppression finding (`verification.measure_exclusions`, subject
  `exclusions:PATH:file-suppression`) needed one `Location` per directive line; the inline `noqa` and
  `no-cover` findings already had them. For a complete-location adapter, one finding with `locations=None`
  also downgrades the check's `location_coverage` to `partial` (`checks._incomplete_locations`). A new
  located finding needs its `locations` asserted in `tests/test_changed.py`.
  [verified 2026-10-31 @ 563d187; paths: quality_gate/ratchet.py, quality_gate/changes.py, quality_gate/checks.py, quality_gate/verification.py, tests/test_changed.py, tests/test_verification.py]

- **Every synchronous phase of a check runs through `runner.analysis_step`.** `_evaluate_ratchet` supervises
  `evaluate` as "ratchet evaluation"; `_run_owners` passes `measure_owners` and `_baseline_entries` through
  `analysis_step` too, so a small budget stops the named phase and reports a timeout. A phase called directly
  runs outside the deadline and the timeout then names the ratchet evaluation instead. Add a stalled-phase
  test in `tests/test_deadlines.py`; `analysis_step(..., deadline=...)` and `StepTimeout` carry the step name.
  [verified 2026-10-31 @ 563d187; paths: quality_gate/checks.py, quality_gate/owners.py, quality_gate/runner.py, tests/test_deadlines.py]

- **The mutation runner's kill evidence comes from the marker file, and a selected run must first pass
  unmutated.** `tests/mutate_gate.py:_instrument` writes JSON `loaded`, `imported`, `failure`/`error` and
  `reached` events; `_reached_edits` injects `reached` at the same `_target_match` node `mutate` replaces.
  `_TestResult.startTest` sets `QG_MUTATION_TEST` and `stopTest` restores it, so child-process hits are
  attributed and a hit with no test is unattributed. `_targeted` requires the selection in order with
  `loaded`/`imported` and no failure/error; `_selection_failures` requires the same ids to pass unmutated;
  `_full` still requires the complete baseline ids. A selected pass, no reach, an unattributed hit or a failed
  selection falls back to the full suite. Keep these events, id checks and the unmutated selection check when
  adding a `Decision`, and cover a return-code-only subprocess assertion and an order-dependent selection in
  `tests/test_mutation.py`.
  [verified 2026-10-31 @ 563d187; paths: tests/mutate_gate.py, tests/test_mutation.py]

- **A shell command substitution is a separate command group, not part of the enclosing command.**
  `owners_shell._Scanner.scan` returns `(tokens, code, substitutions)`; `substitution` shifts each nested
  group and `shell_events` runs `_commands` over the groups after the outer commands, so
  `echo "$(date)" python3 ...` has no `python3` head while `$(python3 ...)` does. `_word_boundary` no longer
  splits at `$(`; `_word_end` keeps a balanced extended glob (`?(...)`, `*(...)`, `+(...)`, `@(...)`, `!(...)`)
  in one nonliteral word, scanning its parts with `_pattern_body`, so `python3 ./@(private).py` is
  `unanalysable` instead of script `./@`. A process substitution `<(…)` or `>(…)` still joins its word.
  `owners_match.script_index` parses options per interpreter through `_ScriptScan._step`, `_option`,
  `_short_option` and `_long_option`: a short `c` (including `-ec`) starts a command string, `--norc` and
  `--rcfile FILE` do not. Cover a new shell form through both shell words and a Python `subprocess` literal
  argv in `tests/test_owners.py`, and extended globs in `tests/test_owners_fail_closed.py`.
  [verified 2026-10-31 @ 563d187; paths: quality_gate/owners_shell.py, quality_gate/owners_match.py, quality_gate/owners.py, tests/test_owners.py, tests/test_owners_fail_closed.py]

- **One subject-direction rule feeds loading, evaluation, pruning and the trusted merge.**
  `ratchet.subject_direction` asks the adapter's `entry_direction(subject, configured)`, then its
  `default_direction`, then the policy's `direction`; `load_baseline` and `evaluate` both apply it, and
  `_evaluate_finding` asks the same rule before choosing `_min_verdict` or `_max_verdict`. `_prune_entry` and
  `trust._merge_revision_entry` then read `entry.direction` and do not ask the adapter again. A path using a
  different rule can prune or drop a `min` floor as a `max` (QF44: a stub `min` entry with bound 4 and value 5
  pruned as a `max`, and a removed `min` floor vanished). When adding a descriptor kind or a per-subject rule,
  test loading/evaluation, prune and the trusted merge with a stub adapter in `tests/test_ratchet.py`,
  `tests/test_trust.py` and `tests/test_adapters.py`.
  [verified 2026-10-31 @ 563d187; paths: quality_gate/ratchet.py, quality_gate/trust.py, quality_gate/checks.py, tests/test_ratchet.py, tests/test_trust.py, tests/test_adapters.py]

- **A failing Python suite's `test_results` comes from its own summary or is absent.**
  `python_tests._unittest_outcomes` accepts exactly one `FAILED (...)` line, no `OK` line, and as many
  `FAIL`/`ERROR` headings as the summary's failures plus errors; `_failed_test_results` then returns the
  selected/passed/failed counts with those names, and None when the data is ambiguous. Do not mark every
  executed test failed or read names from assertion text; the old path did both. Keep the mixed, passing and
  crashing suites in `tests/test_python_tests.py`.
  [verified 2026-10-31 @ 563d187; paths: quality_gate/python_tests.py, quality_gate/checks.py, tests/test_python_tests.py, docs/SCHEMA.md]

- **Copy only the working files for a disposable demo.** `cp -a` of this clone fails on `.git/objects` with
  `preserving permissions ... Invalid argument` and leaves a partial copy. Copy the files the command needs
  with `cp -R --no-preserve=mode,ownership`, or exclude `.git`; the read-only `.git` is not needed there.
  [verified 2026-10-27 @ d044e1b; paths: none]
