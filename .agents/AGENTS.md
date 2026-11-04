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
  [verified 2026-11-04 @ 84907174c50f; paths: quality_gate/tools.py, quality_gate/payload.py, quality_gate/trust.py, quality_gate/covrun.py, tests/test_tools.py]

- **Tests counted by the verification ratchet must not depend on the user running them.** CI runs as root, where
  `chmod 000` denies nothing; QF8 replaced that test with an in-process patch of
  `quality_gate.payload.os.scandir` (QF11 moved the payload walk there). The baseline floors
  `tests:tests:executed` at 675 (QF118) and has no `skipped` entry, so a `skipIf`/`skipUnless` about root,
  permissions or OS adds a skip and fails CI; patch the call instead. That floor is a `min` entry in a protected
  baseline: an unauthorized candidate edit that lowers it merges away (the trusted bound wins), while
  `--allow-protected quality-gate-verification.toml` makes `trust._apply_baselines` read the candidate baseline
  whole, so QF118 deleted the supervisor tests, authorized the file and measured 675 with verification passing.
  Without the authorization a lowered floor cannot take effect.
  [verified 2026-11-04 @ 84907174c50f; paths: tests/test_tools.py, quality_gate/payload.py, quality_gate/verification.py, quality_gate/trust.py, quality-gate-verification.toml, .github/workflows/check.yml]

- **A CRAP baseline entry does not waive the spec's CRAP 6 for a changed function, and deleting tests can
  uncover helpers only they covered.** The baseline keeps the gate green while the spec still requires every
  new or changed function at 6 or below; `quality_gate/python_crap.py:_run_python_crap` is bound at 11.003 and
  `quality_gate/command.py:_expand_run` at 8. QF12 split `_run_python_tests` into setup/outcome/evidence
  helpers and removed its entry. QF112 deleted the owners adapter with its ~800 test lines and the trusted gate
  then failed on five functions the owners tests were the only coverage for: runner's `_proc_member_command`,
  `_live_member` and `_live_group_members` (CRAP 30.0), `_pending_errors` (6.6) and policy's
  `_validate_fixed_header` (11.1). The validator had no caller left and went with its descriptor field; the
  runner helpers had callers and gained focused tests in `tests/test_runner.py`, and the next gate run passed
  CRAP. QF118 later deleted those helpers and their tests with the worker machinery, and its gate reported 751
  functions within threshold. Extract helpers until each touched function is <= 6, then lower or
  remove the entry; the gate's "N functions within threshold" still includes baseline entries, and no baseline
  entry is the fix for a function whose tests were deleted. QF120 restored `runner._proc_group_member` from
  `561a044` with the worker tests gone and the gate scored it 8.1; `ProcGroupMemberTests` in
  `tests/test_runner.py` then wrote real stat lines to a temporary directory for the vanished, unreadable and
  short-line branches, and the accept run reported 753 functions within threshold. Restored code needs its
  tests back with it.
  [verified 2026-11-04 @ 84907174c50f; paths: quality_gate/python_crap.py, quality_gate/command.py, quality_gate/python_tests.py, quality_gate/runner.py, quality_gate/policy.py, tests/test_runner.py, tests/test_policy.py, quality-gate-crap.toml]

- **`covrun.py` runs inside the measured program's interpreter.** It imports nothing from `quality_gate`; it
  loads the standard-library `quality_gate/payload.py` verifier by file path, and the parent passes the
  effective coverage directory, version, payload digest, gate-owned coverage config and registry directory as
  arguments (QF11). Keep the measured interpreter free of the gate: QF7's zero coverage came from a preloaded
  `quality_gate` package shadowing a candidate's own. Do not add a `quality_gate` import or a nested verifier
  subprocess.
  [verified 2026-11-04 @ 1bfa24f12813; paths: quality_gate/covrun.py, quality_gate/payload.py, quality_gate/tools.py, quality_gate/python_tests.py]

- **The trust root is one absolute trusted directory, and a green gate does not prove closure.** `--policy-from`
  takes only an absolute existing directory outside the candidate: `trust._directory_source` refuses a relative path
  or revision ("expected an absolute trusted directory"), a missing or non-directory path, and a directory inside the
  candidate; `prepare_trust` calls `_refuse_inside` so a gate program inside the candidate is refused too. Protected
  inputs are the policy, every baseline it names, `tools.lock.toml` and `[protect] paths` (a glob matches the union
  of trusted and candidate files); candidate versions are read with the non-following `_read_regular` and
  `_candidate_parent`. `trust._TrustedTree` is the only trusted reader: `_safe_join` plus
  `O_NOFOLLOW|O_NONBLOCK`, a symlink reads as missing, only successful reads are cached, `to_json` reports the path
  and digest, and `digest` hashes each read path, a NUL and the file SHA-256 in sorted order. `_materialize` writes
  the trusted policy and baselines to a temporary tree, and the gate validates the effective policy, tool pins and
  every baseline before the checks (`CheckDef.effective_baseline`, `identity_before.effective_inputs`). A baseline
  passed to `--allow-protected` is read whole from the candidate (`_required_candidate_entries`); any other
  changed baseline is merged entry by entry, so a tightening applies and a loosening is ignored. QF116
  refuses `--prune` with `--policy-from` as a usage error before any check; `_write_pruned` is the only remaining
  prune path and no trust identity exemption exists, so any protected or effective input, tool payload or gate file
  that changes during the run is an error. `quality-gate.toml` protects `ruff.toml` and the Ruff check passes it
  explicitly, but any other tool configuration must be added to `[protect] paths` and passed. `prepare_trust`
  removes its two temporary trees when `_prepare_source` raises (`PreparationCleanupTests` in
  `tests/test_trust.py`), so a failed preparation leaves nothing behind. The checklist is
  `.agents/skills/trust-root-change/SKILL.md`.
  [verified 2026-11-04 @ 84907174c50f; paths: quality_gate/trust.py, quality_gate/cli.py, quality_gate/checks.py, quality-gate.toml, docs/TRUST.md, docs/SCHEMA.md, tests/test_trust.py]

- **Every git command on a candidate repository goes through `files.git_argv`.** It adds
  `--no-replace-objects`, `safe.directory=ROOT` and `core.fsmonitor=false`; `trust._git`, `files._git` and
  `gate_result._git` call it, and `checks` and `worklist` use it directly for inventory/hygiene argv,
  pack/clone and churn. A bare `git` call lets a candidate-configured fsmonitor or replacement ref change
  what the gate reads.
  [verified 2026-11-04 @ 84907174c50f; paths: quality_gate/files.py, quality_gate/trust.py, quality_gate/gate_result.py, quality_gate/checks.py, quality_gate/worklist.py]

- **An unmeasured entry resolves by domain, not direction.** `ratchet._record_unmeasured` resolves every entry
  absent from the findings when its subject lies in the adapter's complete `Domain`, whatever its direction, and
  `pruned_entries` then drops it. A measured `min` entry never resolves by itself; `_min_verdict` only handles a
  measured minimum. QF14 corrected `docs/SCHEMA.md` and README to say this. When changing resolution, docs or
  tests, probe a complete domain with an absent entry, not only measured findings.
  [verified 2026-11-04 @ 84907174c50f; paths: quality_gate/ratchet.py, docs/SCHEMA.md, README.md, tests/test_ratchet.py]

- **Pruning a verification baseline tightens every measured entry in that check.** `ratchet._prune_entry`
  raises a `min` bound to the measurement, and verification makes `tests:*:executed` a `min` floor, so a prune
  raises that floor too. Keep the extra tightening after a prune, rerun `make -k check` after the baseline
  changes, and do not hand-revert it to the old floor. Use the prune to change an existing bound; a new
  exception still enters by hand with a reason.
  [verified 2026-11-04 @ 84907174c50f; paths: quality_gate/ratchet.py, quality_gate/verification.py, quality-gate-verification.toml, tests/test_verification.py]

- **A `Finding` without `locations` downgrades `location_coverage` from `complete` to `partial`, and
  per-line locations number at `\n`.** `checks._incomplete_locations` scans `result.ratchet.findings`;
  verification's file-wide suppression finding (`verification.measure_exclusions`, subject
  `exclusions:PATH:file-suppression`) needed one `Location` per directive line, as did the inline `noqa` and
  `no-cover` findings. QF115 deleted `changes.py` and change-scoped marking, so a missing `locations` no longer
  affects a changed-line judgement; it still turns the result's `location_coverage` from `complete` to
  `partial`. `_no_cover_lines` uses `verification._source_lines`, and the tokenizer numbers `noqa` comments the
  same way; `str.splitlines()` also splits U+2028, U+2029, U+0085 and friends and shifts the line number of a
  later directive (QF99). `splitlines()` stays fine for command output. Assert the `locations` of a new
  located finding in `tests/test_verification.py`.
  [verified 2026-11-04 @ 1bfa24f12813; paths: quality_gate/checks.py, quality_gate/ratchet.py, quality_gate/verification.py, tests/test_verification.py]

- **The run has one wall-clock limit; a check's subprocesses share its budget, and every phase is named with
  `mark_step`.** `checks._run_policy_checks` arms one `SIGALRM` timer before its loop for `_run_limit(config)`
  (the sum of `_check_budget(check)` over `config.checks` plus `RUN_ALLOWANCE_SECONDS = 300`) and
  `_disarm_run_limit` cancels it and restores the previous handler in a `finally`; the handler raises
  `runner.RunTimeout`, a `UsageError` (exit 2) that names the limit, the allowance, the check and its step. The
  allowance is load-bearing: the timer starts before every subprocess, so a limit of exactly the budgets always
  wins over a hanging last check's own budget, which must fail only that check with `execution = "budget"`.
  QF118's first attempt had no allowance and worked around it by widening the 3.0 s continuous-output bound to
  8.0 s and adding a warm-up check to `test_timeout_reports_budget`; the reviewed fix added the allowance and
  reverted both, so never widen a subprocess-budget test or add a filler check to make a limit pass. A run hits
  the limit only through in-process work: `checks.run_check` enters `runner.check_deadline(check.id, start,
  _check_budget(check))` for the check, whose step starts as "check setup"; `mark_step` updates it before each
  former `analysis_step` phase (36 call sites), and `remaining_budget` gives a subprocess the smaller of its
  seconds and the check's remaining time. `runner.run` keeps `start_new_session`, the per-subprocess budget,
  capture limits, grace and process-group termination, and kills and reaps the group from a `BaseException`
  handler, so a `RunTimeout` still stops the running subprocess. No worker registry, supervision or
  cancellation is left. `_group_alive` is the one liveness test: `killpg(pid, 0)` raising `ProcessLookupError`
  means dead and another `OSError` means alive; otherwise on Linux it scans `/proc/*/stat` with
  `_proc_group_member` for a member of the group in a state other than `Z` or `X` (a vanished entry is not a
  member, an unreadable entry or `/proc` counts as alive), and off Linux it is alive. `_process_finished`
  therefore ends a run whose orphan a PID 1 left a zombie, and `RunInterruptTests` asserts `_group_alive(pid)`
  is False after the kill instead of `killpg` raising. `RunLimitTests` in `tests/test_check.py` covers allowance
  0 and 1, the JSON error document and timer/handler restoration; `RunInterruptTests` in
  `tests/test_runner.py` covers the kill on an interrupt.
  [verified 2026-11-04 @ 84907174c50f; paths: quality_gate/runner.py, quality_gate/checks.py, quality_gate/cli.py, tests/test_check.py, tests/test_runner.py, README.md, docs/SCHEMA.md]

- **The mutation runner's kill evidence is the probe's `reached` set, and a kill needs a test that passed
  in the probe and does not pass on the mutant.** `tests/mutate_gate.py:_probe` copies the frozen tree once,
  instruments every decision module (`_insert_reached` injects a `reached` call at the same `_target_match`
  node `mutate` replaces) and runs the complete suite as the only unmutated run; `_run_suite` fails that probe
  on a missing or invalid report, an exit inconsistent with the report, skipped or expected-failure tests, zero
  tests, or any failure, and `run_mutations` then returns before a mutant runs. `_TestResult.startTest` and
  `stopTest` set and restore `QG_MUTATION_TEST`, so a child-process hit is attributed to the test that started
  it and a hit with no test is unattributed; `_probe_hits` keeps suite order and records unattributed names.
  `_one` imports each mutant copy with `python3 -I` (`_import_check`) and reports `invalid` on a failed
  import; no reaching test gives `survived` with "no test reached its target" and no suite run; unattributed
  hits run the complete suite (`_full`, which requires the probe's exact IDs); otherwise `_targeted` runs
  exactly the reaching tests in suite order with failfast. Any selected test that fails, errors or unexpectedly
  succeeds is a kill, wherever its assertion sits; an order mismatch, timeout or bad report is `error` or
  `timed out`. `_stable` reruns exactly the non-passing IDs on a fresh pristine copy: a repeat failure is
  `unstable` and fails the run. QF117 deleted the plain unmutated run, `_selection_failures`, the
  `loaded`/`imported`/`failure`/`error`/`fixture` events, the excepthook, the `TestResult` subclass hook and
  all fixture-frame classification; do not reintroduce a mechanism that asks where a failure happened. Default
  workers are 2. Keep `tests/test_mutation.py` covering body/setUp/tearDown/cleanup/subtest/child positions, an
  error kill, an import failure, no reach, unattributed hits, a failing probe, exactly one unmutated run, an
  order-dependent test and the worker default; the QF117 accept run reported 24/24 killed.
  [verified 2026-11-04 @ 84907174c50f; paths: tests/mutate_gate.py, tests/test_mutation.py, README.md]

- **One subject-direction rule feeds loading, evaluation, pruning and the trusted merge.**
  `ratchet.subject_direction` delegates to the adapter descriptor's `direction_for_subject`, which asks
  `entry_direction(subject, configured)`, then `default_direction`, then the policy's `direction`;
  `load_baseline` and `evaluate` both apply it, and `_evaluate_finding` asks the same rule before choosing
  `_min_verdict` or `_max_verdict`. `_prune_entry` and `trust._merge_revision_entry` then read
  `entry.direction` and do not ask the adapter again. A path using a different rule can prune or drop a
  `min` floor as a `max` (QF44: a stub `min` entry with bound 4 and value 5 pruned as a `max`, and a removed
  `min` floor vanished). When adding a descriptor kind or a per-subject rule, test loading/evaluation, prune
  and the trusted merge with a stub adapter in `tests/test_ratchet.py`, `tests/test_trust.py` and
  `tests/test_adapters.py`.
  [verified 2026-11-04 @ 84907174c50f; paths: quality_gate/ratchet.py, quality_gate/adapters.py, quality_gate/trust.py, quality_gate/checks.py, tests/test_ratchet.py, tests/test_trust.py, tests/test_adapters.py]

- **A test check reports the counts it parses, never a reconstruction of per-test outcomes.** The Python and
  Emacs adapters set `tests_ran` and `tests_skipped`; `verification._recorded_test_counts` reads only those,
  and a missing count is "test counts unreliable", never zero. QF111 removed `TestResults`, the
  `test_results` JSON field and the unittest text parsers (`_unittest_outcomes`,
  `_unittest_failure_evidence`, `_counted_test_results`, `_failed_test_results`): each output shape had
  needed another parser fix (QF101, QF105, QF108, 4df9643, 8881549) for fields nothing read. A failing run
  reports `outcome = "fail"` with reason "command exited N" and the output tail in diagnostics; zero executed
  tests is not a pass. Do not re-add parsing of `FAILED (...)`, `FAIL:`/`ERROR:` headings or fixture names;
  add the count to both adapters and a verification test instead.
  [verified 2026-11-04 @ 84907174c50f; paths: quality_gate/python_tests.py, quality_gate/elisp_tests.py, quality_gate/verification.py, quality_gate/checks.py, tests/test_python_tests.py, tests/test_verification.py, docs/SCHEMA.md, README.md]

- **The clone check refuses inline jscpd ignore directives before it runs the tool, and its regression must
  show the bypass.** `clones._refuse_directives` runs after `mark_step("clone source scan")` inside
  `_prepare_clones`; it reads each selected file with the bounded reader (`clones._read_regular`, which moved
  from the removed `owners.py` in QF112) and raises a `GateError` naming the first file, line and directive
  and the total count. The directive strings are assembled from pieces in `clones.py` and
  `tests/test_clones.py`, so no file holds a full directive verbatim. The scan covers test files too: QF118's
  first gate failed on a new clone formed by two stub adapters that each built a `CheckResult`;
  `tests/support.py:stub_check_result` now builds both. A fixture proving the refusal must
  leave enough unique code outside the ignored regions for an unrefused run to be `accepted` with zero
  clones: the first QF98 fixture left that run `unsupported` ("jscpd ... analyzed no files"), and the review
  reproduced `accepted` only after giving each file ~30 unique assignments. Before landing a refusal,
  remove it in a disposable copy and confirm the bypass really passes.
  [verified 2026-11-04 @ 84907174c50f; paths: quality_gate/clones.py, tests/test_clones.py, tests/support.py, tests/test_adapters.py, tests/test_check.py, README.md]

- **Test evidence is released through one helper by both the check command and the worklist.**
  `checks._evidence_last_users` maps each result to its last dependent check; `_release_evidence` clears
  `result.temporary` once that check has run (or when called without a finished check) and reports a failed
  removal through `_cleanup_evidence`: stderr "check: ID: cannot remove evidence directory NAME: ..." plus
  the same message on that result's `diagnostics.error`. `worklist._run_selected` computes last users over
  its selected order, releases after each last user and again in a `finally`, and passes the messages out as
  a fourth list so `_worklist_report` exits 1. Leaving cleanup to the `TemporaryDirectory` finalizer only
  emits an implicit `ResourceWarning` and loses the failure.
  [verified 2026-11-04 @ 84907174c50f; paths: quality_gate/checks.py, quality_gate/worklist.py, tests/test_worklist.py, README.md]

- **A refusal test must assert the refusal, and its removal demonstration must fail there.** A guard added to
  `cli.py` or `trust.py` is proven by a test that asserts exit 2, the message naming the option or path, and the
  unchanged state; a test that only expects a nonzero exit can pass for an unrelated reason. The first QF116
  refusal test used a fixture without the `clones` check, so the removal demo failed on
  "unknown check 'clones'" rather than on the guard's refusal; after setting up the check and asserting both
  option names in stderr plus a byte-identical candidate, removing the guard failed at that assertion. When a
  spec asks for a remove-the-guard demonstration, quote the assertion that fails, not a later symptom.
  [verified 2026-11-04 @ 84907174c50f; paths: quality_gate/cli.py, quality_gate/trust.py, tests/test_trust.py]

- **Copy only the working files for a disposable demo.** `cp -a` of this clone fails on `.git/objects` with
  `preserving permissions ... Invalid argument` and leaves a partial copy. Copy the files the command needs
  with `cp -R --no-preserve=mode,ownership`, or exclude `.git`; the read-only `.git` is not needed there.
  [verified 2026-10-27 @ d044e1b; paths: none]
