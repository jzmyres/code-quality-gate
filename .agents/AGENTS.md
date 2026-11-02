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
  [verified 2026-11-02 @ 85b72352531e; paths: quality_gate/tools.py, quality_gate/payload.py, quality_gate/trust.py, quality_gate/covrun.py, tests/test_tools.py]

- **Tests counted by the verification ratchet must not depend on the user running them.** CI runs as root, where
  `chmod 000` denies nothing; QF8 replaced that test with an in-process patch of
  `quality_gate.payload.os.scandir` (QF11 moved the payload walk there). The baseline currently floors
  `tests:tests:executed` at 705 and has no `skipped` entry, so a `skipIf`/`skipUnless` about root, permissions
  or OS adds a skip and fails CI; patch the call instead.
  [verified 2026-11-01 @ e4f98b7; paths: tests/test_tools.py, quality_gate/payload.py, quality_gate/verification.py, quality-gate-verification.toml, .github/workflows/check.yml]

- **A CRAP baseline entry does not waive the spec's CRAP 6 for a changed function, and deleting tests can
  uncover helpers only they covered.** The baseline keeps the gate green while the spec still requires every
  new or changed function at 6 or below; `quality_gate/python_crap.py:_run_python_crap` is bound at 11.003 and
  `quality_gate/command.py:_expand_run` at 8. QF12 split `_run_python_tests` into setup/outcome/evidence
  helpers and removed its entry. QF112 deleted the owners adapter with its ~800 test lines and the trusted gate
  then failed on five functions the owners tests were the only coverage for: runner's `_proc_member_command`,
  `_live_member` and `_live_group_members` (CRAP 30.0), `_pending_errors` (6.6) and policy's
  `_validate_fixed_header` (11.1). The validator had no caller left and went with its descriptor field; the
  runner helpers still had callers and gained focused tests in `tests/test_runner.py`; the next gate run passed
  CRAP. Extract helpers until each touched function is <= 6, then lower or
  remove the entry; the gate's "N functions within threshold" still includes baseline entries, and no baseline
  entry is the fix for a function whose tests were deleted.
  [verified 2026-11-02 @ 85b72352531e; paths: quality_gate/python_crap.py, quality_gate/command.py, quality_gate/python_tests.py, quality_gate/runner.py, quality_gate/policy.py, tests/test_runner.py, tests/test_policy.py, quality-gate-crap.toml]

- **`covrun.py` runs inside the measured program's interpreter.** It imports nothing from `quality_gate`; it
  loads the standard-library `quality_gate/payload.py` verifier by file path, and the parent passes the
  effective coverage directory, version, payload digest, gate-owned coverage config and registry directory as
  arguments (QF11). Keep the measured interpreter free of the gate: QF7's zero coverage came from a preloaded
  `quality_gate` package shadowing a candidate's own. Do not add a `quality_gate` import or a nested verifier
  subprocess.
  [verified 2026-11-01 @ e4f98b7; paths: quality_gate/covrun.py, quality_gate/payload.py, quality_gate/tools.py, quality_gate/python_tests.py]

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
  every baseline before the checks (`CheckDef.effective_baseline`, `identity_before.effective_inputs`). QF116
  refuses `--prune` with `--policy-from` as a usage error before any check; `_write_pruned` is the only remaining
  prune path and no trust identity exemption exists, so any protected or effective input, tool payload or gate file
  that changes during the run is an error. `quality-gate.toml` protects `ruff.toml` and the Ruff check passes it
  explicitly, but any other tool configuration must be added to `[protect] paths` and passed. The checklist is
  `.agents/skills/trust-root-change/SKILL.md`.
  [verified 2026-11-02 @ 85b72352531e; paths: quality_gate/trust.py, quality_gate/cli.py, quality_gate/checks.py, quality-gate.toml, docs/TRUST.md, docs/SCHEMA.md, tests/test_trust.py]

- **Every git command on a candidate repository goes through `files.git_argv`.** It adds
  `--no-replace-objects`, `safe.directory=ROOT` and `core.fsmonitor=false`; `trust._git`, `files._git` and
  `gate_result._git` call it, and `checks` and `worklist` use it directly for inventory/hygiene argv,
  pack/clone and churn. A bare `git` call lets a candidate-configured fsmonitor or replacement ref change
  what the gate reads.
  [verified 2026-11-02 @ 85b72352531e; paths: quality_gate/files.py, quality_gate/trust.py, quality_gate/gate_result.py, quality_gate/checks.py, quality_gate/worklist.py]

- **An unmeasured entry resolves by domain, not direction.** `ratchet._record_unmeasured` resolves every entry
  absent from the findings when its subject lies in the adapter's complete `Domain`, whatever its direction, and
  `pruned_entries` then drops it. A measured `min` entry never resolves by itself; `_min_verdict` only handles a
  measured minimum. QF14 corrected `docs/SCHEMA.md` and README to say this. When changing resolution, docs or
  tests, probe a complete domain with an absent entry, not only measured findings.
  [verified 2026-11-02 @ 85b72352531e; paths: quality_gate/ratchet.py, docs/SCHEMA.md, README.md, tests/test_ratchet.py]

- **Pruning a verification baseline tightens every measured entry in that check.** `ratchet._prune_entry`
  raises a `min` bound to the measurement, and verification makes `tests:*:executed` a `min` floor, so a prune
  raises that floor too. Keep the extra tightening after a prune, rerun `make -k check` after the baseline
  changes, and do not hand-revert it to the old floor. Use the prune to change an existing bound; a new
  exception still enters by hand with a reason.
  [verified 2026-11-02 @ 85b72352531e; paths: quality_gate/ratchet.py, quality_gate/verification.py, quality-gate-verification.toml, tests/test_verification.py]

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
  [verified 2026-11-02 @ 85b72352531e; paths: quality_gate/checks.py, quality_gate/ratchet.py, quality_gate/verification.py, tests/test_verification.py]

- **Every synchronous phase of a check runs through `runner.analysis_step`.** `_evaluate_ratchet` supervises
  `evaluate` as "ratchet evaluation"; `_adapter_selection` supervises `_select_files` as "file selection";
  the adapters pass `_baseline_entries` through `analysis_step` under "baseline loading" (`python_crap`,
  `elisp_crap`, `clones` and `verification`), so a small budget stops the named phase and reports a timeout.
  A phase called directly runs outside the deadline and the timeout then names the ratchet evaluation instead.
  Add a stalled-phase test in `tests/test_deadlines.py`; `analysis_step(..., deadline=...)` and `StepTimeout`
  carry the step name.
  [verified 2026-11-02 @ 85b72352531e; paths: quality_gate/checks.py, quality_gate/python_crap.py, quality_gate/elisp_crap.py, quality_gate/clones.py, quality_gate/verification.py, quality_gate/runner.py, tests/test_deadlines.py]

- **The mutation runner's kill evidence comes from the marker file, and a selected run must first pass
  unmutated.** `tests/mutate_gate.py:_instrument` writes JSON `loaded`, `imported`, `failure`/`error`,
  `fixture` and `reached` events; `_reached_edits` injects `reached` at the same `_target_match` node
  `mutate` replaces. `_TestResult.startTest` sets `QG_MUTATION_TEST` and `stopTest` restores it, so
  child-process hits are attributed and a hit with no test is unattributed. Fixture classification is one
  traceback-frame list (`_FIXTURE_FRAMES`): a failure is a fixture failure when its traceback names `setUp`,
  `tearDown`, `asyncSetUp`, `asyncTearDown`, `_callSetUp`, `_callTearDown`, `_callCleanup`, `doCleanups`,
  `setUpClass`, `tearDownClass`, `setUpModule`, `tearDownModule` or `doClassCleanups`. `_fixture_failure`
  serves the parent `_TestResult.addFailure`/`addSubTest` and a copy in the child preamble
  (`_qg_mutation_test_fixture`). unittest truncates a subtest traceback at its own context manager, so a
  failing subtest also asks `_cleanup_call`, which matches only the cleanup frames. A recorded `fixture`
  event is rejected by `_targeted` and `_full` as a non-kill. The review of 67a8929 found a gap: a helper
  called from `setUp` whose subtest assertion fails has `setUp` only on the reporting stack
  (`addSubTest > ... > helper > setUp > _callSetUp`), not in the traceback, and the fallback checks only
  cleanup frames, so it still counts as a kill (deferred after QF109; check the whole fixture list there).
  `_targeted` requires the selection in order with `loaded`/`imported`, no failure/error and no fixture
  event; `_selection_failures` requires the same ids to pass unmutated; `_full` still requires the complete
  baseline ids. A selected pass, no reach, an unattributed hit or a failed selection falls back to the full
  suite. Keep these events, id checks, fixture rejection and the unmutated selection check when adding a
  `Decision`, and cover a return-code-only subprocess assertion, an order-dependent selection, a child
  setUp/tearDown/addCleanup failure, an async fixture, a lazy import and the helper-from-setUp subtest in
  `tests/test_mutation.py`.
  [verified 2026-11-02 @ 85b72352531e; paths: tests/mutate_gate.py, tests/test_mutation.py, README.md]

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
  [verified 2026-11-02 @ 85b72352531e; paths: quality_gate/ratchet.py, quality_gate/adapters.py, quality_gate/trust.py, quality_gate/checks.py, tests/test_ratchet.py, tests/test_trust.py, tests/test_adapters.py]

- **A test check reports the counts it parses, never a reconstruction of per-test outcomes.** The Python and
  Emacs adapters set `tests_ran` and `tests_skipped`; `verification._recorded_test_counts` reads only those,
  and a missing count is "test counts unreliable", never zero. QF111 removed `TestResults`, the
  `test_results` JSON field and the unittest text parsers (`_unittest_outcomes`,
  `_unittest_failure_evidence`, `_counted_test_results`, `_failed_test_results`): each output shape had
  needed another parser fix (QF101, QF105, QF108, 4df9643, 8881549) for fields nothing read. A failing run
  reports `outcome = "fail"` with reason "command exited N" and the output tail in diagnostics; zero executed
  tests is not a pass. Do not re-add parsing of `FAILED (...)`, `FAIL:`/`ERROR:` headings or fixture names;
  add the count to both adapters and a verification test instead.
  [verified 2026-11-02 @ 85b72352531e; paths: quality_gate/python_tests.py, quality_gate/elisp_tests.py, quality_gate/verification.py, quality_gate/checks.py, tests/test_python_tests.py, tests/test_verification.py, docs/SCHEMA.md, README.md]

- **The clone check refuses inline jscpd ignore directives before it runs the tool, and its regression must
  show the bypass.** `clones._refuse_directives` is the "clone source scan" `analysis_step` inside
  `_prepare_clones`; it reads each selected file with the bounded reader (`clones._read_regular`, which moved
  from the removed `owners.py` in QF112) and raises a `GateError` naming the first file, line and directive
  and the total count. The directive strings are built from `_IGNORE_PREFIX`, so neither the gate's sources
  nor its tests contain them verbatim. A fixture proving the refusal must leave enough unique code outside
  the ignored regions for an unrefused run to be `accepted` with zero clones: the first QF98 fixture left that
  run `unsupported` ("jscpd ... analyzed no files"), and the review reproduced `accepted` only after giving
  each file ~30 unique assignments. Before landing a refusal, remove it in a disposable copy and confirm the
  bypass really passes.
  [verified 2026-11-02 @ 85b72352531e; paths: quality_gate/clones.py, tests/test_clones.py, README.md]

- **Test evidence is released through one helper by both the check command and the worklist.**
  `checks._evidence_last_users` maps each result to its last dependent check; `_release_evidence` clears
  `result.temporary` once that check has run (or when called without a finished check) and reports a failed
  removal through `_cleanup_evidence`: stderr "check: ID: cannot remove evidence directory NAME: ..." plus
  the same message on that result's `diagnostics.error`. `worklist._run_selected` computes last users over
  its selected order, releases after each last user and again in a `finally`, and passes the messages out as
  a fourth list so `_worklist_report` exits 1. Leaving cleanup to the `TemporaryDirectory` finalizer only
  emits an implicit `ResourceWarning` and loses the failure.
  [verified 2026-11-02 @ 85b72352531e; paths: quality_gate/checks.py, quality_gate/worklist.py, tests/test_worklist.py, README.md]

- **A refusal test must assert the refusal, and its removal demonstration must fail there.** A guard added to
  `cli.py` or `trust.py` is proven by a test that asserts exit 2, the message naming the option or path, and the
  unchanged state; a test that only expects a nonzero exit can pass for an unrelated reason. The first QF116
  refusal test used a fixture without the `clones` check, so the removal demo failed on
  "unknown check 'clones'" rather than on the guard's refusal; after setting up the check and asserting both
  option names in stderr plus a byte-identical candidate, removing the guard failed at that assertion. When a
  spec asks for a remove-the-guard demonstration, quote the assertion that fails, not a later symptom.
  [verified 2026-11-02 @ 85b72352531e; paths: quality_gate/cli.py, quality_gate/trust.py, tests/test_trust.py]

- **Copy only the working files for a disposable demo.** `cp -a` of this clone fails on `.git/objects` with
  `preserving permissions ... Invalid argument` and leaves a partial copy. Copy the files the command needs
  with `cp -R --no-preserve=mode,ownership`, or exclude `.git`; the read-only `.git` is not needed there.
  [verified 2026-10-27 @ d044e1b; paths: none]
