# Sol 6.1 (max) final review of code-quality-gate, 2026-10-25

Read-only review of main 7c3c5b4 (M1a-M1c, CI1, QF1-QF3, AG2), the single Codex review for this milestone (user rule
2026-10-25: one Sol max review per repository when its queued work is finished).

## Claude's triage

- Earlier findings: 12 fixed, 12 partly fixed (their remainders are findings 27-39 here), #2 deferred to M2 as planned.
- QF4 fixes findings 27-40 and 42: the blocker 27 (module-level lambda bodies unmeasured), 28-39 (decorator
  classification, definition-time decisions counted twice, runner escalation after the leader exits, evidence
  processing outside the deadline, test-summary parsing, staged vs untracked enumeration, worktree file types,
  child coverage evidence registry, clone domain scope, late configuration errors and JSON, structured adapter
  reasons, clone termination outcome) and the nits 40 (colon in paths) and 42 (duplicated coverage configuration
  and decorator helper).
- 41 (higher-tier success outcomes) is deferred to M5, where those outcomes arrive; 26 is M2's trust root.
- Per the minimized-review rule, Claude verifies QF4 against each finding; the next Codex review is at M2.

## The review as returned

Earlier findings are assessed against the recorded triage. “Fixed” below refers to code and test inspection; executed checks are listed at the end.

| Earlier # | Original severity | Status | Evidence |
|---|---|---|---|
| 1 | should-fix | **Fixed** | Evidence-based obligations and visible exemptions: [gate_result.py:117](../quality_gate/gate_result.py:117). Tests: `test_lint_only_class_leaves_tier_one_unsatisfied`, `test_missing_required_tier_with_not_applicable`. |
| 2 | should-fix | **Not fixed; intentionally deferred to M2** | Identity is still calculated after execution, without the protected-input manifest: [checks.py:1156](../quality_gate/checks.py:1156). This matches the triage’s deferral, not a milestone miss. See 26. |
| 3 | should-fix | **Fixed for QF2’s scope** | Separate execution, raw outcome and satisfaction: [checks.py:50](../quality_gate/checks.py:50), [ratchet.py:619](../quality_gate/ratchet.py:619). Test: `test_baseline_exception_is_accepted_with_exceptions`. Future outcome handling still needs adjustment; see 41. |
| 4 | should-fix | **Partly fixed** | Baseline headers, shared-path rejection and file domains exist. Tests: `test_two_checks_may_not_share_a_baseline_path`, `test_entry_outside_the_measured_domain_stays_unmeasured`. Clones still use an unrestricted domain: [checks.py:491](../quality_gate/checks.py:491). See 36. |
| 5 | nit | **Fixed** | [SCHEMA.md:3](../docs/SCHEMA.md:3) establishes precedence; its supersession section identifies historical proposals. Documentation finding; no runtime test needed. |
| 6 | blocker | **Fixed** | Definition lines are excluded from function-body coverage; same-line bodies fail: [python_crap.py:330](../quality_gate/python_crap.py:330). Tests: `test_imported_but_uncalled_function_scores_zero_coverage`, `test_one_line_body_is_unmeasured`. |
| 7 | should-fix | **Fixed for configuration isolation** | Explicit configuration and environment scrubbing: [coverage_tool.py:20](../quality_gate/coverage_tool.py:20), [covrun.py:79](../quality_gate/covrun.py:79). Test: `test_repository_coverage_configuration_is_ignored`. Actual 3.12 tracing remains unverified here. |
| 8 | should-fix | **Partly fixed** | The prefix carries the installation path, and combination rejects wholly missing evidence. However, child completion is not tracked: [python_tests.py:11](../quality_gate/python_tests.py:11), [coverage_tool.py:86](../quality_gate/coverage_tool.py:86). `test_qg_python_child_process_is_measured` checks positive coverage only. See 35. |
| 9 | should-fix | **Partly fixed** | Multiline matching, duplicate main summaries and skipped counts are implemented. Tests include `test_all_skipped_tests_fail_as_no_test_executed`. Skipped-summary ambiguity and invalid captures remain: [python_tests.py:49](../quality_gate/python_tests.py:49). See 32. |
| 10 | should-fix | **Partly fixed** | Accessors, overload declarations and module subjects have fixtures: `test_property_accessors_have_distinct_identities`, `test_overload_declarations_are_skipped`, `test_module_and_class_body_code_is_a_subject`. Lambda bodies and decorator classification still have gaps: [python_crap.py:97](../quality_gate/python_crap.py:97), [python_crap.py:202](../quality_gate/python_crap.py:202). See 27–28. |
| 11 | should-fix | **Fixed for the triaged changes** | Semantic irrefutability is implemented: [python_crap.py:40](../quality_gate/python_crap.py:40). Tests: `test_cc_table_counts_each_construct_once`, `test_untested_cc3_fails`. A separate ownership error remains; see 29. |
| 12 | should-fix | **Fixed** | Earlier compatible dependencies are validated: [policy.py:548](../quality_gate/policy.py:548). Tests cover unknown, wrong-adapter and forward references. Failed prerequisites make CRAP unsupported. |
| 13 | should-fix | **Partly fixed** | Genuine gitlinks are excluded from opening and sizing. Tests: `test_gitlink_is_never_opened_and_needs_one_rule`, `test_gate_submodule_passes_the_quick_start_inventory`. Enumeration ambiguity and nonregular files remain: [files.py:97](../quality_gate/files.py:97), [files.py:151](../quality_gate/files.py:151). See 33–34. |
| 14 | blocker | **Fixed** | Leading-dash command filenames gain `./`: [checks.py:131](../quality_gate/checks.py:131). Test: `test_real_ruff_rejects_then_accepts_a_fixture`. |
| 15 | should-fix | **Partly fixed** | Shared runner, process groups and output limits exist. Tests: `test_budget_kills_the_whole_process_group`, `test_output_over_one_mib_is_capped_and_counted`. Closed-pipe descendants and post-process evaluation escape the budget: [runner.py:239](../quality_gate/runner.py:239), [checks.py:365](../quality_gate/checks.py:365). See 30–31. |
| 16 | should-fix | **Fixed against QF1’s plan** | Controlled jscpd options and source-count reconciliation: [clones.py:292](../quality_gate/clones.py:292), [clones.py:318](../quality_gate/clones.py:318). Tests: `test_jscpd_is_invoked_with_the_gate_options_and_files`, `test_jscpd_source_count_mismatch_is_unsupported`. |
| 17 | blocker | **Fixed for the reported malformed structures** | A single jscpd run and explicit results list are required: [clones.py:179](../quality_gate/clones.py:179). Tests: `test_sarif_needs_exactly_one_jscpd_run_with_results`, `test_malformed_location_is_unsupported`. |
| 18 | should-fix | **Fixed** | Finite-value validation and strict JSON serialization: [ratchet.py:195](../quality_gate/ratchet.py:195), [ratchet.py:428](../quality_gate/ratchet.py:428), [checks.py:1264](../quality_gate/checks.py:1264). Tests cover non-finite thresholds, bounds and measurements. |
| 19 | should-fix | **Fixed for the reported installation boundary** | Component validation, unknown-key rejection and destination containment: [tools.py:24](../quality_gate/tools.py:24), [tools.py:301](../quality_gate/tools.py:301). Tests cover names, versions, unknown keys and escaping destinations. |
| 20 | should-fix | **Partly fixed** | Built-ins and subprocess diagnostics are present; `test_failing_command_diagnostics_name_argv_and_exit` verifies command failures. Several adapter failure reasons still disappear: [checks.py:461](../quality_gate/checks.py:461). See 38–39. |
| 21 | should-fix | **Partly fixed** | Unknown-option JSON and NUL command arguments are fixed. Tests: `test_unknown_option_with_json_is_one_error_document`, `test_command_argument_with_nul_is_a_configuration_error`. Late configuration errors still escape the handler: [cli.py:138](../quality_gate/cli.py:138). See 37. |
| 22 | should-fix | **Fixed against QF2’s documented contract** | Prune outcome is explicit and independently affects exit status: [checks.py:1096](../quality_gate/checks.py:1096), [checks.py:1244](../quality_gate/checks.py:1244). Tests: `test_check_prune_reports_refusal_in_json`, `test_prune_round_trips_expiry_files_and_headers`. |
| 23 | should-fix | **Fixed** | [test_command_checks.py:187](../tests/test_command_checks.py:187) contains the real Ruff rejection/repair fixture, including spaces and leading dashes. Its execution was unverified in this review. |
| 24 | should-fix | **Partly fixed** | Most requested regression fixtures were added, including domains, headers, expiry-today and round trips. The runner, child-finalization and JSON gaps below remain uncovered. |
| 25 | should-fix | **Partly fixed** | Both interpreters are wired into CI: [check.yml:14](../.github/workflows/check.yml:14). Most metric fixtures exist; missing-child finalization still lacks coverage. Live CI, action-pin identities and runtime parity are unverified offline. |

Integrity remains dependent on review of the candidate’s enforcement inputs.

26. **Should-fix, intentionally deferred to M2 — [checks.py:1156](../quality_gate/checks.py:1156), [tools.py:414](../quality_gate/tools.py:414), [check.yml:48](../.github/workflows/check.yml:48): an implementing agent can still approve weakened inputs.** It can add baseline exceptions or raise bounds, increase thresholds, remove checks, add exemptions, narrow test discovery, weaken assertions, grow pragma exclusions, weaken Ruff configuration, change tool pins, or alter the gate/Makefile/CI. Repository coverage files are now ignored, but source pragmas and test code remain editable. Existing tool installations are accepted by file presence, without payload authentication.

    QF3’s baseline repayment is verified: comparing `a4f0176` with HEAD finds 34 remaining entries, no new subjects and no raised bounds. All nine QF1 additions are absent. That does not prevent recurrence.

    **Fix in M2:** use an externally selected reviewed SHA and trusted gate invocation; protect the complete configuration/test/tool closure, authenticate installed payloads, record input identities before and after execution, and define reviewed replacements and trusted-policy pruning. This deferral does not itself reject the current milestone.

The following are current correctness findings.

27. **Blocker — [python_crap.py:202](../quality_gate/python_crap.py:202): module-level lambda bodies disappear from complexity measurement.** `_outside_children` traverses only lambda defaults. An in-memory AST and pinned-coverage-parser probe of `f = lambda x: 1 if x else (2 if x is None else 3)` produced only a CC-1 module subject, scoring **2 with zero execution**. The two decisions receive no subject.

    **Fix:** assign orphaned lambda bodies to a measured owner, include their decisions, and handle declaration/body line ambiguity explicitly. Add an imported-but-uncalled module-lambda fixture.

28. **Should-fix — [python_crap.py:97](../quality_gate/python_crap.py:97), [python_crap.py:107](../quality_gate/python_crap.py:107): decorator spelling can suppress code or crash measurement.** Every decorator ending in `overload` causes its function to be skipped, including an ordinary locally defined decorator preserving a real runtime body. Conversely, a valid bare `@setter` decorator reaches an `ast.Attribute` assertion. Both were reproduced in memory.

    **Fix:** recognize actual typing declarations, including their bindings/body shape, and restrict accessor handling to the appropriate attribute forms. Test custom decorators with these names.

29. **Should-fix — [python_crap.py:144](../quality_gate/python_crap.py:144), [python_crap.py:179](../quality_gate/python_crap.py:179): definition-time decisions are counted twice.** Function complexity walks the entire definition, while module complexity separately includes defaults, decorators and annotations. A two-decision default gave a function whose body is only `return x` CC 3 and untested CRAP 12; the module also received those decisions.

    **Fix:** compute function complexity from its executable body, retaining definition-time expressions in their actual enclosing owner. Add composed default/decorator ownership tests.

30. **Should-fix — [runner.py:239](../quality_gate/runner.py:239): timeout handling can leave descendants alive.** The drain loop exits when the direct child exits and pipes close, before escalation. A no-file probe used a descendant ignoring SIGTERM with output redirected away from the pipes. With a 0.5-second budget and 0.1-second grace, the runner returned after 0.502 seconds while that descendant remained sleeping. I killed the probe group afterward.

    **Fix:** complete timeout escalation for the remaining process group even after its leader and pipes disappear. Extend `test_budget_kills_the_whole_process_group` to cover closed-pipe descendants.

31. **Should-fix — [checks.py:334](../quality_gate/checks.py:334), [checks.py:365](../quality_gate/checks.py:365): evidence evaluation is outside the deadline.** A command with budget 1 and `must_match = "(a+)+$"` took **2.586 seconds** on a 27-character output and reported `execution = "completed"`. Larger inputs can stall the gate indefinitely. Coverage combination and analysis likewise lack an enforced remaining deadline.

    **Fix:** carry one absolute deadline through execution and evidence processing, with interruptible isolation for regex evaluation. Add an evidence-processing timeout fixture.

32. **Should-fix — [python_tests.py:36](../quality_gate/python_tests.py:36), [python_tests.py:49](../quality_gate/python_tests.py:49): test summaries can still claim execution incorrectly or escape as exceptions.** Verified probes showed:

    - `skipped=0 … Ran 1 tests … skipped=1` selects the first skipped count and claims one execution.
    - An optional unmatched capture raises uncaught `TypeError`.
    - `ran = 0`, `skipped = -1` is accepted and becomes one executed test.

    **Fix:** reject ambiguous skipped summaries, validate captures as nonnegative integers, normalize absent captures, and reject truncated evidence unless the parser can establish summary completeness. Add these cases to both adapters’ tests.

33. **Should-fix — [files.py:97](../quality_gate/files.py:97): an untracked filename can masquerade as staged git metadata.** Tracked and untracked records share one parser. An untracked pathname shaped as `160000 <40 hex characters> 0<TAB>README.md` becomes a gitlink named `README.md`. An in-memory git-output probe produced no inventory violations, omitted the original pathname and listed README twice.

    **Fix:** enumerate staged entries and untracked names separately, preserving their record types. Add a tab-containing metadata-shaped filename fixture.

34. **Should-fix — [files.py:159](../quality_gate/files.py:159), [files.py:304](../quality_gate/files.py:304): worktree file types remain unchecked.** Shebang inspection follows symlinks and opens nonregular replacements; hygiene follows targets with `stat`. A FIFO can therefore block inventory before the bounded subprocess runner participates, and an external symlink can cause reads outside the repository. The unchecked operations are verified in code; a runtime FIFO reproduction is **unverified** under the no-write restriction.

    **Fix:** validate types with `lstat`, define explicit symlink handling, reject unsupported replacements and bound shebang reads.

35. **Should-fix — [coverage_tool.py:86](../quality_gate/coverage_tool.py:86), [covrun.py:88](../quality_gate/covrun.py:88): successful combination does not establish complete child evidence.** There is no invocation/completion registry. The pinned coverage implementation’s `strict=True` accepts one usable file while warning about another corrupt file; an in-memory probe confirmed this. A child exiting without saving leaves no expected-data record to reject.

    **Fix:** register each coverage invocation and successful finalization, require every registered dataset to be usable, and treat combination corruption as unsupported evidence. Add missing, corrupt and abrupt-child-exit fixtures.

36. **Should-fix — [checks.py:491](../quality_gate/checks.py:491), [ratchet.py:49](../quality_gate/ratchet.py:49): clone pruning still treats unselected scope as resolved.** A completed scan of selected files becomes `Domain.all`, which accepts every baseline fingerprint. An in-memory baseline entry describing files outside the selected scope was resolved and removed by pruning without measuring those files.

    **Fix:** bind clone baselines to their measurement scope and determine membership from structured location/scope information. Preserve out-of-scope entries as unmeasured; distinguish deleted files from unselected files.

37. **Should-fix — [cli.py:124](../quality_gate/cli.py:124), [cli.py:138](../quality_gate/cli.py:138): late configuration errors bypass JSON and exit-code handling.** `command_check` runs outside the `UsageError` handler. A malformed tool lock propagates through clone tool lookup; injected loader/dispatch probes confirmed an escaping `UsageError` with no JSON. The command adapter instead converts the same configuration error into a check result, producing exit 1 rather than documented exit 2.

    **Fix:** validate required configuration before execution and keep the complete dispatch inside the structured usage-error boundary. Test malformed locks through `check --json` for every relevant adapter.

38. **Should-fix — [checks.py:461](../quality_gate/checks.py:461), [checks.py:676](../quality_gate/checks.py:676): several rejection reasons remain stderr-only.** A malformed-report probe returned `unsupported`, exit-code diagnostics of 0, an empty output tail and no findings; the actual “no completed jscpd run” reason appeared only on stderr. Missing summaries, combination failures and some selection failures have the same omission. CRAP’s failure-list diagnostic also bypasses the common tail limit at [checks.py:848](../quality_gate/checks.py:848).

    **Fix:** retain a structured adapter-verdict reason and consistently bound in-process diagnostics. Assert the explanation itself in JSON tests.

39. **Should-fix — [checks.py:466](../quality_gate/checks.py:466): clone termination violates the schema’s raw-outcome rule.** Budget and signal failures become `outcome = "unsupported"`, whereas [SCHEMA.md:274](../docs/SCHEMA.md:274) says they produce raw failure. Adapter probes confirmed both mappings. Commands and Python tests already report `fail`.

    **Fix:** map budget/signal termination to raw `fail`, preserving execution and diagnostics; reserve `unsupported` for unavailable or invalid evidence. Add clone termination contract tests.

Two design details still require attention before later adapters rely on them.

40. **Nit — [ratchet.py:52](../quality_gate/ratchet.py:52): file-domain membership assumes paths contain no colon.** `pkg/a:b.py:f` is outside `Domain.of_files(("pkg/a:b.py",))`, verified in memory. Future Lisp subject names can also contain colons.

    **Fix:** specify an unambiguous adapter identity encoding or carry the path separately. For current Python identities, splitting at the last colon fixes this case without changing ordinary identities.

41. **Nit — [gate_result.py:178](../quality_gate/gate_result.py:178): higher-tier success remains hardcoded as literal `pass`.** A satisfied advisory result with reserved outcome `proved` produces `accepted_with_exceptions`, verified in memory. Execution/outcome/satisfaction separation is sound, but M5 cannot simply add its adapter.

    **Fix:** define adapter success outcomes centrally when adding those verdicts, and test advisory `proved`, `no_counterexample` and `unknown` separately. M2 also needs additive provenance fields; schema 2 currently supplies no complete input identity.

The clearest simplicity issue is duplicated ownership, rather than QF3’s restored bounds.

42. **Nit — [covrun.py:37](../quality_gate/covrun.py:37), [coverage_tool.py:20](../quality_gate/coverage_tool.py:20), [python_crap.py:81](../quality_gate/python_crap.py:81): identical concepts have multiple implementations.** Coverage configuration is generated twice, and every child rewrites the shared file. `_decorator_name` and `_decorator_base` are identical helpers.

    **Fix:** create the coverage configuration once and have children consume it; reuse one decorator-name helper. No additional configuration layer is needed.

Validation: 33 read-only unit tests passed, as did real inventory and hygiene. I also checked JSON usage errors, baseline history, output capture and the probes described above. The full fixture suite, `make -k check`, Python 3.12 runtime behavior, tool-fetch execution and live GitHub Actions remain **unverified** because they require writes or network access. No edits were made; the worktree remains clean.

VERDICT: CHANGES