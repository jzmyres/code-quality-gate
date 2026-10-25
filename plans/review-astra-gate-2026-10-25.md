# Astra (Codex gpt-6-astra, xhigh) review of the gate: design, M1a/M1b/CI1 code and the M1c spec, 2026-10-25

Read-only review of main 0a2905e (before M1c landed). The report is recorded as returned, after Claude's triage.

## Claude's triage

- #6: the main case (def and decorator lines counted as coverage) was fixed in M1c before it landed (a4f0176);
  the one-line `def f(): return x` case remains -> QF1 (such a function is unmeasured, with a message to split it).
- QF1 (metric and evidence correctness): #6 remainder, #7 (gate-controlled coverage configuration), #9 (executed,
  not skipped, tests), #10 (accessor and overload identities; module-level code as a subject), #11 (irrefutable
  case patterns; the spec's example CRAP 30 is wrong, 12 is right), #12 (`requires` validation), #13 (gitlinks in
  inventory), #14 (`{files}` names that start with `-`), #16 and #17 (jscpd configuration control; SARIF
  completeness), #18 (finite numbers), #19 (tool lock names and unknown keys), #23 (a real ruff violation test),
  #25 (CI on 3.12 and 3.13).
- QF2 (result and ratchet contract, decided now so M4/M5 do not rework it): #1 (obligations reported as
  required/satisfied/exempted; tier evidence), #3 (separate execution status, raw outcome and policy satisfaction),
  #4 (resolution only after a complete scan; baselines bound to check id and metric version; shared baseline paths
  rejected), #15 (bounded process-group runner), #20 (diagnostics in JSON), #21 (JSON on usage errors), #22 (prune
  outcome reported), #24 (tests), #5 (one authoritative schema reference; superseded proposals marked).
- #2 goes into the M2 spec (the trust-root contract), written before M2 starts.

## The review as returned

The architecture can meet the owner’s goal, but the contracts and implementation need changes. The approved decisions legitimately supersede the blueprint’s mandatory T3, strong assurance claims, and early MCP/SARIF scope.

Review was offline and read-only; the worktree remains clean. All 12 pure ratchet tests passed. I did not run the fixture suite or CI because they write files. M1c findings concern its spec, not the implementation elsewhere.

1. **Should-fix — Design — [policy.py:376](/home/work/code-quality-gate/.worktrees/review/quality_gate/policy.py:376), [files.py:142](/home/work/code-quality-gate/.worktrees/review/quality_gate/files.py:142): tier labels do not establish tier obligations.**  
   Any command or clone check can claim any tier; inventory checks only the declared number and enforcement. Thus a successful no-op can satisfy T2, and lint alone can satisfy T1. `not_applicable` decisions disappear from JSON. An in-memory probe with T1/T2 exemptions and one successful advisory command returned `accepted` without exposing either exemption.  
   **Fix:** distinguish policy acceptance from assurance compliance; report required, satisfied, exempted and unselected obligations. Define the evidence required to satisfy each tier, including actual tests for T1 and executed properties/fuzzing for T2. Keep `[1]` explicitly transitional until M4.  
   **Three-test failure:** principled—labels substitute for evidence; simplest—missing one central obligation check; general—arbitrary adapters can claim arbitrary assurance.

2. **Should-fix — Design — [Fable review:130](/home/work/code-quality-gate/.worktrees/review/plans/review-fable-tiered-design-2026-10-24.md:130), [checks.py:482](/home/work/code-quality-gate/.worktrees/review/quality_gate/checks.py:482): M2’s trust-root contract needs definition before more evidence is produced.**  
   `--policy-from REV` does not specify who supplies the trusted revision, which enforcement inputs come from it, or how reviewed replacements become effective. Current identity records omit baseline/tool/input digests, and calculate the policy hash **after** commands execute. CI executes the candidate checkout’s gate, lock and Makefile. Also, hashing M1c’s `coverage/__init__.py` would not authenticate the other imported coverage modules.  
   **Fix:** specify externally selected base SHA, trusted gate invocation, protected configuration closure, baseline provenance, and before/after input identity. Authenticate the complete wheel payload. Define reviewed-replacement and trusted-policy prune behavior. M2 implementation can remain scheduled for M2.  
   **Three-test failure:** principled—approval authority remains ambiguous; simplest—a single trusted snapshot contract is missing; general—single-binary integrity does not cover Python packages or indirect configuration.

3. **Should-fix — Design — [m1b-spec.md:58](/home/work/code-quality-gate/.worktrees/review/plans/m1b-spec.md:58), [gate_result.py:72](/home/work/code-quality-gate/.worktrees/review/quality_gate/gate_result.py:72): the result contract cannot preserve the approved higher-tier outcomes or general waivers.**  
   The schema admits only `pass/fail/unsupported/error`; acceptance requires literal `pass`. A baseline-covered violation becomes check `pass`. Commands have neither baseline support nor stable measured subjects, so their applicable failures cannot receive the approved reasoned exception treatment. M4/M5 need execution status, raw assurance outcome and policy satisfaction to remain distinct.  
   **Fix:** define those separate fields now, retaining raw findings when waived. Reserve structured evidence for targets, test identities, example counts, seeds/corpus, bounds, assumptions and replay artifacts. T4 must identify the checked theorem and its implementation relationship, including explicitly unverified correspondence. Specify dependency/profile selection and aggregation.  
   **Three-test failure:** principled—acceptance obscures evidence; simplest—later adapters would need special decision paths; general—binary exit outcomes cannot represent search or proof results.

4. **Should-fix — Design — [m1b-spec.md:44](/home/work/code-quality-gate/.worktrees/review/plans/m1b-spec.md:44), [ratchet.py:361](/home/work/code-quality-gate/.worktrees/review/quality_gate/ratchet.py:361): “not measured” is incorrectly generalized to “resolved.”**  
   `evaluate([], entries)` passes and resolves every entry. That is appropriate only after a complete scan establishes absence. The interface carries no completeness or subject-domain evidence. Baselines also lack check/metric version binding. Two checks may share a baseline path; pruning one drops the other check’s subjects, which I reproduced in memory.  
   **Fix:** require complete measurement of a declared scope before resolution/pruning; distinguish absent, unmeasured and unsupported subjects. Bind baselines to check identity, metric version and scope, with explicit migration. Reject shared baseline destinations unless aggregation is intentional.  
   **Three-test failure:** principled—absence of evidence becomes improvement; simplest—one missing completeness contract; general—clone assumptions do not transfer safely to CRAP, profiles or proof obligations.

5. **Nit — Design — [Fable review:100](/home/work/code-quality-gate/.worktrees/review/plans/review-fable-tiered-design-2026-10-24.md:100), [m1c-spec.md:46](/home/work/code-quality-gate/.worktrees/review/plans/m1c-spec.md:46): the documents contain incompatible schema examples.**  
   Fable’s example has array-valued `requires`, check-scoped `not_applicable`, a separate `[[waiver]]`, and `python-lines-branches/1`. M1b/M1c use a single dependency ID, tier-scoped applicability, baseline exceptions, and `python-lines/1`. M1b’s precedence rule resolves some ambiguity, but no canonical cross-milestone contract records all these decisions.  
   **Fix:** add a concise authoritative schema/supersession reference; preserve historical reviews as historical documents. Explicitly mark mandatory T3, separate clone authority, and early MCP/SARIF proposals as superseded.  
   **Three-test failure:** principled—competing contracts; simplest—duplicated incompatible examples; general—consumers cannot reliably select the intended schema.

6. **Blocker — M1c spec — [m1c-spec.md:59](/home/work/code-quality-gate/.worktrees/review/plans/m1c-spec.md:59): definition-time execution is counted as function-body coverage.**  
   I reproduced this with the pinned wheel and Python 3.13 sysmon:
   ```python
   def f(x):
       return 1 if x else (2 if x is None else 3)
   ```
   Merely defining this uncalled CC-3 function covers its `def` line. The specified span calculation produces coverage `1/2` and CRAP **4.125**, passing threshold 6. Putting the body on the declaration line produces apparent 100% coverage and CRAP 3 without calling it.  
   **Fix:** define executable-body ownership separately from declaration/decorator execution. Treat lines shared between definition and body as ambiguous unless function-entry evidence resolves them. Add imported-but-uncalled and one-line-function fixtures before seeding a baseline.

7. **Should-fix — M1c spec — [m1c-spec.md:22](/home/work/code-quality-gate/.worktrees/review/plans/m1c-spec.md:22), [m1c-spec.md:63](/home/work/code-quality-gate/.worktrees/review/plans/m1c-spec.md:63): effective coverage configuration is not controlled.**  
   The proposed coverage CLI invocation does not disable discovery of repository configuration. The installed coverage code reads configuration files and environment settings affecting exclusions, concurrency and tracing. Its default exclusions also include more than `pragma: no cover`. Reporting only pragma lines does not describe the effective denominator.  
   **Fix:** use an explicit gate-controlled configuration for collection, combination and analysis; force line mode, authenticate permitted exclusions, and report effective exclusion sources. Verify the actual tracer. Sysmon **line** coverage worked on 3.13; installed source supports the proposed line-only approach on 3.12, but 3.12 runtime behavior is **unverified** here. Branch mode must not silently replace this metric.

8. **Should-fix — M1c spec — [m1c-spec.md:35](/home/work/code-quality-gate/.worktrees/review/plans/m1c-spec.md:35), [tests/support.py:358](/home/work/code-quality-gate/.worktrees/review/tests/support.py:358): `QG_PYTHON` does not yet establish complete subprocess evidence.**  
   The spec does not require the coverage prefix to be used, distinguish missing/corrupt data from valid zero execution, or account for children that exit without saving. Its only subprocess acceptance test requires coverage above zero. The existing fixtures override `QG_TOOLS_DIR` with fake-tool directories; a child runner that resolves coverage from that environment will lose the outer installation.  
   **Fix:** include the absolute authenticated coverage installation and evidence identity in the prefix. Specify prefix placement, supported invocation forms and environment inheritance. Require successful evidence finalization and explicit handling of failed combination, abrupt exits and missing child data. Preserve “never imported” as zero coverage only within a valid completed measurement.

9. **Should-fix — M1c spec — [m1c-spec.md:27](/home/work/code-quality-gate/.worktrees/review/plans/m1c-spec.md:27), [m1c-spec.md:70](/home/work/code-quality-gate/.worktrees/review/plans/m1c-spec.md:70): a positive summary count does not demonstrate executed tests.**  
   An in-memory unittest suite with every test skipped reports `Ran 1 test` and succeeds. It satisfies the proposed positive-count rule. The configured `^Ran ...` pattern also does not match normal unittest output without multiline matching, which the spec leaves unspecified. Nested suites or test output can produce multiple matching summaries.  
   **Fix:** define matching flags and summary ownership, reject ambiguous/non-numeric counts, and require executed—not merely collected or skipped—tests. Record identities and executed/skipped/expected-failure outcomes for M2. A small runner reporting hook is stronger than parsing arbitrary combined output.

10. **Should-fix — M1c spec — [m1c-spec.md:50](/home/work/code-quality-gate/.worktrees/review/plans/m1c-spec.md:50): subject identity rejects ordinary Python and leaves executable code outside the metric.**  
    A property getter and setter both become `PATH:Class.property`; overload declarations also repeat identities. The specified duplicate rejection therefore rejects common valid source. Conversely, module-level control flow and module-level lambdas have no enclosing function and receive no subject. A script can contain substantial logic but produce no CRAP findings.  
    **Fix:** specify stable accessor identities and treatment of overload declarations. Assign module execution and otherwise orphaned lambdas to an explicit subject, or report their unsupported/unmeasured scope. Define rename, move and split behavior before adopting baselines.

11. **Should-fix — M1c spec — [m1c-spec.md:55](/home/work/code-quality-gate/.worktrees/review/plans/m1c-spec.md:55), [m1c-spec.md:90](/home/work/code-quality-gate/.worktrees/review/plans/m1c-spec.md:90): the complexity oracle has an incorrect example and an inconsistent catch-all rule.**  
    CC 3 at zero coverage yields **12**, not 30. Thirty corresponds to CC 5. The table excludes unguarded `case _` but counts an equivalent unguarded capture such as `case remaining`, although neither adds a decision. This also conflicts with Fable’s stated catch-all convention.  
    **Fix:** correct the numeric oracle, define irrefutable patterns semantically, and specify ownership of defaults/decorators and nested bodies consistently with coverage ownership. Freeze these rules under the metric version and test composed constructs, not only isolated syntax nodes.

12. **Should-fix — M1c spec — [m1c-spec.md:46](/home/work/code-quality-gate/.worktrees/review/plans/m1c-spec.md:46), [checks.py:413](/home/work/code-quality-gate/.worktrees/review/quality_gate/checks.py:413): dependency execution is unspecified.**  
    M1b executes declaration order; M1c introduces `requires` without defining forward references, nonexistent IDs, wrong adapter types, cycles or dependencies on advisory checks. A CRAP table preceding its tests table has no specified behavior.  
    **Fix:** either validate that dependencies name earlier compatible checks, or execute a validated dependency graph. Define evidence lifetime and how an enforced dependent check handles a failed advisory prerequisite. Test reordered tables and invalid references.

13. **Should-fix — Implementation — [files.py:105](/home/work/code-quality-gate/.worktrees/review/quality_gate/files.py:105), [README.md:45](/home/work/code-quality-gate/.worktrees/review/README.md:45): the documented submodule installation breaks normal inventory.**  
    Git enumeration includes the submodule path as a gitlink. Once classified, `_is_code` attempts to open that directory to inspect its shebang. The directory probe raises `IsADirectoryError`, causing inventory failure with the documented nonempty shebang configuration.  
    **Fix:** enumerate Git entry types and handle gitlinks explicitly, recording their revision and integrity treatment. Use file-type checks before content reads; define treatment of external symlinks and nonregular replacements as well.

14. **Blocker — Implementation — [checks.py:113](/home/work/code-quality-gate/.worktrees/review/quality_gate/checks.py:113): selected filenames can become tool options.**  
    `{files}` inserts raw repository-relative names. For a class containing an extensionless file named `--help`, expansion yields `ruff check --no-cache --help bad.py`. The installed Ruff returned exit 0 and help text for that invocation, performing no lint. No policy edit is needed where the existing inventory permits such filenames.  
    **Fix:** expand filesystem arguments as unambiguous paths, such as `./--help`, while preserving separate arguments and ordering. Document tool-specific `--` requirements. Add a real-tool negative fixture proving the bad file is still checked.

15. **Should-fix — Implementation — [checks.py:189](/home/work/code-quality-gate/.worktrees/review/quality_gate/checks.py:189): command budgets leave descendants running.**  
    `subprocess.run(timeout=...)` terminates the immediate process, not its process tree. A no-write probe confirmed a child remained alive after the adapter returned `termination="budget"`. Captured output is unbounded, and regex evaluation occurs outside the subprocess timeout.  
    **Fix:** use a shared bounded runner with process-group termination/reaping, bounded output capture and a deadline covering evidence processing. Reuse it for clones and M1c subprocesses.

16. **Should-fix — Implementation — [clones.py:145](/home/work/code-quality-gate/.worktrees/review/quality_gate/clones.py:145): clone selection does not guarantee the selected files were analyzed.**  
    The adapter pins `min_tokens` but leaves other filtering defaults active. The installed binary’s merged configuration shows `max_size=1048576` and `min_lines=5`; hygiene permits files up to 10 MiB. A large selected source file can therefore be skipped while another file makes `--fail-on-empty` succeed.  
    **Fix:** explicitly control the complete detection configuration and reconcile analyzed/skipped files against inventory. Report deliberate exclusions and unsupported formats. Specify whether the metric requires only the token threshold or also a line threshold.

17. **Blocker — Implementation — [clones.py:81](/home/work/code-quality-gate/.worktrees/review/quality_gate/clones.py:81): missing SARIF execution evidence becomes a successful zero-clone result.**  
    Both `{"runs":[]}` and `{"runs":[{}]}` were accepted by the parser and returned no findings. The latter defaults missing `results` to an empty list. This can produce `pass` and resolve/prune every baseline entry without establishing a completed scan. Malformed nested location objects can also escape as uncaught attribute errors.  
    **Fix:** validate the expected producer/run structure and successful analysis evidence. Distinguish a valid empty result set from absent execution. Validate nested types and translate malformed reports into structured missing-evidence/error outcomes.

18. **Should-fix — Implementation — [ratchet.py:75](/home/work/code-quality-gate/.worktrees/review/quality_gate/ratchet.py:75): non-finite numeric values are accepted.**  
    TOML `bound = inf` passes validation and covers arbitrary finite regressions. `nan` also loads. Probes produced JSON containing `Infinity` and `NaN`, which are not valid standard JSON numbers.  
    **Fix:** require finite measurements, thresholds and bounds; enforce adapter-specific domains where appropriate. Serialize with `allow_nan=False` after validation. Test non-finite values through the actual baseline loader and JSON command.

19. **Should-fix — Implementation — [tools.py:65](/home/work/code-quality-gate/.worktrees/review/quality_gate/tools.py:65), [tools.py:190](/home/work/code-quality-gate/.worktrees/review/quality_gate/tools.py:190): safe archive members do not ensure safe installation destinations.**  
    Tool names and versions are not validated as path components. An in-memory lock with tool name `/tmp/review-probe-destination` produced a binary path outside `/cache`; installation uses the same construction and may remove an existing destination. Unknown lock keys are also silently accepted—I verified that `binary_sha256="ignored"` loads successfully.  
    **Fix:** reject separators, absolute components, traversal and control characters in names/versions; verify destination containment and reject unknown lock keys. Retain the existing tar member/link checks, which address a different boundary.

20. **Should-fix — Implementation — [checks.py:137](/home/work/code-quality-gate/.worktrees/review/quality_gate/checks.py:137), [checks.py:489](/home/work/code-quality-gate/.worktrees/review/quality_gate/checks.py:489): JSON omits the information needed to explain failures.**  
    A command exiting 7 with a diagnostic produced `outcome="fail"` and `findings=[]`, without exit code, command, output reference or failure reason. Inventory and hygiene are absent from `checks`, despite affecting acceptance. Clone timeout/signal errors become generic errors with default `termination="exit"`.  
    **Fix:** include structured built-in results and execution diagnostics, preserving exit/signal/budget details and bounded output or artifact references. JSON consumers should not need to parse stderr to understand rejection.

21. **Should-fix — Implementation — [cli.py:59](/home/work/code-quality-gate/.worktrees/review/quality_gate/cli.py:59), [checks.py:208](/home/work/code-quality-gate/.worktrees/review/quality_gate/checks.py:208): the one-document JSON promise fails on invalid usage and argv.**  
    `check --json --unknown-option` exits 2 with no JSON because argparse exits before the error-document handler. A TOML string containing an escaped NUL can reach command execution and raise uncaught `ValueError: embedded null byte`; the adapter catches only `OSError`.  
    **Fix:** route requested JSON usage errors through a structured parser error path, validate executable/argument constraints, and normalize expected execution errors without tracebacks or missing documents.

22. **Should-fix — Implementation — [checks.py:479](/home/work/code-quality-gate/.worktrees/review/quality_gate/checks.py:479): prune failure contradicts the reported decision.**  
    `prune_refused` changes only the exit code. I reproduced a failed advisory check with requested prune returning exit 1, JSON `decision="accepted_with_exceptions"`, and no JSON indication that pruning failed. A write failure has the same reporting problem.  
    **Fix:** report the prune operation and its outcome explicitly. Make the overall command decision consistent with its exit status while retaining the independent gate-evaluation decision if needed.

23. **Should-fix — Tests — [test_command_checks.py:138](/home/work/code-quality-gate/.worktrees/review/tests/test_command_checks.py:138): the real Ruff test proves availability, not enforcement.**  
    It invokes only `ruff --version`. No deliberate Ruff violation demonstrates that the configured command rejects bad source, and no successful `{files}` test verifies argument preservation, class union, sorting or dangerous filenames. This falls short of the approved deliberate-failure requirement.  
    **Fix:** run real Ruff against a known violation through `check --json`; assert rejection, then verify the repaired fixture passes. Include spaces and leading-option filenames.

24. **Should-fix — Tests — [test_result.py:18](/home/work/code-quality-gate/.worktrees/review/tests/test_result.py:18), [test_ratchet.py:105](/home/work/code-quality-gate/.worktrees/review/tests/test_ratchet.py:105): current assertions miss—or enshrine—the failure modes above.**  
    Result tests mostly verify field presence. The ratchet test explicitly requires every unmeasured entry to resolve. There are no regression fixtures for empty SARIF runs, shared baseline pruning, non-finite bounds, subprocess descendants, JSON usage errors, or refused-prune decision consistency. Tool tests validate member traversal but not destination traversal.  
    **Fix:** add focused failing fixtures for those behaviors. Add expiry-on-today and expired-but-resolved cases, and round-trip preservation of expiry and adapter metadata. Replace unconditional “unmeasured resolves” with completeness-aware assertions.

25. **Should-fix — Tests/CI — [m1c-spec.md:83](/home/work/code-quality-gate/.worktrees/review/plans/m1c-spec.md:83), [check.yml:15](/home/work/code-quality-gate/.worktrees/review/.github/workflows/check.yml:15): M1c’s acceptance suite will miss its most consequential metric failures.**  
    The listed fixtures omit imported-but-uncalled functions, same-line bodies, property accessors, module-only code, all-skipped suites, conflicting coverage configuration, missing child evidence and dependency ordering. CI runs only Python 3.13 although 3.12 is supported, and its five-minute timeout was measured before coverage was added.  
    **Fix:** add those fixtures to the spec, run metric parity fixtures on 3.12 and 3.13, and remeasure the complete M1c CI workload before adopting baseline values. GitHub execution and the external action-pin identities remain **unverified** in this offline review.

VERDICT: CHANGES