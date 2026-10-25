**Recommend the composition architecture, with revisions before implementation.** The main risks are misleading tier claims, policy changes that can approve themselves, and too much scope in the proposed first milestone. No files were edited; this review is based on source and document inspection.

1. **Keep the orchestrator thin in analysis, but authoritative in policy.**

   It should own file/module inventory, check selection, execution budgets, tool identity, evidence validation, enforcement decisions, waivers, ratchets, and reporting. Engines should supply measurements and findings; the orchestrator should decide whether those satisfy repository policy.

   It should not implement solvers, coverage instrumentation, fuzzing engines, proof generation, or an agent supervisor. The blueprint’s agentic prove-or-falsify loop belongs outside the gate: agents propose changes; the gate evaluates them.

   Preserve the existing QG1 foundation. However, **QG1 is an implementation milestone, not completed Tier 1**: [`command_check`](/home/work/code-quality-gate/.worktrees/qg1/qg.py:1195) currently runs inventory, hygiene, and optional clones. Consumer tests, coverage, lint, and integrity checks still need integration.

2. **Correct the assurance claims and make T3/T4 explicitly opt-in.**

   The [blueprint’s tier table and mandatory T3 stage](/home/work/code-quality-gate/.worktrees/qg1/plans/blueprint-tiered-verification-2026-10-24.md:21) need revision:

   | Tier | Defensible claim |
   |---|---|
   | T1 | Specified checks passed for the exercised cases and measured source. |
   | T2 | No counterexample was found within the recorded generators, corpus, and execution budget. |
   | T3 | Either a bounded verification obligation was discharged, or symbolic exploration found no counterexample; these are different outcomes. |
   | T4 | The named theorem was kernel-checked under recorded definitions, semantics, and assumptions. |

   Tests do not establish general liveness; fuzzing is not a universal quantifier; kernel checking does not imply an unbounded theorem.

   In particular, CrossHair documents that absence of a counterexample does not establish correctness. Its exit code zero means no counterexample was found, and targets without contracts may receive no analysis. Require obligation-level results and distinguish `proved`, `no_counterexample`, `unknown`, and `unsupported`. [CrossHair contracts](https://crosshair.readthedocs.io/en/latest/contracts.html), [limitations](https://crosshair.readthedocs.io/en/latest/limitations.html).

   Replace “T1–T3 every PR” with **T1+T2 by default; T3/T4 only for explicitly selected modules and obligations**. File extensions or `Cargo.toml` presence must not activate formal verification automatically.

3. **Make T2 a minimum obligation at meaningful module boundaries, not a ritual for every file.**

   Requiring both property testing and coverage-guided fuzzing on every glue script or notebook encourages trivial properties and empty harnesses. Require every code module to declare its T2 treatment, with property tests as the normal choice and fuzzing required for suitable input-processing boundaries.

   Examples include serializer round trips, data-loader shape invariants, command-argument preservation, checkpoint restoration, and parser robustness. Thin wrappers can identify the higher-level harness that exercises their behavior. Notebook algorithms should normally move into testable modules.

   Keep three distinctions:

   - **Not applicable:** the check genuinely does not fit the target; record why and what alternative evidence covers it.
   - **Waived:** an applicable obligation is temporarily excused.
   - **Unsupported or unavailable:** the tool or environment cannot perform the check; this is missing evidence.

   “No GPU,” “takes too long,” and “we have not written the harness” are not applicability reasons. They require another execution profile or an explicit waiver.

   Each T2 harness should report its target, property/oracle, accepted inputs, rejected inputs, budget, and replay artifacts. Detect unsatisfiable generators and harnesses that reject everything. Preserve counterexamples as regression tests or explicit examples; Hypothesis documents that its example database is a cache, not a permanent correctness guarantee. [Hypothesis reference](https://hypothesis.readthedocs.io/en/latest/settings.html).

4. **Separate enforcement, applicability, results, and exceptions in the policy schema.**

   The research’s `enforced/advisory/off` model conflates decisions that need different treatment. Use a versioned TOML schema with explicit records:

   | Record | Minimum contents |
   |---|---|
   | Module | Stable ID, paths, profile, owner |
   | Check | Stable ID, adapter, targets, tier, enforcement, budget, acceptance criteria |
   | Applicability decision | Check/module, reason, alternative evidence, review trigger |
   | Waiver | ID, exact scope, reason, owner, expiry, approval reference |
   | Baseline | Metric/version, subject identity, accepted bound, provenance, reason |

   A waiver should modify the policy consequence of a result; it must not replace the underlying result with `pass`.

   Require deterministic precedence and reject unknown keys, unknown check IDs, ambiguous assignments, and uncovered code. An omitted T1/T2 requirement should produce an unmet obligation. An unselected T3/T4 check should remain visibly unselected.

   Approval references must resolve to trusted approval evidence. A branch-local `approved_by = "owner"` string is not approval.

5. **Define acceptance independently of tool exit codes, and test that it fails.**

   The central rule should be:

   **Accept only when integrity checks succeed and every enforced obligation is satisfied or covered by a valid, approved exception.**

   Zero collected tests, missing coverage, malformed reports, missing tools, unexpected skips, interrupted runs, and stale evidence must not satisfy enforced checks. Preserve advisory failures in reports even when they do not block acceptance.

   Distinguish normal budget completion from interruption. A fuzzer completing its configured 60-second search can satisfy a bounded-search requirement; a verifier timing out cannot satisfy a proof requirement.

   Keep CLI exit codes simple—accepted, rejected, execution/configuration error—and put detailed distinctions in JSON. Report `accepted_with_exceptions` and `partial` explicitly. A repository may choose all-advisory analysis, but that must not earn an unqualified “T1+T2 compliant” label.

   Every enforced adapter needs a fixture demonstrating that a real violation makes the combined gate fail. Also exercise missing evidence, zero work, invalid waivers, and weakened configuration. These negative tests are part of the product’s acceptance criteria.

6. **Own one ratchet implementation, and specify CRAP measurement precisely.**

   Do not combine independently authoritative crapkit, jscpd, and orchestrator baselines. Keep one policy authority, while consuming upstream measurements and fingerprints.

   For CRAP, specify complexity rules, coverage denominator, function identity, handling of nested functions and straight-line code, and metric version. Record the constituent complexity and coverage measurements alongside the score. Missing coverage must remain missing; it must not silently become full coverage or a complexity-only score.

   CRAP alone is insufficient: an entirely untested function with complexity 1 scores only 2. Retain separate coverage requirements so low complexity does not excuse absent tests.

   Apply ratchets per function, with defined rename/split handling; do not let repository averages offset regressions. New functions use the configured ceiling, existing debt uses its approved cap, and tightening uses complete, trusted measurements. Metric upgrades require an explicit migration, not automatic reseeding.

   Normal ratchet operations may only tighten. Any newly accepted debt or raised bound is a separately approved policy change. That distinction preserves the meaning of “ratchets only lower.”

7. **Build the integrity foundation; use narc/fakegreen as supplemental detectors.**

   The minimum robust set is:

   - **A trusted reference:** evaluate against an approved base revision or externally supplied manifest that the working agent cannot rewrite.
   - **Protected enforcement inputs:** gate code/submodule pin, tool locks, policy, baselines, waiver ledger, CI entry points, test-discovery settings, coverage exclusions, contracts, golden data, and proof assumptions.
   - **Evidence bound to inputs:** record source—including dirty/untracked inputs—policy, tests, datasets, toolchain, and artifact digests; reject stale or mismatched evidence.
   - **Verification-loss detection:** compare collected test identities and outcomes, flag deletions, added skips/xfails, disabled assertions, reduced generators/budgets, and weakened discovery.
   - **Independent execution:** rerun required checks under a trusted runner, with protected tool installations and bounded subprocesses.

   Hashes establish identity only when their expected values are trusted. CODEOWNERS needs an enforced review mechanism; a path name or repository instruction does not make a file immutable.

   QG1 verifies download archives, but [`_jscpd_binary`](/home/work/code-quality-gate/.worktrees/qg1/qg.py:784) currently checks only that the cached binary exists. Stronger integrity requires validating the installed payload or using an installation the agent cannot modify. `python -I` is useful isolation, not a security boundary.

   Test counts alone are insufficient: deleted meaningful tests can be replaced with trivial ones. Permit reviewed replacements, and retain independent golden behavior checks to catch “reject every input” patches. Add targeted mutation testing later.

   Build these small deterministic controls yourself. Trial one anti-weakening scanner in advisory mode; fakegreen, for example, documents diff-based heuristics rather than semantic verification. Two scanners do not create a trust boundary. [fakegreen](https://github.com/fitzyracing1/fakegreen).

8. **Ship CLI plus canonical JSON first; treat SARIF and MCP as adapters.**

   Agents can already execute a command and consume JSON. MCP does not strengthen verification and adds another interface to maintain. Start with a stable CLI and JSON schema; add SARIF as a projection for code-scanning consumers.

   The result schema should contain:

   | Area | Required information |
   |---|---|
   | Identity | Schema/gate version, run ID, source/base revision and content digests |
   | Policy | Effective profile, policy/baseline hashes, selected and omitted obligations |
   | Finding | Stable fingerprint, check/rule ID, module, tier, location, severity |
   | Decision | Raw outcome, enforcement, applicability, waiver, blocking consequence |
   | Measurement | Actual value, expected bound, prior baseline, units, metric version |
   | Execution | Tool identity, command arguments, working directory, duration, budget, exit/termination reason |
   | Evidence | Test/obligation counts, coverage gaps, counterexample, replay data, artifact paths and hashes |
   | Assurance | Bounds, assumptions, unsupported features, incomplete work |

   Keep JSON stdout clean and send progress to stderr. Provide reproducible argument arrays rather than shell strings assembled from finding text.

   Later, MCP should wrap the same implementation. Reject the research’s proposed unrestricted [`gate_waive`](/home/work/code-quality-gate/.worktrees/qg1/plans/research-tiered-gates-2026-10-24.md:311): an agent may propose an exception, but it should not approve its own acceptance.

9. **Give ML research code separate deterministic and expensive execution profiles.**

   | Risk | Recommended treatment |
   |---|---|
   | Numerics | T1 reference cases; T2 shape/dtype/boundary generation, NaN/Inf handling, metamorphic relations, and reviewed absolute/relative tolerances |
   | Randomness | Record seeds and RNG configuration; use deterministic regression cases plus broader searches; preserve failing inputs |
   | GPU/native operations | Run device-specific integration tests; record framework, driver, device, precision, and deterministic settings |
   | Notebooks | Execute from a fresh kernel with pinned local data; extract reusable logic; map findings back to cells |
   | Training duration | Fast tiny-data tests for forward/backward passes, parameter updates, and checkpoint resume; separate longer validation jobs |
   | Scientific validity | Test splits, leakage prevention, preprocessing, metrics, and dataset identity; protect evaluation fixtures and tolerances |

   A fixed seed is not sufficient for cross-platform reproducibility: PyTorch explicitly does not guarantee identical results across releases or CPU/GPU execution. [PyTorch reproducibility](https://docs.pytorch.org/docs/2.14/notes/randomness.html).

   Avoid making “loss decreased after one stochastic step” a universal gate. Use controlled fixtures and explicit statistical acceptance criteria where necessary. Never retry until a favorable run appears.

   T3 is most plausible for small deterministic indexing, shape, scheduling, and configuration functions. T4 may establish an algorithmic property, but that does not establish correctness of its floating-point GPU implementation.

   Long-running evidence must identify the evaluated code, data, and environment. Missing required GPU evidence should remain pending or blocked, even when the CPU profile passes.

10. **Evaluate young tools by conformance and replaceability, not feature lists or stars.**

   I would not adopt crapkit or narc as the policy authority in the first milestone. Their advertised interfaces are useful references, but the repository needs independent acceptance tests for their measurements and failure behavior.

   There are concrete semantic mismatches to examine. Crapkit documents complexity-only treatment for optional coverage and workflows that advance baselines during verification. Those behaviors require careful adaptation to this gate’s missing-evidence and baseline-control rules. [crapkit](https://github.com/JeanFrancoisGagne/crapkit).

   Prefer a pinned external measurement adapter behind a small contract. For Python CRAP, use established coverage and complexity engines plus a small, independently tested join. Do not replace a young dependency with an equally unvalidated homegrown analyzer.

   Before promotion to enforcement, test unsupported syntax, missing reports, exclusions, identity changes, threshold boundaries, and version migrations. Vendoring means accepting maintenance responsibility; it does not remove risk.

   Retain the standard-library core while isolating third-party engine environments. Pin transitive dependencies and provision them explicitly from offline bundles. Check execution must never install dependencies.

11. **Keep T4 scoped to exact obligations, and defer a Python proof bridge.**

   A checked mathematical model attached to a Python module does not prove that Python module implements the model. Require an explicit implementation relationship: extraction, verified translation, equivalence evidence, or a clearly stated unverified correspondence.

   Protect the theorem’s definitions and semantic dependencies, not just its statement file. Audit the transitive assumptions of the actual required theorem. Grepping for `sorry`, `Admitted`, or `axiom` is useful hygiene but cannot establish this.

   Use the current built-in Lean `leanchecker`; the separate `lean4checker` repository is deprecated. [Lean checker notice](https://github.com/leanprover/lean4checker).

   The cited study supports the proof-generation/checking approach, not turnkey ML verification or the proposed latency targets. Its public artifacts concern specific RISC-V binaries under an explicitly incomplete process model. [Proof corpus](https://github.com/theorem-labs/oss-verify-proofs).

   Also preserve a third outcome in “prove-or-falsify”: **inconclusive**. A failed proof attempt is not a counterexample; a candidate counterexample must be concretely reproduced before becoming a regression test.

12. **Ship a smaller Python T1+T2 milestone with explicit acceptance criteria.**

   The [research’s first milestone](/home/work/code-quality-gate/.worktrees/qg1/plans/research-tiered-gates-2026-10-24.md:337) includes too many integrations. Ship:

   - Versioned policy, explicit applicability, approved waivers, and canonical JSON.
   - Existing inventory/hygiene/clones plus Ruff, tests, fresh coverage, and a per-function CRAP ratchet.
   - Hypothesis on meaningful research-code properties and one real bounded fuzzing target.
   - Trusted-base integrity checks, test-loss detection, evidence provenance, and offline tool provisioning.
   - An end-to-end demonstration in the Python/ML repository.

   Acceptance should demonstrate both success and deliberate failure: broken behavior, a new untested function, removed tests, weakened configuration, expired waiver, missing tool, stale coverage, and an empty property harness.

   Defer MCP, multiple anti-weakening scanners, routine mutation runs, T3/T4 integrations, agent supervision, and automatic proof translation. Add SARIF after JSON stabilizes. Next prioritize the Emacs Lisp adapter using Emacs’s reader, then Bash coverage after validating its measurement semantics; neither should be presented as branch coverage without evidence.

**Overall recommendation:** approve composition with a small, authoritative policy-and-evidence core. Ship trustworthy Python T1+T2 enforcement first; make exceptions visible and independently approved, and add higher assurance only through explicit, accurately described obligations.