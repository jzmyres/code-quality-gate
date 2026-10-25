# Second review (Fable): tiered code-quality gate design, 2026-10-24

Fable (Claude, model fable) wrote this second, independent review after Astra's. Fable read the gate repo, the
blueprint, both research reports, Astra's review, the editor's `tests/crap.el`, `crap-child.el`, `inventory.el` and
`Makefile`, and both consumer `CLAUDE.md` files. It edited nothing. This file records the report as returned.

## 1. Where it differs from Astra

It agrees without comment on Astra's findings 1, 2, 5, 8 and 11.

- **#3, tier 2 per module.**
  - Agrees on the trichotomy of not applicable, waived and unsupported.
  - Disagrees with a separate record in which each module declares its tier-2 treatment. The inventory class is
    already the per-file policy unit, so the obligation goes on the class (`checks = [...]`).
- **#4, the five-record schema with owner, expiry and approval reference.**
  - Too heavy, and the trust claim is hollow for single-user offline repositories. An approval reference would be
    a field that cannot fail.
  - The real control is to evaluate with the policy and baselines from the reviewed base revision
    (`--policy-from REV`), and to fast-forward `main` only after review.
  - Keep waivers as baseline entries: subject, bound and reason, with an optional `expires`.
- **#6, a separate coverage floor.**
  - Agrees on one ratchet, a precise metric specification, and a metric version per adapter.
  - Disagrees with a second coverage number. The editor's rule ("untested code passes only at CC ≤ 2", "unmeasured
    fails") is deliberate, and a second number reintroduces the coverage-percentage game. Offer a total-coverage
    floor as an advisory check only.
- **#7, integrity.**
  - Agrees on a trusted reference, protected inputs and verification-loss detection.
  - Independent execution under a trusted runner is safe-agent-harness's job; the gate must only be runnable there
    deterministically.
  - Pin `binary_sha256` in `tools.lock.toml` and verify it at each use.
- **#9, ML profiles.** These are test-authoring guidelines for the research repo. The gate contributes a
  `[profiles]` table selecting which checks run, plus recorded seeds.
- **#10, crapkit.** Python CRAP needs no third-party analyser. coverage.py's JSON report gives per-file
  executed and missing lines and branches; the standard library's `ast` gives function spans and complexity.
- **#12, the milestone.** Still too large; split it (section 5).

## 2. What both missed

- **Nobody read `crap.el`.** The editor gate has exact semantics to preserve:
  - complexity rules as a data table, with quoted data skipped and catch-all clauses not counted;
  - coverage as Edebug stop points, with lambdas attributed to the enclosing definition;
  - a child Emacs per set, `:allow-empty`, and `crap-excluded` with reasons;
  - unrounded comparison, "exactly at the mark passes" and "a rename is a new function";
  - a baseline update refuses while the check fails;
  - GUI tests are excluded.

  CRAP scores are not comparable across languages. Every result carries a `metric_version` per adapter and is
  never aggregated across adapters.
- **Python function identity** is `module:Class.method`, with nested definitions and lambdas attributed to the
  enclosing top-level definition.
- **Anti-vacuity through an execution log** (the harness's shell-tested rule) generalises as a class obligation,
  `executed_by = "test"`: the only honest tier-1 evidence for Bash.
- **The gate does not own a test runner.** The policy names the consumer's command; an adapter wraps it and
  parses how many tests were selected. Zero selected fails.
- **A generic `command` adapter** (exit code plus an optional `must_match` regular expression) covers Ruff,
  ShellCheck, byte-compile, checkdoc and package-lint with no per-tool code.
- **No SARIF or MCP until a consumer exists.**
- **Protected inputs include coverage exclusions:** count pragma lines as a ratcheted quantity.

## 3. Architecture

A standard-library package `qg/`, with `qg.py` as the stable entry point.

- **Core** (no tool knowledge):
  - policy: loading TOML, rejecting unknown keys, precedence;
  - inventory and hygiene;
  - one generic reasoned ratchet: `--prune` only lowers and refuses while the check fails;
  - the runner: selection, budgets, the decision rule and the JSON result;
  - tools: lock, fetch, path and verify.
- **Adapters** (they measure, never decide):
  - `command`;
  - `clones` (jscpd);
  - `pytest_cov`;
  - `python_crap` (`ast` plus coverage JSON gives complexity, points and hits per function);
  - `elisp_crap` (today's reader, decision table and child-Emacs instrumentation, moved into `elisp/qg-crap.el`
    and emitting JSON);
  - later, `hypothesis` and `atheris`.

  Missing or malformed evidence is `unsupported`, never zero or a pass.
- **Replacing the Emacs Lisp gate without regression:**
  1. move the CRAP measurement into the gate;
  2. add a golden parity test: the new unrounded scores equal today's `make crap` for every set;
  3. convert the three `.eld` baselines in one commit, with no shim;
  4. delete `crap.el`'s scoring and the old targets;
  5. turn inventory rules into `[[rule]]` entries and covering checks into class `checks`.

## 4. Schemas

Policy (`quality-gate.toml`):

```toml
schema = 1
[classes.python]
code = true
checks = ["ruff", "pytest", "crap-py", "clones"]
[checks.crap-py]
adapter = "python_crap"
enforcement = "enforced"
tier = 1
requires = ["pytest"]
threshold = 6
baseline = "quality-gate-crap.toml"
metric_version = "python-lines-branches/1"
[[not_applicable]]
check = "crap-py"
class = "notebook"
reason = "..."
[[waiver]]
check = "ruff"
subject = "scripts/legacy_plot.py"
reason = "..."
expires = "2026-12-31"
```

Baseline entries: `subject`, `bound`, `reason`. Result, on stdout only:
- `schema`, `gate_version`, `revision`, `policy_from`, `policy_sha256`, `dirty_inputs`;
- `decision`: one of accepted, accepted_with_exceptions, rejected or error;
- per check: id, tier, enforcement, adapter, metric_version, outcome, duration, budget, termination, tool
  version;
- per finding: subject, value, bound, measurement, baseline reason, waived, blocking, location;
- `unselected` checks and `resolved_baseline_entries`.

Exit codes are 0, 1 and 2.

## 5. Build order

| Milestone | Content | Acceptance (each must also fail correctly) |
|---|---|---|
| M1: tier 1 on the Python research repo | package split; the policy loader with `[checks]`; the `command`, `pytest_cov` and `python_crap` adapters; the generic ratchet (clones migrated onto it); the JSON result | an untested new function at CC 3 fails; exactly at its mark passes and 0.1 above fails; prune lowers and never raises; zero tests fails; missing coverage is unsupported, not a pass; a Ruff violation fails; an advisory failure is reported without blocking; an added pragma is visible |
| M2: integrity | `--policy-from REV`; `binary_sha256`; a verification-loss detector (deleted tests, added skips, lowered budgets, grown pragma counts) | a working-tree baseline edit is ignored under `--policy-from`; a tampered jscpd fails; a deleted test fails; a reviewed replacement passes |
| M3: Emacs Lisp adapter and cutover | section 3, with the golden parity test | identical unrounded scores; the editor's gate green; its failure tests ported |
| M4: tier 2 | a `hypothesis` adapter (recorded seeds; an empty strategy or zero examples fails; counterexamples committed); one `atheris` target with a corpus and a fixed budget; `executed_by` in the harness | completed budget satisfies; interrupted fails |
| M5 (opt-in) | CrossHair with four outcomes; tier 4 as hand-written Lean artifacts checked by `leanchecker` with an axiom allowlist; GPU profiles | — |

## 6. Top risks

1. **Regressing the editor gate.** Contain it with the parity test, keeping the Emacs Lisp measurement and moving
   only the ratchet.
2. **CRAP scores looking comparable across languages.** Contain it with `metric_version` and no cross-adapter
   sums.
3. **An agent weakening the policy.** Contain it with `--policy-from`, pragma and budget ratchets, and the harness
   running the gate outside the agent's write scope.
4. **A vacuous tier 2.** Reject empty harnesses and zero examples, commit counterexamples, and fix budgets in
   policy.
5. **Scope creep.** Each addition needs a named consumer.
6. **The 1,285-line `qg.py`.** The package split in M1 is a prerequisite; gate it with its own CRAP once
   `python_crap` exists.

## Summary

1. Approve the thin standard-library orchestrator: measurement in adapters, decisions only in the core, one
   generic reasoned ratchet.
2. Reject the heavy five-record policy and approval references; the trust root is the reviewed base revision.
3. Compute Python CRAP from `ast` plus coverage.py JSON. Move today's Emacs Lisp measurement into the gate, proven
   by a golden parity test before `crap.el` is deleted.
4. Build tier 1, then integrity, then the Emacs Lisp cutover, then tier 2. Tiers 3 and 4 are opt-in with explicit
   outcomes. No MCP or SARIF until a consumer exists.
5. Every layer ships deliberate-failure fixtures.
