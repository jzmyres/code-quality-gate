# User blueprint (condensed): high-ROI formal verification and symbolic quality gates in CI

Provided by the user on 2026-10-24. Condensed by Claude for reviewers; the structure and claims are the user's.
Its motivation cites Anthropic's 2026-10-22 article "LLMs are making formal software verification feasible at a
much larger scale" and `theorem-labs/oss-verify-proofs`. Both were verified to exist
(`research-tiered-gates-2026-10-24.md` section 3.6).

## Motivation (as cited)

- Claude produced Rocq proofs, checked by the kernel, for 239 OSS-Fuzz entry points in 123 C/C++ libraries. Fuzz
  harnesses were turned into theorem statements: no fault, abort or unmodelled behaviour for all inputs under
  64 MiB, under a Linux process model.
- Failed proofs acted as a bug oracle, finding bugs that trillions of fuzz executions missed: large-input counter
  underflows, multi-handle state corruption, logic flaws.
- Machine-code-level proofs are infeasible as daily PR gates. Proofs are enormous (630k lines of Rocq for a
  391-line cJSON entry point), checks take 30 minutes to hours and up to 20 GiB, and the scope is limited to crash
  freedom on single-threaded static builds.

## The four-tier assurance funnel (move verification up to source/IR level)

| Tier | Domain | Tools | Guarantees | Why the next tier cannot replace it |
|---|---|---|---|---|
| 1. Concrete unit and integration tests | ∃x over real OS and hardware | pytest, cargo test, ctest | non-vacuity, liveness, real integration | proofs can be vacuous and miss unmodelled boundaries |
| 2. Coverage-guided fuzzing and property-based tests | stochastic ∀x ~ mutated distribution | Hypothesis, libFuzzer, cargo fuzz, CIFuzz | cheap rapid falsification | avoids spending solver or LLM effort proving false theorems |
| 3. Bounded model checking and symbolic execution | ∀x within a bound K | CrossHair + Z3 (Python), Kani + CBMC (Rust/C) | exhaustive search with no proof scripts; finds measure-zero edge cases | fuzzers almost never hit exact magic values; full proofs are too slow for routine code |
| 4. Deductive theorem proving | unbounded ∀x over a math model | Lean 4 (lake + lean4checker), Rocq 9.2 (coqchk) | unbounded certainty, inductive invariants | bounded checkers explode beyond K |

Targets: fast gates under 5 minutes; asynchronous path-filtered gates under 30 minutes.

## Repository topology (anti-reward-hacking by path)

`tests/unit`, `tests/fuzz_corpus` (pinned seeds), `tests/symbolic` (CrossHair/Kani harnesses),
`verification/specs/` (read-only for agents, CODEOWNERS-locked theorem statements) and
`verification/proofs/` (writable by agents, with a shared lemma cache).

## Stages

1. **Zero-proof-script symbolic gate (tiers 1-3, every PR, under 3 minutes).** Write one contract in the host
   language and run it both stochastically and symbolically. Python: `deal` pre/post/purity contracts, Hypothesis
   via `pytest --deal`, and `crosshair check` with Z3 on changed core files. Rust/C: Kani proofs over bounded
   inputs.
2. **Agentic prove-or-falsify loop (tier 4, on core changes or nightly).**
   - The agent has a dual objective with a bounded budget of about 15 compiler interactions: close the proof
     against the locked spec, or turn a stuck subgoal into a concrete counterexample, emitted as a failing tier-1
     test.
   - Context isolation: an orchestrator spawns small sub-agents per unresolved `sorry`/`Admitted`. Each gets
     only the theorem, the shared lemma signatures and the function body.
   - A shared lemma cache (`SharedLemmas.lean`) lets proved lemmas be reused. The blueprint claims about 17% fewer
     tokens from shared-workspace multi-agent runs.
3. **Anti-reward-hacking controls.**
   - Immutable spec hashing: a diff gate rejects agent edits to `verification/specs/` or deletions of tests
     without architect sign-off.
   - Fresh-kernel replay: `lean4checker --fresh`, or `coqchk`, with an axiom audit allowing only the standard
     axioms; `sorry`, `Admitted`, `axiom` and `unsafe` fail.
   - Differential equivalence: a patch must pass both the universal safety proof and the existential golden-trace
     suite, penalizing degenerate input-rejecting patches.

## CI reference

A fast job runs tiers 1-3: a spec-weakening guard, pytest plus Hypothesis seed replay, CrossHair on changed core
files, and Kani if `Cargo.toml` exists. A path-filtered job runs tier 4: lean-action with warnings as errors,
lean4checker, and an axiom audit.

## Decision matrix

| Module profile | Primary gate | Bound | Latency |
|---|---|---|---|
| REST APIs, CLI glue, I/O orchestration | tier 1 | existential paths | 5-30 s |
| parsers, serializers, data loaders | tier 2 (seed corpus + 90 s diff fuzz) | crash freedom on mutated corpora | 60-120 s |
| bit packing, ring buffers, quantization math, tensor indexing | tier 3 (CrossHair or Kani) | exhaustive up to K | 15-90 s |
| consensus state machines, crypto primitives, inductive calibration theorems | tier 4 (Lean or Rocq, agentic repair) | unbounded proof | 1-5 min check |
