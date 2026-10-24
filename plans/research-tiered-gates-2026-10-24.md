# Tiered code-quality gate: does an existing project already provide it?

**Research date:** 2026-10-24 (UTC). **Scope:** Python first (research/ML repositories), then Emacs Lisp and Bash. Tiers 1–2 are the minimum; tiers 3–4 are opt-in per module. The gate must support selective compliance (enforced / advisory / reasoned waiver), machine-readable output or MCP, and fully offline, pinned operation.

**Evidence legend**

- **[V]** — verified in this session by fetching or reading: GitHub API/HTML/Atom, PyPI JSON, raw README/LICENSE, or the project's documentation site.
- **[U]** — unverified, inferred, or a judgement; not established by a fetched source.
- "No X documented" means no X was found in the README/docs reviewed; it is an absence claim, normally **[U]**.
- Stars and last-commit dates were read on 2026-10-24 and will drift. "Last commit" is the newest commit timestamp from the repository Atom feed or API; for a few repos it is the API `pushed_at`.

**Short answer [U, search-based].** No existing open-source project found provides the whole design: a tiered T1–T4 gate with per-check enforced/advisory/waiver policy, one JSON/SARIF/MCP interface, offline operation, and Python → Emacs Lisp → Bash coverage. The pieces exist and several are strong, but the integration layer is missing. The closest single slices are **crapkit** (CRAP + coverage ratchet + JSON + MCP), **narc** / **fakegreen** (anti-reward-hacking with waivers), **Nagini** (Tier 3 Python with an MCP server), **deal** (contracts + property tests + an SMT-based prover), and **Verification Ladder** (state-bound evidence and per-repository required-gate policy). The strongest T4 evidence is the 2026-10-22 Anthropic/Theorem work and the `theorem-labs/oss-verify-proofs` repository — real, kernel-checked, but C/C++/RISC-V proof artifacts, not a reusable Python gate.

---

## 1. Summary

- **[U, search-based]** No project found combines Tier 1 (tests, coverage, per-function CRAP with ratchet, lint, duplicates, inventory/hygiene, anti-reward-hacking), Tier 2 (property-based testing, fuzzing), Tier 3 (bounded model checking / symbolic execution), and Tier 4 (kernel-checked proofs with axiom audit) under one policy engine.
- **[V]** Tier 1 engines exist and most are mature: linters, coverage, duplication and mutation testing have mature implementations; CRAP analyzers exist but the Python ones are young (crap4py 1★, crapkit 1★, crapgate 0★). The missing part is a single ratcheted, reason-bearing policy layer.
- **[V]** Tier 2 is well served for Python by Hypothesis and Atheris; Schemathesis covers HTTP APIs built on Hypothesis; deal generates Hypothesis cases from contracts. None of them is a gate; all are libraries/CLIs that a gate can call.
- **[V]** Tier 3 for Python exists in four materially different forms: CrossHair (concolic/symbolic execution with Z3), deal's prover (experimental, Z3/SMT), Nagini (Viper-based static verification, with an MCP server), and ESBMC-Python (bounded model checking of type-annotated Python). All are partial by design (annotations, subsets, timeouts).
- **[V]** Tier 4 kernels and checkers exist (Lean 4 with the now-built-in `leanchecker`; Rocq with `rocqchk` and `Print Assumptions`), and LeanCIL shows the kernel-check + replay + axiom-audit pattern for .NET. **[U]** Nothing found connects Python code to a Lean/Rocq proof obligation.
- **[V]** The strongest agent interfaces found are crapkit (12 read-side MCP tools, versioned JSON), Nagini (MCP: `verify_file`, `verify_method`, `verify_snippet`, structured diagnostics), aislop (JSON/SARIF + MCP), and the official SonarQube MCP server (source-available, server-backed). **[U]** No unified MCP server spanning tiers was found.
- **[V]** Waivers with a mandatory reason exist in **narc** (single anti-cheat tool) and, in a broader but server-bound form, in SonarQube (issue transitions/quality gates). **[U]** No tiered gate implementing per-check enforced/advisory/waived-with-reason semantics across T1–T4 was found.
- **[V]** The engines named below run locally: Hypothesis, Atheris, CrossHair, Nagini, ESBMC, Kani, Lean and Rocq have no service dependency. **[V]** The exceptions are AProver, PR-Agent and the SonarQube MCP path, which need an LLM API or a SonarQube server. qlty is BSL-1.1; the SonarQube MCP server is source-available, not OSI.
- **[V]** The closest "gate" projects — crapkit, narc, fakegreen, VibeCI, Verification Ladder, agentic-test-forge — are weeks old and have 0–4 stars. **[U]** They are useful designs and small codebases to vendor or reimplement, not dependencies to trust unexamined.
- **[V]** The study cited by the blueprint is real: the repository `theorem-labs/oss-verify-proofs` exists (created 2026-10-22, MIT, 133 stars at fetch) and Anthropic published "LLMs are making formal software verification feasible at a much larger scale" on 2026-10-22. It reports 239 entry points across 123 C/C++ OSS-Fuzz libraries, with Rocq-kernel-checked proofs, not a Python gate. The public repo holds a subset: 60 entry points in 25 libraries.

**Recommendation in one sentence [U].** Compose the mature engines behind a thin, offline orchestrator that owns tiers, policy, waivers and JSON/SARIF/MCP; adopt crapkit or a vendored equivalent for the CRAP ratchet, narc for diff-level anti-cheat waivers, Nagini/CrossHair/deal for Tier 3 Python, and Lean/Rocq checkers for Tier 4; build only the orchestrator, the Emacs Lisp CRAP/coverage adapter, and (if required) the Python→Tier-4 proof bridge.

---

## 2. Table

Metadata is **[V]** from GitHub/PyPI on 2026-10-24 unless the Evidence column says otherwise. "Arch." = archived. **[U]** Tier mappings and maturity labels are my judgement from the fetched docs and activity; they are not the projects' own claims. "Enf./waivers" asks whether it has configurable enforcement levels or reasoned waivers; "JSON/MCP" asks for machine-readable output or an agent interface.

### 2.1 Python, tiers 1–3

| Project | Licence | Stars | Last commit | Arch. | Tiers | Languages | Enf./waivers | JSON/MCP | Offline | Maturity | Evidence |
|---|---|---:|---|---|---|---|---|---|---|---|---|
| [Hypothesis](https://github.com/HypothesisWorks/hypothesis) | MPL-2.0 | 9,108 | 2026-10-23 | no | T2 | Python | none (library) | pytest integration; no CLI/MCP | yes | mature | V meta; V feat |
| [deal](https://github.com/life4/deal) | MIT | 918 | 2025-11-30 | no | T1 linter; T2 cases; T3 prover | Python | none | `deal lint --json`; `deal prove` text | yes | mature, prover experimental | V meta; V feat |
| [icontract](https://github.com/Parquery/icontract) | MIT | 419 | 2026-01-29 | no | T1 contracts | Python | none | library only | yes | mature | V meta; U feat |
| [CrossHair](https://github.com/pschanely/CrossHair) | MIT | 1,342 | 2026-10-23 | no | T3 | Python | none | text CLI; no JSON/MCP found | yes | mature-ish | V meta; V feat |
| [Atheris](https://github.com/google/atheris) | Apache-2.0 | 1,693 | 2026-06-17 | no | T2 fuzzing | Python + native | none | libFuzzer artifacts; no gate JSON | yes | mature | V meta; V feat |
| [Schemathesis](https://github.com/schemathesis/schemathesis) | MIT | 3,701 | 2026-10-24 | no | T2 (HTTP APIs) | HTTP/OpenAPI/GraphQL | none | JSON, JUnit, NDJSON, HAR, HTML | yes, against local app | mature | V meta; V feat |
| [Nagini](https://github.com/marcoeilers/nagini) | MPL-2.0 | 303 | 2026-10-19 | no | T3 | Python 3 | none | MCP server + structured diagnostics | yes (bundled Z3/Viper; Java) | research-grade | V meta; V feat |
| [ESBMC](https://github.com/esbmc/esbmc) | complex/aggregated | 533 | 2026-10-24 | no | T3 | C/C++/Python/Rust/Kotlin/Solidity | none | text counterexamples; no SARIF found | yes | mature | V meta; V feat |
| [crapkit](https://github.com/JeanFrancoisGagne/crapkit) | MIT | 1 | 2026-10-02 | no | T1 CRAP + coverage ratchet | 14 languages incl. Python, shell | partial: scopes, ceilings, advisory hook vs commit gate; no reasoned waivers | JSON schema 1; MCP 12 tools | yes | early | V meta; V feat |
| [crap4py](https://github.com/gabadi/crap4py) | MIT | 1 | 2026-06-24 | no | T1 CRAP | Python | threshold only (`--max-crap`) | table only | yes | early | V meta; V feat |

### 2.2 Other languages, tiers 3–4

| Project | Licence | Stars | Last commit | Arch. | Tiers | Languages | Enf./waivers | JSON/MCP | Offline | Maturity | Evidence |
|---|---|---:|---|---|---|---|---|---|---|---|---|
| [Kani](https://github.com/model-checking/kani) | Apache-2.0 | 3,588 | 2026-10-24 | no | T3 | Rust | none | `--sarif` | yes | mature | V meta; V feat |
| [Verus](https://github.com/verus-lang/verus) | MIT | 3,433 | 2026-10-24 | no | T3 | Rust | none | not verified | yes | mature | V meta; V feat |
| [Dafny](https://github.com/dafny-lang/dafny) | MIT | 3,591 | 2026-10-20 | no | T3 | Dafny | none | report generator exists but stale | yes | mature | V meta; U feat |
| [Frama-C](https://github.com/Frama-C/Frama-C-snapshot) | LGPL-2.1+ (unverified) | 190 | 2020-10-21 | no | T3 | C | none | text | yes | upstream moved to GitLab; GitHub snapshot stale | V meta; V feat |
| [Creusot](https://github.com/creusot-rs/creusot) | LGPL-2.1 | 1,941 | 2026-10-24 | no | T3 | Rust | none | not verified | yes | active | V meta; V feat |
| [Lean 4](https://github.com/leanprover/lean4) | Apache-2.0 | 9,659 | 2026-10-24 | no | T4 | Lean | none | text/artifacts | yes | mature | V meta; V feat |
| [Rocq](https://github.com/rocq-prover/rocq) | LGPL-2.1 | 5,628 | 2026-10-23 | no | T4 | Rocq | none | text/artifacts | yes | mature | V meta; V feat |
| [oss-verify-proofs](https://github.com/theorem-labs/oss-verify-proofs) | MIT | 133 | 2026-10-23 | no | T4 proofs (C/C++ via RISC-V) | C/C++ OSS-Fuzz targets | allowed-axiom list, not waivers | `oft check`; Docker proof checker | yes (`--network none`) | very early (created 2026-10-22) | V meta; V feat |

### 2.3 Orchestrators, agent interfaces, anti-reward-hacking

| Project | Licence | Stars | Last commit | Arch. | Tiers / role | Languages | Enf./waivers | JSON/MCP | Offline | Maturity | Evidence |
|---|---|---:|---|---|---|---|---|---|---|---|---|
| [qlty](https://github.com/qltysh/qlty) | BSL-1.1 | 3,203 | 2026-10-24 | no | T1 linters/coverage; no CRAP | many | quality gates (prior research) | JSON/SARIF (prior research) | local CLI; telemetry unverified | mature | V meta; U feat |
| [SonarQube](https://github.com/SonarSource/sonarqube) | LGPL-3.0 | 11,103 | 2026-10-24 | no | T1 static/coverage; server | many | yes: quality gates + issue waivers | API + MCP via separate server | no (server) | mature | V meta; U feat |
| [MegaLinter](https://github.com/oxsecurity/megalinter) | AGPL-3.0 | 2,622 | 2026-10-20 | no | T1 linters only | many | none | SARIF/JSON | container, mostly offline | mature | V meta; U feat |
| [jscpd](https://github.com/kucherenko/jscpd) | MIT | 6,447 | 2026-10-24 | no | T1 duplicates | 220+ | none | SARIF/HTML/badge | yes | mature | V meta; V feat |
| [aislop](https://github.com/scanaislop/aislop) | MIT | 700 | 2026-10-06 | no | T1 static/AI-slop | 10 incl. Python | baseline + threshold + rule toggles; no reasoned waivers | JSON/SARIF + MCP | scan yes; fix agent may call provider | early | V meta; V feat |
| [VibeCI](https://github.com/piyush588/vibeCI) | MIT | 5 | 2026-10-17 | no | T1 local checks | Python/JS ecosystems | fail/warn; "honest boundaries" | JSON + agent rule files + hook | yes | very early | V meta; V feat |
| [Verification Ladder](https://github.com/Deep-Sixed/Verification-Ladder) | MIT | 1 | 2026-09-28 | no | policy/evidence, not tiers | any | `verification.toml` required gates; missing = BLOCKED; no advisory/waiver ledger found | evidence records; compose protocol | yes | early | V meta; V feat |
| [narc](https://github.com/tranhuuhuy297/narc) | MIT | 0 | 2026-10-18 | no | T1 anti-reward-hacking | 13 + CI/config | `--fail-on` + waivers with mandatory reason | JSON/SARIF/markdown | yes | very early | V meta; V feat |
| [fakegreen](https://github.com/fitzyracing1/fakegreen) | MIT | 4 | 2026-10-15 | no | T1 anti-reward-hacking | diff-level, multi-language | `--fail-on`; ignores reported, no reason requirement | JSON/SARIF | yes | very early | V meta; V feat |
| [mutmut](https://github.com/boxed/mutmut) | BSD-3-Clause | 1,504 | 2026-10-23 | no | T1 mutation testing | Python | none | text | yes | mature | V meta; U feat |
| [SonarQube MCP](https://github.com/SonarSource/sonarqube-mcp-server) | Sonar Source-Available v1.0 (not OSI) | 672 | 2026-10-23 | no | agent interface to SonarQube | many | inherits server gates/waivers | MCP | no (needs SonarQube) | early | V meta; U feat |
| [mcp-code-checker](https://github.com/MarcusJellinghaus/mcp-code-checker) | MIT | 19 | 2026-10-23 | no | T1 agent interface | Python (pylint/pytest) | none | MCP | yes | early | V meta; U feat |
| [PR-Agent](https://github.com/qodo-ai/pr-agent) | MIT | 13,589 | 2026-10-24 | no | AI review, not verification | many | none | PR comments | no (LLM API) | mature | V meta; U feat |

---

## 3. Notes per candidate

### 3.1 Python: tiers 1–3

**Hypothesis** — [V] MPL-2.0, 9,108 stars, last commit 2026-10-23, not archived (LICENSE.txt; GitHub API/Atom). It is a property-based testing library with a pytest plugin, not a CLI gate. It is the Tier 2 engine behind deal.cases and Schemathesis, and it has a first-class CrossHair integration (`hypothesis-crosshair`, `crosshair-tool` extras) [V PyPI dependency metadata]. Offline by construction: a local library with no service dependency [V docs/PyPI]. It has no coverage/CRAP/waiver/reporting layer [U absence].
- Relevance: adopt as the Tier 2 property engine; wrap it in the gate. Do not rebuild a shrinking engine.
- Limitation: Hypothesis finds counterexamples; it does not decide coverage policy, waivers, or "enough" testing.

**deal** — [V] MIT, 918 stars, last commit 2025-11-30, not archived. It is the only Python project found that spans three tiers in one package: contracts (`deal.pre/post/raises`), a linter (`python3 -m deal lint .`, with `--json`), property tests (`deal.cases`, built on Hypothesis), and a built-in formal verifier (`python3 -m deal prove`) that "turns your code into a formal theorem and then proves it" [V deal docs: verification, linter, tests pages]. The prover is explicitly experimental and applies to a small subset: functions/staticmethods, pure Python, fully annotated, unsupported features skipped [V docs].
- Relevance: strong Tier 1/2/3 spine for Python contract-driven code; `deal lint --json` is directly consumable by a gate.
- Limitation: Z3/SMT-based (the `deal-solver` extra) [U: Z3 not named on the verification page fetched]; no coverage/CRAP/duplicates, no enforcement levels or waivers, no MCP [U].

**icontract** — [V] MIT, 419 stars, last commit 2026-01-29, not archived. Runtime design-by-contract decorators; no gate, no CLI reporting [U: not documented in the sources reviewed]. **icontract-hypothesis** ([repo](https://github.com/Parquery/icontract-hypothesis)) is the bridge from contracts to property tests: 0 stars, last commit 2020-12-18, not archived, PyPI 1.1.7 uploaded 2021-07-23, no GitHub licence detected but an MIT classifier on PyPI [V]. Treat the bridge as abandoned; deal or Hypothesis-direct is the safer composition.

**CrossHair** — [V] MIT (with bundled Apache/PSF components), 1,342 stars, last commit 2026-10-23, not archived. It performs symbolic execution of Python functions by calling them with symbolic values and using Z3; contracts are the specification surface; `crosshair watch`/`crosshair check` are the CLI [V docs: "How Does It Work?", "Get Started"]. It is the most general Tier 3 Python tool for ordinary code, but it is bounded by path explosion, unsupported features and timeouts [U: limitations page not read in detail]. No JSON/SARIF/MCP interface was found in the docs reviewed [U absence]. Offline: Z3 is a local dependency (`z3-solver>=4.13`) [V PyPI].
- Relevance: Tier 3 "symbolic execution" engine for Python; invoke per module with a budget.
- Limitation: no native machine-readable verdict; the gate must parse text or use exit codes, or wrap its Python API.

**Atheris** — [V] Apache-2.0, 1,693 stars, last commit 2026-06-17, not archived. Coverage-guided, libFuzzer-based Python fuzzer, Python 3.11–3.14, Linux/macOS, native-extension support with ASan/UBSan [V README]. It is an engine, not a gate: you supply harnesses and get crashes/coverage artifacts [U for output format details]. Offline [V].
- Relevance: Tier 2 fuzzing for parsers/decoders and native extensions; pair with Hypothesis for structured inputs.
- Limitation: no policy/waiver/report layer; harness maintenance is real work; Windows support is absent per README [V].

**Schemathesis** — [V] MIT, 3,701 stars, last commit 2026-10-24, not archived. Schema-driven property testing for OpenAPI/GraphQL APIs, built on Hypothesis; CLI supports JSON, JUnit, NDJSON, HAR, VCR and an offline HTML report [V README]. It can run against a local app/server, so it can be offline [V: local target examples; "offline HTML page"].
- Relevance: Tier 2 for API-shaped research services; not a substitute for function-level PBT.
- Limitation: it tests HTTP surfaces, not Python functions; no CRAP/coverage policy; no MCP found [U].

**Nagini** — [V] MPL-2.0, 303 stars, last commit 2026-10-19, not archived. Static verifier for statically typed Python 3, built on Viper; requires Java; bundles Z3 and Viper JARs; supports Carbon/Boogie backends [V README]. Crucially, it ships an MCP server (`nagini[mcp]`, entry point `nagini_mcp`, stdio) with tools `verify_file`, `verify_method`, `verify_snippet`, `configure`, `cancel`, `flush_cache`, and returns structured diagnostics with positions, messages and optional counterexamples [V README, "Model Context Protocol (MCP) Server"].
- Relevance: the best existing Tier 3 *agent interface* for Python. An AI agent can ask "verify this method" and get structured errors.
- Limitation: research-grade verifier, annotation-heavy, Viper/Java stack; no ratchet/waivers/coverage; no Tier 1/2 [U].

**ESBMC / ESBMC-Python** — [V] 533 stars, last commit 2026-10-24, not archived; licensing is explicitly "complex" because it aggregates many sources and SMT solvers (COPYING) — not a clean single-licence dependency [V]. It is an SMT-based context-bounded model checker for C, C++, CUDA, CHERI, Kotlin, Python, Rust and Solidity [V README]. ESBMC-Python parses type-annotated Python, infers types, and translates to GOTO for BMC; the ISSTA 2024 paper is cited [V README].
- Relevance: Tier 3 bounded model checking for Python modules with annotations and assertions.
- Limitation: no gate interface/SARIF found; Python frontend is a subset; licence review required before redistribution [V/U].

### 3.2 CRAP, coverage ratchet and Tier 1 Python gates

**crapkit** — [V] MIT, 1 star, last commit 2026-10-02, not archived; PyPI 0.8.1 (2026-10-01), Python ≥3.11. It computes per-function CRAP from complexity and branch coverage (coverage.py for Python, istanbul for JS/TS), ranks by churn, and implements a real ratchet: `ratchet seed` marks today's over-ceiling functions at today's score, marks may only fall, and the commit gate judges only functions a change touches [V README]. It supports 14 languages including shell (`.sh`/`.bash`, complexity-only) [V README "Languages"]. It has versioned JSON (schema 1) on every `--json` command and a stdio MCP server with twelve read-side tools, plus Claude Code/Codex plugins and an advisory PostToolUse hook [V README; docs/agent-json.md]. It also has a pre-commit hook and a GitHub Action [V README headings].
- Relevance: the single closest match to "per-function CRAP with a ratchet" plus "machine-readable output / MCP" in Python. It could be adopted as the CRAP/coverage slice.
- Limitation: 1 star, one maintainer, 0.8.x; no reasoned waivers (only scope ceilings, `coverage_optional`, and seeded debt); no Emacs Lisp; shell is complexity-only; it runs your test lane rather than owning a test policy [V/U]. Licence is MIT, so vendoring is possible.

**crap4py** — [V] MIT, 1 star, last commit 2026-06-24, PyPI 0.1.1 (2026-06-24). Per-function CRAP from Python AST cyclomatic complexity and LCOV branch coverage; `--max-crap N` is a simple absolute gate; output is a human table; N/A functions never trip the gate and test files are excluded [V README]. No ratchet, no JSON, no MCP [V absence]. Use only as a reference implementation or a tiny dependency.

**crapgate** ([repo](https://github.com/andresc-cw/crapgate)) — [V] MIT, 0 stars, last commit 2026-08-24, not archived. Go/Python CRAP ranking; always runs tests; prints functions with CRAP > 6; writes a JSON copy to `/tmp/crapgate/<id>.json`; exit 1 means "some functions ranked (normal)", not a gate [V README]. Explicitly "not a green-build gate". Not suitable as the gate; useful as an agent worklist generator.

**agentic-test-forge** ([repo](https://github.com/cheezd/agentic-test-forge)) — [V] LGPL-3.0-or-later, 4 stars, last commit 2026-09-08, not archived, PyPI 1.2.0. Python quality enforcement combining CRAP analysis, mutation testing (mutmut), Gherkin scenario mutation, semantic DRY (advisory), and `forge check --json report.json`; thresholds are per-project in `pyproject.toml` [V README]. It is the closest "Tier 1 Python gate" after crapkit, but it has no ratchet, no reasoned waivers, and no MCP [U absence]. LGPL matters if you distribute a combined work [U].

**crapper / cargo-crap / crap4java** — [V] Uncle Bob's [crapper](https://github.com/unclebob/crapper) (0BSD, 100 stars, last 2026-10-21, not archived) supports Python among Clojure/Java/Go/TS/Rust and writes an EDN snapshot; [cargo-crap](https://github.com/minikin/cargo-crap) (MIT, 429 stars, last 2026-10-20, not archived) is Rust-only but has PR comments and baseline/regression workflows; [crap4java](https://github.com/unclebob/crap4java) (336 stars, last 2026-03-13, no detected licence, not archived) is Java. None is a Python gate with JSON/SARIF/MCP. They are evidence that CRAP is a solved formula, not that the ratchet/policy layer is solved.

### 3.3 Other languages: tiers 3–4

**Kani** — [V] Apache-2.0, 3,588 stars, last commit 2026-10-24, not archived. Bit-precise model checker for Rust; CBMC is a required dependency (README badge and docs); checks safety (UB, panics) and user assertions [V README; Kani book]. It supports SARIF output: `--sarif <path>` [V Kani book, print page]. Offline once CBMC/Kissat/Z3/cvc5 are installed [V book install page].
- Relevance: Tier 3 for Rust modules; its SARIF output fits the gate's reporting model.
- Limitation: Rust-only; no Python; proofs are bounded, not deductive.

**Verus** — [V] MIT, 3,433 stars, last commit 2026-10-24, not archived. Verifies Rust against specifications for all executions of a supported subset, using automated solvers [V README: "statically checks ... for all possible executions"; "relies on powerful solvers"]. It is a deductive verifier, not a kernel proof assistant; no SARIF/MCP was verified [U]. Offline.
- Relevance: Tier 3/4-ish for Rust (SMT-deductive, not kernel-checked); not applicable to Python.

**Dafny** — [V] MIT, 3,591 stars, last commit 2026-10-20, not archived. A verification-aware language with SMT-based verification. [dafny-reportgenerator](https://github.com/dafny-lang/dafny-reportgenerator) exists but is stale: 3 stars, last commit 2023-02-18, MIT, not archived [V]. Not a Python tool; relevant only as prior art for "verification report + thresholds".
- Limitation: you must write Dafny, not Python; the report generator is unmaintained [V].

**Frama-C** — [V] 190 stars on the GitHub snapshot, last commit 2020-10-21; the README says the official repository moved to GitLab and releases after Frama-C 21 are no longer updated on GitHub [V README]. It provides ACSL specifications, abstract interpretation, a WP weakest-precondition proof framework, and E-ACSL runtime verification for C [V README]. Licence is widely stated as LGPL-2.1+, but no licence file was found at the root of the snapshot and the GitLab instance is not reachable under the allowed hosts [U].
- Relevance: Tier 3 for C modules (e.g., native extensions); activity/licence must be confirmed upstream before adoption.
- Limitation: C only; no Python; GitHub metadata is misleading.

**Creusot** — [V] LGPL-2.1, 1,941 stars, last commit 2026-10-24, not archived. Deductive verification for Rust via specifications and SMT (Why3-based) [V description; U for Why3 detail]. Not Python. Relevant as another Tier 3 Rust option; Kani is the more CI-friendly one because of SARIF and the GitHub Action.

**Lean 4** — [V] Apache-2.0, 9,659 stars, last commit 2026-10-24, not archived. The kernel-checked proof assistant. Since Lean v4.28.0 the separate `lean4checker` has been merged into the toolchain as `leanchecker`, run as `lake env leanchecker` (or `--fresh` to replay all constants into a fresh environment) [V lean4checker README]. This is the Tier 4 kernel-check path for Lean projects; it is not a Python verifier.
- Relevance: adopt for Tier 4 proof artifacts; the "fresh environment" replay is exactly the independent kernel check the design wants.
- Limitation: proofs must be written in Lean; no automatic Python→Lean obligation; axiom audit must be added (`#print axioms`) [U: command not separately fetched].

**lean4checker** ([repo](https://github.com/leanprover/lean4checker)) — [V] Apache-2.0, 36 stars, last commit 2026-03-25, **archived**, not maintained [V GitHub API/HTML]. Its README is a deprecation notice: "lean4checker is now built into Lean ... distributed as `leanchecker` ... starting from v4.28.0" [V]. Do not adopt the archived repo; use the built-in tool.

**Rocq** — [V] LGPL-2.1, 5,628 stars, last commit 2026-10-23, not archived. The Rocq Prover (formerly Coq) is a kernel-checked proof assistant [V README]. The repository contains `checker/rocqchk.ml` (and `checker/coqchk.ml`), the standalone kernel checker [V raw source]. The theorem-labs proofs audit assumptions by reading `Print Assumptions` output and rejecting anything outside an allowed list [V oss-verify-proofs README]. That is the concrete Tier 4 axiom-audit pattern to copy.
- Relevance: adopt for Tier 4; `rocqchk` is the independent kernel re-check; `Print Assumptions` is the axiom audit.
- Limitation: no Python integration; proof engineering is expensive; the trusted kernel/semantics/axioms remain in the TCB [V].

**LeanCIL** ([repo](https://github.com/NethermindEth/LeanCIL)) — [V] MIT, 63 stars, last commit 2026-10-24, not archived. A Lean 4 formal-verification framework for .NET CIL: extracts compiled CIL, verifies against Lean semantics, and its `leancil verify` does "kernel check, replay, axiom audit" [V README diagram/text]. It is the clearest existing implementation of the design's "Tier 4 with axiom audit" for a mainstream language, but for .NET, not Python.
- Relevance: design reference for the T4 UX and evidence fields; not directly usable for Python/Elisp/Bash.

**theorem-labs/oss-verify-proofs** — [V] MIT, 133 stars, created 2026-10-22T17:20:28Z, last commit 2026-10-23, not archived; GitHub reports a ~2.1 GB repo. It holds Rocq proofs that, for selected OSS-Fuzz fuzz targets, no crashing input exists within stated limits; proofs are about compiled RISC-V binaries under the LPS Linux-process model, checked with Rocq 9.2.0 [V README]. The public set is 60 entry points in 25 libraries; the Anthropic article reports 239 entry points across 123 libraries, so the repo is a subset [V README + article]. `oft check` verifies binaries by SHA-256, builds memory images/statements, compiles proofs and a wrapper, then reads `Print Assumptions` and rejects assumptions outside `toolchain/allowed-axioms.txt`; the checker runs in Docker with `--network none` [V README "Check a proof"].
- Relevance: proof of concept for LLM-generated Tier 4 at scale, and a concrete axiom-audit/checker design. It is *not* a gate, not Python, and not a general verifier; LPS is "best effort and not complete", with unverified assumptions [V README].
- Maturity: days old; 2 GB repo; one proof check can need up to 20 GiB RAM on 16 cores [V README].

**AProver** ([repo](https://github.com/agentic-prover/aprover)) — [V] BSD-3-Clause-style (LICENSE), 21 stars, last commit 2026-10-20, not archived. "Agentic formal verification for AI-generated and human-written code": an LLM agent generates function contracts, runs bounded model checking, and refines from counterexamples; C with CBMC, Rust with Kani, Java with JBMC [V README]. It requires Python 3.12+, uv, the backend solver, and an LLM API key or a supported local CLI provider [V README].
- Relevance: the closest existing "AI agent calls verification and repairs" pipeline; a design reference for the agent loop.
- Limitation: no Python; not offline by default (LLM provider); 21 stars; research artifact.

### 3.4 Orchestrators, agent interfaces and AI-code gates

**qlty** — [V] BSL-1.1 (LICENSE.md), 3,203 stars, last commit 2026-10-24, not archived. Prior research established: universal linting/formatting/security/maintainability, no CRAP; BSL licensing. **[U, prior research; not re-verified]** Do not re-litigate here. It is the most mature "Tier 1 orchestrator", but it does not satisfy the CRAP ratchet, T2–T4, or the reasoned-waiver model.

**SonarQube** — [V] LGPL-3.0, 11,103 stars, last commit 2026-10-24, not archived. Server-based continuous inspection with quality gates and issue waivers (prior research; **[U]** for current details). It is the most mature "selective compliance" implementation in the field, but it is a server, not an offline repo-local gate, and it has no CRAP/PBT/fuzzing/formal tiers. Its official MCP server is separately licensed under the **Sonar Source-Available License v1.0**, not an OSI licence [V LICENSE], 672 stars, last commit 2026-10-23.

**MegaLinter** — [V] AGPL-3.0, 2,622 stars, last commit 2026-10-20, not archived. Linters only (prior research; **[U]**). Useful as a catalogue of linters, not as the gate.

**jscpd** — [V] MIT, 6,447 stars, last commit 2026-10-24, not archived; 220+ languages, Rust engine, SARIF/HTML/badge reporters [V description]. Already adopted per the brief. It solves duplication detection, nothing else.

**aislop** — [V] MIT, 700 stars, last commit 2026-10-06, not archived. A local scanner/fixer for AI-agent "slop": dead code, unsafe casts, swallowed errors, complexity, security, formatting/linting across TypeScript/JS/Python/Go/Rust/Ruby/PHP/C#/C/C++ [V README]. It has `--json`, `--sarif`, a baseline quality gate ("blocks if score regresses below baseline"), CI mode, an MCP server with `aislop_scan/fix/why/baseline`, and per-rule config [V README]. The scan itself is local; the optional repair agent uses an existing provider CLI [V README].
- Relevance: a ready-made Tier 1 static/AI-slop gate with JSON/SARIF/MCP and a baseline. It is not a test/coverage/CRAP/PBT/formal tool, and it does not audit test weakening [U].
- Limitation: 700 stars but a single young project; rule quality/coverage needs evaluation on our repos.

**VibeCI** — [V] MIT, 5 stars, last commit 2026-10-17, PyPI 0.3.0 (2026-10-15). A local verification engine for AI-written code with five layers: static health/environment preflight, production build, runtime smoke tests, existing tests, and "honest verification boundaries" (skipped/unavailable checks are not reported as passing) [V README]. It produces structured JSON (`vibeci verify --json`), configures agent rule files, and installs a pre-push hook [V README]. Offline.
- Relevance: excellent UX reference for "honest boundaries" and agent-readable reports; not tiered, not CRAP/PBT/formal.
- Limitation: 5 stars, 0.3.0, JS/Python ecosystems only; no coverage ratchet/CRAP.

**Verification Ladder** — [V] MIT, 1 star, last commit 2026-09-28, not archived. A skill + `verify.py` (stdlib + git) implementing nine rungs from baseline through a fresh-reviewer pass, with state-bound evidence: a result belongs to one repository state; a repair invalidates the PASS; a gate that could not run is BLOCKED, never PASS; a required gate nobody ran is MISSING; execution and attestation are different kinds and an attestation cannot satisfy a required execution gate [V README]. Each repository declares required gates and local/CI commands in `verification.toml`; an unconfigured repo is BLOCKED [V README].
- Relevance: the best design model found for "selective compliance" and anti-reward-hacking at the evidence layer. It is a procedure/policy engine, not a tier engine, and it is early.
- Limitation: no advisory/waiver ledger was documented; no built-in T1–T4 checks; 1 star.

**claude-code-quality** ([repo](https://github.com/miit-daga/claude-code-quality)) — [V] MIT, 0 stars, last commit 2026-10-18, not archived. A Claude Code skill that installs strict gates from day one: complexity < 22, cognitive complexity < 22, Halstead difficulty < 80, file length < 500, line+branch coverage 100%, CRAP < 25, zero surviving mutants, zero dead code, zero duplication, no `any`, plus optional gates and a suppression ratchet that fails when `noqa`/skips increase [V README]. It copies Python scripts into `tools/quality/`, has no hooks/MCP/network, and covers multiple languages [V README].
- Relevance: a compact reference implementation of the Tier 1 metric set and the suppression ratchet. The scripts are reusable, but the project is a skill, not a maintained gate.

**SonarQube MCP server** — [V] Sonar Source-Available License v1.0 (not OSI), 672 stars, last commit 2026-10-23. Official MCP server exposing SonarQube code quality/security to AI agents [V description]. It inherits SonarQube's quality gates/waivers but requires a SonarQube server and token; not an offline standalone gate [U].
- Relevance: proof that a mature quality platform can expose an MCP interface; not a fit for a fully offline, repo-local design unless we already run SonarQube.

**mcp-code-checker** — [V] MIT, 19 stars, last commit 2026-10-23. MCP server providing pylint and pytest checks with LLM-friendly prompts [V description]. Tiny, early, and only two checks; illustrates the "MCP facade over existing CLIs" pattern.

**semgrep/mcp** ([repo](https://github.com/semgrep/mcp)) — [V] MIT, 686 stars, last commit 2025-10-28, **archived**. A previously popular Semgrep MCP server; archived, so do not build on it [V]. Semgrep itself (17,248 stars, LGPL-2.1, last 2026-10-22) remains a strong Tier 1 static engine with SARIF output [V metadata/description].

**PR-Agent** — [V] MIT, 13,589 stars, last commit 2026-10-24, not archived. An AI PR reviewer (legacy Qodo OSS project), not a deterministic verification gate; it needs an LLM API [V README; U for offline]. Relevant only as an optional review layer on top of the gate, not as a tier.

### 3.4.1 Other AI-code gate projects screened (not recommended as the gate)

These were found by the "AI-generated code verification" / "quality gate" searches and are recorded for completeness. All metadata is [V]; the fit judgement is [U].

- **CodeTrust** ([repo](https://github.com/GuLu9527/CodeTrust)) — Apache-2.0, 11 stars, last commit 2026-04-04, not archived. Fully local deterministic static analysis for AI-generated code: hallucinated imports, unused imports, missing await, secrets, complexity, 29 rules, JSON output and a trust score [V README]. It is a static-only scorer, not tiered, not test/coverage/PBT/formal.
- **Aurite Agent Verifier** ([repo](https://github.com/Aurite-ai/agent-verifier)) — MIT, 45 stars, last commit 2026-10-13, not archived. A coding-agent skill/automated reviewer checking organizational policies, security and agent patterns [V README]. It is an LLM-driven review skill, not a deterministic gate; no tiers or evidence model.
- **Codex Guard** ([repo](https://github.com/Akimiya-z/codex-guard)) — MIT, 132 stars, last commit 2026-08-31, not archived. A PR quality gate for AI-generated PRs: TODO leftovers, leaked secrets, sloppy commits, red CI [V description/README]. Hygiene only; no tests/coverage/CRAP/PBT/formal.
- **Provability Fabric** ([repo](https://github.com/SentinelOps-CI/provability-fabric)) — Apache-2.0, 13 stars, last commit 2026-09-23, not archived. Lean specifications/proofs plus runtime policy, admission control and evidence ledgers for AI agents [V README]. It is a runtime/agent-policy stack (with neural-network verification adapters), not a repository code-quality gate; too heavy and orthogonal for T1–T4.
- **tend** ([repo](https://github.com/prakhar479/tend)) — no licence detected, 0 stars, last commit 2026-10-22, not archived. A local supervisor for command-line coding agents that records actions and finds loops/test weakening; explicitly a prototype, Claude Code only [V README]. Interesting anti-cheat supervision, not a gate engine.

### 3.5 Anti-reward-hacking (the part most designs underestimate)

**narc** — [V] MIT, 0 stars, last commit 2026-10-18. Diff-aware scanner for agents weakening verification: skipped/deleted tests, weakened assertions, `|| true` in CI, lowered coverage thresholds, `as any`, deleted protected data, and turning narc itself off [V README]. It supports 13 languages including Python, plus CI/config files; it attributes commits to agents; it emits SARIF/JSON/markdown/GitHub formats; it runs offline with no LLM [V README]. Its waiver model is exactly the design's: `// narc:allow <rule> reason="..."` or a `.narc.yml` allow entry with a mandatory `reason`; a waiver without a reason does not count, and reasons appear in reports [V README, "When a change is legitimate"].
- Relevance: adopt or vendor this rule set/UX for the anti-reward-hacking slice. The waiver-with-reason semantics are better than anything else found.
- Limitation: 0 stars, brand new; rule coverage/lexer quality must be tested; not a full gate.

**fakegreen** — [V] MIT, 4 stars, last commit 2026-10-15. Catches agents faking a green build: skipped/deleted tests, weakened assertions, silenced linters, neutered CI; `--json` and `--sarif`; `--fail-on high|medium|low|none`; fast, offline, no LLM [V README]. It has a GitHub Action and rules across pytest/pyproject/tox/coverage/ESLint/tsconfig/CI configs [V README]. It reports added ignore comments but does not require a reason [V].
- Relevance: a second, independent anti-cheat scanner; good for cross-checking narc's rules. The `fail-on` severity is a useful enforcement-level model.
- Limitation: 4 stars; narrower waiver model than narc.

**mutmut** — [V] BSD-3-Clause, 1,504 stars, last commit 2026-10-23, not archived. Python mutation testing [V description]. Mutation score is the strongest evidence that tests actually assert something; it complements diff-level anti-cheat scanners. It has no policy/waiver/report layer [U], and mutation runs can be slow; use it selectively (changed files) rather than repo-wide on every gate run.

**Test-weakening benchmarks** — [V] [benchmark-test-weakening](https://github.com/pooriaarab/benchmark-test-weakening) (0 stars, MIT, 2026-10-16, not archived) is an agent benchmark, not a gate; [fakegreen-action](https://github.com/fitzyracing1/fakegreen-action) wraps fakegreen for PRs [V]. Useful for evaluating our own anti-cheat rules, not for production enforcement.

### 3.6 The study the blueprint cites: what is verifiable and what is not

**Repository: `theorem-labs/oss-verify-proofs` — exists. [V]**
- GitHub API returns id 1430054678, full name `theorem-labs/oss-verify-proofs`, description "Theorem statements about OSS-Fuzz fuzz targets as compiled RISC-V binaries, and machine-checked Rocq proofs of them", created 2026-10-22T17:20:28Z, last push 2026-10-23T03:58:49Z, 133 stars, 8 forks, 3 open issues, MIT, not archived, default branch `main` [V API].
- README: 60 entry points in 25 libraries, Rocq 9.2.0, proofs about compiled RISC-V binaries under LPS (a best-effort Linux-process model), checked in Docker with `--network none`, `Print Assumptions` filtered by `toolchain/allowed-axioms.txt` [V README].
- It is a proof corpus + checker, not a gate, not a Python tool, and not a general verifier. LPS "is best effort and not complete" and makes unchecked assumptions [V README]. The 60/25 public set is a subset of the article's 239/123 [V].

**Anthropic publication — exists, dated 2026-10-22. [V]**
- URL: https://www.anthropic.com/research/formal-verification. Title: "LLMs are making formal software verification feasible at a much larger scale". Published 2026-10-22 (meta `article:published_time` and visible "Oct 22, 2026"), modified 2026-10-23 [V page metadata].
- Claims read in the page: collaboration with Theorem; Claude proved security properties in compiled code of 123 open-source libraries; 239 entry points; "for every input less than 64 MB" and modeled Linux OS responses/memory layouts; single-threaded static RISC-V binary assumptions; Rocq kernel checks the proof; found bugs that had eluded years of testing; proofs can take hundreds of millions of tokens [V article text].
- It also says a subset of proofs and the RISC-V/OS semantics are published, and Theorem is publishing a Claude skill for verifying other code [V article]. The skill itself was not fetched [U].

**What is not verifiable / not supported by the fetched sources:**
- **[U]** That this work provides a reusable, turnkey tiered gate, or any Python/Emacs Lisp/Bash support. The article and repo are C/C++ OSS-Fuzz targets compiled to RISC-V; Python is absent.
- **[U]** That the proofs are assumption-free. The repo explicitly trusts the Rocq kernel, its VM, LPS at a pinned commit, the ELF/memory-image tooling, `oft check`'s wrapper and its reading of `Print Assumptions`, plus an allowed-axioms list. "Proven" means conditional on those.
- **[U]** That "123 libraries" is the same as the 60/25 in the repo. The repo is a subset, and the article says a subset is published.
- **[U]** That Theorem's commercial pipeline (theorem.dev/oss-verify) is open source or offline. That host was not fetched.
- **[U]** Any claim that the study validates Tier 4 for research/ML Python code. It validates the *approach* (LLM writes proofs; kernel checks them; axiom audit filters assumptions) on C/C++ binaries at OSS-Fuzz scale.

---

## 4. Gap analysis against our goal

Legend: **Covered** = a mature component exists; **Partial** = exists but immature, narrow, or missing policy; **Missing** = nothing found that provides it.

| Requirement | Status | What exists | Gap we would still own |
|---|---|---|---|
| T1 unit/integration tests | Covered | pytest, unittest, tox/nox; any runner can be called by a gate [U: general ecosystem, not re-verified] | A single tier runner and result normalisation; not hard |
| T1 coverage | Covered | coverage.py (Apache-2.0, 3,424★), pytest-cov, diff-cover (Apache-2.0, 849★) for diff coverage [V meta] | Coverage policy per module, merge with CRAP |
| T1 per-function CRAP | Partial | crap4py, crapgate, crapper, crapkit, agentic-test-forge, crap4java/cargo-crap [V] | Python CRAP is available; Emacs Lisp CRAP is absent; a stable, maintained Python implementation is not a given |
| T1 CRAP ratchet | **Missing (except one)** | crapkit: seed marks, marks only fall, commit gate judges touched functions [V]; diff-cover gives a coverage ratchet [V] | Mature, widely used ratchet; reasoned waivers; per-module targets; multi-language (Elisp/Bash) |
| T1 lint | Covered | ruff (MIT, 50,263★), pylint, semgrep (LGPL-2.1, 17,248★), qlty/MegaLinter [V meta] | Policy/severity mapping into tiers |
| T1 duplicate code | Covered | jscpd (MIT, 6,447★, SARIF) [V], already adopted | Nothing material |
| T1 file inventory/hygiene | Partial | pre-commit (MIT, 15,657★) hooks, aislop, MegaLinter, qlty [V meta] | A repo-specific inventory policy (generated files, large files, licence headers) is usually custom |
| T1 anti-reward-hacking | Partial | narc (waivers with reasons, JSON/SARIF, offline) [V]; fakegreen (JSON/SARIF, fail-on) [V]; mutmut (mutation) [V]; claude-code-quality suppression ratchet [V] | Maturity; Python-specific rules; integration with the waiver ledger; protection against editing the gate itself |
| T2 property-based testing | Covered | Hypothesis (MPL-2.0, 9,108★); deal.cases; Schemathesis for APIs [V] | Gate integration, per-module budgets, deterministic replay/seed policy |
| T2 fuzzing | Covered | Atheris (Apache-2.0, 1,693★); libFuzzer; ASan/UBSan [V] | Harness generation/maintenance; corpus storage; time budgets; crash triage |
| T3 Python (symbolic/BMC) | Partial | CrossHair (Z3), deal prove (experimental), Nagini (Viper, MCP), ESBMC-Python (BMC) [V] | A common spec language; module selection; timeouts; machine-readable verdicts (only Nagini has an MCP) |
| T3 other languages | Covered (per language) | Kani (Rust, SARIF), Verus (Rust), Dafny, Frama-C (C, GitLab), Creusot (Rust), AProver (agent) [V] | No cross-language orchestration; each has its own spec format |
| T4 kernel-checked proofs | Partial | Lean 4 + built-in `leanchecker`; Rocq + `rocqchk` + `Print Assumptions`; LeanCIL (.NET) [V] | Python/Elisp/Bash obligation generation; proof-artifact layout; axiom allowlists; CI integration |
| T4 axiom audit | Partial | theorem-labs `Print Assumptions` allowlist [V]; LeanCIL "axiom audit" [V] | A standard, tool-agnostic audit record in the gate's JSON/SARIF |
| Selective compliance: enforced/advisory | Partial | SonarQube quality gates (server) [U]; crapkit advisory hook vs commit gate [V]; fakegreen `--fail-on` [V]; Verification Ladder required gates [V] | Per-check, per-module three-state policy across tiers; no tool found |
| Selective compliance: reasoned waivers | Partial | narc: mandatory reason, surfaced in reports [V]; SonarQube issue waivers [U] | A central waiver ledger with expiry, owner, scope, and audit trail across all checks |
| Machine-readable output | Partial | JSON: crapkit (schema 1), Nagini diagnostics, aislop, VibeCI, agentic-test-forge, Schemathesis; SARIF: Kani, aislop, fakegreen, narc, jscpd, semgrep [V] | One stable schema spanning tiers; SARIF merge/dedup; severity mapping |
| Agent interface (MCP) | Partial | crapkit (12 tools), Nagini (verify_file/method/snippet), aislop (scan/fix/why/baseline), SonarQube MCP (server), mcp-code-checker [V] | A single MCP facade that exposes tier runs, findings, waivers and evidence; no unified server found |
| Fully offline | Covered for engines | Hypothesis/CrossHair/Nagini/ESBMC/Kani/Lean/Rocq/crapkit/narc all run locally [V]; exceptions: AProver, PR-Agent, SonarQube MCP [V/U] | Dependency pinning/provenance; no hidden telemetry; offline installer bundle |
| Python first | Covered | Broadest ecosystem by far [V] | Integration, not availability |
| Emacs Lisp | **Missing** | No CRAP/coverage/PBT/fuzz/BMC tool found; ERT/testcover exist as Emacs built-ins [U] | CRAP from testcover/ERT coverage; lint (package-lint/checkdoc); a T1 adapter |
| Bash | Partial | crapkit shell complexity (cc-only); shellcheck/shfmt; bats-core [V for crapkit; U for the rest] | Coverage (kcov/bashcov), CRAP with coverage, PBT/fuzz, tier policy |

**Structural gap.** The design's novel part is not any single check; it is the *policy and evidence layer*: tiers, per-module opt-in, enforced/advisory/waived states, reasons, ratchets, JSON/SARIF/MCP, and offline pinning. No project found owns that layer. crapkit owns a slice (CRAP), narc owns a slice (anti-cheat waivers), Verification Ladder owns a slice (state-bound required gates), and SonarQube owns a slice (server quality gates). They do not compose out of the box: different config formats, different evidence models, no shared waiver ledger.

---

## 5. Recommendation

### 5.1 Adopt (use as-is, pin versions)

| Tier | Adopt | Why |
|---|---|---|
| T1 lint/format | ruff; semgrep for custom rules | Mature, fast, offline, JSON/SARIF [V] |
| T1 duplicates | jscpd | Already adopted; SARIF; mature [V] |
| T1 coverage | coverage.py + pytest-cov; diff-cover for the diff ratchet | Mature, local, machine-readable [V] |
| T1 mutation | mutmut, on changed files only | Mature; strong anti-weak-test evidence [V] |
| T1 anti-cheat | narc (primary) + fakegreen (secondary) | Exact diff-level checks; JSON/SARIF; offline; narc has reasoned waivers [V] |
| T2 PBT | Hypothesis | The Python standard; deal/Schemathesis build on it [V] |
| T2 fuzzing | Atheris | Coverage-guided, local, native-extension support [V] |
| T3 Python | CrossHair (general) + Nagini (annotated code, MCP) | Complementary: symbolic execution vs Viper verification [V] |
| T3 Rust/C | Kani (SARIF), Frama-C (C, confirm upstream) | Mature, per-language [V/U] |
| T4 | Lean 4 (`leanchecker`) and Rocq (`rocqchk` + `Print Assumptions`) | Kernel-checked; axiom audit pattern proven [V] |
| T1 CRAP | crapkit, if its 1-star/0.8.x risk is acceptable; otherwise vendor its ratchet logic | Only CRAP ratchet + JSON + MCP found [V] |

**Adoption caveats [U].** crapkit, narc, fakegreen, VibeCI and Verification Ladder are weeks old and effectively single-maintainer. Pin exact commits, vendor the small ones, and keep a fallback. Do not make them the only enforcement path without tests of our own.

### 5.2 Compose (the recommended path)

Build a thin, offline orchestrator — the only substantial new code — that:

1. **Defines the policy** in one committed file (e.g. `quality-gate.toml`): per module, per tier, per check, one of `enforced`, `advisory`, `off`; ratchet targets; waiver entries with `reason`, `owner`, `expires`, `scope`. This is the "selective compliance" layer no existing tool provides. Use Verification Ladder's state-bound evidence rules (PASS/BLOCKED/MISSING; execution vs attestation) as the semantics [V].
2. **Calls the engines**: pytest/coverage.py, crapkit or crap4py, ruff, jscpd, semgrep, narc/fakegreen, Hypothesis, Atheris, CrossHair, Nagini, ESBMC, Kani/Frama-C, Lean/Rocq checkers. Pin each tool and record its version/hash in the evidence record.
3. **Normalises** findings into one JSON schema (stable `schema` field) and emits SARIF 2.1.0 for code scanning; keeps a waiver ledger and applies waivers only with a reason, surfacing them in the report.
4. **Exposes MCP** tools: `gate_run`, `gate_status`, `gate_findings`, `gate_waive`, `gate_evidence`, `gate_explain`; mirrors the crapkit/Nagini/MCP patterns [V]. The agent gets file:line, rule id, tier, severity, waiver state, and the exact command to reproduce.
5. **Runs offline** from a pinned toolchain (uv/pip lock, npm lock, Rust toolchain, Lean/Rocq versions, Docker images by digest where needed).

Composition choices by slice:

- **CRAP + coverage ratchet:** crapkit (JSON schema 1, MCP, commit gate) [V]; fallback crap4py + diff-cover + a small ratchet store [V].
- **Anti-reward-hacking:** narc for rules + waivers with reasons; fakegreen as a second scanner; mutmut for mutation evidence [V].
- **T2:** Hypothesis + Atheris; Schemathesis only for HTTP APIs [V].
- **T3 Python:** CrossHair for arbitrary functions; Nagini for annotated modules and agent-facing verification; ESBMC-Python for bounded checks of annotated modules [V].
- **T4:** Lean 4 with `lake env leanchecker` (including `--fresh` for a clean replay) and Rocq with `rocqchk` + `Print Assumptions` allowlist; store proof artifacts, checker output, tool hashes and the axiom list in the evidence record [V].
- **T1 static/hygiene:** ruff + semgrep + jscpd + pre-commit hooks; aislop is optional if its AI-slop rules prove useful, but do not depend on its scoring [V/U].

### 5.3 Build (only what nothing provides)

1. **The orchestrator/policy/evidence layer** — per-check three-state enforcement, reasoned waivers with expiry, ratchet store, JSON/SARIF merge, MCP facade, pinned-toolchain verification. No existing project does this across tiers [U, search-based].
2. **Emacs Lisp Tier 1 adapter** — per-function CRAP needs complexity + coverage. Emacs has `testcover` for coverage and ERT for tests [U: not fetched]; no CRAP tool was found [U]. Implement a small Elisp reader (defun/defmacro/cl-defun) and a testcover/ERT coverage adapter; lint via package-lint/checkdoc/byte-compile. This is genuinely missing.
3. **Bash Tier 1 coverage/CRAP adapter** — crapkit gives complexity-only CRAP for shell [V]; coverage needs kcov/bashcov [U]. Add a coverage lane if Bash modules are in scope.
4. **Python→Tier-4 bridge (only if T4 is required for Python modules)** — there is no existing automatic obligation generator from Python to Lean/Rocq. Options: (a) restrict T4 to hand-written proof artifacts attached to a module; (b) generate proof obligations from a restricted Python subset (very large); (c) use a deductive Python verifier (Nagini) as the "T3.5" substitute and reserve T4 for algorithm kernels rewritten in Lean/Rocq. Option (a) or (c) is realistic; (b) is a research project [U].
5. **A gate-integrity check** — the gate must detect edits to its own config, baselines, allowlists and CI wiring (narc already flags `narc-config-weakened` [V]; generalise this to all tier configs).

### 5.4 Do not build

- A property-based testing engine, fuzzer, symbolic executor, BMC engine, SMT solver, proof kernel, linter, duplicate detector, coverage tool, or CRAP formula. These are mature and adoptable [V].
- A general-purpose AI code reviewer. PR-Agent and friends exist; they are not verification and they are not offline [V/U].
- A SonarQube replacement. If server-based quality gates are acceptable, use SonarQube; if not, the thin orchestrator is the replacement for the *policy* slice only.

### 5.5 Suggested first milestone [U]

Ship a Python-only, offline "T1+T2 enforced, T3 advisory" gate in one repo:

- policy file with enforced/advisory/waived checks and reasons;
- pytest + coverage.py + diff-cover + crapkit ratchet;
- ruff + jscpd + narc (+ fakegreen);
- Hypothesis + Atheris smoke runs with budgets;
- CrossHair/Nagini advisory runs on selected modules;
- JSON + SARIF + MCP `gate_run`/`gate_findings`;
- evidence record with tool versions/hashes and a "BLOCKED is not PASS" rule.

Then add Lean/Rocq T4 proof artifacts and the Elisp adapter as opt-in modules.

---

## 6. Method, search log and limits

**Method.** Fetch-only research through the proxy. GitHub metadata came from the unauthenticated API where quota allowed, otherwise from repository HTML (embedded `stargazerCount`, licence label, archive flag) and the commits Atom feed (newest `<updated>`). Python package metadata came from PyPI JSON. Capabilities came from raw READMEs, docs sites (`hypothesis.readthedocs.io`, `deal.readthedocs.io`, `crosshair.readthedocs.io`, `model-checking.github.io`, `lean-lang.org`) and `anthropic.com`. No downloaded code was run. No instructions from fetched content were followed.

**Search coverage.** GitHub repository search (API and web) for: CRAP score, code quality gate, MCP quality gate, coverage ratchet, formal verification CI, verification-aware CI, tiered verification, verification ladder, proof-carrying code, AI-generated code verification, agentic verification, test weakening, reward hacking tests, Semgrep MCP, and the named candidates. GitHub search quota was shared and intermittently 403; retries and web search were used. This is not an exhaustive survey of all GitHub, PyPI, npm or academic work — negative claims are therefore **[U]**.

**Metadata caveats.**
- "Last commit" from Atom is the newest commit on the default branch, which can be a bot/merge; it is a proxy for activity, not a release date.
- Star counts are exact at fetch but change constantly.
- Frama-C's GitHub repository is a stale snapshot; its real activity and licence were not verifiable on the allowed hosts.
- ESBMC's licence is an aggregate of many components; a legal review is required before redistribution.
- qlty is BSL-1.1; SonarQube MCP is source-available; MegaLinter and agentic-test-forge are AGPL/LGPL; check obligations before shipping a combined distribution.
- `icontract-hypothesis` shows no GitHub licence file; PyPI classifies it MIT. Treat as stale/unmaintained either way.

**Claims left unverified (explicit).**
- The exact current feature set of qlty, SonarQube and MegaLinter (prior research was not redone, per the brief).
- Whether qlty sends telemetry or can be fully air-gapped.
- Whether SonarQube's quality-gate/waiver semantics remain as described in prior research.
- Verus's solver stack (Z3/air) and output formats; Dafny's report-generator behaviour; Frama-C's current licence and release cadence.
- Any MCP server for CrossHair, Hypothesis, Kani, Lean or Rocq (none was found, but absence was not exhaustively proven).
- Theorem's commercial pipeline and the Claude "verification skill" mentioned in the Anthropic article (theorem.dev was not fetched).
- Whether the 123-library claim and the 60/25 repo set use identical assumptions (the repo documents its own LPS/axiom assumptions; the article gives high-level assumptions).

---

## 7. Three-line recommendation (also repeated in the reply)

**Adopt** Hypothesis + Atheris (T2), CrossHair + Nagini + ESBMC-Python (T3), Lean 4 `leanchecker` + Rocq `rocqchk`/`Print Assumptions` (T4), narc/fakegreen (anti-cheat), jscpd/ruff/coverage.py/diff-cover (T1) — and crapkit for the CRAP ratchet if its 1-star/0.8.x risk is acceptable.

**Compose** them behind a thin offline orchestrator that owns the tier policy, reasoned waivers, ratchet store, JSON/SARIF merge and one MCP facade; use Verification Ladder's state-bound evidence rules and crapkit/Nagini's MCP patterns as the design reference.

**Build** only the orchestrator/policy layer, the Emacs Lisp CRAP/coverage adapter, the Bash coverage adapter if needed, and a hand-written Python→Tier-4 proof-artifact bridge (or use Nagini as the T3.5 substitute).
