# Code-quality gates for AI-written code: landscape and build-vs-adopt review

**Date:** 2026-10-24 (UTC)  
**Scope:** repositories in Emacs Lisp, Python and Bash; current gate = per-function CRAP + coverage, token clone ratchet, per-file check inventory, hygiene, lint and executing tests.  
**Question:** is there an existing open-source tool/repo that runs a broad quality-metric suite with gating on an arbitrary repository, or should we compose/build?

**Evidence convention**

- **[V]** = verified against data fetched on 2026-10-24 from api.github.com (repository/search/org JSON) or from a README/LICENSE fetched from raw.githubusercontent.com.
- **[U]** = unverified: inferred, self-reported by a project, or a negative that the fetched README does not establish.
- Stars, pushed_at, licence, archived and language are API fields from GET /repos/{owner}/{repo} or GET /search/repositories [V]. They are not repeated as [V] in every table cell.
- **Maturity labels are judgments** [J] derived from the [V] stars/push/archived fields and project age; they are not API facts.
- No downloaded code was executed, and no instruction found in fetched content was followed. Only READMEs, LICENSEs, metadata and one qlty source file were read.

**Method and limits.** Unauthenticated GitHub REST: 60 core requests/hour and 10 search requests/minute. One early metadata batch failed because the scratchpad root was read-only (metadata was then staged under /tmp); three discovery searches hit the search limit, two were retried successfully, and one (AI generated code quality) was not completed. The completed searches are listed in the appendix. Negative claims ("not listed", "no repo") are marked as such and should be read as evidence from the fetched page, not proof of universal absence.

---

## 1. Bottom line

**No single open-source project does our full gate, and none covers Emacs Lisp plus Bash plus Python.** [V for the candidates below; U for the universal negative]

The broadest candidates are:

- **qlty** — 40+ languages, lint + complexity + duplication + coverage, local CLI, but **BSL 1.1 (not OSI open source)**, no Emacs Lisp, and Bash gets lint only. [V]
- **SonarQube Community Build** — broad static analysis, quality gates on new code and coverage, but a **server product**, not a single local CLI; no CRAP; no verified Emacs Lisp or Bash analyzer. [V/U]
- **MegaLinter** — 67 languages of linters and jscpd copy-paste, Bash included, but **no CRAP/coverage join, no Emacs Lisp**, and its jscpd default (threshold 0) is a known legacy-clone trap. [V]
- **jscpd v5** — the standout reusable component: 224 formats, explicitly supports **Emacs Lisp (.el) and Bash**, default min-tokens 50, and a real clone baseline (--baseline ... --fail-on-new-clones). It is MIT and a self-contained binary. [V]
- **lizard**, **PMD/CPD**, **wily**, **radon**, **crap4py**, **crapper**, **cargo-crap**, **diff-cover**, **mutmut**, **ShellCheck**, **elisp-lint**, **vulture**, **import-linter**, **xenon** each cover one slice; none is a repository-wide gate for our three languages. [V]

**Recommendation:** **compose several tools and build a thin reusable gate package** for the missing pieces. Adopt **jscpd v5** for clone detection/ratchet; keep the existing linters/tests and add **package-lint**; reuse **crap4py**'s algorithm/LCOV join as a reference for Python; **build** the Elisp/Bash CRAP adapters, the per-file inventory, the hygiene checks, and the reasoned ratchet file. Do **not** adopt qlty (licence + language gaps), SonarQube (server weight + language gaps + no CRAP), Trunk (closed CLI), or elisp-lint (no licence, stale). [V for the facts behind each; J for the recommendation]

---

## 2. Summary table

All stars / last-push / licence / archived cells are [V] from the GitHub API on 2026-10-24 unless marked.

| Candidate | URL | Licence | Stars | Last push (UTC) | Archived | Languages; Elisp / Bash? | Metrics covered (our list) | Offline local CLI? | Maturity [J] |
|---|---|---|---|---|---|---|---|---|---|
| **qlty** | https://github.com/qltysh/qlty | BSL 1.1 (NOASSERTION; change date 2028-12-10, then GPL-3.0) | 3,204 | 2026-10-24T01:59:54Z | false | 40+ technologies; **Elisp no; Bash lint-only** (shellcheck/shfmt) | CC, cognitive, duplication, total/diff coverage, lint; **no CRAP documented**; no inventory; triage/ignores but no numeric ratchet documented | Yes, native binary; plugin/tool downloads need network on first use [V/U] | Active, young; BSL |
| **SonarQube Community Build** | https://github.com/SonarSource/sonarqube | LGPL-3.0 | 11,101 | 2026-10-23T20:08:51Z | false | 40+ advertised, Community subset; **Elisp no; Bash no** (no official analyzer found) [V/U] | Issues, maintainability, duplication and cognitive complexity (core product; not verified in this fetch), coverage on new code, quality gate; **no CRAP documented** | No: server + DB, scanner is a client [V] | Mature |
| **sonar-scanner-cli** | https://github.com/SonarSource/sonar-scanner-cli | LGPL-3.0 | 429 | 2026-10-23T21:08:47Z | false | Scanner only; language support comes from the server | Uploads analysis; no metric engine of its own | Scanner CLI, but needs a SonarQube server [V] | Mature-ish |
| **MegaLinter** | https://github.com/oxsecurity/megalinter | AGPL-3.0 | 2,622 | 2026-10-24T00:47:18Z | false | 67 languages; **Bash yes** (bash-exec, shellcheck, shfmt); **Elisp no** | Lint + copy-paste via jscpd; **no CRAP, no coverage, no complexity gate, no mutation** | Yes via Docker/podman; offline after image pull [V] | Mature; widely used |
| **lizard** | https://github.com/terryyin/lizard | MIT-style text; API NOASSERTION | 2,562 | 2026-10-24T02:18:00Z | false | 26 listed languages; **Elisp no; Bash no** | CC, NLOC, params, cognitive (extension), duplicate detection (extension); warns/fails on CCN/param thresholds; **no coverage** | Yes, Python 3.8+ CLI [V] | Mature, active |
| **jscpd v5** | https://github.com/kucherenko/jscpd | MIT | 6,445 | 2026-10-24T05:22:39Z | false | 224 formats; **Elisp yes (.el), Bash yes** | Token clones (default 50 tokens), baseline/fail-on-new-clones, threshold; dead code (JS/TS/Py) and file-level complexity estimate; **no coverage/CRAP** | Yes, self-contained Rust binary [V] | Mature project; v5 Rust engine is a recent rewrite (date [U]) |
| **PMD / CPD** | https://github.com/pmd/pmd | BSD-style; API NOASSERTION | 5,516 | 2026-10-23T19:02:14Z | false | PMD: Java/Apex + 16 others; CPD 30+; **Elisp no; Bash no** | CPD token clones; PMD rules incl. complexity; **no coverage join** | Yes, Java zip [V] | Mature (since 2002) |
| **wily** | https://github.com/tonybaloney/wily | Apache-2.0 | 1,333 | 2026-10-07T12:28:08Z | false | Python only | Complexity/MI history over git revisions, wily diff; **no coverage, no threshold gate documented** | Yes [V] | Niche, active |
| **radon** | https://github.com/rubik/radon | MIT | 2,036 | 2024-10-20T09:52:54Z | false | Python only | CC, maintainability index, raw metrics; reporting, not gating (README points to xenon) | Yes [V] | Mature but stale (last push 2024-10) |
| **crap4py** | https://github.com/gabadi/crap4py | MIT | 1 | 2026-06-24T04:45:21Z | false | Python only | **CRAP per function** from Python AST CC + LCOV branch coverage; --max-crap exits non-zero; no ratchet | Yes [V] | Experimental |
| **crapper** | https://github.com/unclebob/crapper | 0BSD | 100 | 2026-10-21T14:16:08Z | false | Clojure, Java, Go, JS/TS, Rust, Python; **no Elisp/Bash** | **CRAP** per language, --threshold exit 2, .metrics/crap.edn snapshot, --changed; coverage read from existing reports | Yes (first run creates venv/installs) [V] | Young |
| **cargo-crap** | https://github.com/minikin/cargo-crap | MIT | 429 | 2026-10-23T10:12:46Z | false | Rust only | **CRAP** from syn + LCOV, threshold/regression gate, PR comment, duplicate triage; **no Elisp/Bash** | Yes [V] | Active |
| **diff-cover** | https://github.com/Bachmann1234/diff_cover | Apache-2.0 | 849 | 2026-10-23T00:51:03Z | false | Report-format agnostic (Cobertura/Clover/JaCoCo/LCov); not a language analyzer | Diff/changed-line coverage, --fail-under; no complexity/CRAP, not per-function | Yes [V] | Mature, active |
| **mutmut** | https://github.com/boxed/mutmut | BSD-3-Clause | 1,502 | 2026-10-23T18:17:28Z | false | Python only | Mutation testing; coverage.py can filter mutants; **no documented mutation-score threshold/ratchet** [U] | Yes [V] | Mature, active |
| **Trunk Check** | https://github.com/trunk-io (org); https://github.com/trunk-io/plugins | CLI not public; plugins/action MIT | 172 (plugins) / 248 (action) | 2026-10-23T11:00:18Z / 2026-10-24T00:26:20Z | false | Many via plugins; Bash via shellcheck; **Elisp no known plugin** [U] | Lint orchestration only; no CRAP/coverage/metrics suite | Local CLI exists, but repo/licence not public; plugins download [U] | Commercial/mature product; **CLI not verifiable OSS** |

### Supporting/adjacent tools (same API snapshot)

| Tool | URL | Licence | Stars | Last push (UTC) | Elisp / Bash? | Slice | Maturity [J] |
|---|---|---|---:|---|---|---|---|
| ShellCheck | https://github.com/koalaman/shellcheck | GPL-3.0 | 40,228 | 2026-10-19T01:25:10Z | Bash/sh only | Lint, exit codes | Very mature |
| elisp-lint | https://github.com/gonewest818/elisp-lint | **none detected** (no LICENSE file; API null) | 73 | 2022-04-19T02:54:03Z | Elisp only | Lint (byte-compile, checkdoc, indent, ...) | Abandoned; **no licence** |
| package-lint | https://github.com/purcell/package-lint | GPL-3.0 | 223 | 2026-09-03T21:19:38Z | Elisp only | Package metadata lint | Mature, active |
| vulture | https://github.com/jendrikseipp/vulture | MIT | 4,859 | 2026-10-12T10:56:51Z | Python only | Dead code, confidence, whitelist, exit 3 | Mature |
| import-linter | https://github.com/seddonym/import-linter | BSD-2-Clause | 1,234 | 2026-10-13T10:46:44Z | Python only | Import contracts/cycles/layers | Mature |
| xenon | https://github.com/rubik/xenon | MIT | 282 | 2024-10-21T10:27:41Z | Python only | Complexity thresholds (radon), non-zero exit | Stale |
| codemetrics | https://github.com/emacs-vs/codemetrics | GPL-3.0 | 79 | 2026-06-19T08:45:44Z | **Elisp yes; Bash yes** | Cognitive complexity (live Emacs/tree-sitter; not a CLI gate) | Niche, active |
| bats-core | https://github.com/bats-core/bats-core | MIT | 6,325 | 2026-10-20T12:07:34Z | Bash only | Test runner | Mature |
| bashcov | https://github.com/infertux/bashcov | MIT | 175 | 2026-10-21T15:24:30Z | Bash only | Line coverage for Bash | Niche, active |
| kcov | https://github.com/SimonKagstrom/kcov | GPL-2.0 | 837 | 2026-10-23T14:00:15Z | Bash (also Python/compiled) | Coverage via debug info | Mature |
| riskratchet | https://github.com/KayhanB21/riskratchet | MIT | 8 | 2026-10-18T20:44:06Z | Python/TypeScript only | Per-function risk (coverage gaps + CC + churn + surface), baseline ratchet, exit 1/2 | Experimental |
| keeler | https://github.com/minikin/keeler | MIT | 4 | 2026-09-08T19:32:57Z | Rust only | WIP AI-Rust gates: CRAP + mutation + property tests | Experimental |
| skylos | https://github.com/duriantaco/skylos | Apache-2.0 | 848 | 2026-10-24T03:34:56Z | Python (per repo map) | Local-first PR scanner: dead code, security, quality regressions, AI-code mistakes | Active, young |
| aislop | https://github.com/scanaislop/aislop | MIT | 699 | 2026-10-24T06:05:16Z | 10 language targets (self-described) | 50+ deterministic AI-code rules, CLI/CI | Active, young |
| complexipy | https://github.com/rohaquinlop/complexipy | MIT | 895 | 2026-10-24T03:10:18Z | Python only | Cognitive complexity | Active |

---

## 3. Capability matrix against our gate

Legend: **Yes** = documented and usable for the stated scope; **Partial** = only some languages, only report-level, or only via another tool; **No** = not provided; **?** = not established from fetched data.

| Tool | CRAP / CC+cov join | Cognitive | Clones | Mutation | Dead code | Per-function coverage | Baseline/ratchet | Check inventory |
|---|---|---|---|---|---|---|---|---|
| qlty | No (CC and coverage reported separately) | Yes | Yes | No | Partial (knip on JS/TS) | Coverage is line/diff, not per-function | Triage/ignore; no numeric ratchet documented | No (plugin inventory only) |
| SonarQube | No | ? (core product; not verified) | ? (core product; not verified) | No | Partial (rules) | Line coverage, not per-function | Quality gate on **new code** (temporal ratchet; branch/PR analysis is commercial) | No |
| MegaLinter | No | No (some linters do it) | Yes via jscpd | No | No | No | No | No |
| lizard | No | Yes (extension) | Yes (extension) | No | No | No | CCN/param warnings, exit non-zero; no stored baseline | No |
| jscpd v5 | No | No (file-level complexity estimate) | **Yes** | No | JS/TS/Python only | No | **Clone baseline + fail-on-new-clones** | No |
| PMD/CPD | No | Partial (rules) | Yes (CPD) | No | Partial (unused rules) | No | No (threshold only) | No |
| wily | No | No | No | No | No | No | History/diff, no gate | No |
| radon | No | No | No | No | No | No | No | No |
| crap4py | **Yes (Python)** | No | No | No | No | **Yes** | --max-crap only; no ratchet | No |
| crapper | **Yes (6 langs)** | No | No | No | No | **Yes** (from reports) | Threshold + snapshot; no reasoned ratchet | No |
| cargo-crap | **Yes (Rust)** | No | Partial (duplicate triage) | No | No | **Yes** | Threshold/regression + PR comment | No |
| diff-cover | No | No | No | No | No | Changed lines only | --fail-under; diff-scoped, not a ratchet | No |
| mutmut | No | No | No | **Yes (Python)** | No | Uses coverage.py | No documented score gate | No |
| ShellCheck | No | No | No | No | No | No | Exit code on findings | No |
| elisp-lint | No | No | No | No | No | No | Exit code on findings (batch) [U] | No |
| vulture | No | No | No | No | **Yes (Python)** | No | Whitelist, min-confidence; no ratchet | No |
| import-linter | No | No | No | No | No (cycles yes) | No | Contract pass/fail | No |
| codemetrics | No | **Yes (Elisp + Bash)** | No | No | No | No | No (editor display) | No |
| riskratchet | **CRAP-like risk (Python/TS)** | No | No | No | No | **Yes** | **Yes (JSON baseline + exit codes)** | No |

---

## 4. Notes per candidate

### 4.1 qlty

- **URL / licence / activity:** https://github.com/qltysh/qlty. API: stargazers_count=3204, pushed_at=2026-10-24T01:59:54Z, archived=false, license.spdx_id=NOASSERTION [V]. The licence is **Business Source License 1.1**; LICENSE.md states "The Business Source License ... is not an Open Source license", change date **2028-12-10**, change licence **GPL-3.0**, and the additional use grant forbids use for a "Code Quality Service" or an "Artificial Intelligence Coding Service" [V].
- **Languages:** README claims "70+ static analysis tools for 40+ languages" [V]. The language matrix lists complexity/duplication for C#, Elixir, Go, Java, JavaScript, Kotlin, PHP, Python, Ruby, Rust, TypeScript, VB.NET, etc.; **Shell has only shellcheck and shfmt** (README row Shell); **Emacs Lisp is not listed** [V].
- **Metrics:** README's feature table lists "Maintainability — code smells like copy-paste detection and complexity", "Code coverage — total coverage and diff coverage", "Quality metrics — complexity, duplication, LOC"; the metrics table defines duplication density/lines/blocks, complexity density, **Total Complexity = cognitive complexity**, cyclomatic complexity, line coverage and diff coverage [V]. I found **no CRAP metric or per-function coverage join** in the README [V for absence].
- **Gating:** the qlty check source exposes --fail-level ("Minimum level of issues to fail on"), --no-fail, and --no-error (qlty-cli/src/commands/check.rs) [V]. That gates lint findings; I found no CLI flag for a CRAP/coverage threshold or a numeric ratchet in the README/source checked [U].
- **Offline:** installs native binaries and runs locally; plugins/tool binaries are fetched, so first use needs network [V for local binary; U for "fully offline"].
- **Fit:** broad and pleasant, but disqualified as the single gate by (a) BSL and the AI-service restriction, (b) no Emacs Lisp, (c) Bash lint-only, (d) no CRAP. [V facts; J fit]
- **Maturity [J]:** active, 3.2k stars, but young and source-available rather than open source.

### 4.2 SonarQube Community Build + sonar-scanner

- **URL / licence / activity:** https://github.com/SonarSource/sonarqube (11,101 stars, push 2026-10-23T20:08:51Z, archived=false, LGPL-3.0); scanner: https://github.com/SonarSource/sonar-scanner-cli (429 stars, push 2026-10-23T21:08:47Z, LGPL-3.0) [V].
- **Scope:** README says the Community Build is "the free, open-source edition" and "shares the same analysis"; it "analyzes more than 40 programming languages and frameworks; the Community Build supports a subset" [V]. A **Quality Gate is a pass-or-fail check on new code**, and "Coverage on new code" is a listed capability [V]. Commercial editions add branch and pull-request analysis [V]. The scanner repo describes itself as "Scanner CLI for SonarQube (Server, Cloud)" — it is a client, not the analysis engine [V].
- **Metrics:** the README verifies issues, maintainability/structural issues, and coverage on new code [V]. Cognitive complexity and duplication are standard SonarQube metrics, but the fetched README does not name them [U]. I found **no CRAP** [V for README absence].
- **Languages / our two:** no official Emacs Lisp analyzer; Bash is not in the Community Build's advertised set. I could not fetch the official language matrix (docs host not reachable), so the precise negative is **[U]**. Do not plan on Elisp/Bash support without a spike.
- **Offline/local:** self-hosted server plus database; the scanner is a CLI but needs a running server [V from product/scanner description; DB requirement U].
- **Fit:** excellent dashboard/quality-gate semantics for Python and a good "new code" ratchet, but too heavy for a local pre-commit/CI gate and does not solve Elisp/Bash or CRAP. [J]
- **Maturity [J]:** very mature.

### 4.3 MegaLinter

- **URL / licence / activity:** https://github.com/oxsecurity/megalinter; AGPL-3.0, 2,622 stars, push 2026-10-24T00:47:18Z, archived=false [V].
- **Languages:** README says "Supports 67 languages, 23 formats, 22 tooling formats" [V]. It has **Bash** descriptors (bash-exec, shellcheck, shfmt) [V]; I found **no Emacs Lisp descriptor** in the languages table [V for absence].
- **Metrics:** it is a linter/formatter orchestrator. Copy-paste is delegated to **jscpd** (COPYPASTE_JSCPD) [V]. It has no CRAP, coverage, mutation, per-function coverage or complexity threshold [V for README feature list absence]. Its Docker image bundles all linters, so it is local/offline after pull [V].
- **Gating trap:** jscpd's own README says "Super Linter and MegaLinter both run jscpd with threshold: 0 by default, which fails a build on any duplication at all, including clones that were already there", and recommends a baseline instead [V quote from jscpd README, not MegaLinter's]. That is exactly the legacy-clone problem our ratchet solves.
- **Fit:** a reasonable lint-only layer, but not a metrics gate; AGPL matters if we modify and redistribute it. [J]
- **Maturity [J]:** mature/widely used.

### 4.4 lizard

- **URL / licence / activity:** https://github.com/terryyin/lizard; NOASSERTION in the API, but LICENSE.txt is an MIT-style permission grant ("Permission is hereby granted, free of charge...") [V]. 2,562 stars, push 2026-10-24T02:18:00Z, archived=false [V].
- **Languages:** the README lists 26: C#, C/C++, Erlang, Fortran, GDScript, Go, Java, JavaScript, Kotlin, Lua, Objective-C, Perl, PHP, PL/SQL, Python, R, Ruby, Rust, Scala, Solidity, Structured Text, Swift, TTCN-3, TypeScript, VueJS, Zig [V]. **No Bash, no Emacs Lisp** [V].
- **Metrics:** NLOC, CCN, token count, parameter count; -C/-a limits generate warnings and **the exit code is non-zero if there are warnings** [V]. Extensions cover duplicate detection and **cognitive complexity** [V]. No coverage [V].
- **Offline:** Python 3.8+ CLI, local [V].
- **Fit:** a good cheap CC/cognitive/duplicate check for Python (and the other listed languages), but it cannot gate Elisp/Bash and has no coverage join. [J]
- **Maturity [J]:** mature, active.

### 4.5 jscpd (v5)

- **URL / licence / activity:** https://github.com/kucherenko/jscpd; MIT, 6,445 stars, push 2026-10-24T05:22:39Z, archived=false [V].
- **Languages:** "224 language formats" [V]; FORMATS.md has a **bash** row (.sh, .ksh, .bash, .zsh, .bats, shebang) and a **lisp** row (.cl, .lisp, .el, described as "Common Lisp and Emacs Lisp source files") [V]. This is the key finding: **jscpd can tokenize both of our non-mainstream languages**.
- **Metrics:** token-based Rabin-Karp duplicate detection; default **--min-tokens = 50** and --min-lines = 5 [V from docs/rust.md]; Type-2/3/4 variants; --threshold, --exit-code; **clone baseline** --baseline .jscpd-baseline.json --fail-on-new-clones[=N] and --baseline-from-ref origin/main; --changed for changed files [V from README]. It also has --dead-code (JS/TS/Python only), --complexity (file/folder ranking, not per-function CC), --health, --history, SARIF/codeclimate reporters [V].
- **Not covered:** coverage, CRAP, per-function coverage, mutation, check inventory [V for README absence].
- **Offline:** "self-contained binary — no runtime required" (Rust engine), installable via npm/PyPI/cargo/Homebrew/Nix/Docker [V]. The optional semantic model must be downloaded once, but exact-clone detection does not need it [V].
- **Fit:** **adopt for clones**. Configure --min-tokens 50 (already default), keep the baseline file under version control, and wrap it to attach reasons. Validate the .el tokenizer on our code, because a Lisp tokenizer may treat reader macros/quoting differently from our normalizer [U].
- **Maturity [J]:** mature project, but v5 is a Rust-engine rewrite; v4 remains on master-v4 [V]. The v5 release date is [U]; pin the version.

### 4.6 PMD / CPD

- **URL / licence / activity:** https://github.com/pmd/pmd; NOASSERTION in the API, LICENSE says "PMD's BSD-style license" [V]. 5,516 stars, push 2026-10-23T19:02:14Z, archived=false [V].
- **Languages:** PMD supports Java, JavaScript, Apex/Visualforce, Kotlin, Swift, Modelica, PL/SQL, Velocity, JSP, WSDL, Maven POM, HTML, XML, XSL, Scala; CPD adds Coco, C/C++, C#, CSS, Dart, Fortran, Gherkin, Go, Groovy, HTML, Java, JavaScript, JSP, Julia, Kotlin, Lua, Matlab, Modelica, Objective-C, Perl, PHP, PL/SQL, **Python**, Ruby, Apex, Visualforce, Scala, Swift, T-SQL, TypeScript, Velocity, WSDL, XML, XSL [V]. **No Bash, no Emacs Lisp** [V].
- **Metrics:** CPD is a token-based clone detector; PMD has 400+ rules including complexity rules [V]. No coverage join, no per-function coverage, no mutation [V for README absence].
- **Offline:** Java binary zip; local [V].
- **Fit:** a credible clone engine for Python but redundant if jscpd is adopted, and it cannot see Elisp/Bash. [J]
- **Maturity [J]:** very mature (since 2002).

### 4.7 wily

- **URL / licence / activity:** https://github.com/tonybaloney/wily; Apache-2.0, 1,333 stars, push 2026-10-07T12:28:08Z, archived=false [V].
- **Scope:** "tracking, reporting on complexity of Python tests and applications"; uses git to walk revisions and run complexity metrics; wily diff compares against a revision [V]. Python only [V].
- **Metrics:** complexity and MI history (radon-backed); no coverage, no CRAP, no threshold gate documented [V for README absence; U for "no hidden gate"].
- **Fit:** interesting for trend reporting, not for a pass/fail gate. [J]
- **Maturity [J]:** niche but active.

### 4.8 radon

- **URL / licence / activity:** https://github.com/rubik/radon; MIT, 2,036 stars, push 2024-10-20T09:52:54Z, archived=false [V]. Last push is ~2 years before this review; treat as stale [J].
- **Scope:** Python only; McCabe CC, maintainability index, raw metrics [V]. README explicitly says radon is a reporting tool and points CI users to **xenon** for non-zero exit on thresholds [V].
- **Fit:** fine as a Python CC library, but not a gate and not multi-language. [J]

### 4.9 Python CRAP-score tools: crap4py, crapper, cargo-crap

**crap4py** — https://github.com/gabadi/crap4py; MIT; 1 star; push 2026-06-24T04:45:21Z; Python only [V]. It computes CRAP = CC² × (1 − coverage)³ + CC per function from Python AST CC and **LCOV branch-coverage** records, with --lcov and --max-crap N (non-zero exit if any function exceeds N) [V from README]. No baseline/ratchet, no reasons, no Elisp/Bash; coverage is an external LCOV, not necessarily same-run [V/U]. Experimental maturity [J]. This is the closest implementation to our Python CRAP, but too small to depend on directly.

**crapper** — https://github.com/unclebob/crapper; 0BSD; 100 stars; push 2026-10-21T14:16:08Z [V]. It detects the language per file and computes CRAP for **Clojure, Java, Go, TypeScript/JavaScript, Rust and Python** [V]. Options include --threshold 30 (exit 2 when the worst score is higher), --changed, --use-existing-coverage, and a .metrics/crap.edn snapshot; coverage is read from existing reports (or computed by invoking test tooling) [V]. **No Elisp/Bash** [V]. Young maturity [J]. Its documented threshold example (30) is much looser than our 6.

**cargo-crap** — https://github.com/minikin/cargo-crap; MIT; 429 stars; push 2026-10-23T10:12:46Z [V]. Rust only: parses with syn, reads LCOV, computes per-function CRAP, and supports a threshold/regression gate with PR comments and duplicate triage [V from README]. No Elisp/Bash [V]. Active; a good design reference for CRAP-in-CI and baseline output, not a reusable engine for us. [J]

### 4.10 diff-cover

- **URL / licence / activity:** https://github.com/Bachmann1234/diff_cover; Apache-2.0, 849 stars, push 2026-10-23T00:51:03Z [V].
- **Scope:** compares an XML/LCOV coverage report with git diff and reports coverage on new/modified lines; supports Cobertura, Clover, JaCoCo XML and LCov; --fail-under returns non-zero below a threshold; diff-quality can run a few Python linters on the diff [V from README]. Not a complexity or CRAP tool; line-level, not per-function [V].
- **Fit:** useful as a **changed-line coverage gate** alongside CRAP, and it could consume kcov/coverage.py output if the format matches [U for Bash/Elisp]. It is not a ratchet by itself. [J]
- **Maturity [J]:** mature, active.

### 4.11 mutmut

- **URL / licence / activity:** https://github.com/boxed/mutmut; BSD-3-Clause, 1,502 stars, push 2026-10-23T18:17:28Z [V].
- **Scope:** Python mutation testing; can use coverage.py to avoid mutating uncalled lines; mutmut browse, apply, badges; incremental re-testing of changed functions [V from README]. I found **no documented mutation-score threshold or ratchet** in the README; gating would require parsing results or a wrapper [U].
- **Fit:** a good optional Python-only signal; **no Bash/Elisp mutation tool** exists in the candidates reviewed [V for candidates; U for universal absence]. Mutation for Elisp/Bash would be a research/build project, not an off-the-shelf adoption. [J]

### 4.12 Trunk Check

- **URL / licence / activity:** https://api.github.com/repos/trunk-io/trunk returns **404**; so do trunk-io/trunk-cli, trunk-io/trunk-check and trunk-io/cli [V]. GET /orgs/trunk-io/repos?per_page=100&sort=pushed (first page of 100, sorted by push) contains **no CLI repository**; it contains trunk-io/plugins (MIT, 172 stars, push 2026-10-23T11:00:18Z) and trunk-io/trunk-action (MIT, 248 stars, push 2026-10-24T00:26:20Z) [V].
- **Implication:** the Trunk Check **CLI is not public/open source** in the GitHub org; only the plugin catalog and GitHub Action are. I could not verify the CLI licence or source [V for absence; U for licence]. It orchestrates many linters and supports shellcheck via plugins, but has no CRAP/coverage/metrics suite of its own [U].
- **Fit:** not suitable as the reusable open-source component of our gate; a commercial dependency at best. [J]

### 4.13 ShellCheck, elisp-lint, package-lint, vulture, import-linter, xenon, codemetrics

- **ShellCheck** — https://github.com/koalaman/shellcheck; GPL-3.0; 40,228 stars; push 2026-10-19T01:25:10Z [V]. Static analysis for bash/sh; "canonical use of exit codes" for builds [V]. Lint only; no complexity/coverage. Mature [J].
- **elisp-lint** — https://github.com/gonewest818/elisp-lint; API license=null; 73 stars; last push **2022-04-19**; LICENSE, LICENSE.md, LICENSE.txt, COPYING all 404 [V]. Batch Emacs Lisp linter with validators for byte-compile (all warnings), checkdoc, indent, indent-character, etc. [V]. **No licence and abandoned** → do not adopt or vendor; use built-in byte-compile/checkdoc plus package-lint instead. [J]
- **package-lint** — https://github.com/purcell/package-lint; GPL-3.0; 223 stars; push 2026-09-03 [V]. Lints Emacs Lisp package metadata/headers; complements checkdoc/byte-compile. [V from description; detailed rules U]
- **vulture** — https://github.com/jendrikseipp/vulture; MIT; 4,859 stars; push 2026-10-12 [V]. Finds dead Python code with confidence values and whitelists; exit code 3 when dead code is found [V]. Python only.
- **import-linter** — https://github.com/seddonym/import-linter; BSD-2-Clause; 1,234 stars; push 2026-10-13 [V]. Imposes import-layer/forbidden/cycle contracts on Python modules; pass/fail [V]. Python only.
- **xenon** — https://github.com/rubik/xenon; MIT; 282 stars; push 2024-10-21 [V]. Radon-based complexity thresholds with non-zero exit [V]. Python only, stale [J].
- **codemetrics** — https://github.com/emacs-vs/codemetrics; GPL-3.0; 79 stars; push 2026-06-19 [V]. Live Emacs cognitive-complexity calculation via tree-sitter; supported languages include **Bash and Elisp** ("fairly complete") plus C/C++/C#, Go, Java/JS/JSX/Julia, Kotlin, Lua, PHP/Python, Ruby/Rust, Swift, TypeScript/TSX [V]. It is an editor plugin, not a batch CLI/gate [V]. This is the only tool found that computes cognitive complexity for **both** Bash and Elisp. [V]

### 4.14 Other 2025-2026 search hits

- **riskratchet** — https://github.com/KayhanB21/riskratchet; MIT; 8 stars; push 2026-10-18 [V]. "A maintainability ratchet for AI-assisted Python and TypeScript"; per-function risk from coverage gaps, CC, churn, public surface and sprawl; baseline/check exit 1 on regression, --fail-above N for no-baseline gating [V from README]. Closest philosophy to our gate, but only Python/TypeScript and very young [V/J]. Use it as a **design reference** for baseline UX/exit codes, not as a dependency.
- **keeler** — https://github.com/minikin/keeler; MIT; 4 stars; push 2026-09-08 [V]. Self-described WIP "Make AI-written Rust trustworthy: human-approved specs, strict TDD, and independent gates — coverage, CRAP score, property tests, and mutation testing" [V description]. Rust-only, experimental [V/J].
- **skylos** — https://github.com/duriantaco/skylos; Apache-2.0; 848 stars; push 2026-10-24 [V]. Self-described "local-first PR scanner that finds dead code, security bugs, secrets, quality regressions, and AI-code mistakes before merge" [V description]. Python-oriented; not a multi-language metric suite [U for exact language coverage].
- **aislop** — https://github.com/scanaislop/aislop; MIT; 699 stars; push 2026-10-24 [V]. Self-described "50+ deterministic rules across 10 language targets, with CLI, CI, and GitHub Actions. No LLM at runtime" [V description]. Rule-based AI-slop scanner, not CRAP/coverage/mutation [V description].
- **complexipy** — https://github.com/rohaquinlop/complexipy; MIT; 895 stars; push 2026-10-24 [V]. "Blazingly fast cognitive complexity analysis for Python" [V description]. Python only; a possible optional cognitive check.
- **Agent/skill packs** from the code quality gate search (e.g. amElnagdy/guard-skills, 1,281 stars, MIT, push 2026-07-04; soumatheusgomes/vibe-coding-toolkit, 1,969 stars, MIT, push 2026-10-19; modu-ai/moai-adk, 1,235 stars, Apache-2.0, push 2026-10-24) are **prompt/workflow packs that wrap tests and linters**, not metric engines [V descriptions; U for internals]. They confirm the demand but do not close the gap.

---

## 5. Gap analysis against our gate

| Our gate component | Best available off-the-shelf | Gap vs our requirement | Verdict |
|---|---|---|---|
| **Per-function CRAP** = CC² × (1−cov)³ + CC, threshold 6, in-run coverage, reasoned ratchet | crap4py (Python; LCOV branch coverage; --max-crap), crapper (6 langs; threshold 30), cargo-crap (Rust; baseline/PR) [V] | No Elisp or Bash implementation. Python tools take coverage from a separate LCOV report, not necessarily the same run. None has a **reasoned exception baseline** or threshold 6. | **Build/wrap** the adapters; reuse crap4py's formula/LCOV join for Python as reference. |
| **Token clone detection ≥50 normalized tokens + ratchet** | jscpd v5: 224 formats incl. .el and Bash, default --min-tokens 50, baseline + --fail-on-new-clones, SARIF [V] | Normalization differs from ours; need to validate .el and Bash token streams; baseline has no reasons (sidecar needed). | **Adopt** jscpd; wrap baseline with reasons. |
| **Inventory: every tracked code file covered by a check** | No candidate implements it. qlty/MegaLinter have plugin/linter inventories, not file-to-check coverage [V/U]. | Complete gap. | **Build** (small: git ls-files × per-language check map). |
| **Hygiene: no tracked ignored files; no file >10 MB** | No candidate implements it [V/U]. | Complete gap. | **Build** (small). |
| **Lint: byte-compile, checkdoc, ShellCheck, Ruff** | Built-in Emacs byte-compile/checkdoc; package-lint; ShellCheck; Ruff (via MegaLinter/qlty or direct) [V] | elisp-lint is unlicensed/abandoned; qlty's Shell is lint-only anyway. | **Compose** direct tools; avoid elisp-lint. |
| **Tests execute scripts** | ERT/buttercup (Elisp), pytest (Python), bats-core (Bash) [V for bats; U for ERT/buttercup details] | Existing gate already does this; no new tool needed. | **Keep/compose.** |
| **Branch coverage (considered)** | coverage.py (Python); kcov/bashcov (Bash, line); Emacs testcover (form/line, not branch) [V/U] | No branch coverage for Elisp/Bash; our "coverage measured in the same run" is stronger than most. | **Python: reuse; Elisp/Bash: build/wrap or defer.** |
| **Cognitive complexity (considered)** | qlty (40+), SonarQube (core), lizard (extension), codemetrics (Elisp + Bash), complexipy (Python) [V/U] | No CLI gate for Elisp/Bash except codemetrics (editor plugin). | **Advisory** at first; reuse codemetrics logic if batchable. |
| **Mutation score (considered)** | mutmut (Python) [V]; Stryker, PIT and Infection for other ecosystems [V from search descriptions]; other mutators exist [U] | None for Bash/Elisp. mutmut has no documented score threshold [U]. | **Defer**; Python-only optional wrapper. |
| **Dead code (considered)** | vulture (Python), jscpd --dead-code (JS/TS/Python) [V] | None for Bash/Elisp. | **Python-only optional; defer for our two.** |
| **Dependency cycles (considered)** | import-linter (Python) [V]; no Bash/Elisp equivalent found [U] | None for Bash/Elisp. | **Python-only optional; defer.** |

---

## 6. Recommendation

### 6.1 Adopt, compose or build?

**Compose the commodity parts; build a thin reusable gate for the gaps.** In practice: **~70% compose, ~30% build** (judgment, not a measured ratio).

Do **not** adopt a monolith:

- **qlty** is the closest "one command, many metrics" CLI, but its **BSL 1.1** is not open source, the additional use grant restricts code-quality/AI-coding services, it has **no Emacs Lisp**, Bash is lint-only, and it has **no CRAP**. [V facts; J]
- **SonarQube Community Build** has the best quality-gate semantics and a real "new code" ratchet, but it is a server + DB product, the scanner is only a client, the Community Build lacks branch/PR analysis (commercial), and Emacs Lisp/Bash are not supported. [V/U]
- **MegaLinter** is a linter aggregator, not a metric gate; AGPL; jscpd threshold 0 legacy trap. [V]
- **Trunk Check**'s CLI is not public in its GitHub org; only plugins/action are MIT. [V]

### 6.2 What to reuse (with licences)

| Need | Reuse | Licence | Why |
|---|---|---|---|
| Clones / clone ratchet | **jscpd v5** | MIT [V] | Supports .el and Bash; default 50 tokens; baseline/fail-on-new-clones; SARIF; self-contained binary [V] |
| Python CRAP reference | **crap4py** | MIT [V] | Exactly our CRAP formula, per-function LCOV branch coverage, --max-crap [V]; copy the join/algorithm, pin/patch if used |
| Python coverage | **coverage.py** (via crap4py/diff-cover) | Apache-2.0 [U] | Branch coverage and LCOV/XML output; standard [V via tools] |
| Python complexity | **radon** (library) or lizard | MIT / MIT-style [V] | CC/MI; radon is stale as a CLI but usable as a library [J] |
| Elisp lint | **byte-compile + checkdoc** (built-in) + **package-lint** | Emacs / GPL-3.0 [V] | Active, no licence trap; package-lint covers headers [V] |
| Bash lint | **ShellCheck** | GPL-3.0 [V] | De facto standard; exit codes [V] |
| Python lint | **Ruff** | MIT (widely reported; direct licence [U]) | Fast, covers our current Ruff rule [V from qlty/MegaLinter references] |
| Elisp cognitive (optional) | **codemetrics** | GPL-3.0 [V] | Only tool found with Elisp **and** Bash cognitive complexity [V]; editor plugin, needs batch wrapper [U] |
| Python dead code / cycles (optional) | **vulture**, **import-linter** | MIT / BSD-2 [V] | Good, but Python-only |
| Python mutation (optional) | **mutmut** | BSD-3 [V] | Python-only; no score gate [U] |
| Bash tests / coverage | **bats-core**, **kcov** or **bashcov** | MIT / GPL-2.0 / MIT [V] | Tests and line coverage; no per-function join [V/U] |

**Licence note:** if the repository is GPL-3.0 (typical for a Spacemacs config), GPL-3.0 tools (ShellCheck, codemetrics, package-lint, kcov) are compatible; MIT/Apache/BSD are compatible too. Avoid **elisp-lint** (no licence) and treat **qlty** (BSL) as a service/tool dependency only after legal review; AGPL MegaLinter is fine to invoke in CI but imposes obligations if modified and distributed. [V licences; U legal interpretation]

### 6.3 What to build

Build a small, reusable **quality-gate** package (Python CLI + Emacs batch helper) that owns only what no tool owns:

1. **Elisp/Bash CRAP adapters**
   - Elisp: compute per-function CC from the Emacs Lisp reader/AST; obtain per-function coverage from testcover/undercover or an instrumented ERT run; join and compute CRAP.
   - Bash: parse with tree-sitter-bash or mvdan.cc/sh/v3/syntax; compute CC per function; obtain line coverage from kcov or bashcov; map lines to functions; compute CRAP.
   - Python: either call crap4py (if pinned) or reuse its LCOV join; ensure coverage is produced in the same CI run.
2. **Unified ratchet**
   - A versioned JSON/YAML baseline with per-item reason, owner, expires, and a content hash; fail when a new violation appears or a score worsens, not when legacy debt is unchanged.
   - This generalizes the clone baseline (jscpd) and CRAP baseline; jscpd's baseline remains the source of truth for clones, wrapped by our reasons sidecar.
3. **Inventory**
   - git ls-files → map every tracked code file (.el, .py, .sh, .bash, etc.) to at least one check; fail on unmapped files. This is the piece no candidate has.
4. **Hygiene**
   - git ls-files -ci --exclude-standard (tracked ignored files) and git ls-files -z | xargs -0 stat for >10 MB. Trivial, but ours.
5. **Orchestration/CI entry point**
   - One command that runs: inventory → hygiene → jscpd clone gate → per-language lint → tests/coverage → CRAP → ratchet; emits SARIF/JUnit and a human summary.
   - Keep the existing per-language commands (byte-compile, checkdoc, ShellCheck, Ruff, ERT/pytest/bats) rather than reimplementing them.

**Do not build:** a general linter runner, a clone detector, a Python coverage engine, or a SonarQube clone. Those are commodity and better maintained upstream.

### 6.4 Suggested rollout

1. **Phase 1 (quick win):** wire **jscpd** with --min-tokens 50, --baseline .jscpd-baseline.json, --fail-on-new-clones; add package-lint to the Elisp lint step; keep existing ShellCheck/Ruff/byte-compile/checkdoc. [V tools; J plan]
2. **Phase 2:** add the inventory + hygiene checks and the reasoned ratchet wrapper; migrate the existing CRAP baseline into it (no score changes).
3. **Phase 3:** implement the Elisp and Bash CRAP adapters; validate against the current gate on a sample of commits. Keep the Python CRAP implementation as-is or swap to a pinned crap4py join.
4. **Phase 4 (optional):** Python-only mutation (mutmut), dead code (vulture) and cycles (import-linter); cognitive complexity as an advisory metric (codemetrics logic for Elisp/Bash, lizard/qlty-style for Python). Do not gate on these until the false-positive rate is understood.

### 6.5 What not to adopt

- **qlty** as the single gate: BSL, no Elisp, Bash lint-only, no CRAP documented. [V]
- **SonarQube CE** as the local gate: server/DB, no Elisp/Bash, no CRAP documented, branch/PR analysis commercial. [V/U]
- **MegaLinter** as the metric gate: linter-only, no CRAP/coverage, jscpd threshold 0 trap. [V]
- **Trunk Check** as the reusable core: CLI not public. [V]
- **elisp-lint** as a dependency: no licence, last push 2022. [V]
- **radon/xenon** as the Python gate alone: reporting/CC thresholds, no coverage join, stale. [V]

---

## 7. Open questions / risks

- **jscpd .el normalization:** FORMATS.md says it handles Emacs Lisp, but the tokenizer may treat quoting/reader macros differently from our normalizer; run it on a known clone pair before relying on it. [U]
- **Emacs coverage granularity:** testcover gives form/line coverage, not branch coverage; mapping it to per-function coverage needs a spike. [U]
- **Bash CC parser:** tree-sitter-bash vs mvdan.cc/sh AST; either is a small build, but function/line mapping and source/dynamic dispatch are edge cases. [U]
- **SonarQube language matrix:** official docs host was not reachable; the Emacs Lisp/Bash negative is [U]. If SonarQube is a serious candidate, verify with a local instance.
- **qlty BSL:** the additional use grant explicitly targets code-quality/AI-coding services; internal CI use is likely fine, but a reusable package that others run as a service needs legal review. [V licence text; U legal conclusion]
- **Rate limits:** unauthenticated API allowed 60 core/hour and 10 search/min; one discovery query (AI generated code quality) was not completed. Re-run with a token if exhaustive discovery is required. [V]
- **Maturity labels** are judgments; they are not API facts. [J]

---

## Appendix A: API queries and evidence

Core metadata (GET https://api.github.com/repos/{owner}/{repo}) used fields: full_name, html_url, license.spdx_id, stargazers_count, pushed_at, archived, language, default_branch, description.

Organisation listing: GET https://api.github.com/orgs/trunk-io/repos?per_page=100&sort=pushed — first page of 100; no CLI repo; trunk-io/plugins and trunk-io/trunk-action present, both MIT [V].

Search queries completed (repository search, sort=stars, per_page=12-15):

| Query | Total results | Notable hits used |
|---|---:|---|
| CRAP score | 58 | unclebob/crapper, gabadi/crap4py, minikin/keeler, cargo-crap (via follow-up) |
| code quality gate | 1,447 | agent/skill packs; qlty/Sonar not in top 15 (searched separately) |
| maintainability ratchet | 8 | KayhanB21/riskratchet |
| cognitive complexity | 273 | complexipy, emacs-vs/codemetrics, gocognit, flake8-cognitive-complexity |
| clone detection | 1,725 | mibk/dupl, Deckard (not adopted) |
| mutation testing | 3,313 | boxed/mutmut, stryker-js, infection, mutant, PIT |
| dead code | 3,098 | vulture, skylos, aislop |
| elisp lint | 11 | gonewest818/elisp-lint, purcell/package-lint, tychoish/elisp-ci |
| trunk check linter | 0 | — |

AI generated code quality hit the search limit and was not completed; code quality gate was used as the nearest substitute. [V]

Raw files fetched (selected): qltysh/qlty/README.md, LICENSE.md, qlty-cli/src/commands/check.rs; SonarSource/sonarqube/README.md, sonar-scanner-cli/README.md; oxsecurity/megalinter/README.md; terryyin/lizard/README.rst, LICENSE.txt; kucherenko/jscpd/README.md, FORMATS.md, docs/rust.md; pmd/pmd/README.md; tonybaloney/wily/README.md; rubik/radon/README.rst; Bachmann1234/diff_cover/README.rst; boxed/mutmut/README.rst; koalaman/shellcheck/README.md; gonewest818/elisp-lint/README.md; jendrikseipp/vulture/README.md; seddonym/import-linter/README.md; emacs-vs/codemetrics/README.md; gabadi/crap4py/README.md; unclebob/crapper/README.md; minikin/cargo-crap/README.md; KayhanB21/riskratchet/README.md; rubik/xenon/README.rst. [V]

## Appendix B: one-line decision table

| Decision | Tool | Reason |
|---|---|---|
| **Adopt** | jscpd v5 (MIT) | Only mature clone engine verified to support .el and Bash, with a 50-token default and a baseline/ratchet mode [V] |
| **Compose** | ShellCheck, Ruff, byte-compile, checkdoc, package-lint, pytest, bats-core | Commodity lint/test layers; no reason to rebuild [V] |
| **Reference only** | crap4py, cargo-crap, riskratchet, codemetrics | Good algorithms/UX, but too narrow/young or editor-only for our three-language gate [V/J] |
| **Build** | Elisp/Bash CRAP adapters, inventory, hygiene, reasoned ratchet, orchestration | No candidate covers them [V/U] |
| **Do not adopt** | qlty, SonarQube CE, MegaLinter-as-gate, Trunk CLI, elisp-lint | Licence, server weight, language gaps, no CRAP, or unmaintained [V/U] |
