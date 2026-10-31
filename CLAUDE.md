# code-quality-gate - Agent Guide

A reusable, offline code-quality gate any repository can run, built to keep AI-written code high
quality and maintainable. Consuming repositories pin it as a git submodule and declare their own
configuration (`quality-gate.toml`); this repository gates itself with the same tool. The
implementation is the `quality_gate/` package (`policy`, `adapters`, `command`, `files`, `tools`, `runner`,
`ratchet`, `clones`, `owners`, `output_patterns`,
`python_tests`, `python_crap`, `elisp_tests`, `elisp_crap`, `elisp_lint`, `elisp/qg-elisp-child.el`,
`elisp/qg-elisp-complexity.el`, `elisp/qg-elisp-lint.el`, `verification`, `covrun`,
`coverage_tool`, `checks`, `gate_result`,
`trust`, `cli`);
`qg.py` is only the entry point. Each adapter module owns its specification type, parsing and
adapter-specific rules. `adapters.py` declares descriptors and keeps shared baseline and CRAP
specification helpers; `policy` holds shared value readers and policy validation.
Core package modules import only core package modules, with `adapters.py` the sole registry allowed to
import adapters.
`check --policy-from REV` takes its policy, baselines, tool lock and protected paths from `REV`;
`docs/TRUST.md` is the contract.

Policy declares `schema = 2`, code classes with their `checks`, and one `[checks.ID]` table per check
(`command`, `clones`, `python_tests`, `elisp_tests`, `python_crap`, `elisp_crap`, `elisp_compile`,
`elisp_checkdoc`, `verification` or `owners`). Adapters declare evidence
(`tests`, `crap`, `duplication`, `static`) and the result reports one obligation per code class and
required tier.
Adapters measure subjects; the core in `ratchet.py` decides raw outcome, policy satisfaction, expiry,
resolution, unmeasured domains and pruning. Every subprocess goes through `runner.py`. Python
coverage uses one gate-owned
configuration, never repository coverage files or `COVERAGE_*` overrides; Python subjects include
property accessors, overload declarations are skipped, and each file's outside-function code is a
`PATH:<module>` subject. Clone evidence is complete only when jscpd's own source count covers every
selected file and its SARIF has one jscpd run with results. `check --json` writes one machine-readable
schema-2 result to stdout (schema 3 with a `trust` object under `--policy-from`), with execution, raw
outcome, satisfaction, diagnostics, obligations, unmeasured baseline entries and prune reporting; human
lines go to stderr. A baseline starts with `check` and
`metric_version` matching the policy, and a requested prune that is refused still exits 1 while the
decision reports the gate evaluation. Start by reading `README.md` and `docs/SCHEMA.md`, then the module
that owns the concern; tests execute the real command on disposable fixture repositories.

The implementer agents' learned memory lives in `.agents/AGENTS.md`, written by the runner's reflection
step and reviewed before landing.

## Principles

* Simplest implementation that fully meets the current requirements; no speculative configuration,
  plugin layers or indirection. Grow in layers on top of a version that works end to end.
* Compose maintained tools where they fit (pinned and checksum-verified in `tools.lock.toml`); build
  only what no tool provides (inventory, hygiene, reasoned ratchets, CRAP adapters).
* A gate must be able to fail: every check gates on a measured quantity, and every failure mode has a
  test that makes it fail. A missing input is an error, never a skipped check or a plausible default.
* Tests execute the real command on disposable fixture repositories; no network, no real home.
* Messages name what failed, the offending input, and expected versus actual.
* Ratchets only tighten: a new exception enters a baseline only by hand, with a reason.

## Rules

* The core is standard-library Python 3.12 only, run as `python3 -I`; the Python adapters
  load the pinned coverage wheel from the tools cache.
* `make -k check` passes before committing.
* Never commit binaries or downloaded tools; they live in the external tools cache
  (`QG_TOOLS_DIR`, default `~/.local/share/code-quality-gate/tools`).
