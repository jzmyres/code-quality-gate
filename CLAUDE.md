# code-quality-gate - Agent Guide

A reusable, offline code-quality gate any repository can run, built to keep AI-written code high
quality and maintainable. Consuming repositories pin it as a git submodule and declare their own
configuration (`quality-gate.toml`); this repository gates itself with the same tool. The
implementation is the `quality_gate/` package (`policy`, `files`, `tools`, `ratchet`, `clones`,
`python_tests`, `python_crap`, `covrun`, `coverage_tool`, `checks`, `gate_result`, `cli`);
`qg.py` is only the entry point.

Policy declares `schema = 1`, code classes with their `checks`, and one `[checks.ID]` table per check
(`command`, `clones`, `python_tests` or `python_crap`). Adapters measure subjects; the core in
`ratchet.py` decides pass/fail, expiry, resolution and pruning. Python coverage uses one gate-owned
configuration, never repository coverage files or `COVERAGE_*` overrides; Python subjects include
property accessors, overload declarations are skipped, and each file's outside-function code is a
`PATH:<module>` subject. Clone evidence is complete only when jscpd's own source count covers every
selected file and its SARIF has one jscpd run with results. `check --json` writes one machine-readable
result to stdout; human lines go to stderr. Start by reading `README.md`, then the module that owns the
concern; tests execute the real command on disposable fixture repositories.

## Principles

* Simplest implementation that fully meets the current requirements; no speculative configuration,
  plugin layers or indirection. Grow in layers on top of a version that works end to end.
* Compose maintained tools where they fit (pinned and checksum-verified in `tools.lock.toml`); build
  only what no tool provides (inventory, hygiene, reasoned ratchets, CRAP adapters).
* A gate must be able to fail: every check gates on a measured quantity, and every failure mode has a
  test that makes it fail. A missing input is an error, never a skipped check or a plausible default.
* Tests execute the real command on disposable fixture repositories; no network, no real home.
* Messages name what failed, the offending input, and expected versus actual.
* Ratchets only lower: a new exception enters a baseline only by hand, with a reason.

## Rules

* The core is standard-library Python 3.12 only, run as `python3 -I`; the Python adapters
  load the pinned coverage wheel from the tools cache.
* `make -k check` passes before committing.
* Never commit binaries or downloaded tools; they live in the external tools cache
  (`QG_TOOLS_DIR`, default `~/.local/share/code-quality-gate/tools`).
