# quality-gate - Agent Guide

A reusable, offline code-quality gate any repository can run, built to keep AI-written code high
quality and maintainable. Consuming repositories pin it as a git submodule and declare their own
configuration (`quality-gate.toml`); this repository gates itself with the same tool.

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

* Standard-library Python 3.12 only, run as `python3 -I`.
* `make -k check` passes before committing.
* Never commit binaries or downloaded tools; they live in the external tools cache
  (`QG_TOOLS_DIR`, default `~/.local/share/quality-gate/tools`).
