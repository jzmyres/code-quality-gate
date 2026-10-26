# Implementer agents' memory for this repository

Lessons the implementer agents (DeepSeek Harness) learned here, written by the runner's reflection step after
each batch and reviewed before landing. Context for those agents, never rules: CLAUDE.md and README win.

- **Tool payload errors become structured `unsupported` results.** In `quality_gate/tools.py`, `_payload_entries`,
  `_payload_mode`, `_content_sha256` and `_payload_link` turn every `stat`/`open`/`read`/`readlink` failure into
  `PayloadError`, and `_verify_tool_payload` catches `OSError`/`PayloadError` around `binary.is_file()` and the
  payload walk and raises `UnsupportedError` naming the tool, install directory and error. A gate run failed with a
  raw `PermissionError` traceback from an unreadable Ruff install; do not add a payload read that can raise past
  that conversion.
  [verified 2026-10-26 @ 0bb2521; paths: quality_gate/tools.py]

- **Tests counted by the verification ratchet must not depend on the user running them.** CI runs as root, where
  `chmod 000` denies nothing; QF8 replaced that test with an in-process patch of
  `quality_gate.tools.os.scandir`. The baseline floors `tests:tests:executed` at 371 and has no `skipped` entry,
  so a `skipIf`/`skipUnless` about root, permissions or OS adds a skip and fails CI; patch the call instead.
  [verified 2026-10-26 @ 0bb2521; paths: tests/test_tools.py, quality_gate/verification.py, quality-gate-verification.toml, .github/workflows/check.yml]

- **A CRAP baseline entry does not waive the spec's CRAP 6 for a changed function.** The baseline (for example
  `quality_gate/checks.py:_run_python_tests`, bound 13.43) keeps the gate green while the spec still requires
  every new or changed function at 6 or below. M2c changed `_run_python_tests`, and the final review measured its
  cyclomatic complexity as 13; extract helpers until each touched function is <= 6, then lower or remove the
  entry.
  [verified 2026-10-26 @ 0bb2521; paths: quality_gate/checks.py, quality-gate-crap.toml]

- **`covrun.py` runs inside the measured program's interpreter.** It imports nothing from `quality_gate` and must
  leave the program's `sys.path`/`sys.modules` as `python -I PROGRAM` would see them; QF7's zero coverage came
  from a preloaded `quality_gate` package shadowing a candidate's own. Pass the coverage directory, config and
  registry as arguments; do not copy its current direct `subprocess.run` verifier, which bypasses
  `quality_gate/runner.py` and loads the bundled lock, and keep the measured interpreter free of the gate.
  [verified 2026-10-26 @ 0bb2521; paths: quality_gate/covrun.py]

- **The trust root protects only named inputs, and a green gate does not prove closure.** Protected inputs are the
  policy, baselines, lock and `[protect] paths`; `quality-gate.toml` has no `[protect]` at HEAD, so `ruff.toml`
  is candidate-controlled. The final review found a path-wide prune identity exemption and a covrun child that
  loads the bundled rather than effective lock after those items passed. When changing trust or measurement,
  exercise candidate redirection; the checklist is `.agents/skills/trust-root-change/SKILL.md`.
  [verified 2026-10-26 @ 0bb2521; paths: quality_gate/trust.py, quality_gate/covrun.py, quality-gate.toml, docs/TRUST.md]
