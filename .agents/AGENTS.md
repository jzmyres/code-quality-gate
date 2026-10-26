# Implementer agents' memory for this repository

Lessons the implementer agents (DeepSeek Harness) learned here, written by the runner's reflection step after
each batch and reviewed before landing. Context for those agents, never rules: CLAUDE.md and README win.

- **Tool payload errors become structured `unsupported` results.** In `quality_gate/payload.py`,
  `_payload_entries`, `_payload_mode`, `_content_sha256` and `_payload_link` turn every `stat`/`open`/`read`/
  `readlink` failure into `PayloadError`; `quality_gate/tools.py:_verify_tool_payload` catches
  `OSError`/`PayloadError` around `binary.is_file()` and the payload walk and raises `UnsupportedError` naming
  the tool, install directory and error. A gate run failed with a raw `PermissionError` traceback from an
  unreadable Ruff install; do not add a payload read that can raise past that conversion.
  [verified 2026-10-26 @ 580058a; paths: quality_gate/tools.py, quality_gate/payload.py]

- **Tests counted by the verification ratchet must not depend on the user running them.** CI runs as root, where
  `chmod 000` denies nothing; QF8 replaced that test with an in-process patch of
  `quality_gate.payload.os.scandir` (QF11 moved the payload walk there). The baseline floors
  `tests:tests:executed` at 371 and has no `skipped` entry, so a `skipIf`/`skipUnless` about root, permissions
  or OS adds a skip and fails CI; patch the call instead.
  [verified 2026-10-26 @ 580058a; paths: tests/test_tools.py, quality_gate/payload.py, quality_gate/verification.py, quality-gate-verification.toml, .github/workflows/check.yml]

- **A CRAP baseline entry does not waive the spec's CRAP 6 for a changed function.** The baseline keeps the
  gate green while the spec still requires every new or changed function at 6 or below;
  `quality_gate/checks.py:_run_python_crap` is still bound at 12.16. M2c changed `_run_python_tests` at
  complexity 13; QF12 split it into setup/outcome/evidence helpers and removed its entry. Extract helpers until
  each touched function is <= 6, then lower or remove the entry; the gate's "N functions within threshold"
  still includes baseline entries.
  [verified 2026-10-26 @ 580058a; paths: quality_gate/checks.py, quality-gate-crap.toml]

- **`covrun.py` runs inside the measured program's interpreter.** It imports nothing from `quality_gate`; it
  loads the standard-library `quality_gate/payload.py` verifier by file path, and the parent passes the
  effective coverage directory, version and payload digest as arguments (QF11). Keep the measured interpreter
  free of the gate: QF7's zero coverage came from a preloaded `quality_gate` package shadowing a candidate's
  own. Do not add a `quality_gate` import or a nested verifier subprocess.
  [verified 2026-10-26 @ 580058a; paths: quality_gate/covrun.py, quality_gate/payload.py, quality_gate/tools.py]

- **The trust root protects only named inputs, and a green gate does not prove closure.** Protected inputs are
  the policy, baselines, lock and `[protect] paths`; `quality-gate.toml` protects `ruff.toml` and the Ruff
  check passes `--config ruff.toml`, but an unlisted configuration file remains candidate-controlled: add
  each tool config to `[protect] paths` and pass it explicitly. QF10
  replaced the path-wide prune exemption with an after-checks snapshot and an exact-bytes allowance for the
  gate's own write (`Trust.before_prune`, `record_prune_write`, `_allowed_change`). When changing trust or
  measurement, exercise candidate redirection; the checklist is `.agents/skills/trust-root-change/SKILL.md`.
  [verified 2026-10-26 @ 580058a; paths: quality_gate/trust.py, quality_gate/checks.py, quality-gate.toml, docs/TRUST.md]

- **Every git command on a candidate repository goes through `files.git_argv`.** It adds
  `--no-replace-objects`, `safe.directory=ROOT` and `core.fsmonitor=false`; `trust._git`, `files._git` and
  `gate_result._git` call it. A bare `git` call lets a candidate-configured fsmonitor or replacement ref
  change what the gate reads.
  [verified 2026-10-26 @ 580058a; paths: quality_gate/files.py, quality_gate/trust.py, quality_gate/gate_result.py]
