# Implementer agents' memory for this repository

Lessons the implementer agents (DeepSeek Harness) learned here, written by the runner's reflection step after
each batch and reviewed before landing. Context for those agents, never rules: CLAUDE.md and README win.

- **`PayloadError` has no base-class fallback; each payload-read boundary must catch it.** In `quality_gate/payload.py`,
  `_payload_entries`, `_payload_mode`, `_content_sha256` and `_payload_link` turn every `stat`/`open`/`read`/
  `readlink` failure into `PayloadError`; since QF11 it is a plain `Exception`, not a `GateError`.
  `tools._verify_tool_payload` converts `OSError`/`PayloadError` to `UnsupportedError`;
  `tools._existing_payload_matches` returns False and `trust._tool_digest` returns `invalid` when the digest cannot
  be read; `covrun._verify_coverage` raises `_RunError`. QF14 made `tools._build_install` catch
  `payload_digest(build)` and raise `UsageError` naming the tool and build path; `command_tools_fetch` returns
  `error.exit_code` (2 for this `UsageError`), so no traceback escapes.
  When moving or adding a payload read, grep every `payload_digest` call, add its catch and a test that injects a
  read failure with `mock.patch("quality_gate.payload.os.scandir", ...)`.
  [verified 2026-10-26 @ 2b71580; paths: quality_gate/tools.py, quality_gate/payload.py, quality_gate/trust.py, quality_gate/covrun.py, tests/test_tools.py]

- **Tests counted by the verification ratchet must not depend on the user running them.** CI runs as root, where
  `chmod 000` denies nothing; QF8 replaced that test with an in-process patch of
  `quality_gate.payload.os.scandir` (QF11 moved the payload walk there). The baseline floors
  `tests:tests:executed` at 400 and has no `skipped` entry, so a `skipIf`/`skipUnless` about root, permissions
  or OS adds a skip and fails CI; patch the call instead.
  [verified 2026-10-27 @ d044e1b; paths: tests/test_tools.py, quality_gate/payload.py, quality_gate/verification.py, quality-gate-verification.toml, .github/workflows/check.yml]

- **A CRAP baseline entry does not waive the spec's CRAP 6 for a changed function.** The baseline keeps the
  gate green while the spec still requires every new or changed function at 6 or below;
  `quality_gate/checks.py:_run_python_crap` is still bound at 12.16. M2c changed `_run_python_tests` at
  complexity 13; QF12 split it into setup/outcome/evidence helpers and removed its entry. Extract helpers until
  each touched function is <= 6, then lower or remove the entry; the gate's "N functions within threshold"
  still includes baseline entries.
  [verified 2026-10-26 @ d0dd33d; paths: quality_gate/checks.py, quality-gate-crap.toml]

- **`covrun.py` runs inside the measured program's interpreter.** It imports nothing from `quality_gate`; it
  loads the standard-library `quality_gate/payload.py` verifier by file path, and the parent passes the
  effective coverage directory, version and payload digest as arguments (QF11). Keep the measured interpreter
  free of the gate: QF7's zero coverage came from a preloaded `quality_gate` package shadowing a candidate's
  own. Do not add a `quality_gate` import or a nested verifier subprocess.
  [verified 2026-10-26 @ 2b71580; paths: quality_gate/covrun.py, quality_gate/payload.py, quality_gate/tools.py]

- **The trust root protects only named inputs, and a green gate does not prove closure.** Protected inputs are
  the policy, baselines, lock and `[protect] paths`; `quality-gate.toml` protects `ruff.toml` and the Ruff
  check passes `--config ruff.toml`, but an unlisted configuration file remains candidate-controlled: add
  each tool config to `[protect] paths` and pass it explicitly. QF10
  replaced the path-wide prune exemption with an after-checks snapshot and an exact-bytes allowance for the
  gate's own write (`Trust.before_prune`, `record_prune_write`, `_allowed_change`). When changing trust or
  measurement, exercise candidate redirection; the checklist is `.agents/skills/trust-root-change/SKILL.md`.
  [verified 2026-10-26 @ d0dd33d; paths: quality_gate/trust.py, quality_gate/checks.py, quality-gate.toml, docs/TRUST.md]

- **Every git command on a candidate repository goes through `files.git_argv`.** It adds
  `--no-replace-objects`, `safe.directory=ROOT` and `core.fsmonitor=false`; `trust._git`, `files._git` and
  `gate_result._git` call it. A bare `git` call lets a candidate-configured fsmonitor or replacement ref
  change what the gate reads.
  [verified 2026-10-26 @ d0dd33d; paths: quality_gate/files.py, quality_gate/trust.py, quality_gate/gate_result.py]

- **An unmeasured entry resolves by domain, not direction.** `ratchet._record_unmeasured` resolves every entry
  absent from the findings when its subject lies in the adapter's complete `Domain`, whatever its direction, and
  `pruned_entries` then drops it. A measured `min` entry never resolves by itself; `_min_verdict` only handles a
  measured minimum. QF14 corrected `docs/SCHEMA.md` and README to say this. When changing resolution, docs or
  tests, probe a complete domain with an absent entry, not only measured findings.
  [verified 2026-10-27 @ d044e1b; paths: quality_gate/ratchet.py, docs/SCHEMA.md, README.md, tests/test_ratchet.py]

- **Pruning a verification baseline tightens every measured entry in that check.** QF15 removed `qg.py`'s
  dead `# noqa: E402` and ran `python3 -I qg.py check --prune verification`; the prune dropped the resolved
  `exclusions:qg.py:noqa` entry and also raised `tests:tests:executed` from 371 to the measured 400. Keep that
  extra tightening and rerun `make -k check` after the baseline changes; do not hand-revert it to the old
  floor. Use the prune to change an existing bound; a new exception still enters by hand with a reason.
  [verified 2026-10-27 @ d044e1b; paths: qg.py, quality_gate/ratchet.py, quality_gate/verification.py, quality-gate-verification.toml]

- **Copy only the working files for a disposable demo.** `cp -a` of this clone fails on `.git/objects` with
  `preserving permissions ... Invalid argument` and leaves a partial copy. Copy the files the command needs
  with `cp -R --no-preserve=mode,ownership`, or exclude `.git`; the read-only `.git` is not needed there.
  [verified 2026-10-27 @ d044e1b; paths: none]
