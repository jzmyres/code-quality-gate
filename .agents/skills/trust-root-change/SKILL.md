---
name: trust-root-change
description: Checklist for changing the gate's trusted directory, protected inputs, baseline merge or run identity.
verified: 2026-11-04
commit: e7bb45595b63
paths: docs/TRUST.md, docs/SCHEMA.md, quality-gate.toml, quality_gate/trust.py, quality_gate/cli.py, quality_gate/files.py, quality_gate/gate_result.py, quality_gate/checks.py, quality_gate/policy.py, quality_gate/covrun.py, quality_gate/payload.py, quality_gate/tools.py, quality_gate/worklist.py, tests/test_trust.py, tests/test_ratchet.py, tests/test_verification.py, tests/test_inventory.py
---

# Changing the trust root

`--policy-from DIR` is the only trust mode: a caller-extracted, read-only tree outside the candidate, read
with plain file reads. QF115 deleted the revision reader, `--changed-from` and the gitlink comparison; QF116
refuses `--prune` with `--policy-from`. A green `make -k check` does not prove trust closure: the suite covers
the probes below, but a new trust path needs its own adversarial test. Use this for `quality_gate/trust.py`,
`cli.py`, `[protect]`, identity or baseline-merge changes.

1. **Read the contract.** `docs/TRUST.md` defines protected inputs, statuses, the baseline merge, the
   directory and identity; `docs/SCHEMA.md` has the `trust` result and exit codes. `tests/test_trust.py`
   builds fixture repositories and extracts a trusted directory with `trusted_directory`; follow its helpers.
   `prepare_trust` resolves the candidate root, calls `_refuse_inside` so a gate program inside the candidate
   is refused, then `_directory_source`: it requires an absolute path, resolves it, refuses a missing path, a
   non-directory and a directory inside the candidate. A relative path or revision is "expected an absolute
   trusted directory". With `--policy-from`, `cli._run_trusted_check` calls `_reject_partial_options`, which
   refuses `--only` with `--prune` or `--policy-from`, then refuses `--prune`, all before `prepare_trust`;
   the trusted check writes nothing into the candidate. If a check depends on a configuration file, add that
   file to `[protect] paths` and pass it explicitly (Ruff uses `--config ruff.toml`); otherwise a candidate
   changes tool behavior without touching a protected input.
2. **One Git policy, no trusted input from the candidate's `.git`.** `files.git_argv` builds every command the
   gate runs on a candidate repository: `git --no-replace-objects -c safe.directory=ROOT -c
   core.fsmonitor=false -C ROOT`; `trust._git`, `files._git` and `gate_result._git` call it, and `checks` and
   `worklist` use it directly for inventory/hygiene argv, pack/clone and churn. `trust._TrustedTree` reads
   `DIR` with no Git command; candidate inventory still runs `git ls-files`. A new bare `git` call or a
   hand-built argument list loses replacement-ref and fsmonitor isolation.
3. **Candidate and trusted-tree reads are regular files.** `_open_candidate` opens with
   `O_NOFOLLOW|O_NONBLOCK`, and `_read_regular` requires `fstat` to report a regular file;
   `_candidate_parent` rejects a symlinked parent. `Path.read_text()` follows symlinks and can block on a FIFO;
   do not use it for a protected input. `trust._TrustedTree` uses `_safe_join` and the same
   `O_NOFOLLOW|O_NONBLOCK` open, follows no symlink (a symlink reads as missing), walks no symlinked directory,
   caches only successful reads, and `digest()` hashes each read path, a NUL and the file SHA-256 in sorted
   order. `Trust.to_json` reports the directory path and that digest, never `policy_from`.
4. **Use the subject's direction everywhere.** `load_baseline` and `evaluate` both set each
   `BaselineEntry.direction` with `ratchet.subject_direction`, which asks the adapter's
   `entry_direction(subject, configured)`, then its `default_direction`, then the policy's `direction`.
   `_evaluate_finding` asks the same rule before choosing `_min_verdict` or `_max_verdict`, and
   `_merge_revision_entry`/`_prune_entry` read `entry.direction` rather than asking the adapter again. A merge
   or prune that recomputed direction locally, or dropped a floor, loosens the ratchet (QF44).
   `_merge_revision_entry` keeps a trusted `min` floor when the candidate omits it, applies a candidate
   removal only for `max`, and preserves every trusted entry when the candidate baseline cannot be parsed.
   The merged tuple goes on `CheckDef.effective_baseline`; `checks._baseline_entries` returns it first, and no
   check passes a baseline path to a child process. An authorized policy's new baseline is read from the
   candidate, but still validated before the checks. `_apply_baselines` reads a baseline named in
   `--allow-protected` whole from the candidate (`_required_candidate_entries`); any other changed baseline
   is merged entry by entry, so a tightening applies and a loosening is ignored.
5. **Identity and no trust writes.** `_capture_identity` runs before the checks and records `revision` (the
   `DIR` path), `protected` file SHA-256 pairs, `effective_inputs` (policy, lock, tool pins and each effective
   baseline digest), `tools` and `gate`. There is no revision or gitlink variant left: `_capture_identity`
   always uses `_tree_protected_identity`, and `Trust.finish` records `identity_after` and compares it with
   `_identity_problems`. Any protected or effective input, tool payload or gate file that changes during the
   run makes the decision `error` (exit 2) naming it. `prepare_trust` cleans up its two temporary trees
   when `_prepare_source` raises, so a failed preparation leaves no `qg-tree-*` or `qg-merge-*` directory
   (`PreparationCleanupTests`). `--prune` and `--only` with `--policy-from` are usage errors before
   the checks, and `_write_pruned` is the plain path used only without trust; do not reintroduce a trust
   prune write, an identity exemption or `Config.prune_paths`.
6. **Child processes carry effective inputs.** `covrun.py` gets the effective coverage directory, version,
   payload digest, gate-owned coverage config and registry directory as arguments and loads the
   standard-library `payload.py` by file path, so the measured interpreter never imports `quality_gate` (QF7).
   Do not move that verifier into the package import graph or start a nested verifier interpreter.
   `payload.PayloadError` is a plain exception, not a `GateError`; each caller that reads a payload catches it
   at its own boundary and converts it to that boundary's error; `tools._build_install` raises `UsageError`
   (exit 2) for an unreadable build tree, and `command_tools_fetch` returns `error.exit_code`.
7. **Probe the cases.** Cover a loosened and a tightened baseline, a candidate that omits a `min` floor, a
   malformed candidate baseline, a protected file that is blocked or authorized, a protected symlink, FIFO and
   symlinked parent, a protected file created or changed during a check, an authorized policy and lock, a
   replaced object in the candidate store (the directory still wins), a candidate `ruff.toml` that weakens
   lint, a candidate repository with `core.fsmonitor` set (record it with a marker file), a missing directory
   and one inside the candidate, `--policy-from` with a relative path, `HEAD` and a commit id (exit 2), the
   unknown `--changed-from`, and a symlinked policy or protected file inside `DIR` (not followed). Cover the
   prune and partial refusals with `--prune ID --policy-from DIR` and `--only ID --policy-from DIR`: exit 2,
   both names in stderr, no check line printed, and every candidate file byte-identical. Run `python3 -I -m unittest discover -s tests -p 'test_trust.py'` and the same for
   `test_inventory.py`, then `test_verification.py`/`test_ratchet.py` when the merge or identity changes; the
   owner runs the full gate and mutation.
8. **Deleting a trust feature.** Delete the feature's `tests/mutate_gate.py` `Decision`, the tests that
   reached it, and every doc/result field only it set; then grep outside `.agents` for each named symbol.
   Replace its tests with directory-form tests that still reach and kill the remaining trust decisions. For a
   new refusal, remove the guard in a disposable copy and confirm the refusal test fails at the guard
   assertion, not at a later symptom.
