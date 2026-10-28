---
name: trust-root-change
description: Checklist for changing the gate's trust root, protected inputs, baseline merge, prune or run identity.
verified: 2026-10-28
commit: 76be052
paths: docs/TRUST.md, quality-gate.toml, quality_gate/trust.py, quality_gate/files.py, quality_gate/gate_result.py, quality_gate/checks.py, quality_gate/policy.py, quality_gate/covrun.py, quality_gate/payload.py, quality_gate/tools.py, tests/test_trust.py, tests/test_verification.py
---

# Changing the trust root

`--policy-from` treats the candidate working tree as untrusted. A green `make -k check` does not prove trust
closure: the suite covers the probes below, but a new trust path needs its own adversarial test. Use this for
`quality_gate/trust.py`, `covrun.py`, `[protect]` or identity/prune changes.

1. **Read the contract.** `docs/TRUST.md` defines protected inputs, statuses, the baseline merge and identity;
   `docs/SCHEMA.md` has the `trust` result and exit codes. `tests/test_trust.py` builds fixture repositories with
   `git init`; follow its helpers. If a check depends on a configuration file, add that file to `[protect] paths`
   and pass it explicitly (Ruff uses `--config ruff.toml`); otherwise a candidate changes tool behavior without
   touching a protected input.
2. **One Git invocation policy.** `files.git_argv` builds every command the gate runs on a candidate repository:
   `git --no-replace-objects -c safe.directory=ROOT -c core.fsmonitor=false -C ROOT`; `trust._git`,
   `files._git` and `gate_result._git` call it. Blobs are read with `git cat-file blob`, and `_refuse_graft` runs
   before the revision is read. A new bare `git` call or a hand-built argument list loses replacement-ref and
   fsmonitor isolation.
3. **Candidate reads are regular files.** `_read_regular` opens with `O_NOFOLLOW|O_NONBLOCK` and requires `fstat`
   to report a regular file; `_candidate_parent` rejects a symlinked parent. `Path.read_text()` follows symlinks
   and can block on a FIFO; do not use it for a protected input.
4. **Respect metric direction in the merge.** `_merge_revision_entry` keeps a trusted `min` floor when the
   candidate omits it, applies a candidate removal only for `max`, and preserves every trusted entry when the
   candidate baseline cannot be parsed. A merge that parses a bad candidate as empty or drops floors loosens the
   ratchet. The merged tuple goes on `CheckDef.effective_baseline`; `checks._baseline_entries` returns it
   first, and no check passes a baseline path to a child process. An authorized policy's new baseline is read
   from the candidate, but still validated before the checks.
5. **Identity and prune.** `_capture_identity` runs before the checks and records `protected`,
   `effective_inputs` (policy, lock, tool pins and each effective baseline digest), `tools` and `gate`; when
   a prune is requested, `Trust.before_prune` captures it again after the checks and must find no difference
   in any of those sections before anything is written. `_write_pruned` records exactly the bytes
   `write_baseline` returned with `Trust.record_prune_write`, and `Trust.finish` allows that write to change
   only the path's `candidate_sha256` to the digest of those bytes; every other difference fails the run
   naming the path. Do not reintroduce a path-wide or per-check exemption.
6. **Child processes carry effective inputs.** `covrun.py` gets the effective coverage directory, version and
   payload digest as arguments and loads the standard-library `payload.py` by file path, so the measured
   interpreter never imports `quality_gate` (QF7). Do not move that verifier into the package import graph or
   start a nested verifier interpreter. `payload.PayloadError` is a plain exception, not a `GateError`;
   each caller that reads a payload catches it at its own boundary and converts it to that boundary's error;
   `tools._build_install` raises `UsageError` (exit 2) for an unreadable build tree, and `command_tools_fetch`
   returns `error.exit_code`.
7. **Probe the cases.** Cover a replacement ref (`git replace A B`, checked with `git --no-replace-objects
   show A:FILE`), an `info/grafts` file, a candidate that omits a `min` floor, a malformed candidate baseline,
   a protected symlink, FIFO and symlinked parent, a prune through a symlinked parent, a protected file created
   during a check, a check that rewrites an authorized baseline then requests a prune, a candidate `ruff.toml`
   that weakens lint, and a candidate repository with `core.fsmonitor` set (record it with a marker file). Run
   `python3 -I -m unittest discover -s tests -p 'test_trust.py'`, then `make -k check`.
