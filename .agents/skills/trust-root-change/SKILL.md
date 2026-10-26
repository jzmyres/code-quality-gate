---
name: trust-root-change
description: Checklist for changing the gate's trust root, protected inputs, baseline merge, prune or run identity.
verified: 2026-10-26
commit: 0bb2521
paths: quality_gate/trust.py, quality_gate/covrun.py, quality_gate/checks.py, quality_gate/tools.py, docs/TRUST.md, tests/test_trust.py, quality-gate.toml
---

# Changing the trust root

`--policy-from` treats the candidate working tree as untrusted. A green `make -k check` does not prove trust
closure: the suite does not try a candidate that lies about Git objects or races the after-run identity, so probe
the adversarial paths before calling a trust change done. Use this for `quality_gate/trust.py`, `covrun.py`,
`[protect]` or identity/prune changes.

1. **Read the contract.** `docs/TRUST.md` defines protected inputs, statuses, the baseline merge and identity;
   `docs/SCHEMA.md` has the `trust` result and exit codes. `tests/test_trust.py` builds fixture repositories with
   `git init`; follow its helpers.
2. **Trusted Git reads go through `trust._git`.** It runs `git --no-replace-objects -c safe.directory=ROOT -c
   core.fsmonitor=false -C ROOT`, and blobs are read with `git cat-file blob`. `_refuse_graft` runs before the
   revision is read. A new bare `git` call loses replacement-ref and fsmonitor isolation.
3. **Candidate reads are regular files.** `_read_regular` opens with `O_NOFOLLOW|O_NONBLOCK` and requires `fstat`
   to report a regular file; `_candidate_parent` rejects a symlinked parent. `Path.read_text()` follows symlinks
   and can block on a FIFO; do not use it for a protected input.
4. **Respect metric direction in the merge.** `_merge_revision_entry` keeps a trusted `min` floor when the
   candidate omits it, applies a candidate removal only for `max`, and preserves every trusted entry when the
   candidate baseline cannot be parsed. A merge that parses a bad candidate as empty or drops floors loosens the
   ratchet.
5. **Identity and prune.** `_capture_identity` runs before and after and includes ignored untracked files. Only the
   gate's prune write may change a protected input, and `_prune_exemption` currently exempts the whole path:
   compare the exact content the gate generated, not the path, and never widen the exemption. The final review
   reproduced a floor weakened before prune and accepted.
6. **Child processes carry effective inputs.** `covrun.py` starts a coverage verifier through `_VERIFY_INSTALL` and
   `subprocess.run`; that child imports `quality_gate.tools` and loads the bundled lock, so under `--policy-from`
   or an authorized lock it can disagree with the parent. Pass the effective coverage descriptor and lock
   explicitly, keep the measured interpreter free of `quality_gate` (QF7), and do not copy the direct
   `subprocess.run` verifier: it bypasses `quality_gate/runner.py` and the effective lock.
7. **Probe the cases.** Cover a replacement ref (`git replace A B`, checked with `git --no-replace-objects
   show A:FILE`), an `info/grafts` file, a candidate that omits a `min` floor, a malformed candidate baseline, a
   protected symlink, FIFO and symlinked parent, a prune through a symlinked parent, and a protected file created
   during a check. Run
   `python3 -I -m unittest discover -s tests -p 'test_trust.py'`, then `make -k check`.
