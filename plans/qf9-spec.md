# QF9: the trust root cannot be redirected by the candidate

Repository: `~/code-quality-gate`. Work only in the clone `~/code-quality-gate/.worktrees/qg1`. Read
`CLAUDE.md`, `docs/TRUST.md`, `README.md` (the trust root, `--policy-from`, `[protect]`, `--prune`),
`quality_gate/trust.py`, `quality_gate/ratchet.py` (`subject_direction`, `tighter_bound`), `quality-gate.toml` and
`quality-gate-verification.toml`, `tests/test_trust.py`, and the review record
`plans/review-astra-gate-2026-10-26-partial.md` first.

Why (Astra's review of M2b, 2026-10-26, verified by Claude): `--policy-from REV` reads the trusted policy from the
candidate's own repository. The candidate controls that repository's refs, config and files, and four paths let it
weaken the policy while the result still names the trusted revision.
- **Replacement refs.** Claude reproduced this in a scratch repository: after `git replace A B`,
  `git rev-parse A^{commit}` still prints A, but `git show A:policy` prints B's content.
  `git --no-replace-objects show A:policy` prints A's.
- **Dropped baseline entries.** `_merge_entries` drops every trusted entry the candidate leaves out. That is
  tightening for a maximum (an allowance), but a minimum such as `tests:...:executed` (a floor, M2c) is loosened.
  A malformed candidate baseline is parsed as an empty list (`trust.py:362-375`), which drops every trusted
  entry while reporting `ignored`.
- **Symlinks.** Protected reads follow symlinks (`trust.py:188`), so a protected path linked to a FIFO hangs the
  read. Prune writes can follow a symlinked parent directory out of the candidate.
- **Frozen identity.** The after-run identity check revisits only the paths enumerated before execution, and
  that enumeration skips ignored untracked files. A protected path created during the checks goes unseen.

## Changes

1. **Trusted git reads ignore candidate redirection.** Every git command in `trust.py` runs with
   `--no-replace-objects` and `-c core.fsmonitor=false`. Blobs are read with `git cat-file blob`, which applies no
   textconv or filter. The trust root refuses, with a message naming the file, a candidate repository that has a
   graft file (`info/grafts` under the git directory).
2. **Removal never loosens a floor.** In the baseline merge, a trusted entry whose direction is `min` is kept with
   its trusted bound when the candidate omits it. Removal still tightens a `max` entry. A malformed candidate
   baseline keeps every trusted entry unchanged, and its status stays `ignored` with the parse error. The
   verification baseline's header no longer says pruning only lowers bounds: it states the rule per direction.
3. **Protected files are regular files inside the candidate.** A protected path that is a symlink, is not a regular
   file, or has a symlink among its parent components inside the candidate is refused with a message naming it,
   before anything is read. Reads open without following symlinks and without blocking (`O_NOFOLLOW`,
   `O_NONBLOCK`, then `fstat` must say regular file). Prune writes go only to a regular file reached the same way.
4. **Identity is re-enumerated after the run.** The protected scope is enumerated before and after execution,
   including ignored untracked files. A path added, removed or changed under it is reported in the identity
   record and fails the run, with the paths named.
5. **A fixed digest oracle.** A test pins the payload digest of a small fixture tree to a literal value. The tree
   covers file ordering, a non-ASCII name, a directory, a symlink and an executable bit, so a change to the
   digest encoding fails the test.

## Tests

Write each test failing first: a replacement ref and a graft file; a candidate that omits a floor entry; a
malformed candidate baseline; a protected symlink, a FIFO and a symlinked parent (the FIFO test must finish in a
second); a prune through a symlinked parent; a protected file created during a check; and the digest oracle. Each
must pass after the change.

## Docs

`docs/TRUST.md` (what the trust root ignores and refuses), README where it describes `--policy-from` and pruning.
Commit label `fix (the trust root cannot be redirected by the candidate)`.

ACCEPT: make -k check
