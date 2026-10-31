# The trust root: `qg check --policy-from REV`

A gate that reads its policy, baselines and tool lock from the tree it is
checking cannot measure that tree honestly: the same working tree can weaken
the policy, add a baseline exception, raise a threshold, remove a check, change
a tool pin, narrow test discovery or edit a script a check executes. The trust
root makes the enforcement inputs come from a revision the candidate cannot
change.

```
python3 -I qg.py check --policy-from REV
python3 -I qg.py check --policy-from REV --allow-protected PATH
```

`REV` is any Git revision that resolves to a commit. `--allow-protected` is
repeatable and requires `--policy-from`.

## Parties

* The **candidate** is the working tree being checked. It is untrusted.
* The **trusted revision** `REV` is a commit chosen by the caller outside the
  candidate: a runner passes the batch's base commit, and a person passes the
  commit they reviewed. The gate resolves it to a commit id and reports that id
  as `trust.policy_from`.
* The **gate program** is trusted only when it runs from a copy the candidate
  cannot modify. With `--policy-from`, the gate refuses to run (exit 2) when
  its own program files lie inside the candidate root, naming both paths. Run a
  trusted copy instead: for a consumer, `REV`'s pinned submodule commit
  extracted outside the candidate; for this repository, `REV` itself.

Without `--policy-from`, nothing changes. A developer checking their own tree
trusts that tree.

## Protected inputs

For every `--policy-from` run, the protected inputs are, in `REV`:

* the policy file, `quality-gate.toml`;
* every baseline file the policy names;
* the tools lock, `tools.lock.toml` at the candidate root; and
* every path or glob listed in `REV`'s policy under `[protect] paths`, for
  example the pinned gate submodule, `ruff.toml`, `Makefile`, CI workflows,
  or a test runner such as `tests/run_tests.py`:

  ```toml
  [protect]
  paths = ["code-quality-gate", "ruff.toml", "Makefile", ".github/workflows/*.yml", "tests/run_tests.py"]
  ```

This repository's own policy protects `ruff.toml`, and its Ruff check names
that file with `--config ruff.toml`, so a discovered configuration file
elsewhere cannot change lint policy.

A literal path is protected whether or not it exists. A glob is matched against
the union of `REV`'s files and gitlinks and the candidate's tracked and
untracked paths, so a new candidate path under a protected glob is a protected
input too. The protected list always comes from `REV`; a candidate policy
cannot unprotect a path.

`REV`'s file contents are read from Git objects (`git cat-file blob`), and its
gitlink commits from its tree, never from the working tree. Every Git command
the trust root runs ignores replacement refs (`--no-replace-objects`) and
candidate-configured fsmonitors, and a candidate repository with a graft file
(`info/grafts` under its Git directory) is refused. Candidate versions are
read from the working tree only to compare them with `REV`, to apply an
allowed tightening, or after the caller authorizes the path.

For a protected gitlink, the candidate's value is the commit in its index. If
the submodule is checked out, its HEAD must also match that index commit. A
missing or empty uninitialized checkout is allowed. A directory containing
other files without a submodule checkout is a directory, and an unreadable
checkout or unresolved index is refused. A gitlink on one side and a file,
directory or missing path on the other is a protected change; the result and
text report name both kinds. A file or directory in the worktree cannot hide
a staged gitlink either. These changes have the same `blocked` and
`--allow-protected` behavior as other protected paths. Protecting the pinned
gate path prevents an unreviewed change from becoming the next trusted gate.

A protected file in the candidate must be reached without following a symlink:
a symlink, a FIFO or another non-regular file, or a symlink among the path's
parent components inside the candidate, is refused (exit 2) with a message
naming the path before anything is read. A directory is reported as a changed
kind when compared with a gitlink; otherwise the regular-file rule still
applies.

## Effective inputs

Before any candidate check command runs, the gate validates and fixes the
effective policy, tool pins and every baseline in its own process. The merged
baseline entries, including an authorized replacement or a baseline introduced
by an authorized policy, are held in memory and supplied directly to the
checks. Candidate commands cannot change the entries by editing a temporary
file or the original baseline. No baseline file is passed to a child process.

Python coverage collection uses a gate-owned configuration file. After the
tests, the gate opens it without following symlinks or blocking, requires a
regular file and compares its contents with the canonical settings in a worker
bounded by the check's remaining deadline. A difference or non-regular file is a
configuration error. Coverage combination and CRAP analysis use the canonical
settings passed as data, even if the file changes after that comparison.

For each protected input whose candidate content differs from `REV`:

### Baseline files

Baselines tighten only:

* a candidate removal takes effect for a `max` entry, and is ignored for a
  `min` floor: the removed entry keeps `REV`'s bound;
* an entry whose bound the candidate tightens takes effect (a lower `max`
  bound or a higher `min` bound, with an earlier expiry);
* an entry the candidate adds, a bound it loosens, an expiry it later removes,
  reasons it changes and metadata it changes are ignored, and `REV`'s entry is
  used;
* a candidate baseline that cannot be parsed is ignored in full, and every
  `REV` entry is used unchanged.

Each entry and finding use the same `max` or `min` direction for their
subject. The adapter's per-subject rule, descriptor default or check's
configured `direction` decides it, including before any finding exists.

The entry set used for the run is therefore `REV`'s entries with candidate
removals of `max` entries and tightened bounds applied. The entries whose
candidate form was ignored, including a removed `min` floor, are listed in the
protected input's `ignored_entries`. A baseline that only tightens is
`tightened`; one whose differences were all ignored is `ignored`; identical
content is `unchanged`.

### Authorized paths

When the caller passes `--allow-protected PATH` (a reviewed spec authorizes
it), the candidate's version of that path is used and reported as
`authorized`. This applies to the policy file, a baseline, the tools lock and
any `[protect]` path. For a protected baseline it uses the candidate's entries
as written; the candidate is then the reviewed replacement.

### The policy file and the tools lock

Unauthorized changes to the policy file and the tools lock are ignored:
`REV`'s version is used. The checks therefore run `REV`'s checks, thresholds,
classes, exemptions and pinned tool set, not the candidate's. The protected
entry is reported as `ignored`.

An authorized lock is the effective lock for the whole run. The coverage
adapter passes that lock's coverage version and payload digest to each coverage
invocation, and the invocations verify the install against them with the same
payload encoding before importing it. An authorized coverage upgrade therefore
does not fall back to the bundled pin.

### Any other protected path

An unauthorized change to any other protected path makes the decision
`blocked` (exit 1), naming the path in the result and on stderr. The gate
cannot substitute `REV`'s version of a file another program reads or executes
(for example Ruff's configuration or a test runner), so it refuses to accept
the run. The checks still run against the candidate and are reported in full.

## Prune under `--policy-from`

`check --prune ID --policy-from REV` writes the effective baseline, which is
`REV`'s baseline tightened by the measurement: a `max` bound is lowered, a
`min` floor is raised. It never adds an entry, loosens a bound, or keeps an
entry that exists only in the candidate. A baseline path whose parent is a
symlink inside the candidate is refused before the write.

The gate validates the run identity after the checks and before this write. A
protected input that changed during the checks fails the run (exit 2) and
nothing is pruned, so a check cannot weaken a baseline and have pruning keep
the weakened value. After the write, the pruned path may differ from its
pre-prune content only by exactly the bytes the gate generated; any other
difference fails the run naming the path. The written content is derived from
`REV` and the measurement, never from the candidate's loosened entries.

## Identity

Before any check runs, the gate records in `trust.identity_before`:

* `REV`'s commit id;
* each protected file's `REV` and candidate SHA-256, or a protected gitlink's
  kinds, `REV` commit, candidate index commit and checked-out HEAD (stored per path);
* the effective policy and tool lock file SHA-256, a digest of the captured
  tool pins, and a digest of each effective baseline held in memory;
* each pinned tool's actual install-tree payload digest (the M2a encoding); and
* a digest and per-file SHA-256 of the gate program's own files
  (`qg.py` and every file under `quality_gate/`, regardless of extension or
  tracking status, except the running interpreter's `__pycache__` directories).

It enumerates the protected scope again after the checks, including ignored
untracked files, and compares those facts before any prune write. Any protected
path added, removed or changed under that scope, any effective input whose
recorded value changed, and any pinned tool payload or gate file that changed
during the run makes the decision `error` (exit 2) with a message naming what
changed, and a requested prune writes nothing. The identity also tracks the
candidate source of a baseline introduced by an authorized policy. Without a
prune write `trust.identity_after` records that same
snapshot; after a performed prune it records the identity captured once more
after the write, where only the pruned path may differ and only by exactly the
bytes the gate generated (see above). A missing tool install is recorded as
`null`; a tree that has no payload digest is recorded as `invalid`; a candidate
path that is refused as a non-regular file or unreadable submodule is recorded
as `refused`.

The `effective_inputs` identity maps `policy quality-gate.toml` and
`tool lock tools.lock.toml` to file SHA-256 values and `tool pins` to the
captured tool definitions' digest. Each `baseline PATH` value is the SHA-256
of UTF-8 JSON containing the check id, metric version, and validated entries
in order, including bounds, reasons, expiry and metadata. JSON object keys are
sorted, separators are `,` and `:`, dates are ISO strings, and non-ASCII text
is encoded directly. The same encoding is used for the `tool pins` digest.

## Result document

A trust run writes result `schema = 3` and adds:

```json
{
  "schema": 3,
  "trust": {
    "policy_from": "8dbb703...",
    "protected": [
      {
        "path": "quality-gate-clones.toml",
        "rev_sha256": "c2a2...",
        "candidate_sha256": "d29f...",
        "status": "tightened",
        "ignored_entries": []
      }
    ],
    "identity_before": {
      "revision": "8dbb703...",
      "protected": {"quality-gate-clones.toml": {"rev_sha256": "c2a2...", "candidate_sha256": "d29f..."}},
      "effective_inputs": {
        "policy quality-gate.toml": "5a37...",
        "tool lock tools.lock.toml": "8c51...",
        "tool pins": "a43d...",
        "baseline quality-gate-clones.toml": "e137..."
      },
      "tools": {"ruff": {"version": "0.17.0", "payload_sha256": "720b..."}},
      "gate": {"digest": "...", "files": {"qg.py": "...", "quality_gate/checks.py": "..."}}
    },
    "identity_after": {}
  }
}
```

`status` is one of `unchanged`, `tightened`, `ignored`, `authorized` or
`blocked`. Only baseline entries carry `ignored_entries`. For a comparison
involving a gitlink, the entry and both identity snapshots use `rev_kind` and
`candidate_kind` (`gitlink`, `file`, `directory`, `missing`, or `refused` in
an identity snapshot), `rev_commit`, `candidate_commit` and `candidate_head`.
The commit values are full Git object IDs; a value is `null` when that side
has no gitlink, and `candidate_head` is `null` when it is not checked out.
A file side also carries its `rev_sha256` or `candidate_sha256`. If the
candidate index contains a gitlink but its worktree path is a file or
directory, `candidate_index_commit` records that staged commit. For example:

```json
{
  "path": "code-quality-gate",
  "rev_kind": "gitlink",
  "candidate_kind": "gitlink",
  "rev_commit": "1111111111111111111111111111111111111111",
  "candidate_commit": "2222222222222222222222222222222222222222",
  "candidate_head": "2222222222222222222222222222222222222222",
  "status": "blocked"
}
```

The text report includes those commits and kinds. The result
`decision` adds `blocked`; exit codes remain `0` for accepted results, `1`
for `rejected`/blocked or a failed prune, and `2` for usage or configuration
errors and an identity change. Without `--policy-from`, the result remains
schema 2 and has no `trust` key.

## Out of scope

* **Evidence produced by test code.** Tests are executed candidate code, and
  the gate trusts their measurements. A Python test process can write a
  coverage dataset that is merged even with the gate-owned configuration. An
  ERT suite runs in the same Emacs as the staged helper and can redefine it or
  write its result file. In-process measurement cannot be protected from the
  process being measured. Review test diffs, use `--changed-from` to reject
  located threshold violations on changed lines, and use mutation testing to
  assess the tests. These mitigations do not make in-process evidence
  tamper-proof.
* **A consumer's pinned gate commit.** The submodule pin is a candidate input
  unless its path is listed or matched by a glob in `REV`'s `[protect] paths`.
  An unprotected pin can change and become the trusted gate in a later run
  whose trusted base contains that change.
* **CI trust.** The workflow file is part of the candidate; branch protection
  and review cover it. A `[protect]` glob can still block an unreviewed change
  to it.
* **Verification loss inside test code.** Deleted tests, added skips and grown
  pragmas are measured by the `verification` adapter (M2c), not by this
  contract; its baseline is protected like every other baseline.
