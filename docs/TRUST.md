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
  example `ruff.toml`, `Makefile`, CI workflows, or a test runner such as
  `tests/run_tests.py`:

  ```toml
  [protect]
  paths = ["ruff.toml", "Makefile", ".github/workflows/*.yml", "tests/run_tests.py"]
  ```

A literal path is protected whether or not it exists. A glob is matched against
the union of `REV`'s files and the candidate's tracked and untracked files, so
a new candidate file under a protected glob is a protected input too. The
protected list always comes from `REV`; a candidate policy cannot unprotect a
path.

`REV`'s versions of protected inputs are read from Git objects
(`git cat-file`), never from the working tree. Candidate versions are read
from the working tree only to compare them with `REV`, to apply an allowed
tightening, or after the caller authorizes the path.

## Effective inputs

For each protected input whose candidate content differs from `REV`:

### Baseline files

Baselines tighten only:

* an entry the candidate removes takes effect;
* an entry whose bound the candidate lowers takes effect (the lower bound and
  an earlier expiry are used);
* an entry the candidate adds, a bound it raises, an expiry it later removes,
  reasons it changes and metadata it changes are ignored, and `REV`'s entry is
  used;
* a candidate baseline that cannot be parsed is ignored in full, and `REV`'s
  baseline is used.

The entry set used for the run is therefore `REV`'s entries with candidate
removals and lower bounds applied. The entries whose candidate form was ignored
are listed in the protected input's `ignored_entries`. A baseline that only
tightens is `tightened`; one whose differences were all ignored is
`ignored`; identical content is `unchanged`.

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

### Any other protected path

An unauthorized change to any other protected path makes the decision
`blocked` (exit 1), naming the path in the result and on stderr. The gate
cannot substitute `REV`'s version of a file another program reads or executes
(for example Ruff's configuration or a test runner), so it refuses to accept
the run. The checks still run against the candidate and are reported in full.

## Prune under `--policy-from`

`check --prune ID --policy-from REV` writes the effective baseline, which is
`REV`'s baseline lowered by the measurement. It never adds an entry, raises a
bound, or keeps an entry that exists only in the candidate. The gate's own
prune write to that one baseline is the only protected-input change the
after-run identity permits; the written content is derived from `REV` and the
measurement, never from the candidate's weakened entries.

## Identity

Before any check runs, the gate records in `trust.identity_before`:

* `REV`'s commit id;
* each protected input's `REV` and candidate SHA-256 (stored per path);
* each pinned tool's actual install-tree payload digest (the M2a encoding); and
* a digest and per-file SHA-256 of the gate program's own files
  (`qg.py` and every Python module under `quality_gate/`).

It records the same facts after the checks as `trust.identity_after`. Any
protected input, pinned tool payload or gate file whose recorded value changed
during the run makes the decision `error` (exit 2) with a message naming what
changed. A missing tool install is recorded as `null`; a tree that has no
payload digest is recorded as `invalid`. The gate's own prune write to the
pruned baseline is exempt, as described above.

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
      "tools": {"ruff": {"version": "0.17.0", "payload_sha256": "720b..."}},
      "gate": {"digest": "...", "files": {"qg.py": "...", "quality_gate/checks.py": "..."}}
    },
    "identity_after": {}
  }
}
```

`status` is one of `unchanged`, `tightened`, `ignored`, `authorized` or
`blocked`. Only baseline entries carry `ignored_entries`. The result
`decision` adds `blocked`; exit codes remain `0` for accepted results, `1`
for `rejected`/blocked or a failed prune, and `2` for usage or configuration
errors and an identity change. Without `--policy-from`, the result remains
schema 2 and has no `trust` key.

## Out of scope

* **CI trust.** The workflow file is part of the candidate; branch protection
  and review cover it. A `[protect]` glob can still block an unreviewed change
  to it.
* **Verification loss inside test code.** Deleted tests, added skips and grown
  pragmas are M2c, not this contract.
