# Schema reference (version 2, with trust result version 3)

This is the authoritative contract for the gate's policy, baseline and result
formats. The files in `plans/` are historical records; where they disagree with
this document, this document wins. The trust-root semantics behind
`--policy-from` are specified in [`TRUST.md`](TRUST.md).

Version 2 is a breaking change from version 1: policy files declare
`schema = 2`, result documents declare `schema = 2`, baselines begin with the
check identity header, and the result separates execution, the adapter's raw
outcome and policy satisfaction. A result produced with `--policy-from` adds a
`trust` object and declares `schema = 3`; a result without it remains version
2 and has no `trust` key.

## Policy: `quality-gate.toml`

```toml
schema = 2

[code]
patterns = ["*.py"]
shebangs = ["python*"]

[hygiene]
max_bytes = 10485760          # optional

[levels]
required_tiers = [1]          # optional; must contain 1

[classes.python]
code = true
description = "Python programs"
checks = ["ruff", "clones", "tests", "crap"]

[classes.config]
code = false
description = "Configuration"

[checks.ruff]
adapter = "command"
tier = 1
enforcement = "enforced"
run = ["{tool:ruff}", "check", "--no-cache", "{files}"]
budget_seconds = 600          # optional
must_match = "Success"        # optional

[checks.clones]
adapter = "clones"
tier = 1
enforcement = "enforced"
min_tokens = 50               # optional
baseline = "quality-gate-clones.toml"

[checks.tests]
adapter = "python_tests"
tier = 1
enforcement = "enforced"
run = ["{python}", "-m", "unittest", "discover", "-s", "tests"]
tests_pattern = "^Ran (\\d+) tests? in"   # required; one capture group
skipped_pattern = "skipped=(\\d+)"        # optional; one capture group
budget_seconds = 900          # optional

[checks.legacy-tests]
adapter = "elisp_tests"
tier = 1
enforcement = "enforced"
suite = "tests/config-tests.el"     # required repository-relative regular file
load_path = ["lisp", "emacs/lisp"]  # optional repository-relative directories
emacs = "emacs"                     # optional command or path
budget_seconds = 900                # optional

[checks.compile]
adapter = "elisp_compile"
tier = 1
enforcement = "enforced"
load_path = ["lisp", "emacs/lisp"]  # optional repository-relative directories
emacs = "emacs"                     # optional command or path
budget_seconds = 900                # optional

[checks.checkdoc]
adapter = "elisp_checkdoc"
tier = 1
enforcement = "enforced"
load_path = ["lisp", "emacs/lisp"]
emacs = "emacs"
budget_seconds = 900

[checks.crap]
adapter = "python_crap"
tier = 1
enforcement = "enforced"
requires = "tests"            # an earlier python_tests check
threshold = 6                 # optional; finite
baseline = "quality-gate-crap.toml"

[checks.legacy-crap]
adapter = "elisp_crap"
tier = 1
enforcement = "enforced"
requires = "legacy-tests"     # an earlier elisp_tests check
threshold = 6                 # optional; finite
baseline = "quality-gate-crap-legacy.toml"

[checks.verification]
adapter = "verification"
tier = 1
enforcement = "enforced"
requires = "tests"            # optional; defaults to every earlier test-producing check
baseline = "quality-gate-verification.toml"

[protect]                     # optional; used only with --policy-from
paths = ["ruff.toml", "Makefile", ".github/workflows/*.yml"]

[[not_applicable]]
class = "python"
tier = 2
reason = "tier 2 has no adapter yet"

[[rule]]
pattern = "*.py"
class = "python"
reason = "Python source"
```

Rules:

* `schema = 2` is mandatory. Unknown keys are configuration errors.
* `tier` is an integer from 1 to 4. `enforcement` is `enforced` or
  `advisory`. `direction` is `max` (the default) or `min`: a `max`
  metric's value must not exceed its bound and tightening lowers the bound,
  while a `min` metric's value must not fall below its bound and tightening
  raises it.
* A command's `run` is an argument list; no element may contain NUL.
  `{files}` expands to the sorted selected files, with a leading `./` when a
  path begins with `-`. `{tool:NAME}` expands to a pinned tool binary.
* `python_tests` requires a one-group `tests_pattern`; `skipped_pattern` is
  optional, has one group, and is only valid with `tests_pattern`. Both are
  searched with `re.MULTILINE` over combined stdout and stderr.
* The `{python}` token expands to the gate's `covrun.py` under the current
  interpreter with a fresh data directory, the source root, the pinned coverage
  install, the gate-owned coverage configuration path and the registry
  directory.
* A command check may also declare `tests_pattern` and `skipped_pattern`.
  It then has `tests` evidence and counts executed tests the same way:
  `executed = ran - skipped`, and zero executed tests fail.
* `python_crap.requires` names an earlier `python_tests` check. Anything else
  is a configuration error.
* `elisp_crap.requires` names an earlier `elisp_tests` check. Every file selected
  for CRAP must belong to a class that also lists that test check.
* `elisp_crap.decision_rules` is an optional table overriding the
  [Emacs Lisp default decision rules](../README.md#emacs-lisp-crap). Its only keys
  are `branch`, `operands`, `cond`, `bindings`, `handlers`, `case`, `loop`,
  `loop_clauses` and `catch_all`. Each value is an array of non-empty, printable
  symbol-name strings without whitespace. A supplied array replaces that list;
  omitted lists retain their defaults and empty arrays are allowed. The first
  seven keys select forms for the corresponding counting algorithms; a form
  must occur in only one of those families. `loop_clauses` selects top-level
  conditional loop keywords, and `catch_all` selects final clause heads exempt
  from `cond` and `case` clause counts (default `t`, `_`, `otherwise`). Entries
  must be unique within each array; auxiliary lists may overlap form families.
  Unknown keys, wrong types, invalid names and duplicate assignments are
  configuration errors naming the key and offending entry. For example,
  `decision_rules = { branch = ["if", "my-branch"] }` replaces the entire
  branching list with those two forms, retaining every other default list.
  Without this key, scores are unchanged.
* `elisp_compile` and `elisp_checkdoc` select files from the classes listing
  them. Their optional `load_path` entries are repository-relative directories;
  `emacs` is a command or path and `budget_seconds` is a positive integer.
  The defaults are no load paths, `emacs`, and 900 seconds. An empty selection
  fails.
* `verification.requires`, when present, names an earlier test-producing
  check: a check whose parsed evidence includes `tests` (`python_tests`,
  `elisp_tests`, or `command` with `tests_pattern`). Without it the adapter
  uses every earlier check with that evidence. A reference to a check that
  produces no tests is a configuration error naming its id and adapter;
  for a command it also identifies the missing `tests_pattern`.
* A baseline path must be used by exactly one check. Two checks naming the
  same resolved path is a configuration error.
* Every class named by a rule and every check named by a class must exist.
  Every code class must list at least one check.
* `[[not_applicable]]` entries are the explicit, reasoned exemption for a
  class and required tier. A missing entry is an unsatisfied obligation, not a
  configuration error.
* `[protect]` has one optional key, `paths`, a list of repository-relative
  paths or `fnmatch` globs. It is the caller's protected-input list for
  `check --policy-from DIR`; without that option it is parsed and ignored. The
  list used by a trust run always comes from `DIR`.

### Evidence and obligations

Each adapter's parser declares the evidence for the configured check.
The same `tests` evidence identifies producers for verification and its
`requires` validation, and for evidence obligations:

| Adapter | Evidence |
|---|---|
| `command` without `tests_pattern` | `static` |
| `command` with `tests_pattern` | `tests` |
| `python_tests` | `tests` |
| `elisp_tests` | `tests` |
| `elisp_compile` | `static` |
| `elisp_checkdoc` | `static` |
| `clones` | `duplication` |
| `python_crap` | `crap` |
| `elisp_crap` | `crap` |
| `verification` | none |

A code class has one obligation per required tier:

| Tier | Required evidence |
|---|---|
| 1 | `tests`, from a satisfied enforced check with at least one executed test |
| 2 | `properties` or `fuzzing` |
| 3 | `bounded` |
| 4 | `proof` |

Tier 1 is deliberately transitional in version 2: lint, duplication and CRAP
evidence do not satisfy it, and a policy with only a lint check rejects. Tiers
2-4 name the evidence later adapters (M4/M5) will produce; no version-2 adapter
produces them, so a required tier 2, 3 or 4 must be exempted until its adapter
exists. An unsatisfied obligation rejects the gate.

The `verification` adapter measures verification loss. For each earlier
test-producing check it records `tests:CHECK:executed` (direction `min`,
value `ran - skipped`) and `tests:CHECK:skipped` (direction `max`). For each
selected Python file it records `exclusions:FILE:no-cover` (lines matching the
`pragma: no cover` coverage exclusion), `exclusions:FILE:noqa` (inline `# noqa`
comments), and `exclusions:FILE:file-suppression` (file-wide lint suppression
directives), all `max`. File-wide directives include Ruff's `# ruff: noqa`,
with or without codes, `# ruff: file-ignore[...]`, Flake8's `# flake8: noqa`
forms, and isort's `# isort: skip_file` (also recognized by Ruff). Each directive
contributes one to the file-wide count, separate from the inline count. The lint
directives are recognized in comment tokens using their directive syntax;
matching text inside a string does not count. The file-wide finding's location
includes the first directive and its line. Exclusion locations are numbered at
each `\n` after universal-newline decoding, as Git and the tokenizer number
them, so other Unicode line separators do not shift a later line.

Command producers supply their parsed ran and skipped counts through the same
normalized count fields as the test adapters. A missing or unmatched summary
leaves verification's counts unmeasured, never zero.

Test counts do not depend on Python files being selected: an empty selection
scans no suppressions, while no valid producer result means no measured
counts and makes the check unsupported.

These verification `max` metrics have threshold 0, so a missing baseline entry
accepts only 0; a `min` metric without an entry is unmeasured and fails until an
entry exists. A file-wide suppression needs its own baseline entry with a
non-empty reason, and the entry resolves when the count returns to 0. Replacing
inline `noqa` comments with a file-wide directive therefore still fails unless
the file-wide subject is covered.

## Tool lock: `tools.lock.toml`

Each top-level table names a pinned tool:

```toml
[jscpd]
version = "5.4.1"
url = "https://example.invalid/jscpd.tar.gz"
sha256 = "f2017a17..."          # archive SHA-256
payload_sha256 = "b44982df..."  # install-tree payload digest
binary = "jscpd"                # safe relative path inside the tree
format = "tar"                  # optional; tar or wheel
```

`version`, `url`, `sha256`, `payload_sha256` and `binary` are required;
`format` defaults to `tar`. Unknown keys are configuration errors, as is a
missing, non-string or non-hexadecimal `payload_sha256`. `sha256` is the
SHA-256 of the downloaded archive; `payload_sha256` is the digest of the
installed tree, computed from a fresh install of that archive.

### Payload digest encoding

The payload digest is the SHA-256 of a byte string built from every entry
under the install directory, excluding the directory itself. Relative paths
are POSIX paths relative to the install directory; there is no leading slash
and no `.` component. Entries are sorted by relative-path string (Unicode code
point order), independent of directory traversal order. Symbolic links are
recorded, never followed.

For each entry, in sorted order, append one line: the compact JSON encoding of
an array (separators `,` and `:`, standard JSON escaping) followed by one
line feed. The arrays are:

* regular file: `["file", PATH, EXECUTABLE, CONTENT_SHA256]`
* directory: `["directory", PATH]`
* symbolic link: `["symlink", PATH, TARGET]`

`EXECUTABLE` is the string `"1"` when any execute bit (mode `0o111`) is set
and `"0"` otherwise. `CONTENT_SHA256` is the lowercase hexadecimal SHA-256 of
the file's bytes. `TARGET` is the link target text exactly as stored on the
filesystem. The resulting digest is lowercase hexadecimal. A tree containing
any other entry type (for example a FIFO, socket or device) is invalid and has
no payload digest.

## Baseline files

Baseline entries and findings use the same direction for each subject: the adapter descriptor's
`entry_direction(subject, configured)` rule, then its `default_direction`, then the policy's
configured `direction`. Loading, merging, evaluation and pruning all use this rule. Verification's
executed-test subjects remain minimum floors even under a maximum default.

A baseline is a TOML file with an identity header and zero or more entries:

```toml
check = "clones"
metric_version = "jscpd-clone-occurrences/1"

[[entry]]
subject = "76c7cbddc2677be2"
bound = 1
files = ["src/a.el", "src/b.el"]   # adapter metadata; preserved by prune
reason = "the two front ends deliberately mirror each other"
expires = 2026-12-31
```

* `check` and `metric_version` are mandatory and must match the policy's
  check id and metric version. A missing or mismatched header is a
  configuration error; migration is a hand edit of the baseline.
* `subject` is the measured thing. Adapters use clone fingerprints, Python
  function identities such as `PATH:Qualified.name`, `PATH:<lambda@LINE>`
  for a lambda outside every function, or `PATH:<module>` for code outside
  every function.
* `bound` must be finite and is compared unrounded. For a `max` metric it
  is the largest accepted value; for a `min` metric it is the smallest. Exactly
  at the bound passes.
* `reason` must be non-empty. An empty reason fails even when the value is
  within the bound.
* `expires` is an optional TOML date. A date equal to today still covers
  today; only a date before today expires.
* Each extra metadata key declared by the adapter descriptor (for example clone
  `files`) is a list of strings and is preserved by `--prune`. Empty-reason
  diagnostics list present, nonempty extras in the descriptor's declared order.
* An absent baseline means no exception is accepted. An existing file with
  only the header is allowed. A `max` metric without an entry passes at or
  below its threshold. A `min` metric needs an entry: without one it is
  unmeasured and fails.

Resolution requires a complete scan. An adapter reports the subject domain it
measured completely (the selected files for CRAP; for clones, the selected
files each entry's `files` metadata names). A `max` entry in that domain
resolves when its subject was not found above the threshold; prune drops it. A
measured `min` entry never resolves by itself; prune raises its floor to the
measured value. Any subject absent from a completely measured domain resolves
and is pruned, whatever its direction. An entry outside the domain is reported
as `unmeasured` and kept; prune never drops it. A clone entry naming a file
deleted from the repository resolves.

## Result: `check --json`

```json
{
  "schema": 2,
  "gate_version": "f1d0810...",
  "revision": "8dbb703...",
  "dirty": false,
  "policy_sha256": "5a3781...",
  "decision": "accepted_with_exceptions",
  "checks": [
    {
      "id": "tests",
      "kind": "check",
      "tier": 1,
      "enforcement": "enforced",
      "adapter": "python_tests",
      "evidence": ["tests"],
      "metric_version": "test-count/1",
      "execution": "completed",
      "outcome": "pass",
      "satisfied": true,
      "duration_seconds": 12.5,
      "budget_seconds": 900,
      "diagnostics": {
        "argv": ["python3", "-I", "...", "-m", "unittest"],
        "exit_code": 0,
        "signal": null,
        "output_bytes": 412,
        "output_tail": "Ran 12 tests in 0.42s\n",
        "output_truncated": false
      },
      "findings": [],
      "resolved_baseline_entries": [],
      "unmeasured_baseline_entries": [],
      "reason": null,
      "location_coverage": "none",
      "measurement": {"tests": 12}
    }
  ],
  "obligations": [
    {
      "class": "python",
      "tier": 1,
      "status": "satisfied",
      "required": ["tests"],
      "checks": ["tests"],
      "reason": null
    }
  ],
  "prune": {
    "requested": [],
    "performed": false,
    "reason": null
  }
}
```

Top-level keys:

* `schema` - `2`, or `3` when a `trust` object is present.
* `gate_version` - the gate's own revision, or `unknown: ...`.
* `revision`, `dirty` - the consumer's HEAD (or null) and worktree state.
* `policy_sha256` - the effective policy file's SHA-256, or null. With
  `--policy-from` and an unauthorized candidate policy, this is the trusted
  directory's policy; an authorized replacement is the candidate's.
* `decision` - `accepted`, `accepted_with_exceptions`, `rejected`,
  `blocked` or `error`.
* `checks` - inventory, hygiene and every configured check, in that order.
* `obligations` - one entry per code class and required tier.
* `prune` - the prune request, whether it was performed and its refusal
  reason.
* `trust` - present only on a `--policy-from` result; see below.
* `error` - present only on a `decision = "error"` document.

### Trust object

A `--policy-from` result adds one `trust` object and declares schema 3:

```json
{
  "schema": 3,
  "trust": {
    "path": "/trusted/tree",
    "digest": "9e12...",
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
      "revision": "/trusted/tree",
      "protected": {
        "quality-gate-clones.toml": {
          "rev_sha256": "c2a2...",
          "candidate_sha256": "d29f..."
        }
      },
      "effective_inputs": {
        "policy quality-gate.toml": "5a37...",
        "tool lock tools.lock.toml": "8c51...",
        "tool pins": "a43d...",
        "baseline quality-gate-clones.toml": "e137..."
      },
      "tools": {
        "ruff": {"version": "0.17.0", "payload_sha256": "720b..."}
      },
      "gate": {
        "digest": "a1b2...",
        "files": {"qg.py": "9c40...", "quality_gate/checks.py": "6842..."}
      }
    },
    "identity_after": {}
  }
}
```

* `path` is the trusted directory and `digest` is a SHA-256 over the trusted
  files the gate read, in sorted path order.
* `protected` has one entry per protected input. `path` is
  repository-relative; `rev_sha256` and `candidate_sha256` are lowercase
  SHA-256 hex or null when the file is absent (in `identity_after`, `refused`
  means the candidate file could not be read safely). `status` is `unchanged`,
  `tightened`, `ignored`, `authorized` or `blocked`. A baseline entry also
  carries `ignored_entries`, the subjects whose candidate entry was ignored.
* `identity_before` and `identity_after` record `DIR`'s path as `revision`,
  each protected input's file SHA-256 values, the effective policy, tool lock,
  tool pins and each in-memory baseline under `effective_inputs`, every pinned
  tool's `payload_sha256` (or null when not installed, or `invalid` when the
  tree has no digest), and the gate program's own per-file SHA-256 values plus
  one combined `digest`. The protected scope is enumerated again for
  `identity_after`, including ignored untracked files, and an added or removed
  path is a difference; a refused candidate path is recorded as `refused`.
  `identity_after` is captured after the checks and, when a prune was
  performed, after that write. A difference in any protected or effective
  input, tool payload or gate file makes the decision `error` (exit 2) naming
  the changed input, and a requested prune writes nothing. The one permitted difference is
  the baseline the gate itself wrote for a performed prune: that path must
  equal exactly the bytes the gate generated, which is the trusted baseline
  tightened by the measurement.

Check keys:

* `id`, `kind` (`inventory`, `hygiene` or `check`), `tier` (null for
  built-ins), `enforcement`, `adapter`, `evidence` (array),
  `metric_version`.
* `execution` - `completed`, `budget`, `signal` or `error`. It says how
  the attempt to produce evidence ended, independently of its verdict. One
  absolute deadline covers the command, pattern matching, coverage
  combination and analysis; an overrun is `budget`.
* `outcome` - the adapter's raw verdict: `pass`, `fail`, `unsupported` or
  `error`. Tier 3 adapters later add `proved`, `no_counterexample` and
  `unknown`.
* `satisfied` - whether the policy obligation is met after baselines and
  enforcement. A baseline-covered violation keeps `outcome = "fail"` and sets
  `satisfied = true`. An advisory check does not block the whole-tree
  judgement.
* `duration_seconds`, `budget_seconds` (null for built-ins).
* `diagnostics` - `argv` (array or null), `exit_code` (integer or null),
  `signal` (integer or null), `output_bytes`, `output_tail` (at most 4 KiB),
  `output_truncated`, and `error` when execution failed. Check subprocess
  output is captured up to 1 MiB; later bytes are counted and discarded.
* `findings`, `resolved_baseline_entries`, `unmeasured_baseline_entries`.
* `location_coverage` - `complete`, `partial` or `none` for the check's
  violations. Verification is partial because test counts have no location;
  a clone finding without complete ranges makes its check partial.
* `reason` - a structured explanation of a non-passing adapter verdict
  (for example `no completed jscpd run`), or null when the adapter passed.
* `measurement` - optional adapter facts, for example `{"tests": 12}`.
* `tool` - optional measured tool identity supplied by any adapter: an object with string
  `name` and `version` fields, for example `{"name": "Emacs", "version": "30.1"}` for an
  Emacs Lisp test, compile or checkdoc measurement. It is absent when no identity has been
  reported, such as when Emacs is missing. This replaces `emacs_version`.
* `definitions` - an optional report entry supplied by the Emacs Lisp test adapter: an array of objects
  with `symbol`, repository-relative `file`,
  one-based character `position`, `stop_points` and `reached`. Lambda definitions have generated symbols.
  These counts are also retained as evidence for later checks.

A test check reports its `outcome` and `reason` and keeps the command's output tail in
`diagnostics`; the executed count is in `measurement`. It records the executed and skipped counts
for verification, which reports them as `tests:ID:executed` and `tests:ID:skipped`. Per-test
outcomes are not reconstructed.

A finding has `subject`, its raw `value`, `bound` (or null), `threshold`,
`baseline_reason` (or null), `covered_by_baseline`, `blocking`, `location`,
`locations` and `expired`. `locations` is an array of objects with `path`,
`start_line` and `end_line`, or null when the source locations are incomplete.
Baseline errors carry `error`.
Python CRAP findings carry `measurement` with `cc`, `statements`, `executed` and `excluded_lines`.
Emacs Lisp CRAP findings carry `measurement` with `cc` (cyclomatic complexity), `points` (Edebug
stop points) and `hits` (reached stop points); their metric version is `elisp-edebug/1`.

Obligation status is `satisfied`, `exempted` (with `reason`) or
`unsatisfied`. `required` names the evidence the tier needs; `checks` names
the checks that counted.

The decision is `rejected` when inventory or hygiene fails, when an enforced
check is not satisfied, or when any obligation is `unsatisfied`.
`accepted_with_exceptions` means every obligation and enforced check is
satisfied, but a baseline exception or a non-passing advisory check exists.
`blocked` (exit 1, trust runs only) means an unauthorized protected path other
than the policy, a baseline or the tools lock differs from the trusted
directory; the checks still ran and are reported. `error` (exit 2) is invalid policy, usage,
configuration, or a protected input, effective input, tool payload or gate
file that changed during the run.

`execution` does not change the decision: a budget or signal makes the raw
outcome fail, and policy satisfaction then decides acceptance. A prune that is
refused or fails makes the command exit 1 while `decision` still reports the
gate evaluation.

## Result: `worklist --json`

Selected checks and their prerequisites run in a temporary working-tree copy with its Git index and
history. Symlinks keep their targets unchanged. FIFOs, sockets and devices, including ignored ones,
stop the worklist before any check runs, naming the path and type. Git configuration used by inventory
enumeration is carried over, including `core.excludesFile` as an absolute path. The enumerated file
lists must match in the original and copy; differences stop the worklist and name the paths.
Each adapter descriptor declares `argument_fields`: spec fields holding a command or path string
or a sequence of argument strings. The worklist checks exactly these fields for every selected check
and prerequisite; the default empty tuple checks none.
Declared arguments in selected checks and prerequisites must not contain the original repository's
absolute path or resolved real path. A violation stops the worklist before any check runs, naming the
check and argument and asking for a repository-relative path. These failures exit 1 with no document.

A check's writes through its working directory, relative paths and configured paths land in the copy;
baselines are relocated there. The copy is not a sandbox: code that computes an absolute path to the
original, or follows a symlink targeting the original, can still write there. Run untrusted code under
a sandbox.

`worklist --json` writes exactly one JSON document to stdout. Its schema is 1:

```json
{
  "schema": 1,
  "rows": [
    {
      "check": "crap",
      "subject": "pkg/alpha.py:alpha",
      "churn": 2,
      "bound": 25,
      "value": 20.0,
      "churn_x_value": 40.0,
      "location": "pkg/alpha.py:1-6"
    }
  ],
  "slack": [
    {
      "check": "verification",
      "subject": "tests:tests:executed",
      "bound": 1,
      "value": 3,
      "slack": 2
    }
  ],
  "notes": [
    {"check": "crap", "subject": "other/existing.py:ghost", "reason": "unmeasured"},
    {"check": "verification", "subject": "tests:missing:executed", "reason": "not measured"},
    {"check": "crap", "subject": "pkg/alpha.py:removed", "reason": "no longer exists"},
    {
      "check": "crap",
      "subject": "pkg/ghost.py:ghost",
      "reason": "churn not measured",
      "file": "pkg/ghost.py"
    }
  ]
}
```

All four top-level fields are required: `schema` is the integer version `1`; `rows`, `slack` and
`notes` are arrays of objects, including empty arrays when there are no entries to report.

`rows` holds only `max` baseline entries whose bound is strictly above the check's threshold, whose
subject is measured and whose finding's file has Git history. Rows are ranked by `churn_x_value`
descending. Maximum bounds at or below the threshold do not appear in rows or notes.

| Row field | JSON type | Meaning |
| --- | --- | --- |
| `check` | string | Selected check id. |
| `subject` | string | Baseline subject identifier. |
| `churn` | integer | Complete number of commits `git log --follow` reports for the finding's file, treating its path literally. |
| `bound` | number | Baseline maximum allowed value. |
| `value` | number | Current measured value. |
| `churn_x_value` | number | `churn * value`, used for ranking. |
| `location` | string | Finding's display location, such as a file and line range. |

`slack` holds every measured `min` baseline entry, independently of the check's threshold. Minimum
bounds do not appear in `rows` and need neither a source location nor churn. Maximum bounds have no
`slack` field or entry; their rows report the current value and maximum bound instead.

| Slack entry field | JSON type | Meaning |
| --- | --- | --- |
| `check` | string | Selected check id. |
| `subject` | string | Baseline subject identifier. |
| `bound` | number | Baseline minimum required value. |
| `value` | number | Current measured value. |
| `slack` | number | `value - bound`: the measured room above the minimum floor. |

Numeric values are unrounded. The human report displays bounds, values, products and slack to one
decimal.

`notes` holds eligible maximum entries and minimum entries that cannot be reported in `rows` or
`slack`. Every note has `check` (string check id), `subject` (string baseline subject identifier) and
`reason` (string from the table below). The optional `file` is a string present only for
`churn not measured`, naming the finding's file.

| Note reason | Meaning |
| --- | --- |
| `unmeasured` | A missing `max` subject lies outside the adapter's completed measurement domain; its absence is not evidence of deletion. |
| `not measured` | A missing `min` subject lies outside the adapter's completed measurement domain; no slack is fabricated. |
| `no longer exists` | A missing subject, for either bound direction, is absent within the adapter's completed measurement domain and is classified as resolved. |
| `churn not measured` | A current maximum-bound finding exists, but Git reports no commits for its file. |

A missing current finding alone does not mean a subject no longer exists: the ratchet's measurement
domain determines which of the first three states applies. A Git command that fails makes the command
exit 1 and write no document.

## Versions and superseded proposals

* Policy: `schema = 2`.
* Result: `schema = 2`; `schema = 3` when `--policy-from` adds `trust`.
* Baseline: the `check`/`metric_version` header above; no separate baseline
  schema number.
* Worklist result: `schema = 1`.
* Metric versions: `command-exit/1`, `test-count/1`,
  `jscpd-clone-occurrences/1`, `python-lines/1`, `elisp-edebug/1`, `elisp-lint/1`, `verification/1`,
  `inventory/1`, `hygiene/1`.

The following proposals in the historical plans are superseded and are not part
of the version-2 contract:

* mandatory tier 3 for every module;
* a separate `[[waiver]]` table;
* MCP and SARIF result surfaces before a consumer exists;
* the `python-lines-branches/1` metric (line coverage only is version 2).

The plans remain as design history. Use this document when implementing or
consuming the gate.
