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

[checks.crap]
adapter = "python_crap"
tier = 1
enforcement = "enforced"
requires = "tests"            # an earlier python_tests check
threshold = 6                 # optional; finite
baseline = "quality-gate-crap.toml"

[checks.verification]
adapter = "verification"
tier = 1
enforcement = "enforced"
requires = "tests"            # optional; defaults to every earlier python_tests check
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
* `verification.requires`, when present, names an earlier `python_tests`
  check. Without it the adapter reuses every earlier `python_tests` check.
* A baseline path must be used by exactly one check. Two checks naming the
  same resolved path is a configuration error.
* Every class named by a rule and every check named by a class must exist.
  Every code class must list at least one check.
* `[[not_applicable]]` entries are the explicit, reasoned exemption for a
  class and required tier. A missing entry is an unsatisfied obligation, not a
  configuration error.
* `[protect]` has one optional key, `paths`, a list of repository-relative
  paths or `fnmatch` globs. It is the caller's protected-input list for
  `check --policy-from REV`; without that option it is parsed and ignored. The
  list used by a trust run always comes from `REV`.

### Evidence and obligations

Each adapter declares the evidence it produces:

| Adapter | Evidence |
|---|---|
| `command` without `tests_pattern` | `static` |
| `command` with `tests_pattern` | `tests` |
| `python_tests` | `tests` |
| `clones` | `duplication` |
| `python_crap` | `crap` |
| `verification` | none |
| `owners` | `static` |

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

The `verification` adapter measures verification loss. For each reused
`python_tests` check it records `tests:CHECK:executed` (direction `min`,
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
includes the first directive and its line.

These verification `max` metrics have threshold 0, so a missing baseline entry
accepts only 0; a `min` metric without an entry is unmeasured and fails until an
entry exists. A file-wide suppression needs its own baseline entry with a
non-empty reason, and the entry resolves when the count returns to 0. Replacing
inline `noqa` comments with a file-wide directive therefore still fails unless
the file-wide subject is covered.

### Single-owner rules

An `owners` check has `tier = 1`, `enforcement = "enforced"`, a `baseline`
path, and a non-empty array `[[checks.ID.rule]]`. It has `static` evidence,
metric version `owners/1`, direction `max`, and threshold 0. Each rule requires
a unique non-empty `name`, a non-empty `reason`, one or more distinct
repository-relative `owners` file paths, and a non-empty `forbid` array of
patterns. `allow` is an optional array of patterns. Owner paths are literal
files, not globs, and must be enumerated regular files. Each pattern is a table
with a non-empty `kind` and `value`, and optional `paths`, a non-empty list of
repository-relative `fnmatch` globs. Within either array, pattern kind and
value must be unique. No `paths` means that the pattern applies everywhere.
Unknown keys, kinds, invalid regexes, non-max directions and other malformed
policy values are configuration errors.

Every regular file in the inventory is examined, whether tracked, stageable
untracked, changed, unchanged, or assigned to a class that does not list the
check. Inventory symlinks and gitlinks are not read; a symlinked parent is
refused. Pattern paths restrict which matches count. All forbids and allows
must match at least once in the applicable files, including owners; a missing
owner or a stale forbid or allow is a configuration error (exit 2) naming the
rule and the item. A matching forbid outside an owner is a violation unless a
matching allow covers that particular occurrence.

| Pattern kind | Meaning of `value` |
|---|---|
| `python-call` | Exact called name or dotted attribute in Python's AST. |
| `python-import` | Exact imported module, including the module in a `from` import. |
| `python-argv` | First string literal in a Python list or tuple passed as a call's first argument or returned from a builder. |
| `python-script` | Literal script argument following a recognized interpreter and options in such a literal argv list. |
| `shell-command` | Unquoted shell command word; a path also matches its basename. |
| `shell-script` | Unquoted script argument of an interpreter, including after options such as `-I`. |
| `text-regex` | Python regular expression over masked code; this last-resort form is marked in the finding. |

Python AST patterns ignore comments and strings except for the literal argv
elements they inspect. Shell tokenization ignores comments, quoted words and
here-document bodies and finds commands after `|`, `&&`, `;` and `$(`,
including a substitution inside double quotes. `-c` and `-m` do not identify a
script. Text patterns use Python or shell tokenization to mask comments and
strings; other text uses a common lexer that masks quoted strings, `#` and
`//` comments, `/* ... */` comments, and `.el` semicolon comments. Regexes run
in a bounded child; only non-empty matches count. Syntactic matching cannot resolve aliases, evaluate
computed argv, or detect arbitrary semantic duplication.

An allow covers a Python forbid in the same call or import; a call nested in
the outer call's first argument can also cover that outer call. Shell allows
cover forbids in the same simple command. A text allow must contain the
forbidden text match. An unrelated occurrence on the same line does not cover
a forbid. For example, the following rules allow the two peak-helper callers
while flagging a different script in the selected callers or an illustrative
duplicate of the hour computation:

```toml
[checks.architecture]
adapter = "owners"
tier = 1
enforcement = "enforced"
baseline = "owners-baseline.toml"

[[checks.architecture.rule]]
name = "peak-window"
reason = "the helper owns the peak-window decision"
owners = ["peak-window.py"]
forbid = [
  { kind = "shell-command", value = "python3", paths = ["dsh-implement.sh", "opencode.sh"] },
  { kind = "python-argv", value = "python3", paths = ["agent-usage.py", "opencode.py"] },
  { kind = "text-regex", value = 'hour\s*>=\s*17', paths = ["*.py", "*.sh"] },
]
allow = [
  { kind = "shell-script", value = "peak-window.py" },
  { kind = "python-script", value = "peak-window.py" },
]
```

`python3 -I peak-window.py` and
`subprocess.run(["python3", "-I", "peak-window.py"])` are allowed.
`python3 -I copied-window.py` in a listed shell file, `now.hour >= 17`, and
`(( hour >= 17 ))` outside the owner are violations. The path scopes are
necessary when the same interpreter is also used for unrelated concerns.

The Git rule below instead makes a literal argv builder the owner:

```toml
[checks.architecture]
adapter = "owners"
tier = 1
enforcement = "enforced"
baseline = "owners-baseline.toml"

[[checks.architecture.rule]]
name = "git"
reason = "files.git_argv owns candidate Git invocation options"
owners = ["quality_gate/files.py"]
forbid = [{ kind = "python-argv", value = "git" }]
```

The returned list in `files.git_argv` matches inside the owner. A caller
using `run(git_argv(root, "status"))` contains no literal Git argv and passes;
`subprocess.run(["git", "status"])` elsewhere violates the rule. No `allow`
is needed for the safe call.

A subject is the compact JSON array `[rule, path, kind, value]`, without a
line number, using JSON ASCII escapes for non-ASCII characters. Its value is
the number of uncovered occurrences, and its
location and `measurement.lines` report current line numbers.
`measurement.rule`, `pattern`, `owners` and `text_fallback` describe the
finding. Every occurrence is also printed as
`owners: RULE: PATH:LINE: PATTERN outside its owners (OWNERS)`. A baseline
exception for the Git example uses the generic reasoned ratchet:

```toml
check = "architecture"
metric_version = "owners/1"

[[entry]]
subject = '["git","bypass.py","python-argv","git"]'
bound = 1
reason = "legacy invocation pending migration"
```

Removing the occurrence resolves the entry; adding another exceeds its bound,
and pruning only tightens or removes entries. The scan's domain is the entire
inventory. Policy rules and the baseline are protected inputs in a trust run.
Do not self-adopt this adapter in the batch that adds it: a runner executes the
trusted gate from the batch base, and an older gate rejects the unknown
adapter before acceptance. Adopt it in a later batch based on a revision that
already contains the adapter.

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
  every function, and `owners` uses `[rule, path, kind, value]` as compact JSON.
* `bound` must be finite and is compared unrounded. For a `max` metric it
  is the largest accepted value; for a `min` metric it is the smallest. Exactly
  at the bound passes.
* `reason` must be non-empty. An empty reason fails even when the value is
  within the bound.
* `expires` is an optional TOML date. A date equal to today still covers
  today; only a date before today expires.
* Adapter metadata (for example clone `files`) is preserved by `--prune`.
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

## Change-scoped enforcement

`check --changed-from REV` preserves the full-tree checks and ratchets and adds
a judgement for threshold violations on added or modified worktree lines. A
located violation that overlaps those lines blocks regardless of baseline or
whether the check is advisory. A measurement at or within its threshold does
not fail this extra judgement. Unchanged violations remain subject to the
ordinary ratchet; a check with a changed-line violation cannot be pruned.

`REV` must resolve to a commit. Git compares that commit to the current
worktree, including committed, staged and unstaged changes and stageable
untracked files. Every line of an inventory file absent from the base is new.
The gate compares raw base blobs with worktree bytes in an isolated temporary
directory, so index flags and candidate Git clean filters cannot hide edits.
Line-ending changes are changes. The gate runs a zero-context textual Git
diff with rename detection off. Files containing lone carriage returns are
normalized for line numbering; if only their line endings differ, all lines
are marked changed.
For a finding through a symlink, a new or retargeted link marks all its source
lines new. An unchanged link to an inventoried file uses the target's changed
lines; a target outside that inventory cannot be compared and the finding is
reported as not change-scoped.
Moved code is judged where Git reports added lines; Git's alignment determines
which lines those are. A deletion alone adds no lines. Ignored untracked files
and deleted files are not in inventory. A bad revision or failed diff is a
usage error (exit 2).

CRAP supplies the full function or lambda range including decorators. Its
outside-function module subject uses the span of its first through last
outside-function node, which can also include intervening functions. Owners
supply every occurrence line. Clones supply both ranges of every clone in a
fingerprint group. Verification supplies every suppression line, while its
test-count metrics have no source location. Command checks, Python tests,
inventory and hygiene have no complete source locations. Unlocated checks and
metrics retain their ordinary whole-tree judgement and are reported as
`not change-scoped`; clone findings with missing or incomplete ranges are also
reported this way. Locations are inclusive and repository-relative.

A consumer runner passes its externally selected batch base to both options,
using a trusted gate program outside the candidate:

```
python3 -I /path/to/trusted-gate/qg.py --repo "$candidate" check --json \
    --policy-from "$batch_base" --changed-from "$batch_base"
```

The harness's trusted gate already knows the batch base. The trusted base must
contain this option before a runner can use it. `--changed-from` by itself
does not establish a trusted policy or baseline.

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
  `--policy-from` and an unauthorized candidate policy, this is `REV`'s
  policy; an authorized replacement is the candidate's.
* `decision` - `accepted`, `accepted_with_exceptions`, `rejected`,
  `blocked` or `error`.
* `checks` - inventory, hygiene and every configured check, in that order.
* `obligations` - one entry per code class and required tier.
* `prune` - the prune request, whether it was performed and its refusal
  reason.
* `changed_from` - the full resolved commit id, present only when
  `--changed-from` was requested and the comparison succeeded.
* `trust` - present only on a `--policy-from` result; see below.
* `error` - present only on a `decision = "error"` document.

### Trust object

A `--policy-from` result adds one `trust` object and declares schema 3:

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

* `policy_from` is the full commit id `REV` resolved to.
* `protected` has one entry per protected input. `path` is
  repository-relative; `rev_sha256` and `candidate_sha256` are lowercase
  SHA-256 hex or null when the file is absent (in `identity_after`, `refused`
  means the candidate path is not a regular file). `status` is `unchanged`,
  `tightened`, `ignored`, `authorized` or `blocked`. A baseline entry also
  carries `ignored_entries`, the subjects whose candidate entry was ignored.
* `identity_before` and `identity_after` record `REV`'s commit id, each
  protected input's two SHA-256 values, the effective policy, tool lock, tool
  pins and each in-memory baseline under `effective_inputs`, every pinned tool's
  `payload_sha256` (or null when not installed, or `invalid` when the tree has
  no digest), and the gate program's own per-file SHA-256 values plus one
  combined `digest`. The protected scope is enumerated again for
  `identity_after`, including ignored untracked files, and an added or removed
  path is a difference; a refused candidate path is recorded as `refused`.
  `identity_after` is captured after the checks and, when a prune was
  performed, after that write. A difference in any protected or effective
  input, tool payload or gate file makes the decision `error` (exit 2) naming
  the changed input, and a requested prune writes nothing. The one permitted difference is
  the baseline the gate itself wrote for a performed prune: that path must
  equal exactly the bytes the gate generated, which is `REV`'s baseline
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
  `satisfied = true` unless it is on changed lines. An advisory check does not
  block the whole-tree judgement; a located threshold violation on changed
  lines blocks even when the check is advisory.
* `duration_seconds`, `budget_seconds` (null for built-ins).
* `diagnostics` - `argv` (array or null), `exit_code` (integer or null),
  `signal` (integer or null), `output_bytes`, `output_tail` (at most 4 KiB),
  `output_truncated`, and `error` when execution failed. Check subprocess
  output is captured up to 1 MiB; later bytes are counted and discarded.
* `findings`, `resolved_baseline_entries`, `unmeasured_baseline_entries`.
* `location_coverage` - `complete`, `partial` or `none` for the check's
  violations. Verification is partial because test counts have no location;
  a clone finding without complete ranges or a finding through an uncomparable
  symlink makes its check partial.
* `reason` - a structured explanation of a non-passing adapter verdict
  (for example `no completed jscpd run`), or null when the adapter passed.
* `measurement` - optional adapter facts, for example `{"tests": 12}`.
* `reused_from` - present when a passing check was reused, naming its record tree.

A finding has `subject`, its raw `value`, `bound` (or null), `threshold`,
`baseline_reason` (or null), `covered_by_baseline`, `blocking`, `location`,
`locations` and `expired`. `locations` is an array of objects with `path`,
`start_line` and `end_line`, or null when the source locations are incomplete.
With `--changed-from`, `on_changed_lines` is a boolean for a finding with
complete, comparable locations and null otherwise. A baseline-covered finding may have
`blocking = true` when it violates its threshold on changed lines. Baseline errors carry `error`; CRAP findings carry
`measurement` with `cc`, `statements`, `executed` and `excluded_lines`.

Obligation status is `satisfied`, `exempted` (with `reason`) or
`unsatisfied`. `required` names the evidence the tier needs; `checks` names
the checks that counted.

The decision is `rejected` when inventory or hygiene fails, when an enforced
check is not satisfied, when any obligation is `unsatisfied`, or when a located
threshold violation is on changed lines under `--changed-from`.
`accepted_with_exceptions` means every obligation and enforced check is
satisfied, but a baseline exception or a non-passing advisory check exists.
`blocked` (exit 1, trust runs only) means an unauthorized protected path other
than the policy, a baseline or the tools lock differs from `REV`; the checks
still ran and are reported. `error` (exit 2) is invalid policy, usage,
configuration, or a protected input, effective input, tool payload or gate
file that changed during the run.

`execution` does not change the decision: a budget or signal makes the raw
outcome fail, and policy satisfaction then decides acceptance. A prune that is
refused or fails makes the command exit 1 while `decision` still reports the
gate evaluation.

## Versions and superseded proposals

* Policy: `schema = 2`.
* Result: `schema = 2`; `schema = 3` when `--policy-from` adds `trust`.
* Baseline: the `check`/`metric_version` header above; no separate baseline
  schema number.
* Metric versions: `command-exit/1`, `test-count/1`,
  `jscpd-clone-occurrences/1`, `python-lines/1`, `verification/1`,
  `owners/1`, `inventory/1`, `hygiene/1`.

The following proposals in the historical plans are superseded and are not part
of the version-2 contract:

* mandatory tier 3 for every module;
* a separate `[[waiver]]` table;
* MCP and SARIF result surfaces before a consumer exists;
* the `python-lines-branches/1` metric (line coverage only is version 2).

The plans remain as design history. Use this document when implementing or
consuming the gate.
