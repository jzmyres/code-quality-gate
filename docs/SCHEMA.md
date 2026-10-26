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
`pragma: no cover` coverage exclusion) and `exclusions:FILE:noqa` (`# noqa`
comments), both `max`. A missing baseline entry accepts only 0 for a `max`
metric; a `min` metric without an entry is unmeasured and fails until an entry
exists.

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
  every function.
* `bound` must be finite and is compared unrounded. For a `max` metric it
  is the largest accepted value; for a `min` metric it is the smallest. Exactly
  at the bound passes.
* `reason` must be non-empty. An empty reason fails even when the value is
  within the bound.
* `expires` is an optional TOML date. A date equal to today still covers
  today; only a date before today expires.
* Adapter metadata (for example clone `files`) is preserved by `--prune`.
* An absent baseline means no exception is accepted. An existing file with
  only the header is allowed. An absent entry accepts only 0 for a `max`
  metric and leaves a `min` metric unmeasured.

Resolution requires a complete scan. An adapter reports the subject domain it
measured completely (the selected files for CRAP; for clones, the selected
files each entry's `files` metadata names). An entry is resolved or pruned only
when its subject lies in that domain and was not found outside its bound. A
`max` entry inside its bound resolves and prune drops it; a `min` entry is
kept and prune raises its floor to the measured value. An entry outside the
domain is reported as `unmeasured` and kept; prune never drops it. A clone
entry naming a file deleted from the repository resolves.

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
  protected input's two SHA-256 values, every pinned tool's
  `payload_sha256` (or null when not installed, or `invalid` when the tree has
  no digest), and the gate program's own per-file SHA-256 values plus one
  combined `digest`. The protected scope is enumerated again for
  `identity_after`, including ignored untracked files, and an added or removed
  path is a difference; a refused candidate path is recorded as `refused`.
  `identity_after` is captured after the checks and, when a prune was
  performed, after that write. A difference in any protected input, tool
  payload or gate file makes the decision `error` (exit 2) naming the changed
  input, and a requested prune writes nothing. The one permitted difference is
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
  `satisfied = true`; an advisory check never creates a blocking obligation.
* `duration_seconds`, `budget_seconds` (null for built-ins).
* `diagnostics` - `argv` (array or null), `exit_code` (integer or null),
  `signal` (integer or null), `output_bytes`, `output_tail` (at most 4 KiB),
  `output_truncated`, and `error` when execution failed. Check subprocess
  output is captured up to 1 MiB; later bytes are counted and discarded.
* `findings`, `resolved_baseline_entries`, `unmeasured_baseline_entries`.
* `reason` - a structured explanation of a non-passing adapter verdict
  (for example `no completed jscpd run`), or null when the adapter passed.
* `measurement` - optional adapter facts, for example `{"tests": 12}`.

A finding has `subject`, its raw `value`, `bound` (or null), `threshold`,
`baseline_reason` (or null), `covered_by_baseline`, `blocking`, `location`
and `expired`. Baseline errors carry `error`; CRAP findings carry
`measurement` with `cc`, `statements`, `executed` and `excluded_lines`.

Obligation status is `satisfied`, `exempted` (with `reason`) or
`unsatisfied`. `required` names the evidence the tier needs; `checks` names
the checks that counted.

The decision is `rejected` when inventory or hygiene fails, when an enforced
check is not satisfied, or when any obligation is `unsatisfied`.
`accepted_with_exceptions` means every obligation and enforced check is
satisfied, but a baseline exception or a non-passing advisory check exists.
`blocked` (exit 1, trust runs only) means an unauthorized protected path other
than the policy, a baseline or the tools lock differs from `REV`; the checks
still ran and are reported. `error` (exit 2) is invalid policy, usage,
configuration, or a protected input, tool payload or gate file that changed
during the run.

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
  `inventory/1`, `hygiene/1`.

The following proposals in the historical plans are superseded and are not part
of the version-2 contract:

* mandatory tier 3 for every module;
* a separate `[[waiver]]` table;
* MCP and SARIF result surfaces before a consumer exists;
* the `python-lines-branches/1` metric (line coverage only is version 2).

The plans remain as design history. Use this document when implementing or
consuming the gate.
