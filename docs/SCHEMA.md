# Schema reference (policy version 2, result version 3, trust result version 4)

This is the authoritative contract for the gate's policy, baseline and result
formats. The files in `plans/` are historical records; where they disagree with
this document, this document wins. The trust-root semantics behind
`--policy-from` are specified in [`TRUST.md`](TRUST.md).

Policy version 2 is a breaking change from version 1: policy files declare
`schema = 2`, baselines begin with the check identity header, and the result
separates execution, the adapter's raw outcome and policy satisfaction. Result
documents declare `schema = 3`, which adds `caused_by` to every check and every
obligation, naming the root check ids a failure follows from or null for a root
and for a satisfied entry. A result produced with `--policy-from` adds a
`trust` object and declares `schema = 4`; a result without it is schema 3 and
has no `trust` key.

## Policy: `quality-gate.toml`

```toml
schema = 2

[code]
patterns = ["*.py"]
shebangs = ["python*"]

[modules.app]
files = ["app/*.py"]
entry_points = []
allowed_dependencies = ["library"]

[modules.library]
files = ["library/*.py"]
entry_points = ["library/api.py"]
allowed_dependencies = []

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

[checks.module-contracts]
adapter = "module_contracts"
tier = 1
enforcement = "enforced"

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
* `[checks.module-contracts]` enables the built-in and requires `[modules]`. The shared loader
  applies that requirement to standalone commands and historical `debt --revision` reads.
  Existing policies can omit both tables.
* Each `[modules.NAME]` has three required arrays of unique strings. `files` is nonempty
  and uses case-sensitive `fnmatchcase` over the full repository-relative path. A wildcard can
  span slashes. `entry_points` names exact repository-relative files. Both path arrays reject
  empty, `.` and `..` components and NUL characters. `allowed_dependencies` names modules anywhere
  in the table. The optional `protected_paths` array uses the same path validation and names
  exact, case-sensitive repository-relative files without glob syntax. Each path may be
  declared only once across all modules. Non-code paths are allowed. Invalid declarations exit 2.
  The `module-contracts` check ID requires `adapter = "module_contracts"`, a tier from 1 to 4
  and `enforcement = "enforced"`.
  It produces a built-in result with a null tier and supplies no class obligation evidence.
  An optional nonblank `shared_base` revision opts into both shared entry point rules.
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
* `python_mutation` requires `base` and has no `baseline` key. `scope`, when present, is
  `changed`; `mutant_seconds` (default 10), `function_mutants` (default 20) and
  `run_seconds` (default 300) are positive integers.
* `python_shape` requires `base` and `crap_check`, and has no `baseline` key. `scope`
  is `changed` or `tree`; `crap_check` names a `python_crap` check whose `threshold`
  is CPF's limit; `max_chain` is an integer of at least 1; `clone_min_tokens` is 20-49;
  `clone_similarity` is a finite number in [0.5, 1.0]. An unknown or invalid value is a
  configuration error, never a skipped rule.
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
* A policy must list every `python_crap` check before every `verification`
  check: loading one that does not is a configuration error naming both
  checks, because verification counts the exclusions of every CRAP check.
  Checks run in policy order, so a full run and an `--only` selection run
  every prerequisite before the check that needs it.
* A baseline path must name an existing file and must be used by exactly one
  check. A key naming a missing file, or two checks naming the same resolved
  path, is a configuration error naming the check, the key and the path. A
  check with no debt has no key, so a refusal means the path is wrong rather
  than the debt gone. A consumer whose policy still names a missing file must
  first update to a gate where the key is optional, then delete the key, and
  only then take this version.
* Every class named by a rule and every check named by a class must exist.
  Every code class must list at least one check.
* `[[not_applicable]]` entries are the explicit, reasoned exemption for a
  class and required tier. A missing entry is an unsatisfied obligation, not a
  configuration error.
* `[protect]` has one optional key, `paths`, a list of repository-relative
  paths or `fnmatch` globs. It is the caller's protected-input list for
  `check --policy-from DIR`; without that option it is parsed and ignored. The
  list used by a trust run always comes from `DIR`.

### Python module graph policy

The `module_graph` adapter requires `classes`, a nonempty array of inventory class
names. It reads the Python files in those classes. The optional `suites` array
contains case-sensitive `fnmatch` patterns for repository-relative paths. It defaults
to an empty array. The adapter uses a fixed maximum threshold of zero findings.

For each import, the adapter searches the repository root followed by the importing
file's directory. Relative imports resolve from the importing file's package. A
`from P import N` edge points to `P.N` when that module is in scope and otherwise
points to `P` when it is in scope. Only edges between measured files are recorded.

### Environment access policy

The `env_surface` adapter reads all files in the classes that list the check.
Its optional `allow` array defaults to empty. Each entry specifies exactly one
nonempty `name` or `prefix` and a nonempty `owner`. Names and prefixes match
case-sensitively. This policy allows `HOME` and names beginning with `XDG_`.

```toml
[checks.env_surface]
adapter = "env_surface"
tier = 1
enforcement = "enforced"
allow = [
  { name = "HOME", owner = "POSIX" },
  { prefix = "XDG_", owner = "XDG Base Directory" },
]
```

The Python AST driver reads `.py` files and Python shebang scripts. The Emacs
reader handles `.el` files in batch mode. A selected file without a driver or
with a reader error fails the check and appears in its reason.

The Python reader follows direct local aliases such as `env = os.environ`.
A wildcard import from `os` produces a computed finding at the import line.

The Emacs Lisp reader reports `getenv` reads, `setenv` writes, and one
write per binding in `with-environment-variables`. It reports writes to
`process-environment` through `add-to-list`, `push`, `setq`, and `let` or
`let*` bindings. Other references to `process-environment` are reads. A
literal `NAME=value` supplies the name. A reference to `initial-environment`
produces a computed read of the entire environment.

### Source comments policy

The `comments` adapter reads every file in the classes that list its check.
It accepts the common check keys and uses a fixed table of
[tool-required lines](../README.md#source-comments).

```toml
[checks.comments]
adapter = "comments"
tier = 1
enforcement = "enforced"
```

The comments, module graph, and clone adapters use the language recorded by
inventory. For regular files, inventory takes the first-line shebang interpreter
after any `env` launcher and options, uses its basename, and strips trailing
version digits, including dotted versions. If that name matches a configured
`[code].shebangs` pattern, inventory uses its interpreter family when the
name is in the family table.
The shell family includes `sh`, `bash`, `rbash`, `dash`, `ksh`, `mksh`, and
`posh`. The Python and Emacs Lisp families use `python` and `emacs`,
respectively. The suffix decides the language when the interpreter is unmatched
or outside the family table. For example, a `.sh` file with a configured `zsh`
shebang still uses the shell driver. An eligible extensionless symlink
to a regular file with a configured Python shebang uses the Python driver.
Inventory resolves such a symlink's language when a check selects it for
language dispatch and caches the result for the rest of the run. Inventory
leaves unselected symlink targets unopened. Language precedence is
independent of which checks a class lists.

The shared `quality_gate/shell_syntax.py` module feeds source bytes to the
pinned shfmt from the tools directory on stdin with `--to-json` and
`--filename` in Bash mode. It validates the caller's declared JSON fields and
checks the remaining deadline before launch and after decoding. The comments
driver reads `Hash.Line` and `Text` from every object with a `Hash` key and
treats omitted `Text` as an empty comment body. The shell exception applies to
a line-1 shebang that matches the allowed form.

Any forbidden comment, parser error, timeout, or selected file without a driver produces
an outcome of `fail`. The reason includes each finding and each file error,
sorted by repository-relative path and line. File errors sort at line 0.
A complete scan with zero findings passes.

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
| `python_shape` | `duplication` |
| `module_graph` | `static` |
| `env_surface` | `static` |
| `comments` | `static` |
| `python_mutation` | `static` |
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
file a `python_crap` check measured it records `exclusions:FILE:no-cover`:
the number of distinct lines CRAP's coverage excluded in that check's measured
functions, one subject per file even when several CRAP checks measure it. The
count is read from the `excluded_lines` the checks reported, not from matching
text and not from verification's file selection, so a file CRAP measures but
verification's classes do not select is counted. The policy lists every
`python_crap` check before every `verification` check; loading a policy that
does not is a configuration error naming both checks, because verification
counts the exclusions of every CRAP check. Checks run in policy order, so a
full run and `--only verification` run every `python_crap` check before
verification. A `python_crap` check that ran without a measurement leaves the exclusion count
unmeasured: the check is an error naming that check, never 0. With no
`python_crap` check there are no `no-cover` subjects. It also records
`exclusions:FILE:noqa` (inline `# noqa` comments) and
`exclusions:FILE:file-suppression` (file-wide lint suppression
directives) for each selected Python file; all three exclusion subjects are
`max`. File-wide directives include Ruff's `# ruff: noqa`,
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
deleted from the repository resolves. A baseline whose entries all resolve
keeps its header and no entries, and prune reports that it is now empty; the
policy's `baseline` key and the file are then deleted by hand.

### Module contracts and consumer cutover

`module-contracts` assigns each inventoried code file exactly one module. It uses present tracked
and staged files and nonignored untracked files, excluding gitlinks and non-code files. Each
pattern must match code. Patterns within one module may overlap. Entry points must be present,
uniquely owned code files of the declaring module. An empty `[modules]` requires a code-free tree.

A cross-module direct edge must satisfy both requirements. The source must list the destination
in `allowed_dependencies`, and the target must appear in the destination's `entry_points`. The
enabled check runs after inventory and hygiene and before the other configured checks in full,
`--only` and `--base` runs, including an empty diff.
With successful inventory and a valid map declaring at least two modules, it extracts the full
owned-code graph using the existing Python, Emacs Lisp and shell extractors. Required extraction
failures, including Emacs preparation and reader errors, reject with exit 1, as do ownership
and interface violations. Ordinary outside-extractor records are nonblocking. A valid zero- or
one-module map requires no extraction. `worklist` omits the built-in.

With `shared_base` enabled, `--base` takes precedence and supplies its affected-scope diff
from the merge base. Otherwise, the check compares the run's resolved `QG_DIFF_BASE` commit
to `HEAD` when set, or the configured `shared_base` revision to `HEAD` when unset. Use
`shared_base = "HEAD"` to check staged and unstaged edits on a plain local run. Each diff
includes committed, staged and unstaged changes. Rename detection is disabled so the diff
includes both names of a rename. Invalid bases and unreadable diffs are command errors even
when inventory reports violations.

For opted-in policies, Git must report each declared protected path as a regular file in the
selected base commit's tree. Directories, symlinks, gitlinks and missing entries in that tree
are configuration errors. The candidate worktree does not determine whether a declaration is valid.
Policies without `shared_base` skip the base tree validation and both shared entry point rules.

The `shared-entry-point` rule blocks each pair of a changed protected path and a changed,
present, uniquely owned code file outside the declared protected paths. A content edit, deletion,
rename away or replacement by a directory or symlink counts when Git reports the protected path
in the diff. The rule can report these pairs even when inventory enumeration succeeds with
violations. Put the registration or documentation beside the feature file in its owning module.

The `multi-module-file` rule blocks each present, index-tracked code file with direct
dependents in at least two declared modules in the full extracted graph, even with an
empty diff. Callers in the target's own module count, and each caller module counts once.
Both rules block with exit 1 and use the effective policy, including trusted policy.

Land policy support before enabling module contracts. When the harness enables the check,
cut over its gate pin and trusted policy snapshot together. Include the check declaration,
a valid map and any required shfmt pin in the `--policy-from` snapshot. The trusted lane
validates the snapshot before considering an authorized candidate policy. An enabled
snapshot must therefore supply its own map. Cut over the editor's gate pin and local policy
together. Either consumer can start with one explicit module with `files = ["*"]` and both
other arrays empty.

When either consumer adds a second module, every enabled check run with successful inventory
and a valid map extracts the full owned-code graph. Allow for three shfmt calls per selected shell
file and one Emacs batch when Lisp is selected. Trusted runs use the effective policy and tool lock.
Measure the incremental runtime when each consumer introduces its split.

## Result: `check --json`

The example shows the configured tests result from the `checks` array.

```json
{
  "schema": 3,
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
      "caused_by": null,
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
      "caused_by": null,
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

* `schema` - `3`, or `4` when a `trust` object is present.
* `gate_version` - the gate's own revision, or `unknown: ...`.
* `revision`, `dirty` - the consumer's HEAD (or null) and worktree state.
* `policy_sha256` - the effective policy file's SHA-256, or null. With
  `--policy-from` and an unauthorized candidate policy, this is the trusted
  directory's policy; an authorized replacement is the candidate's.
* `decision` - `accepted`, `accepted_with_exceptions`, `partial`,
  `rejected`, `blocked` or `error`.
* `checks` - `inventory`, `hygiene`, `module-contracts` if enabled, and the remaining
  configured checks that ran, in that order.
* `obligations` - one entry per code class and required tier; empty on a
  partial run.
* `selected` - present only on a `check --only` result. Lists the requested check IDs and
  prerequisites in policy order, with `module-contracts` first when requested by ID.
* `prune` - the prune request, whether it was performed and its refusal
  reason.
* `trust` - present only on a `--policy-from` result; see below.
* `error` - present only on a `decision = "error"` document.

### Trust object

A `--policy-from` result adds one `trust` object and declares schema 4:

```json
{
  "schema": 4,
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
  `tightened`, `authorized` or `blocked`; an unauthorized changed protected
  input reports `blocked` and blocks the decision. Every baseline carries
  `ignored_entries`, the subjects whose candidate entry the run did not apply;
  it is empty for an unchanged or authorized baseline and for a blocked
  baseline whose bytes changed while its entries did not.
* `identity_before` and `identity_after` record `DIR`'s path as `revision`,
  each protected input's file SHA-256 values, the effective policy, tool lock,
  tool pins and each in-memory baseline under `effective_inputs`, every pinned
  tool's `payload_sha256` (or null when not installed, or `invalid` when the
  tree has no digest), and the gate program's own per-file SHA-256 values plus
  one combined `digest`. The protected scope is enumerated again for
  `identity_after`, including ignored untracked files, and an added or removed
  path is a difference; a refused candidate path is recorded as `refused`.
  `identity_after` is captured after the checks. A difference in any protected
  or effective input, tool payload or gate file makes the decision `error`
  (exit 2) naming the changed input. `--prune` with `--policy-from` is a usage
  error (exit 2) naming both options.

Check keys:

* `id`, `kind` (`inventory`, `hygiene`, `module-contracts` or `check`), `tier` (null for
  built-ins), `enforcement`, `adapter`, `evidence` (array),
  `metric_version`.
* `execution` - `completed`, `budget` (a budget expired),
  `signal` or `error`. It says how the attempt to produce evidence ended,
  independently of its verdict. A run that exceeds its overall limit (the sum
  of selected check budgets plus a 300-second allowance) produces a
  decision error instead of a check result. The run limit adds 600 seconds
  when module contracts are enabled, inventory succeeds and the policy declares at least two modules.
* `outcome` - the adapter's raw verdict: `pass`, `fail`, `unsupported` or
  `error`. Tier 3 adapters later add `proved`, `no_counterexample` and
  `unknown`.
* `satisfied` - whether the policy obligation is met after baselines and
  enforcement. A baseline-covered violation keeps `outcome = "fail"` and sets
  `satisfied = true`. An advisory check does not block the whole-tree
  judgement.
* `caused_by` - the root check ids this failure follows from, or null for a
  root and for a satisfied entry; see [Roots and consequences](#roots-and-consequences).
* `duration_seconds`, `budget_seconds`. The module contract reports 600 seconds when it attempts
  extraction, covering extraction and edge evaluation. Built-ins otherwise report a null budget.
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

`module-contracts` uses matching `id`, `kind` and `adapter`, `enforcement = "enforced"`,
and `metric_version = "module-contracts/1"`. Failed inventory makes the contract unsatisfied
with `caused_by = ["inventory"]`. Its `findings` array retains ownership, extraction,
interface and shared entry point diagnostics. Reader errors include `file`, `stage`,
`line` and `message`.
Each distinct violating edge produces a `module-interface` finding ordered by source path, line,
target path and edge kind. It has `rule`, `edge` (`source`, `line`, `target`, `kind`),
`source_module`, `target_module`, `failed_conditions` and `permitted_entry_points`.
`failed_conditions` lists each applicable condition, `dependency-not-allowed` and
`target-not-entry-point`. `permitted_entry_points` is sorted and can be empty.
Each `shared-entry-point` finding has the feature `file`, its `module`, the
`protected_path` and a diagnostic `message`. Findings are ordered by feature path,
then protected path. Each `multi-module-file` finding has the target `file`, sorted
dependent `modules` and a diagnostic `message`. Findings are ordered by target path.

A completed `module_graph` check reports `measurement.modules` as sorted
repository-relative paths and `measurement.edges` as objects with `source`, `target`
and one-based `line`, sorted by those fields. Each distinct source, target and
line is included. The `fan_in` and `fan_out` objects map each module path to its
number of distinct importing or imported modules, respectively. The `value`
is the total number of findings and `threshold` is zero. The adapter has no baseline.
Cycle findings include their sorted `component` and a shortest witness `cycle`
as an ordered array of edges. When several shortest cycles exist, the adapter
chooses the lexicographically first edge sequence. Suite findings include the
offending `edge`. Both findings use the import lines as their locations.

An `env_surface` check reports `measurement.findings`, an array sorted by
repository-relative `path` and one-based `line`. Each row has `name`, `path`,
`line`, and `access`. Access is `read`, `write`, or `computed`. A computed row
has a null `name` because the source provides no literal name. The check fails
on any computed row, any name outside the allowlist, or any file the drivers
cannot read. The inventory includes allowed rows and retains rows from files
that were read successfully when other files fail.

A `comments` check reports `measurement.findings` sorted by repository-relative
`path` and one-based `line`. Each row has `path`, `line`, and `text`. The text
contains the first 60 characters of the forbidden comment. Findings from
successfully parsed files remain in the result when another file fails to parse.

Python CRAP findings carry `measurement` with `cc`, `statements`, `executed` and `excluded_lines`.
Emacs Lisp CRAP findings carry `measurement` with `cc` (cyclomatic complexity), `points` (Edebug
stop points) and `hits` (reached stop points); their metric version is `elisp-edebug/1`.

Obligation status is `satisfied`, `exempted` (with `reason`) or
`unsatisfied`. `required` names the evidence the tier needs; `checks` names
the checks that counted. `caused_by` is the root check ids of an unsatisfied
obligation's consequence, or null for a root and for a satisfied entry.

### Roots and consequences

A failed check is a **consequence** when the gate itself can name its cause: its
`requires` check is unsatisfied, or, without `requires`, a check it measures tests
from is unsatisfied (a test-measuring check depends on every earlier check that
produces `tests` evidence). A chain resolves to its roots, deduplicated in summary
order, which is the order of the checks in the policy. An unsatisfied obligation is a
consequence when at least one of the class's checks declares the tier's required
evidence and every such candidate check is unsatisfied; its `caused_by` is the roots
of every candidate, in the same policy order. An obligation with no candidate
check is a root, because that is a policy gap. Every other failure is a root.
The rule is decided from the policy and the results' `satisfied` status, never
from message text.

The stderr summary's `check: failed (...)` line lists only root failures, in
the existing order. When consequences exist, the next line is
`check: consequences (ENTRY because CAUSE[, CAUSE...]; ...)`, where each entry
is spelled as the summary spells it: a check id or `obligation CLASS tier
TIER`. A consequence still rejects and still exits 1.

The decision is `rejected` when inventory, hygiene or module contracts fail, when an enforced
check is not satisfied, or when any obligation is `unsatisfied`. A
`check --only` run evaluates no obligations; it is `rejected` when a built-in
or any enforced check that ran is not satisfied, and `partial` (exit
0) otherwise. `accepted_with_exceptions` means every obligation and enforced
check is satisfied, but a baseline exception or a non-passing advisory check
exists.
`blocked` (exit 1, trust runs only) means an unauthorized protected input
differs from the trusted directory: the policy, the tools lock or another
protected path, or a baseline whose candidate entries are not all at least as
strict as the trusted ones, or whose bytes changed while its entries did not.
For the policy and a baseline the run reports the trusted version it applied; a
check that reads another protected path reads the candidate's file. The checks
still ran and are reported. `error` (exit 2) is invalid policy, usage,
configuration, a run that exceeds its limit, or a protected input, effective input, tool payload
or gate file that changed during the run.

`execution` does not change the decision: a budget or signal makes the raw
outcome fail, and policy satisfaction then decides acceptance. A prune that is
refused or fails makes the command exit 1 while `decision` still reports the
gate evaluation.

## Result: `worklist --json`

Selected checks and their prerequisites run in the repository itself, as with `check`, and may
write what `check` writes. The worklist no longer runs its checks in a temporary copy.

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

## Result: `debt --json`

`debt --json` reads the policy and every baseline it names without running any check and writes exactly
one JSON document to stdout. Its schema is 1:

```json
{
  "schema": 1,
  "revision": "0123456789abcdef0123456789abcdef01234567",
  "checks": [
    {
      "id": "crap",
      "baseline": "quality-gate-crap.toml",
      "entries": 2,
      "debt": 1,
      "rows": [
        {
          "subject": "pkg/alpha.py:alpha",
          "bound": 8,
          "threshold": 6,
          "reason": "measured above the threshold"
        }
      ]
    }
  ],
  "debt": 1
}
```

`revision` is the resolved commit SHA read by `--revision`, or null when the policy and baselines come
from the working tree. With `--revision`, the report depends only on files committed at that revision:
no adapter reads a candidate input from the working tree. `checks` follows policy order and holds one
object per check with a baseline, including a check with no debt. A policy with no baseline has an empty
`checks` array and `debt` 0. `debt` is the sum of every check's `debt`.

| Check field | JSON type | Meaning |
| --- | --- | --- |
| `id` | string | Check id. |
| `baseline` | string | Baseline path as the policy names it. |
| `entries` | integer | Number of baseline entries. |
| `debt` | integer | Number of entries that excuse a finding. |
| `rows` | array | One object per debt entry, in baseline order. |

An entry is debt when its direction is `max` and either the check has no threshold or its bound is
strictly above the threshold. A `min` entry is a floor and never appears. Every row has `subject`
(string), `bound` (number), `threshold` (number, or null when the check has no threshold) and `reason`
(string).

An unreadable revision, a policy or baseline that cannot be read or parsed, or a baseline the policy
names that is missing at that revision exits 2 with a message naming the revision and path. A baseline
path with an embedded NUL is rejected the same way in either mode. It never reports zero for an error.

## Versions and superseded proposals

* Policy: `schema = 2`.
* Result: `schema = 3`; `schema = 4` when `--policy-from` adds `trust`.
* Baseline: the `check`/`metric_version` header above; no separate baseline
  schema number.
* Worklist result: `schema = 1`.
* Debt result: `schema = 1`.
* Metric versions: `command-exit/1`, `test-count/1`,
  `jscpd-clone-occurrences/1`, `python-lines/1`, `elisp-edebug/1`, `elisp-lint/1`, `verification/1`,
  `inventory/1`, `hygiene/1`, `module-contracts/1`.

The following proposals in the historical plans are superseded and are not part
of the version-2 contract:

* mandatory tier 3 for every module;
* a separate `[[waiver]]` table;
* MCP and SARIF result surfaces before a consumer exists;
* the `python-lines-branches/1` metric (line coverage only is version 2).

The plans remain as design history. Use this document when implementing or
consuming the gate.
