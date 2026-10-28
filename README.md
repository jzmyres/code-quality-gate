# code-quality-gate

A reusable, offline code-quality gate for repositories that want every file classified, every
reason recorded, every check declared by policy, and every metric exception explicit and ratcheted.
Its core is one standard-library Python 3.12 command plus pinned external tools; the Python adapters
also load the pinned coverage wheel from the tools cache. A consuming repository pins it as a git
submodule and keeps its own `quality-gate.toml` and baselines. The authoritative policy, baseline and
result contract is [`docs/SCHEMA.md`](docs/SCHEMA.md); the trust-root contract for
`check --policy-from` is [`docs/TRUST.md`](docs/TRUST.md); this README explains how to use it.

The gate is deliberately narrow. It owns the orchestration no maintained tool owns end to end:

* **inventory** - every tracked or stageable file matches exactly one class rule, with a reason;
* **obligations** - every code class is checked against the evidence its required tiers demand, with
  reasoned exemptions reported rather than hidden;
* **hygiene** - no tracked file is ignored, no file is oversized, enumeration never lies;
* **checks** - checks are declared in policy and run in policy order; adapters measure, the core decides;
* **one reasoned ratchet** - measured checks fail by default, and a baseline entry can accept a
  measured subject outside its threshold only with a non-empty reason and an optional expiry;
* **tools** - external tools are pinned by version, URL, archive SHA-256 and payload SHA-256,
  and fetched explicitly;
* **result** - `check --json` writes one machine-readable schema-2 result that separates execution,
  the adapter's raw outcome and policy satisfaction, and carries diagnostics, obligations and prune
  reporting; `--policy-from` adds a `trust` object and result schema 3.

Tier 1 now includes Python tests and per-function CRAP scores; the next metric layer is an Emacs Lisp
CRAP adapter.

## Requirements

* Python 3.12 or later (the command uses `tomllib` and coverage uses `sys.monitoring`).
* Git.
* The pinned jscpd binary in the tools cache for clone checks.
* The pinned ruff binary in the tools cache for this repository's own command check.
* The pinned coverage 7.16.2 wheel in the tools cache for the Python adapters.

`tools fetch` downloads every pinned tool once; checks never download. The core is standard-library
Python; only the Python adapters put the pinned coverage wheel on `sys.path`. The command is intended
to run as `python3 -I qg.py`, so the consuming repository's modules cannot leak into it.

The implementation lives in the `quality_gate/` package next to `qg.py`: `policy.py` loads and validates
the configuration, `files.py` resolves the repository and runs inventory and hygiene, `tools.py` owns the
pinned tool lock and extraction, `ratchet.py` owns baseline decisions and pruning, `clones.py` measures
jscpd clones, `python_tests.py` and `covrun.py` run tests under coverage, `python_crap.py` joins
coverage with `ast` complexity, `verification.py` measures test counts and source exclusions,
`coverage_tool.py` loads and combines the pinned wheel's data,
`runner.py` is the one bounded subprocess runner, `checks.py` runs every adapter and assembles the
result, `gate_result.py` computes identity, obligations and the decision, `trust.py` owns
`--policy-from` protected inputs, effective inputs and run identity, and `cli.py` holds the
argument parser and dispatch. `owners.py` and its matchers enforce declared single-owner rules.
`qg.py` is only the entry point. The implementer agents' learned memory
lives in `.agents/AGENTS.md`, written by the runner's reflection step after each batch and reviewed
before landing.

## Quick start in a consuming repository

Add the gate as a submodule at `code-quality-gate/`, fetch the pinned tools once, write the configuration,
and run the gate:

    git submodule add https://github.com/jzmyres/code-quality-gate.git code-quality-gate
    python3 -I code-quality-gate/qg.py tools fetch
    $EDITOR quality-gate.toml
    python3 -I code-quality-gate/qg.py check

A submodule is a gitlink: it is never opened, read for a shebang, or sized, so it needs exactly one
class rule and may live in a class with `code = false`. The quick-start configuration therefore also
classifies the submodule path and `.gitmodules`:

    [classes.gate]
    code = false
    description = "The pinned code-quality-gate submodule"

    [[rule]]
    pattern = "code-quality-gate"
    class = "gate"
    reason = "the gate is pinned as a submodule"

    [[rule]]
    pattern = ".gitmodules"
    class = "config"
    reason = "submodule declarations"

`check` never downloads a tool. If a configured check needs a pinned tool and it is missing, the check's
outcome is `unsupported` and the message names `python3 -I code-quality-gate/qg.py tools fetch`.

## Commands

All commands accept the repository selector before the command:

    python3 -I qg.py [--repo DIR] COMMAND

`DIR` defaults to the current directory and must be the top level of a git work tree. Configuration is
`DIR/quality-gate.toml`. Staged entries come from `git ls-files -s -z` and untracked names from
`git ls-files --others --exclude-standard -z`; the two record types are parsed separately, so tracked
and stageable untracked files are checked, ignored files are not, and an untracked name shaped like a
staged record cannot become a gitlink. Tracked entries deleted from the working tree
(`git ls-files --deleted -z`) are excluded: a deletion is not inspected, sized or classified, and a
rule that then matches no file still fails as stale. A tracked path whose worktree entry was replaced
by something else (for example a directory) is not deleted and keeps its usual handling. Only staged
records carry a git mode; mode `160000` identifies a gitlink, which matches exactly one rule like any
other enumerated path but is never opened or measured as a file. Every other entry is inspected with
`lstat`: a symlink is recorded as a symlink and never followed or read, while FIFOs, sockets and
devices are rejected with a message. Shebang inspection reads at most 4096 bytes and only from a
regular file.

### inventory

    python3 -I qg.py inventory
    python3 -I qg.py --repo /path/to/repo inventory
    python3 -I qg.py inventory --list python

The first form prints a summary such as `inventory: 42 files match 7 rules`. `--list CLASS` prints the
files of one class, one per line, and prints nothing for a known but empty class. It exits 2 for an
unknown class, so a Makefile can use it as the single source of file lists:

    python_files=$(python3 -I qg.py inventory --list python)

Inventory fails (exit 1) and prints every violation when a file matches no rule, a file matches more
than one rule, a rule matches no file, a rule has an empty reason, a rule names a class that does not
exist, or a code file (by pattern or shebang) is placed in a class whose `code` is not true.

Inventory also fails when a code class lists no check or lists an id with no `[checks.ID]` table.
Whether a class has the evidence a required tier demands is reported by `check` as obligations, so
`inventory` alone does not decide assurance. A code file is detected by fnmatch against
`[code].patterns` or by the basename of its shebang interpreter after `env` matching `[code].shebangs`.

### hygiene

    python3 -I qg.py hygiene

Hygiene fails (exit 1) when a tracked file matches the repository's ignore rules
(`git ls-files -z -c -i --exclude-standard` returns it), an enumerated file is larger than
`[hygiene].max_bytes` (default `10485760`), an enumerated path is a FIFO, socket or device, or
enumeration or a size measurement fails. Sizes are measured with `lstat`, so a symlink is never
followed. It prints every offending path and, for oversized files, the actual and allowed sizes.

### clones

    python3 -I qg.py clones
    python3 -I qg.py clones --prune

`clones` runs every configured check whose adapter is `clones`. It takes the files of the classes that
list that check from the inventory, runs jscpd with its JSON and SARIF reporters in a temporary directory,
groups the SARIF clone fingerprints into subjects, and sends every fingerprint occurrence count through the
generic ratchet. The adapter owns the detection configuration: an empty `--config`, the configured
`--min-tokens`, `--min-lines 5`, `--max-size` at the hygiene limit, an ignore pattern that matches
nothing, `--no-gitignore` and a format list covering the selected extensions when they are all known.
The JSON report's `statistics.total.sources` must equal the number of selected files; a mismatch is
`unsupported` and names the files jscpd did not analyse. The SARIF report must contain exactly one run
produced by jscpd with a `results` list; absent, malformed or foreign evidence is `unsupported`
(`no completed jscpd run`), never zero clones. A clone fingerprint is a subject; its value is how many reported clones have that
fingerprint; the threshold is `0`, so any occurrence needs a baseline entry.

A clone baseline entry is bound to its measured scope through its `files` metadata: an entry whose
files all lie outside the selected files, but still exist in the repository, is `unmeasured` and kept;
an entry naming a file that no longer exists in the repository is resolved. An entry without `files`
cannot be scoped and is resolved by the completed scan. A budget or signal termination of jscpd is the
raw outcome `fail` with its execution and diagnostics; `unsupported` remains for unavailable or
invalid evidence such as a missing report or a source-count mismatch.

`clones --prune` lowers each surviving bound to the measured occurrence count and drops resolved entries.
It never adds an entry and never raises a bound, and it refuses (exit 1, writing nothing) while that
check fails. Add a new exception by hand, with a reason. A baseline that would be empty is removed
instead of written.

### Python tests

    [checks.tests]
    adapter = "python_tests"
    tier = 1
    enforcement = "enforced"
    run = ["{python}", "-m", "unittest", "discover", "-s", "tests"]
    tests_pattern = "^Ran (\\d+) tests? in"
    skipped_pattern = "skipped=(\\d+)"  # optional; one capture group
    budget_seconds = 900                  # optional; this is the default

`python_tests` runs the consumer's own test command from the repository root. The token `{python}`
expands in place to a prefix that starts the current interpreter under coverage: `-I`, the gate's
`covrun.py`, a fresh data directory, the source root, the pinned coverage install, that install's
version and payload digest from the effective tool lock, the gate-owned coverage configuration path,
and the registry directory. The adapter writes and every child uses one
gate-owned coverage configuration (line mode, `branch = False`, `sigterm = true`, `source` the
repository root, `exclude_lines` exactly the `pragma: no cover` expression) for collection,
combination and analysis. Repository `.coveragerc`, `setup.cfg`, `tox.ini` and
`pyproject.toml` configuration is ignored, and every `COVERAGE_*` environment variable other than
`COVERAGE_CORE` is removed before the test command and by `covrun.py`. The prefix runs `coverage run --data-file=DATA_DIR/.coverage.ID
--source=ROOT --rcfile=GATE_CONFIG` with `COVERAGE_CORE=sysmon` on the rest of the arguments, so
`run` can name a script or `-m MODULE`; each invocation gets its own data file. `covrun.py` verifies
the install against that version and payload digest with the same encoding `tools.py` uses, loading
the shared verifier by path, so it starts no extra interpreter and adds no gate package or gate
repository path to the measured program's imports. Two tests hold that invariant: one runs the
runner with a measured script that reports every `quality_gate` module in its `sys.modules`, and
one parses `covrun.py` for a `quality_gate` import. With `--policy-from`, the version and payload
digest are the authorized effective lock's, so the parent and the coverage runner agree on an
authorized coverage upgrade.

A test launcher that starts the consumer's Python programs as subprocesses must use the same prefix.
The gate exports it as `QG_PYTHON`, a JSON array of strings, in the test command's environment:

    prefix = json.loads(os.environ["QG_PYTHON"]) if "QG_PYTHON" in os.environ else [sys.executable, "-I"]
    subprocess.run([*prefix, "path/to/program.py"], env=os.environ.copy(), check=True)

Pass the environment through to the child. The child then writes its own coverage dataset, which the
adapter combines with the test process's data. The adapter creates the one gate-owned coverage
configuration before the test command starts, and every child consumes it instead of rewriting it.
Each coverage invocation registers itself under `registry/` in the data directory before it runs,
naming the dataset it will write and the program it runs (the script path or `-m MODULE`, not its
arguments). Combination requires every registered dataset to exist and load. Complete means saved: a
program that ends with an uncaught exception or is stopped by SIGTERM still counts when coverage wrote
its dataset. The gate-owned configuration sets `sigterm = true`, so SIGTERM saves the dataset; coverage
then re-delivers SIGTERM, leaving the child's exit status unchanged. A child stopped before coverage
saves (for example SIGKILL or `os._exit`) or a corrupt dataset makes the tests evidence `unsupported`
rather than a pass.

`tests_pattern` is required and must contain exactly one capture group: the number of tests that ran.
`skipped_pattern` is optional and also has exactly one capture group: the number of skipped tests (for
example `skipped=(\d+)` for unittest). Both patterns are searched with `re.MULTILINE` over the
combined stdout and stderr. Executed tests are `ran - skipped`; the outcome is `fail` when the command
exits non-zero, times out (`execution = "budget"`) or executes no tests, with
`no test executed: N ran, N skipped`. An optional capture that did not participate counts as 0; a
negative or non-numeric count is invalid. It is `unsupported` when `tests_pattern` does not match,
matches more than once (`ambiguous test summary`), `skipped_pattern` matches more than once
(`ambiguous skipped summary`), a captured count is not a non-negative integer, or coverage is not
installed. On `pass` the adapter combines the registered coverage datasets and keeps the combined data
as the evidence for checks that require it. Pattern matching runs in an interruptible child bounded by
the check's remaining budget, together with coverage combination.

### Python CRAP

    [checks.crap]
    adapter = "python_crap"
    tier = 1
    enforcement = "enforced"
    requires = "tests"                    # an earlier python_tests check id
    threshold = 6                         # optional; finite; this is the default
    baseline = "quality-gate-crap.toml"   # the file may not exist yet

`python_crap` measures every function in the files of the classes that list it. `requires` must name a
`python_tests` check declared earlier in the policy; an unknown, later or different-adapter reference is
a configuration error naming the check, the reference and what was expected. If the required check did
not pass, the outcome is `unsupported` with `coverage unreliable: CHECK did not pass`; nothing is
scored.

A measured function is every `def` or `async def` that is not inside another function: module-level
functions and methods of classes at any depth. Nested functions and lambdas belong to their enclosing
function. A lambda with no enclosing function and at least one decision is its own subject,
`PATH:<lambda@LINE>`: its body is measured on the lines after its declaration, and a body sharing the
declaration line is `unmeasured` with a message asking for the body on its own line. A `@property`
getter is `PATH:Class.x`, and its `@x.setter` and `@x.deleter` functions are
`PATH:Class.x.setter` and `PATH:Class.x.deleter`; a bare `@setter` is an ordinary decorator.
Declarations decorated with `typing.overload`, an `overload` imported from `typing` or
`typing_extensions`, or `typing.overload` are skipped only when the body is `...`; a decorator with
that spelling and a runtime body keeps its subject. Every other function's identity is
`PATH:Qualified.name`, for example `quality_gate/policy.py:load_config` or
`quality_gate/files.py:Rule.matches`; two remaining functions with the same identity in one file fail
the check, naming both lines.

Executable code outside every function - module and class bodies - is one subject per file,
`PATH:<module>`. Its CC is the complexity of those statements and its coverage is their combined
coverage, so top-level control flow goes through the same ratchet as a function.

Cyclomatic complexity is 1 plus one for each `if` (an `elif` is a nested `if`), conditional expression,
`for`, `async for`, `while`, comprehension `for` clause and comprehension `if`, `except` handler
(including `except*`), `match` case that is not an unguarded irrefutable pattern, and each operand of
`and`/`or` after the first. An irrefutable pattern is a capture name, `_`, or an or-pattern with an
irrefutable alternative, so `case remaining` and `case 1 | _` add nothing, like `case _`. Nested
function and lambda bodies add to the enclosing function. A function's own CC counts only its
executable body: defaults, decorators and annotations count once, in the owner where they execute (the
enclosing function, or the module subject for a module-level definition). The rules are one data table
in `quality_gate/python_crap.py`.

Coverage comes from coverage's own analysis of the combined data (`Coverage.analysis2`) under the same
gate-owned configuration as collection and combination, which also reports files the tests never imported
with every statement missing. A function's statements are those whose line falls between its first body
statement and its `end_lineno`: the `def` and decorator lines run when the module is imported, so
counting them would credit a function no test calls. A function whose first body statement shares the
`def` line is therefore `unmeasured` and fails with `body shares the def line; put the body on its own
line`; it is never scored as covered. A function with no statements is also `unmeasured`. `cov` is
executed divided by statements. CRAP is `CC^2 * (1 - cov)^3 + CC`. Findings go through the generic
ratchet with the identity as `subject` and the unrounded CRAP as `value`; the human report rounds to one
decimal, comparisons do not. An untested CC-3 function has value `3^2 * 1^3 + 3 = 12`.

Each finding carries `measurement`: `cc`, `statements`, `executed` and `excluded_lines` (the lines
excluded by `# pragma: no cover` inside the measured span). An added pragma is therefore visible in
`check --json`. The metric version is `python-lines/1`.

### Single-owner rules

The `owners` adapter checks a declared concern across the **entire inventory**, including tracked and
stageable untracked files, whether or not the file's class lists the check. It is an enforced tier 1
static check; a separate test check is still needed for the tier 1 tests obligation. Each rule names
its implementation files, explains why, and specifies forbidden patterns. A matching occurrence
outside an owner is a violation unless an `allow` pattern covers that occurrence. The rules are in the
protected policy; the named baseline is protected just like other baselines under `--policy-from`.

Patterns are inline tables with `kind`, `value`, and optional `paths`, a non-empty array of
repository-relative `fnmatch` globs. `paths` limits where that pattern can match. Use it when a broad
pattern, such as `python3`, would otherwise include unrelated callers. All files still go through the
inventory; a pattern applies only to its configured paths. An owner must be an enumerated regular file.
Gitlinks and symlinks are not read, and symlinked parents are refused.

| `kind` | Matches |
|---|---|
| `python-call` | An AST call's exact name or dotted attribute, such as `subprocess.run`. |
| `python-import` | An imported module, including `from MODULE import ...`. |
| `python-argv` | A Python list or tuple whose first element is the literal string `value`, when passed as the first argument of a call or returned from a builder. |
| `python-script` | The literal script argument of a Python or shell interpreter in such a literal argv list. |
| `shell-command` | An unquoted command word, including after `|`, `&&`, `;` and `$(`. A path also matches its basename. |
| `shell-script` | An unquoted script argument after an interpreter and its options, such as `python3 -I peak-window.py`. |
| `text-regex` | A Python regular expression over code with comments and quoted strings masked; a last resort, identified as `text-regex` in findings. |

Python matching parses the AST and never matches text inside a comment or ordinary string. An argv
pattern deliberately inspects literal **elements** of a list or tuple passed directly to a call or
returned by a builder, not a data list assigned to a variable or text that merely looks like a list.
Shell matching skips comments, quoted words and here-document bodies; commands in
`$(...)` are scanned, including inside double quotes. Interpreter patterns require literal words;
`-c` and `-m` do not name a script. Text patterns mask Python and shell comments and strings with their
language tokenizers. For other text they mask quoted strings, `#` and `//` line comments, `/* ... */`
block comments, and, in `.el` files, `;` comments. Use a more specific pattern when those conventions do
not describe the file. Regular expressions run in a bounded child process; only non-empty matches
count.

An allowance covers a forbidden Python event in the same call or import, or an allowed call nested in
the first argument of that call; for shell, both must be in the same simple command. A text allowance
must contain the forbidden text match. An allowance elsewhere on the same line does not cover it.
These are syntactic rules: they do not resolve aliases, infer computed argv or prove that two
algorithms are equivalent. Choose patterns and path scopes that describe the actual bypasses and
reimplementations in the repository.

For example, this peak-window policy allows the shell runner and Python `agent-usage.py` to launch
the helper, but flags a different script in those call sites and a matching window computation in
any Python or shell file. The hour expression is an illustrative repository-specific signature:

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

For instance, `python3 -I peak-window.py` and
`subprocess.run(["python3", "-I", "peak-window.py"])` are covered by the respective allowances.
`python3 -I copied-window.py` in a listed shell file and either `now.hour >= 17` or
`(( hour >= 17 ))` outside the owner are findings. Scope the interpreter patterns to files where every
such launch is relevant to this concern.

The gate's Git invocation policy illustrates an argv builder rather than a subprocess owner:

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

`files.git_argv` returns a list starting with `"git"`, which is the rule's owner witness. A call using
`run(git_argv(root, "status"))` has no literal `"git"` argv and passes. A call such as
`subprocess.run(["git", "status"])` elsewhere is a violation; no `allow` is needed for the builder
call. Every forbid and allow pattern must match at least once somewhere in its scope, including
owners. A missing owner, a never-matching forbid, or a never-matching allow is a configuration error
(exit 2), naming the rule and offending item.

Violations have a stable subject: a compact JSON array of rule name, repository path, pattern kind,
and pattern value, with no line number; non-ASCII characters use JSON ASCII escapes. The finding's
location and `measurement.lines` report the
current lines, and its value is the count of occurrences for that subject. The usual max ratchet
applies: a new or increased count fails; a reviewed exception needs a reason, and prune lowers bounds
or removes resolved entries. For the Git example, an exception might be:

```toml
check = "architecture"
metric_version = "owners/1"

[[entry]]
subject = '["git","bypass.py","python-argv","git"]'
bound = 1
reason = "legacy invocation pending migration"
```

Adopt this check only in a later batch whose trusted base already contains the adapter. The runner
uses the gate from the batch base; adding this adapter and naming it in that same batch's policy would
make the older trusted gate reject the unknown adapter before acceptance.

### tools

    python3 -I qg.py tools fetch
    python3 -I qg.py tools fetch --lock /path/to/tools.lock.toml
    python3 -I qg.py tools path ruff

`tools fetch` reads the gate's `tools.lock.toml` (or `--lock FILE`) and installs every pinned tool under
`QG_TOOLS_DIR`, which defaults to `~/.local/share/code-quality-gate/tools`, as `NAME-VERSION/`. It
downloads with `urllib`, verifies the archive SHA-256, extracts into a temporary directory inside the
tools directory, and computes the install tree's payload digest before moving it into place. It refuses
an archive hash or payload digest mismatch, or an unsafe archive member (absolute path, `..`, link, or
non-regular file), without installing anything. Tool names and versions must match
`[A-Za-z0-9][A-Za-z0-9._-]*`, the install destination must resolve inside the tools directory, and a
lock table accepts only `version`, `url`, `sha256`, `payload_sha256`, `binary` and `format`;
other keys are configuration errors and a missing `payload_sha256` is a lock error. An existing install
is kept only when its payload digest matches the lock; otherwise `tools fetch` replaces it.

Every later use of a tool recomputes the install's payload digest before the tool runs or is imported:
Ruff and jscpd binaries, and the coverage package for collection and analysis. The coverage adapter
passes the effective lock's coverage version and payload digest to `covrun.py`, which verifies the
install against them before importing it, so an authorized coverage upgrade is checked by the same
descriptor in the parent and the child. A mismatch or an invalid tree makes the check `unsupported`; the
message names the tool, the install directory, and the expected and actual digests, and nothing from
that install runs. Reinstall the pinned tools with `tools fetch`
after upgrading the gate. Existing installs made before payload pinning, or with a `__pycache__`
directory, fail this verification and must be reinstalled with `tools fetch`.
Imports of the installed coverage package run with bytecode writing disabled in the gate process,
`covrun.py` and the children it starts, so a verified install stays byte-identical after use.

An archive without `format` is a tar archive. `format = "wheel"` marks a Python wheel: it is a zip, so
it is extracted with `zipfile` under the same safety rules. The wheel's install directory is what the
Python adapters put on `sys.path`; for coverage that is `coverage-7.16.2/`, and its `binary` entry
`coverage/__init__.py` is looked up inside the verified tree.

`tools path NAME` prints the expected binary path, whether or not the tool is installed, so scripts can
locate the cache. An unknown tool name exits 2.

The default tools directory is shared by every repository using the gate on this machine. Set
`QG_TOOLS_DIR` to use a different cache (for example in a container or a test).

### check

    python3 -I qg.py check
    python3 -I qg.py check --json
    python3 -I qg.py check --prune clones
    python3 -I qg.py check --policy-from REV
    python3 -I qg.py check --policy-from REV --allow-protected ruff.toml
    python3 -I qg.py check --changed-from REV

`check` runs inventory and hygiene (built in, always), then every configured check in policy order. It
prints progress on stdout and failures on stderr. When inventory fails, configured checks are reported
as skipped and the combined check still fails; hygiene still runs. Configuration errors exit 2 before
any check starts.

`check --json` writes exactly one JSON result to stdout and sends all human-readable lines to stderr.
The result schema is `2`; a `--policy-from` result is schema `3` and adds `trust` (see below). Its
top-level keys are `schema`, `gate_version`, `revision`, `dirty`, `policy_sha256`, `decision`,
`checks`, `obligations` and `prune`; a `decision = "error"` document also has `error`.
With `--changed-from`, `changed_from` is the full resolved commit id.

`checks` contains inventory, hygiene and every configured check, in that order. Each check has `id`,
`kind` (`inventory`, `hygiene` or `check`), `tier` (null for built-ins), `enforcement`, `adapter`,
`evidence` (the evidence names the adapter produces), `metric_version`, `execution`, `outcome`,
`satisfied`, `duration_seconds`, `budget_seconds`, `diagnostics`, `findings`,
`resolved_baseline_entries`, `unmeasured_baseline_entries`, `location_coverage` and `reason` (a structured explanation of
a non-passing adapter verdict, null otherwise); a measuring check may also carry a `measurement`
object (for example `{"tests": 12}`).

`execution` is `completed`, `budget`, `signal` or `error`. `outcome` is the adapter's raw verdict:
`pass`, `fail`, `unsupported` or `error`; later tier-3 adapters add `proved`, `no_counterexample` and
`unknown`. `satisfied` is true when the policy obligation is met after baselines and enforcement: a
finding inside a valid baseline keeps `outcome = "fail"` and sets `satisfied = true`. Advisory checks
do not block the whole-tree judgement. With `--changed-from`, a located threshold violation on changed
lines blocks even in an advisory check. Missing evidence is `unsupported`, never `pass`. A check has one absolute
deadline: the command, its pattern matching, coverage combination and analysis share the configured
budget, and an overrun reports `execution = "budget"` with the diagnostics collected so far.

`diagnostics` carries `argv`, `exit_code` or `signal`, `output_bytes`, `output_tail` (at most 4 KiB),
`output_truncated` and, when execution failed, `error`. Every subprocess the gate starts (git
enumeration and identity, command checks, jscpd and test runs) uses one bounded runner: it starts its own
process group, terminates the whole group at the budget (SIGTERM, then SIGKILL after 5 seconds) and reaps
it. Check output is captured up to 1 MiB; later bytes are counted and discarded. A consumer therefore
never has to parse stderr to learn why a check failed.

A finding has `subject`, its raw `value`, `bound` (or null when no baseline entry exists), `threshold`,
`baseline_reason` (or null), `covered_by_baseline`, `blocking`, `location`, `locations` and `expired`; baseline
errors carry `error`, and CRAP findings carry a `measurement` with `cc`, `statements`, `executed` and
`excluded_lines`. Unrounded values are compared: exactly at a bound passes, and a value `0.1` above the
bound fails.

### New and changed lines

`check --changed-from REV` runs the same full-tree gate and ratchets, then adds a stricter judgement:
every threshold violation with complete source locations that overlaps an added or modified line fails,
even if a baseline covers the subject. This applies to advisory checks too. A passing measurement is
never rejected by this rule. An unchanged violation may still be accepted by its baseline, and all
whole-tree failures continue to fail. A check with a changed-line violation cannot be pruned.

`REV` must resolve to a commit. Git compares that commit to the current worktree, including changes
already committed after `REV`, staged and unstaged changes, and every stageable untracked file. New
files have all their lines marked as added. The gate compares the raw base blobs and worktree bytes in
an isolated temporary directory, so index flags and candidate Git clean filters cannot hide edits.
This also treats line-ending changes as changes. It uses a zero-context textual diff without
rename detection: a moved block is judged at the added lines Git identifies at its new location.
For files with lone carriage returns, line endings are normalized for the diff so its line numbers
match the source readers; a change consisting only of line endings marks the whole file as changed.
If an adapter reports a finding through a symlink, a new or retargeted link marks its source lines as
new. An unchanged link to an inventoried file uses the target's changed lines; a target outside that
inventory cannot be compared and its finding is reported as not change-scoped.
Git's line matching decides which lines count as additions, and a deletion alone adds no lines. Ignored
untracked files and deleted files are outside inventory. A bad revision or failed diff exits 2.

The `python_crap`, `owners` and `clones` adapters provide complete locations: respectively the entire
function range (including decorators), every occurrence line, and both ranges of every clone in a
fingerprint group. CRAP's module subject uses the span from its first to last outside-function node;
that conservative span can include intervening functions. Verification supplies every suppression
line, but its test-count metrics have no source location. Command checks, Python test results, inventory
and hygiene have no complete source locations. These unlocated checks and metrics retain their normal
whole-tree judgement and are reported as **not change-scoped**. Clone evidence missing a range or one
of the two locations is also reported as not change-scoped for that finding.

Each result's `location_coverage` is `complete`, `partial` or `none`. A finding's `locations` is an
array of `{path, start_line, end_line}` ranges, or null when its locations are incomplete. With
`--changed-from`, `on_changed_lines` is true or false for a comparable measurement and null when its
locations or symlink target cannot be compared. `covered_by_baseline` still describes the whole-tree ratchet; it may be true alongside
`blocking = true` when a violation is on changed lines.

A consumer runner should pass the batch base from its own trusted context as both the policy and
change comparison base, using a gate program extracted from that base outside the candidate:

    python3 -I /path/to/trusted-gate/qg.py --repo "$candidate" check --json \
        --policy-from "$batch_base" --changed-from "$batch_base"

The harness's trusted gate already knows the batch base. An older trusted gate without this option
cannot enforce it; enable the flag when the trusted base includes this implementation. `--changed-from`
alone does not make candidate policy or baselines trusted; use `--policy-from` for that purpose.

`obligations` has one entry per code class and required tier with `class`, `tier`, `status`
(`satisfied`, `exempted` or `unsatisfied`), `required` (the evidence names the tier demands), `checks`
(the checks that counted) and `reason` (for an exemption; otherwise null). Tier 1 needs a satisfied
enforced check producing `tests` evidence with at least one executed test, so a lint-only class leaves
tier 1 unsatisfied and rejects. Tier 2 needs `properties` or `fuzzing`; tiers 3 and 4 reserve
`bounded` and `proof`. No version-2 adapter produces those evidence names yet, so a required tier above
1 is exempted by a `[[not_applicable]]` entry until its adapter lands.

`prune` reports `requested` (the requested check ids), `performed` and `reason`. `check --prune ID`
runs the same checks, then prunes only check `ID` when it is satisfied; an unknown id or a check without
a baseline exits 2. A refused or failed prune writes nothing, makes the command exit 1, and leaves
`decision` reporting the gate evaluation. Under `--policy-from`, the run identity is validated after
the checks and before the write, and after the write the pruned path may differ only by the exact
bytes the gate generated; any other difference is an identity error (exit 2).

The decision is `error` (exit 2) for invalid policy, usage or configuration, `rejected` (exit 1) when
inventory, hygiene, any enforced check or any obligation is not satisfied, or a located threshold
violation is on changed lines, `accepted_with_exceptions`
(exit 0) when every obligation and enforced check is satisfied but at least one finding passes only through
a baseline entry or an advisory check does not pass, and `accepted` (exit 0) otherwise. With `--json`,
usage errors (unknown options, bad arguments) still write one error document with `decision = "error"`
and exit 2. An argument containing NUL is a configuration error.

### Trust root

`check --policy-from REV` evaluates the working tree against `REV`'s policy, baselines and tools lock,
and `REV`'s `[protect] paths`, instead of the candidate's copies. Trusted Git reads ignore
replacement refs and candidate-configured fsmonitors, and a repository with an `info/grafts` file is
refused. An unauthorized candidate baseline edit can only tighten: a removed `max` entry takes effect,
a removed `min` floor keeps `REV`'s entry, added or loosened entries are ignored, and a malformed
candidate baseline keeps every `REV` entry. Protected candidate paths must be regular files reached
without following a symlink. An unauthorized change to another protected path makes the decision
`blocked` (exit 1), while `--allow-protected PATH` accepts a reviewed replacement and reports it as
authorized. The gate records protected-input, tool-payload and gate-program digests before the checks,
again after them before a prune write, and once more after a prune write, re-enumerating the
protected scope (including ignored untracked files); an added, removed or changed protected path makes
the decision `error` (exit 2). A performed prune may change its baseline path only by exactly the bytes
the gate generated. It refuses to run from a gate program inside the candidate root. The full contract
is [`docs/TRUST.md`](docs/TRUST.md); the result fields are in [`docs/SCHEMA.md`](docs/SCHEMA.md).

### Exit codes

* `0` - the command passed, possibly with exceptions;
* `1` - a check failed, an obligation was unsatisfied, a missing tool made a check unsupported, a
  baseline was malformed, a requested prune was refused or failed, or a trust run is `blocked` by an
  unauthorized protected path;
* `2` - missing or invalid configuration (including a baseline header that does not match the policy or
  two checks sharing a baseline path), invalid command line, a repository that is not the top level of a
  git work tree, an unknown inventory class or check id for pruning, a malformed tool lock, a missing
  `--policy-from` or `--changed-from` revision, a gate program inside the candidate, or a protected input, tool payload or
  gate file that changed during the run.

## Configuration

`quality-gate.toml` is read with `tomllib`. A missing file or an invalid value exits 2, naming the
file, the key, and expected versus actual. Unknown keys anywhere are configuration errors naming the key
and the allowed keys. The complete shape is:

    schema = 2

    [code]
    patterns = ["*.py", "*.sh", "*.el"]   # fnmatch on the repository-relative path
    shebangs = ["sh", "bash", "python*"]  # fnmatch on the first-line interpreter basename, after env

    [hygiene]
    max_bytes = 10485760                  # optional; this is the default

    [levels]
    required_tiers = [1]                  # optional; must contain 1; this is the default

    [classes.python]
    code = true                           # may hold code files
    description = "Python programs and tests"
    checks = ["ruff", "clones", "tests", "crap"]  # ids of [checks.ID] tables

    [classes.test]
    code = true
    description = "Python tests"
    checks = ["ruff", "clones", "tests"]

    [classes.config]
    code = false
    description = "Configuration and pinned data"

    [checks.ruff]
    adapter = "command"                   # also clones, python_tests, python_crap, verification, owners
    tier = 1                              # 1-4
    enforcement = "enforced"              # enforced or advisory
    run = ["{tool:ruff}", "check", "--no-cache", "--config", "ruff.toml", "{files}"]
    budget_seconds = 600                  # optional; this is the default
    must_match = "Success"                # optional regular expression on combined output
    # tests_pattern = "^Ran (\\d+) tests? in"  # optional; makes evidence tests
    # skipped_pattern = "skipped=(\\d+)"       # optional; with tests_pattern

    [checks.clones]
    adapter = "clones"
    tier = 1
    enforcement = "enforced"
    min_tokens = 50                       # optional; this is the default
    baseline = "quality-gate-clones.toml"

    [checks.tests]
    adapter = "python_tests"
    tier = 1
    enforcement = "enforced"
    run = ["{python}", "-m", "unittest", "discover", "-s", "tests"]
    tests_pattern = "^Ran (\\d+) tests? in"
    skipped_pattern = "skipped=(\\d+)"  # optional; one capture group
    budget_seconds = 900                  # optional; this is the default

    [checks.crap]
    adapter = "python_crap"
    tier = 1
    enforcement = "enforced"
    requires = "tests"                    # an earlier python_tests check id
    threshold = 6                         # optional; finite; this is the default
    baseline = "quality-gate-crap.toml"

    [checks.verification]
    adapter = "verification"
    tier = 1
    enforcement = "enforced"
    requires = "tests"                    # optional; earlier python_tests check(s)
    baseline = "quality-gate-verification.toml"

    [protect]                             # optional; used only with --policy-from
    paths = ["ruff.toml", "Makefile", ".github/workflows/*.yml"]

    [[not_applicable]]
    class = "python"                      # a configured class
    tier = 2                              # a required tier it has no evidence for
    reason = "tier 2 has no adapter yet"  # non-empty

    [[rule]]
    pattern = "*.py"                      # fnmatch on the repository-relative path
    class = "python"
    reason = "Python source and tests"

    [[rule]]
    pattern = "*.toml"
    class = "config"
    reason = "configuration and baselines"

This example is a shape, not a universal inventory: delete a rule if your repository has no matching
file, and add a rule for every other file it does have (for example a README, a Makefile, or a baseline).
The configuration file itself is enumerated, so it needs a rule too.

Notes:

* `pattern` is matched with `fnmatch.fnmatchcase` against the repository-relative path. `*` matches
  slashes too, so `*.py` matches Python files at any depth.
* Every enumerated file must match exactly one rule, and every rule must match at least one file.
* `reason` is mandatory and must be non-empty for every rule. `description` is mandatory and non-empty
  for every class.
* A class with `code = true` may hold code files. A code file may not be placed in a class with
  `code = false`.
* Every class named by a rule must exist in `[classes]`. A class may exist without any file.
* Every code class must list at least one check. Every code class has an obligation for each
  `[levels].required_tiers` entry; tier 1 needs `tests` evidence with at least one executed test. A
  `[[not_applicable]]` entry with a non-empty reason reports the obligation as `exempted` instead of
  `unsatisfied`.
* A command check's `run` is an argument list. The token `{files}` expands in place to the sorted files
  of every class that lists this check, as separate arguments. A selected path beginning with `-` is
  passed as `./PATH`, so it cannot become a tool option. The token `{tool:NAME}` expands to the binary
  of a tool pinned in `tools.lock.toml`; an unknown or unfetched tool makes the check `unsupported`
  and names `qg.py tools fetch`. A check using `{files}` with no selected files fails: zero inputs is
  not a pass. A command check without `tests_pattern` produces `static` evidence; with a one-group
  `tests_pattern` it produces `tests` evidence, counts executed tests as `ran - skipped`, and fails when
  none executed.
* A clone check's files come from the classes that list it. Clone baselines use the generic ratchet
  format below; the old top-level `[clones]` table and the old `[[clone]]` baseline are gone.
* A `python_tests` check needs `run` and a one-group `tests_pattern`; `skipped_pattern` is optional
  with one group. Its `{python}` token and `QG_PYTHON` export are described above.
* A `python_crap` check needs `requires`, naming one `python_tests` check declared earlier in the
  policy, and a `baseline` path. Its `threshold` defaults to 6 and must be finite. Its files come from
  the classes that list it.
* A `verification` check needs a `baseline` path. Its optional `requires` names an earlier
  `python_tests` check; without it every earlier `python_tests` check is reused. It measures executed
  tests (a `min` floor), skipped tests, `pragma: no cover` lines and `# noqa` comments for the selected
  files, without running the tests again.
* An `owners` check needs a `baseline` and declared rules. Its full-inventory scope, pattern forms,
  allowances and examples are described under [Single-owner rules](#single-owner-rules).
* A check's optional `direction` is `max` (the default: the value must not exceed its bound and
  tightening lowers it) or `min` (the value must not fall below its bound and tightening raises it).
* `[protect] paths` is a list of repository-relative paths or `fnmatch` globs that `--policy-from`
  treats as protected inputs. The list always comes from `REV`, so a candidate cannot unprotect a path;
  without `--policy-from` it is parsed and ignored. The example protects `ruff.toml` and its Ruff check
  passes `--config ruff.toml`: a candidate cannot weaken lint policy, and Ruff cannot discover a
  different configuration file elsewhere.

## The generic ratchet

An adapter that measures subjects returns findings with a `subject`, a numeric `value` and a
`location`. The policy gives the check's `threshold` (clones use `0`, so the value is the number of
extra occurrences) and, for measuring adapters, a `baseline` path. A baseline begins with the check's
identity and then holds `[[entry]]` tables:

    check = "clones"
    metric_version = "jscpd-clone-occurrences/1"

    [[entry]]
    subject = "76c7cbddc2677be2"
    bound = 1
    files = ["src/a.el", "src/b.el"]
    reason = "the two front ends deliberately mirror each other"
    expires = 2026-12-31

* `check` and `metric_version` must match the policy's check id and metric version. A missing or
  mismatched header is a configuration error; migration is a hand edit.
* Two checks may not name the same baseline path, including `./PATH` aliases. That is a configuration
  error, because pruning one would drop the other's subjects.
* `subject` identifies the measured thing (a clone fingerprint, a Python function identity, or a file's
  `PATH:<module>` outside-function subject).
* `bound` is the largest value a `max` entry accepts and the smallest value a `min` entry
  accepts. It must be finite (`inf` and `nan` are errors), and is compared unrounded; exactly at the
  bound passes.
* `reason` must be non-empty. An empty or missing reason fails the check even if the value is covered.
* `expires` is optional. A TOML date before today no longer covers its subject and is reported as
  expired. An entry expiring today still covers today.
* Adapter-specific informational keys are preserved by prune, for example clone `files`.

Thresholds, baseline bounds and measured values must be finite: a non-finite threshold or bound is a
configuration error, and a non-finite measured value makes the check `unsupported`. JSON output is
written with `allow_nan=False`.

A `max` finding without a baseline entry passes at or below its threshold; an entry is needed only
above it. A `min` metric needs an entry: without one it is unmeasured and fails, whatever its value.
A finding above its `max` threshold passes when a baseline entry for its subject exists, has not
expired, has a non-empty reason, and is within its bound; a `min` finding passes when such an entry
exists and its value is at or above the entry's bound. Such a finding keeps its raw value and is
reported with `covered_by_baseline = true`, `blocking = false`, and check `satisfied = true` even
though its raw `outcome` may remain `fail`. A finding outside both fails, naming subject, value,
threshold or bound, and location. A baseline that is absent means no exception is accepted; a file
with only the header and no entries is allowed. For verification's `max` metrics, whose threshold is
0, a missing entry therefore accepts only 0.

Resolution requires a complete scan. Each adapter reports the subject domain it measured completely: for
CRAP the selected files, and for clones the selected files each baseline entry names. A `max` entry
in that domain resolves when its subject was not found above the threshold; prune drops it. A measured
`min` entry never resolves by itself; prune raises its floor to the measured value. Any subject absent
from a completely measured domain resolves and is pruned, whatever its direction. An entry outside the
domain is reported as `unmeasured` in `unmeasured_baseline_entries` and kept; prune never drops it. A
clone entry naming a file deleted from the repository resolves; one naming a file that still exists but
was not selected stays unmeasured.

`--prune` tightens each bound to the measured value (lowers a `max` ceiling, raises a `min` floor)
and drops resolved entries. It never weakens a bound or adds an entry, and it refuses (exit 1, writing
nothing) while that check is not satisfied. A new exception enters a baseline only by hand, with a
reason. Because the clone fingerprint covers the clone's
token sequence, changing the duplicated code makes the old entry resolve and the new clone fail until a
human accepts it.

## Pinned tools and this repository

`tools.lock.toml` in the gate repository is the only place tool versions live. It pins jscpd 5.4.1,
ruff 0.17.0 and coverage 7.16.2, including the archive URL, SHA-256, payload SHA-256, archive format and
binary path.
`tools fetch` accepts `--lock FILE` for testing or for a private mirror; `file://` URLs exercise
installation without a network.

This repository gates itself with `quality-gate.toml`:

* the `python` class lists `ruff`, `clones`, `tests` and `crap`; the `test` class lists
  `ruff`, `clones` and `tests`;
* `ruff` runs the pinned binary through `{tool:ruff}` with `--no-cache` on the inventory's Python files;
  its `ruff.toml` selects `E`, `F`, `W`, `B` and `RUF100`, which reports a `# noqa` directive that
  suppresses no diagnostic, so an unused suppression is itself a lint finding;
* `clones` uses jscpd with `min_tokens = 50` and the generic baseline format;
* `tests` runs the gate's own unittest suite under the pinned coverage wheel;
* `crap` measures every function and each module/class body in `qg.py` and `quality_gate/*.py` and
  requires `tests`; `quality-gate-crap.toml` lists the subjects above 6, each with its measured bound
  and a worklist reason;
* `verification` reuses the `tests` counts and measures `# noqa` and `pragma: no cover` lines in the
  Python source; `quality-gate-verification.toml` floors the executed tests and ceilings the skips and
  exclusions measured at adoption;
* `levels.required_tiers = [1]` makes tier 1 mandatory for both code classes; the `tests` check
  provides the required `tests` evidence and each class's obligation is reported as satisfied.

`make check` is the single entry point and runs only `python3 -I qg.py check`; Ruff, the tests and
CRAP are policy checks, so the Makefile does not duplicate them.

The tests execute `qg.py` as a subprocess on disposable fixture git repositories. `tests/support.py`
starts those subprocesses through `QG_PYTHON` when the gate exports it, so the gate's own Python
programs are measured by the `crap` check. Clone-gate tests use a fake jscpd in a temporary
`QG_TOOLS_DIR`; one test runs the real pinned jscpd and fails, rather than skipping, when the tool is
not installed. Command-check tests use the real command; the real ruff test runs only when the pinned
ruff binary exists and proves enforcement: an unused import is rejected with F401, then the repaired
fixture is accepted, including files whose names contain a space and begin with `-`. `tools fetch`
tests use fixture tarballs and wheels with `file://` URLs, including wrong hashes, unknown keys, unsafe
archive members, payload mismatches and destinations outside the tools directory, and prove that a
tampered Ruff or coverage install is `unsupported` before it runs and that a full run leaves the coverage
install unchanged. Contract tests cover schema-2 typing,
obligations and exemptions, diagnostics, baseline identity and domain rules, prune reporting and
round-trips, the bounded runner's group kill and output cap, JSON usage errors, and the trust root's
baseline, policy, protected-path, prune and identity rules.

## Mutation-testing the gate

`make mutation` runs the gate's own complete unittest suite against isolated copies of its code.
It freezes the source and tests once, requires a passing unmodified suite, then runs one targeted
mutation per copy. The declared
decisions in `tests/mutate_gate.py` cover baseline bounds, threshold and expiry comparisons,
verification floors, prune refusal and exit status, gate decisions, trust-root identity and protection,
and single-owner checks. They use comparison flips, boolean negation, an opposite boolean return,
and removal of a raise. This is a selected set of faults, not an exhaustive measurement of every
possible change.

Each copied module reports a marker when it is loaded. A mutant is killed only when the same complete
test suite runs, loads that mutant, and fails an assertion without test execution or import errors.
Survivors, timeouts, missing markers, skipped tests, suite errors, invalid decisions and a failing
unmodified suite all fail the command. Each suite has a 900-second limit; independent mutant copies
run concurrently and their results are printed in declaration order. The slow mutation run is separate
from `make check` and uses the same pinned tools cache as the ordinary tests.

To protect another decision, add a named `Decision` to the list with its module, function, operator,
exact source expression or statement, and a reason. The target must identify exactly one applicable
node in that function; missing functions, ambiguous targets and decisions that yield no mutation fail
closed. Add a test that would fail for that fault, then run `make mutation` to confirm the mutant is
killed.

## Continuous integration

Every push to `main` and every pull request runs `.github/workflows/check.yml` on GitHub Actions;
the workflow can also be dispatched manually. A matrix runs the job in `debian:13` with Python 3.13
and in `ubuntu:24.04` with Python 3.12, the two supported interpreter versions. It restores the pinned
tools cache keyed on the image and `tools.lock.toml`, fetches any missing pinned tools (including the
coverage wheel), and runs `make -k check`, which is the gate's self-check: Ruff, clones, the test suite
under coverage and Python CRAP. A separate Ubuntu job runs `make mutation`.

Reproduce it locally with the same tools cache:

    export QG_TOOLS_DIR=/tmp/qg-tools
    python3 -I qg.py tools fetch
    make -k check
    make mutation

## Planned later layers

The core gate is deliberately language-agnostic; adapters measure and the core decides. Tier 1 now
includes the Python tests and CRAP adapters described above. The policy and baseline contract is fixed
at schema 2 (a trust result adds schema 3) so M4 (tier 2 properties/fuzzing) and M5 (tiers 3/4
bounded/proof) add adapters without reworking the core. The next metric layer is:

* **Emacs Lisp CRAP adapter** - reuse the same baseline and reporting model, but compute complexity and
  coverage through an Emacs batch helper, since Emacs Lisp has no maintained standalone CRAP tool.

Every layer uses the same rule: a new exception is a hand-written baseline entry with a reason, and
pruning only removes resolved entries or tightens bounds.
