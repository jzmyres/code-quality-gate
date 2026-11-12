# code-quality-gate

A reusable, offline code-quality gate for repositories that want every file classified, every
reason recorded, every check declared by policy, and every metric exception explicit and ratcheted.
Its core is one standard-library Python 3.12 command plus pinned external tools; the Python test
and CRAP adapters also load the pinned coverage wheel from the tools cache. A consuming repository pins it as a git
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

Tier 1 includes Python and Emacs Lisp tests and per-function CRAP scores. Emacs Lisp CRAP uses
the Edebug coverage collected by the test adapter.

The archived implementation can be inspected with
`git show archive/result-reuse-2026-10-30:PATH`, or by checking out that tag.
The archived owners adapter can be inspected with
`git show archive/owners-2026-10-31:PATH`.
The agent learned memory can be restored with
`git checkout archive/learned-memory-2026-11-11 -- .agents`.

## Adopting the gate

Any repository adopts the gate by meeting the same six-part protocol; this repository's own
configuration is one instance of it, and the three examples below are the others.

**Pin.** The gate is a submodule at a commit, so the revision a consumer uses is recorded in that
consumer's own tree. The [quick start](#quick-start-in-a-consuming-repository) adds it and classifies
its path.

**Policy.** `quality-gate.toml` declares the classes and rules that classify every file, `[code]`
detection, and one `[checks.ID]` table per check naming its adapter, tier, enforcement and that
adapter's keys (for a measuring adapter, its threshold and baseline), while the baseline files hold
the reasoned exceptions and `[protect]` adds further paths the trust root guards. The shape is in
[Configuration](#configuration) and [`docs/SCHEMA.md`](docs/SCHEMA.md).

**Tools.** `tools fetch` installs the pinned tools once, and every later run is offline and verifies
each install before it is used. See [tools](#tools).

**Run.** `python3 -I qg.py check` runs inventory, hygiene and every configured check in policy order,
with `--json` for one result document and `--only` for a partial run; a caller that must not trust
the candidate passes `--policy-from DIR` so the policy, baselines, tools lock and protected paths come
from a trusted directory outside the candidate. See [check](#check) and [Trust root](#trust-root).

**Result.** The run reports a decision, an exit code and, with `--json`, one machine-readable result
document. See [Exit codes](#exit-codes) and [the result contract](docs/SCHEMA.md).

**Languages.** A language plugs in through an adapter, or through the generic `command` adapter for
any tool that reports its result through an exit status. See [Configuration](#configuration).

The three consumers differ in language, in how `[code]` is detected, in their classes and checks, and
in how each one invokes the gate.

| Consumer | Language | `[code]` | Classes, then checks | How it runs the gate |
| --- | --- | --- | --- | --- |
| This repository | Python, with Emacs Lisp helpers | `*.py`, `*.sh`, `*.el`; shebangs `sh`, `bash`, `python*` | `python`, `test`, `elisp`, `elisp-suite`, `config`, `build`, `doc`; `ruff` (`command`), `clones`, `tests` (`python_tests`), `crap` (`python_crap`), `verification`, `elisp-tests`, `elisp-crap`, `elisp-compile`, `elisp-checkdoc` | `make check` runs `python3 -I qg.py check`; CI runs `make -k check` |
| A shell and Python agent harness | Shell and Python | `*.py`, `*.sh`; shebangs `sh`, `bash`, `python*` | `python`, `test`, `shell-tested`, `shell-sourced`, `shell-probe`, `config`, `build`, `doc`, `gate`; `ruff`, `shellcheck`, `json` (`command`), `clones`, `tests` (`python_tests`), `crap` (`python_crap`), `verification` | A runner gates each candidate with `--policy-from` the last landed commit |
| An Emacs Lisp editor configuration | Emacs Lisp, with shell helpers | Emacs Lisp sources and their shell helpers | `modules`, `tools`, `suites`, `startup`, `shell`, `config`, `data`, `docs`, `fixture`, `gate`; `emacs-tests`, `tooling-tests` (`elisp_tests`), `emacs-crap`, `tooling-crap` (`elisp_crap`), `elisp-compile`, `elisp-checkdoc`, `shellcheck` (`command`) | Ran beside its own older gate, recording parity first |

## Requirements

* Python 3.12 or later (the command uses `tomllib` and coverage uses `sys.monitoring`).
* Git.
* Emacs 30.1 or later for the Emacs Lisp checks.
* The pinned jscpd binary in the tools cache for clone checks.
* The pinned ruff binary in the tools cache for this repository's own command check.
* The pinned coverage 7.16.2 wheel in the tools cache for the Python adapters.

`tools fetch` downloads every pinned tool once; checks never download. The core is standard-library
Python; only the Python adapters put the pinned coverage wheel on `sys.path`. The command is intended
to run as `python3 -I qg.py`, so the consuming repository's modules cannot leak into it.

The implementation lives in the `quality_gate/` package next to `qg.py`: `policy.py` loads and validates
the configuration, `adapters.py` declares every adapter once in its descriptor and holds the only
supported-adapter registry, `files.py` resolves the repository and runs inventory and hygiene,
`tools.py` owns the pinned tool lock and extraction, `ratchet.py` owns baseline decisions and pruning,
`clones.py` measures jscpd clones, `python_tests.py` and `covrun.py` run tests under coverage,
`python_crap.py` joins coverage with `ast` complexity, `elisp_tests.py` and
`elisp/qg-elisp-child.el` run an ERT suite with Edebug coverage, `elisp_crap.py` and
`elisp/qg-elisp-complexity.el` join that coverage with the Emacs Lisp default or policy decision rules,
`elisp_lint.py` and `elisp/qg-elisp-lint.el` run byte compilation and checkdoc,
`verification.py` measures test counts and source
exclusions, `coverage_tool.py` loads and combines the pinned wheel's data,
`runner.py` is the one bounded subprocess runner, `checks.py` runs every adapter and assembles the
result, `gate_result.py` computes identity, obligations and the decision, `trust.py` owns
`--policy-from` protected inputs, effective inputs and run identity, and `cli.py` holds the
argument parser and dispatch. `qg.py` is only the entry point.

An adapter is a descriptor, not a branch in the core. It declares its name, configuration keys and
parser, run function, location coverage, number display, subject noun, failure wording,
direction rule, extra baseline keys ("extra trusted inputs"), baseline handling and budget. The parser declares each
configured check's evidence; a check produces tests exactly when that evidence includes `tests`.
The registry is the only list of supported adapters. A test adapter reports how many tests ran and
were skipped, and its outcome. A metric adapter returns findings. Verification's
prerequisite is every earlier check with `tests` evidence: `python_tests`, `elisp_tests`, and
`command` checks with `tests_pattern`.

The parent process decodes JSON evidence documents and tool results through one strict loader before
validating their adapter-specific shape. Duplicate object names at any depth are invalid, even when
their values agree; the diagnostic names the duplicated name with a bounded excerpt. `NaN`, `Infinity`
and `-Infinity` are invalid JSON too. Each reader reports these through its existing invalid-JSON path,
so a later object member cannot erase an earlier failure or measurement.

The descriptor's `subject_noun` labels subjects in failure messages: `"clone"` gives
`clone X` for an existing baseline entry and `new clone X` for a new subject. The default
empty noun prints the bare subject. Its `failure_wording` defaults to `"metric"` for
`value X exceeds threshold Y` (or minimum-bound wording). The `"occurrences"` form used
by clones prints `occurs X time(s), exceeding threshold Y`. These choices come from
the descriptor, including when it is registered under another name.

An adapter's baseline entries and findings use the same direction for each subject. A descriptor can
declare `entry_direction(subject, configured)` to choose it; otherwise its `default_direction` applies,
or the policy's configured `direction` when no descriptor default is set. This subject rule is the
only source of direction for loading, merging, evaluation and pruning. For example, verification's
rule identifies executed-test subjects as minimum floors before findings exist, so the trusted
baseline merge can preserve them even under a maximum default.

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

`--policy-from DIR` compares protected files by SHA-256 against the extracted
trusted directory. A submodule pin is not a file in that directory, so the
caller checks it. Run the gate from a trusted copy outside the candidate, as
described below.

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
    python3 -I /path/to/trusted-gate/qg.py --repo /path/to/repo inventory --list python --policy-from /path/to/trusted-copy
    python3 -I /path/to/trusted-gate/qg.py --repo /path/to/repo inventory --policy-from /path/to/trusted-copy --allow-protected quality-gate.toml

The first form prints a summary such as `inventory: 42 files match 7 rules`. `--list CLASS` prints the
files of one class, one per line, and prints nothing for a known but empty class. It exits 2 for an
unknown class, so a Makefile can use it as the single source of file lists:

    python_files=$(python3 -I qg.py inventory --list python)

`--policy-from DIR` classifies the working tree using the effective policy from an absolute path to
a trusted directory outside the candidate, with the same protected-input validation as `check`. An
unapproved change to any protected path, the policy included, blocks inventory before it prints a
summary or file list. It uses the same blocked report as `check`, naming the path and the trusted and
candidate file hashes. To use a reviewed replacement, pass `--allow-protected PATH`; repeat the option for
multiple paths. The option requires `--policy-from`. Run the gate from a trusted copy outside the
candidate, as described under [Trust root](#trust-root).

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

### Clone checks

    python3 -I qg.py check
    python3 -I qg.py check --prune clones

`check` runs every configured check, including those whose adapter is `clones`. Each clone check takes
the files of the classes that list it from the inventory, runs jscpd with its JSON and SARIF reporters
in a temporary directory, groups the SARIF clone fingerprints into subjects, and sends every fingerprint
occurrence count through the generic ratchet. The adapter owns the detection configuration: an empty
`--config`, the configured `--min-tokens`, `--min-lines 5`, `--max-size` at the hygiene limit, an ignore
pattern that matches nothing, `--no-gitignore` and a format list covering the selected extensions when
they are all known. Inline jscpd ignore directives are refused: the check reads every selected file with
the bounded regular-file reader and fails on any line containing either directive, naming the first file,
line and directive and the total count. A clone is accepted only through a baseline entry with a reason.
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

`check --prune clones` lowers each surviving bound in the `clones` check to the measured occurrence count
and drops resolved entries. It never adds an entry and never raises a bound, and it refuses (exit 1,
writing nothing) while that
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
combination and analysis. Repository roots containing spaces or non-ASCII letters are supported.
Before coverage runs, a pure rule refuses roots containing a comma, `$`, any `str.splitlines()`
separator (including LF, CR, vertical tab, U+0085, U+2028 and U+2029), or leading or trailing
whitespace, naming the root and offending character. These characters let coverage's list parser
or the analysis parser split, substitute or strip the root. A persistent test checks the rule against
the pinned coverage parser and the analysis parser; building the settings text needs no coverage import.
Repository `.coveragerc`, `setup.cfg`, `tox.ini` and
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
Combination and CRAP analysis never read that file: they use the same canonical configuration held in
memory, so a test that edits it cannot change which lines are excluded from the measurement. After the
test command the gate opens the file without following symlinks or blocking, requires a regular file,
and compares it with the canonical text. A non-regular file or difference
fails the tests check as a configuration error naming the file.
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
as the evidence for checks that require it. The core keeps one run directory for all check evidence
and removes it when the run ends, including when a check fails or the run limit stops the run. A run
directory that cannot be removed is an error (exit 2). The `worklist` command runs its checks through
the same loop, so it uses the same run directory and run limit. Pattern matching runs in an
interruptible child with its own budget.

A completed run records the parsed run and skipped counts for verification, which reports them as
its `tests:ID:executed` and `tests:ID:skipped` findings. It does not reconstruct individual test
outcomes. A failing run has `outcome = "fail"`; its reason is `command exited N`, extended with the
zero-test detail when no test executed. Unittest's own failure details, when the command printed any,
are in `diagnostics.output_tail`.

### Emacs Lisp tests

    [checks.legacy-tests]
    adapter = "elisp_tests"
    tier = 1
    enforcement = "enforced"
    suite = "tests/config-tests.el"       # required repository-relative file
    load_path = ["lisp", "emacs/lisp"]    # optional repository-relative directories, in order
    emacs = "emacs"                       # optional command on PATH or path; the default
    budget_seconds = 900                  # optional; the default

All Emacs Lisp checks require Emacs 30.1 or later. An older Emacs makes the check `unsupported`,
naming the version found and the minimum, before any suite or source file is loaded.
Truncated version-probe output or output over 128 characters before whitespace is stripped also
makes the check `unsupported`, naming the command and a bounded output excerpt. Failed version
probes use the same excerpt bound. Test and lint reports must give an `emacs_version` exactly equal
to the version accepted by that check's probe. A mismatch is `unsupported`, naming the expected
version and a bounded excerpt of the reported value before it can be used in output or `tool`.
Every lint batch is checked against the probed version, including the first batch.
The suite must be a regular file, and every `load_path`
entry must be a directory in the repository. Unknown keys and invalid configuration are errors. The
adapter instruments the files of every class listing the check with Edebug, preserving each file's
`load-file-name` context; a class may be empty. The suite itself must not be instrumented. A temporary,
renamed copy of the gate's child helper does the measuring, so the original helper may be among the
measured files without replacing the active measuring code.

The suite must load its tests and call `ert-run-tests-batch-and-exit` exactly once, as a suite ending
in `suite-guard-run` does. The helper intercepts that call and records ERT's statistics without exiting;
the suite runs once, in that same child Emacs. Expected ERT results count as passed, unexpected results
as failed, and skipped tests are counted separately. A passing check requires an exit status of zero,
a valid result, at least one executed test (`selected - skipped`), and no unexpected results.

A failed test names the test and its printed ERT condition. Zero executed tests, a missing or repeated
batch call, errors instrumenting a file or loading the suite, and an expired budget fail the check;
a timeout reports `execution = "budget"`. A missing Emacs command or a child that exits, crashes or
writes an invalid result without completing a valid measurement is `unsupported`. Errors identify the
input, and invalid-result messages state what was expected and found.

The check reports `tool` (`{"name": "Emacs", "version": "30.1"}`), its executed and skipped counts
for verification, and `definitions` in JSON; the human report includes the Emacs version. Each
definition entry, including generated lambda symbols, gives its repository-relative file, character
position, total stop points and reached stop points. This evidence is retained for a later check that
requires it.

### Emacs Lisp compile and checkdoc

    [checks.compile]
    adapter = "elisp_compile"
    tier = 1
    enforcement = "enforced"
    load_path = ["lisp", "emacs/lisp"]    # optional repository-relative directories, in order
    emacs = "emacs"                       # optional command on PATH or path; the default
    budget_seconds = 900                  # optional; the default

    [checks.checkdoc]
    adapter = "elisp_checkdoc"
    tier = 1
    enforcement = "enforced"
    load_path = ["lisp", "emacs/lisp"]
    emacs = "emacs"
    budget_seconds = 900

Each check selects the files of the classes that list it; no selected files fails. `load_path`
entries must be directories within the repository. Each check independently chooses its Emacs binary,
so a repository can use a no-X build for both. Unknown keys and invalid configuration are errors.
Both checks produce static evidence; a class still needs test evidence to satisfy its tier 1 obligation.

Compilation runs each selected file, in path order, in its own fresh `emacs -Q --batch` process with
warnings treated as errors. The generated `.elc` files go to a temporary directory that is removed
after the check, so they cannot shadow source files in the repository. A warning or error fails and
reports the file and compiler messages. Checkdoc runs once for all selected files; each issue fails
and is reported with its file, line and message.

An expired budget fails with `execution = "budget"`. A missing Emacs command or a process that does
not produce a valid report is `unsupported`. Completed measurements report the measured Emacs
version in the generic `tool` object in JSON and in the human output.

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

### Emacs Lisp CRAP

    [checks.legacy-crap]
    adapter = "elisp_crap"
    tier = 1
    enforcement = "enforced"
    requires = "legacy-tests"                  # an earlier elisp_tests check id
    threshold = 6                              # optional; finite; this is the default
    baseline = "quality-gate-crap-legacy.toml" # the file may not exist yet

`requires` must name an `elisp_tests` check declared earlier. Every file selected by this CRAP
check must belong to a class that also lists the required test check, so that it was instrumented.
An unknown, later or different-adapter reference, or a selected file without that instrumentation,
is a configuration error. If the required check did not pass, CRAP is `unsupported` with
`coverage unreliable: CHECK did not pass` and nothing is scored. The suite runs once; CRAP consumes
its recorded Edebug evidence.

Subjects are top-level `defun`, `defsubst`, `defmacro` and `cl-defun` forms in the selected files.
The subject is `PATH:NAME`, using Emacs `symbol-name`, and the location is the form's first line.
Other top-level forms are not subjects. Two definitions with the same identity in one file fail,
with both lines reported. A batch Emacs using the required check's `emacs` reads the source without
evaluating or instrumenting it; an unreadable form fails the check and names the file and error.

Complexity is 1 plus decisions in the body after the argument list. The table below is the
Emacs Lisp default; nested functions and lambdas contribute to their enclosing subject.
Quoted data is skipped. Each family uses the listed forms and counting algorithm.

| Family | Default forms | Decisions added |
|---|---|---|
| `branch` | `if`, `when`, `unless`, `while`, `dolist`, `dotimes`, `cl-dolist`, `cl-dotimes`, `cl-do`, `cl-do*`, `dolist-with-progress-reporter`, `ignore-errors`, `bound-and-true-p` | One per form. |
| `operands` | `and`, `or` | One per operand after the first. |
| `cond` | `cond` | One per clause, except a final `t`, `_` or `otherwise` clause. |
| `bindings` | `if-let`, `if-let*`, `when-let`, `when-let*`, `and-let*` | One per binding. |
| `handlers` | `condition-case`, `condition-case-unless-debug` | One per handler. |
| `case` | `pcase`, `pcase-exhaustive`, `cl-case`, `cl-ecase`, `cl-typecase` | One per clause, except a final `t`, `_` or `otherwise` clause; patterns are data and are not counted. |
| `loop` | `cl-loop` | One for the loop and one for each top-level conditional clause keyword: `when`, `if`, `unless`, `while`, `until`, `always`, `never`, `thereis`. |

An `elisp_crap` check may set one optional policy key, `decision_rules`, to a table of
symbol-name arrays. A supplied family **replaces** its default list; omitted families keep the
Emacs Lisp default. An empty array disables that family. The additional `loop_clauses` and
`catch_all` lists replace the default loop keywords above and the catch-all symbols
`["t", "_", "otherwise"]`, respectively. Catch-all exemption applies only to the final clause
of the `cond` and `case` families. An empty `catch_all` array counts every clause.

For example, this adds `my-branch` to the branching family while retaining its default forms:

```toml
[checks.legacy-crap.decision_rules]
branch = ["if", "when", "unless", "while", "dolist", "dotimes", "cl-dolist", "cl-dotimes",
          "cl-do", "cl-do*", "dolist-with-progress-reporter", "ignore-errors", "bound-and-true-p",
          "my-branch"]
```

Only the nine documented family/list keys are accepted. Entries must be non-empty, printable
symbol names without whitespace, and unique within each list. A form may belong to only one
of the seven counting families; move it by replacing both affected lists. Loop keywords and
catch-all symbols may overlap form lists. Invalid rules are configuration errors naming the
policy key and offending entry. The helper receives these effective rules as data and never
evaluates symbol names. Omitting `decision_rules` preserves all existing default scores.

Edebug entries are attributed to the first subject in the same physical file whose character span
contains the entry's position, including the start and excluding the end; symlinks and hard links
to the same file match, and entries outside every subject are ignored.
This includes lambda points in the enclosing subject. `points` is the sum of its entries' stop points,
and `hits` the sum reached. With `cov = hits / points`, CRAP is `CC^2 * (1 - cov)^3 + CC`. A subject
with no stop points is `unmeasured` and fails with `no Edebug stop point in this definition`.

Findings use `PATH:NAME` as `subject` and unrounded CRAP as `value` in the generic ratchet; the human
report rounds to one decimal. Each finding's `measurement` contains `cc`, `points` and `hits`, and the
metric version is `elisp-edebug/1`. The measured domain is the selected files, so resolved baseline
entries and `--prune` follow the same ratchet rules as Python CRAP.

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
`[A-Za-z0-9][A-Za-z0-9._+-]*`, the install destination must resolve inside the tools directory, and a
lock table accepts only `version`, `url`, `sha256`, `payload_sha256`, `binary` and `format`;
other keys are configuration errors and a missing `payload_sha256` is a lock error. An existing install
is kept only when its payload digest matches the lock; otherwise `tools fetch` replaces it.

Once a payload matches its pinned digest, `tools fetch` removes every write bit from every directory and
file in the tree and installs it read-only, and a matching existing install is made read-only the same
way. Read and executable bits stay as the archive set them, so the payload digest does not change. A
matching install is not downloaded again, so rerunning `tools fetch` hardens an existing cache without
using the network. The payloads are read-only because the cache is shared: a process that imports from one,
such as coverage, can otherwise leave bytecode files or a `__pycache__` directory behind as the cache's
owner, and a later run as another user cannot read the altered tree. With the write bits removed, such a
process cannot add files, and any install that still matches its pinned payload keeps working. Replacing a
read-only install first restores the owner's write bit on the tree's directories and then removes it.

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
`format = "deb"` marks a Debian package: the standard library reads the `ar` container, extracts its
single `data.tar.*` member and unpacks that with the same tar safety rules. A debian package's payload
digest is the declared binary's content hash; the other formats digest the whole install tree. This
format also supports locks in trusted historical revisions.

`tools path NAME` prints the expected binary path, whether or not the tool is installed, so scripts can
locate the cache. An unknown tool name exits 2.

The default tools directory is shared by every repository using the gate on this machine. Set
`QG_TOOLS_DIR` to use a different cache (for example in a container or a test).

### check

    python3 -I qg.py check
    python3 -I qg.py check --json
    python3 -I qg.py check --only ruff clones
    python3 -I qg.py check --prune clones
    python3 -I qg.py check --prune clones --prune verification
    python3 -I qg.py check --prune all
    python3 -I qg.py check --policy-from DIR
    python3 -I qg.py check --policy-from DIR --allow-protected ruff.toml

`check` runs inventory and hygiene (built in, always), then every configured check in policy order. It
prints progress on stdout and failures on stderr. When inventory fails, configured checks are reported
as skipped and the combined check still fails; hygiene still runs. Configuration errors exit 2 before
any check starts.

`check --only CHECK [CHECK ...]` runs inventory and hygiene, then exactly those checks and the checks
they require, in policy order. Nothing else runs. An unknown or repeated check id is a usage error
(exit 2) naming it, before any check runs. A partial run never prunes and never runs under a trusted
directory: `--only` with `--prune` or with `--policy-from` is a usage error (exit 2) naming both
options, before any check runs. A partial run is never a verdict on the tree; use the full `check` for
that.

`check --json` writes exactly one JSON result to stdout and sends all human-readable lines to stderr.
The result schema is `2`; a `--policy-from` result is schema `3` and adds `trust` (see below). Its
top-level keys are `schema`, `gate_version`, `revision`, `dirty`, `policy_sha256`, `decision`,
`checks`, `obligations` and `prune`; a `decision = "error"` document also has `error`, and a
`check --only` document has `selected`.

`checks` contains inventory, hygiene and every configured check, in that order. Each check has `id`,
`kind` (`inventory`, `hygiene` or `check`), `tier` (null for built-ins), `enforcement`, `adapter`,
`evidence` (the evidence names the adapter produces), `metric_version`, `execution`, `outcome`,
`satisfied`, `duration_seconds`, `budget_seconds`, `diagnostics`, `findings`,
`resolved_baseline_entries`, `unmeasured_baseline_entries`, `location_coverage` and `reason` (a structured explanation of
a non-passing adapter verdict, null otherwise); a measuring check may also carry a `measurement`
object (for example `{"tests": 12}`). Any adapter can report its measured tool identity as
`tool`, an object with string `name` and `version` fields; it is absent when no identity is reported.

`execution` is `completed`, `budget` (a subprocess budget expired), `signal` or `error`.
`outcome` is the adapter's raw verdict: `pass`, `fail`, `unsupported` or `error`; later
tier-3 adapters add `proved`, `no_counterexample` and `unknown`. `satisfied` is true when the
policy obligation is met after baselines and enforcement: a finding inside a valid baseline keeps
`outcome = "fail"` and sets `satisfied = true`. Advisory checks do not block the whole-tree
judgement. Missing evidence is `unsupported`, never `pass`. The policy checks have one wall-clock
run limit: the sum of every check's configured budget (command, Python test and Emacs Lisp checks use
their configured budgets; clone, CRAP and verification checks each have 600 seconds) plus a
300-second allowance. The allowance covers in-process analysis over bounded input and keeps the
backstop from racing a subprocess budget, which must end its check and never the run. The check loop
arms one timer before the first check and restores the previous `SIGALRM` handler after the last,
releasing test evidence in between. A run that exceeds the limit ends with `decision = "error"`
(exit 2) and a message naming the limit, the current check and step; a subprocess still running at
that point is killed with its process group.

`diagnostics` carries `argv`, `exit_code` or `signal`, `output_bytes`, `output_tail` (at most 4 KiB),
`output_truncated` and, when execution failed, `error`. Every subprocess the gate starts (git
enumeration and identity, command checks, jscpd and test runs) uses one bounded runner: it starts in its
own process group, is terminated at its own budget and is reaped. The budget is the smaller of the
requested seconds and the current check's remaining time. At a check's budget it sends SIGTERM to the
group followed immediately by SIGKILL; a subprocess outside a check has a five-second grace before
SIGKILL. An interrupt that ends the run kills the group immediately. A group whose remaining members
are all zombies counts as stopped, because a zombie cannot run and a container's PID 1 may never reap
it. Termination and reaping can add a small amount of time after the budget. Check output is captured
up to 1 MiB; later bytes are counted and discarded. A consumer therefore never has to parse stderr to
learn why a check failed.

A partial run's `selected` lists the check ids that ran, in policy order, prerequisites included. It
has no `selected` key on a full run. A partial run evaluates no obligations, so its `obligations` is
empty.

A finding has `subject`, its raw `value`, `bound` (or null when no baseline entry exists), `threshold`,
`baseline_reason` (or null), `covered_by_baseline`, `blocking`, `location`, `locations` and `expired`; baseline
errors carry `error`. Python CRAP findings carry `cc`, `statements`, `executed` and `excluded_lines` in
`measurement`; Emacs Lisp CRAP findings carry `cc`, `points` and `hits`. Unrounded values are compared: exactly at a bound passes, and a value `0.1` above the
bound fails.

### worklist

    python3 -I qg.py worklist
    python3 -I qg.py worklist --json
    python3 -I qg.py worklist crap
    python3 -I qg.py --repo /path/to/repo worklist crap elisp-crap

`worklist` ranks the debt a reasoned baseline still carries. With no `CHECK` it covers every
configured check that has a baseline and a threshold; with ids it covers exactly those checks. For
each selected check it runs the check and every check it requires, in policy order, using the same
producer selection as `check`, including every earlier test producer needed by verification when
`requires` is omitted. The checks run in the repository itself, as with `check`, and may write what `check` writes.
The worklist no longer runs its checks in a temporary copy.

The report lists every `max` baseline entry whose
bound is above the check's threshold, ranked by churn times the current measured value, highest first.
Churn is the complete number of commits `git log --follow` reports for the file in the finding's
location; the filename is treated literally. A row gives churn, bound, current value, churn x value,
subject and location. Unrounded values are compared; the human report displays them to one decimal.

Alongside that debt, the report lists each measured `min` entry's bound, current value and slack
(current value minus bound). These floors do not need a source location or a churn count. `--json`
adds a `slack` array containing `check`, `subject`, `bound`, `value` and `slack` for each floor;
the existing `rows` for `max` entries are unchanged.

The ratchet distinguishes entries outside the measured domain from subjects absent from a completed
measurement. A missing `max` subject outside the domain is a note reading `unmeasured`; an absent
subject is a note reading `no longer exists`. A floor outside the measured domain is a note reading
`not measured`. A finding whose file Git cannot follow is a note reading `churn not measured`.
`--json` writes one machine-readable document of rows and notes; its schema is in `docs/SCHEMA.md`.

The command exits 0 after writing the report. It exits 1, ranking nothing, when a selected check or one
it requires does not pass, or when Git fails or its output is truncated; the error names the problem. It exits 2 for an unknown or repeated check id, or a check with no baseline
or threshold.

### Locations

The `python_crap`, `elisp_crap` and `clones` adapters provide complete locations: respectively the entire
function range (including Python decorators) and both ranges of every clone in a fingerprint group.
CRAP's module subject uses the span from its first to last outside-function node; that conservative
span can include intervening functions. Verification supplies every inline and file-wide suppression
line, one location per directive, but its test-count metrics have no source location. Command checks,
Python test results, inventory and hygiene have no complete source locations.

Each result's `location_coverage` is `complete`, `partial` or `none`. A finding's `locations` is an
array of `{path, start_line, end_line}` ranges, or null when its locations are incomplete.
`covered_by_baseline` describes the whole-tree ratchet.

`obligations` has one entry per code class and required tier with `class`, `tier`, `status`
(`satisfied`, `exempted` or `unsatisfied`), `required` (the evidence names the tier demands), `checks`
(the checks that counted) and `reason` (for an exemption; otherwise null). Tier 1 needs a satisfied
enforced check producing `tests` evidence with at least one executed test, so a lint-only class leaves
tier 1 unsatisfied and rejects. Tier 2 needs `properties` or `fuzzing`; tiers 3 and 4 reserve
`bounded` and `proof`. No version-2 adapter produces those evidence names yet, so a required tier above
1 is exempted by a `[[not_applicable]]` entry until its adapter lands.

`prune` reports `requested` (the supplied ids or `all`), `performed` and `reason`. Repeat
`--prune ID` to tighten several baselines in one run, or use `--prune all` to select every configured
baseline. Each selected check must be satisfied; `all` also requires every other check to be satisfied.
The gate validates the entire request before writing, so a failed check refuses all requested prunes.
An unknown id or a check without a baseline exits 2. A refused or failed prune makes the command exit 1
and leaves `decision` reporting the gate evaluation. If a write itself fails, earlier writes in the
same request may already have completed. `--prune` with `--policy-from` is a usage error (exit 2)
naming both options, before any check runs; `--prune` without `--policy-from` is unchanged.

The decision is `error` (exit 2) for invalid policy, usage or configuration, when the run exceeds
its limit, or when the run directory cannot be removed, `rejected` (exit 1) when
inventory, hygiene, any enforced check or any obligation is not satisfied, `partial` (exit 0) when a
`--only` run's inventory, hygiene and every enforced check that ran are satisfied, and
`accepted_with_exceptions` (exit 0) when every obligation and enforced check is satisfied but at least
one finding passes only through a baseline entry or an advisory check does not pass, and `accepted`
(exit 0) otherwise. A partial run evaluates no obligations, so its rejection depends only on the checks
that ran. With `--json`,
usage errors (unknown options, bad arguments) still write one error document with `decision = "error"`
and exit 2. An argument containing NUL is a configuration error.

### Trust root

`check --policy-from DIR` evaluates the working tree against the policy, baselines, tools lock and
`[protect] paths` from an absolute path to a trusted directory instead of the candidate's copies. The
directory is an extracted tree outside the candidate; it is the only trusted source. Any other value,
including a revision or a relative path, is a usage error naming it. A missing directory or one inside
the candidate root is also a usage error. The gate reads the trusted files with plain file reads, never
follows a symlink inside `DIR`, and reads nothing from the candidate's `.git` for them. Make the copy
outside the candidate and make it read-only:

    git -C TRUSTED_REPO archive REV | tar -x -C DEST
    chmod -R a-w DEST

A candidate cannot commit a protected change the trusted gate did not apply. An unauthorized
candidate baseline edit can only tighten: a removed `max` entry takes effect, and a removed `min`
floor keeps the trusted entry. An entry that tightens one field and loosens another takes effect only
in the tightened field, so the loosened part is not applied. A baseline whose every candidate entry is
at least as strict as its trusted entry in every field is `tightened` and does not block; one whose
added or loosened entries, or malformed content, the run did not apply is `blocked` and lists the
unapplied entries in `ignored_entries`, and so is a byte change with identical entries, such as a
comment, which has none. An unauthorized change to the policy, the tools lock or any other
protected path makes the decision `blocked` (exit 1) too, naming the path, while `--allow-protected
PATH` accepts a reviewed replacement and reports it as authorized. With an authorized policy, only that
policy is checked against the candidate's files; the trusted policy then sets only the protected scope.
Protected candidate files must be reached without following a symlink. The trusted directory compares
files and globs only, so the caller checks a submodule pin. The gate records protected-input, tool-payload
and gate-program identities before the checks and again after them, re-enumerating the protected scope
(including ignored untracked files); an added, removed or changed protected path makes the decision `error`
(exit 2). `--prune` with `--policy-from` is a
usage error (exit 2).
It refuses to run from a gate program inside the candidate root. A trust result reports `trust.path`
and `trust.digest`. The full contract is [`docs/TRUST.md`](docs/TRUST.md); the result fields are in
[`docs/SCHEMA.md`](docs/SCHEMA.md). Test-process measurements are trusted, and a consumer's pinned gate
commit is a candidate input until its submodule path is handled by the caller. See the
[out-of-scope limits](docs/TRUST.md#out-of-scope) and their mitigations.

### Exit codes

* `0` - the command passed, possibly with exceptions;
* `1` - a check failed, an obligation was unsatisfied, a missing tool made a check unsupported, a
  baseline was malformed, a requested prune was refused or failed, or a trust run is `blocked` by an
  unauthorized protected path;
* `2` - missing or invalid configuration (including a baseline header that does not match the policy or
  two checks sharing a baseline path), invalid command line, a repository that is not the top level of a
  git work tree, an unknown inventory class or check id for pruning, a malformed tool lock, a missing
  `--policy-from` trusted directory, a trusted directory inside the candidate, a gate program inside
  the candidate, or a protected input, tool payload or gate file that changed during the run.

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
    adapter = "command"                   # see adapter sections above for other choices
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
    requires = "tests"                    # optional; an earlier test-producing check
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
  none executed. Its recorded ran and skipped counts are available to verification.
* A clone check's files come from the classes that list it. Clone baselines use the generic ratchet
  format below; the old top-level `[clones]` table and the old `[[clone]]` baseline are gone.
* A `python_tests` check needs `run` and a one-group `tests_pattern`; `skipped_pattern` is optional
  with one group. Its `{python}` token and `QG_PYTHON` export are described above.
* A `python_crap` check needs `requires`, naming one `python_tests` check declared earlier in the
  policy, and a `baseline` path. Its `threshold` defaults to 6 and must be finite. Its files come from
  the classes that list it.
* An `elisp_tests` check needs a repository-relative `suite` file; `load_path`, `emacs` and
  `budget_seconds` are optional. Its measured files come from the classes that list it.
* `elisp_compile` and `elisp_checkdoc` select files from the classes that list them. Their `load_path`,
  `emacs` and `budget_seconds` settings are optional and independent for each check.
* An `elisp_crap` check needs `requires`, naming an earlier `elisp_tests` check, and a `baseline` path.
  Its `threshold` defaults to 6 and must be finite. Every selected file's class must list both checks.
* A `verification` check needs a `baseline` path. Its optional `requires` names an earlier check with
  `tests` evidence: `python_tests`, `elisp_tests`, or a `command` with `tests_pattern`.
  A reference to a check without test evidence is a configuration error; for a command the error
  identifies its missing `tests_pattern`. Without `requires` every earlier test-producing check is used. It
  measures executed tests (a `min` floor) and skipped tests from those results, and `pragma: no cover`
  lines, inline `# noqa` comments and file-wide lint suppressions for the selected Python files, without
  running the tests again. An empty Python selection has nothing to scan, but the test counts still come
  from every producer; without valid producer results the counts are not measured and the check is
  unsupported. File-wide directives
  are counted separately as `exclusions:FILE:file-suppression`: Ruff's `# ruff: noqa`, with or without
  codes, `# ruff: file-ignore[...]`, Flake8's `# flake8: noqa` forms, and isort's `# isort: skip_file`
  (also recognized by Ruff). Directives are recognized in comment tokens, so text inside strings does
  not count. An added file-wide suppression fails unless a baseline entry with a non-empty reason covers
  its count; removing all such suppressions from the file resolves that entry. Replacing inline
  suppressions with a file-wide directive cannot use the inline baseline entry.
* A check's optional `direction` is `max` (the default: the value must not exceed its bound and
  tightening lowers it) or `min` (the value must not fall below its bound and tightening raises it).
* `[protect] paths` is a list of repository-relative paths or `fnmatch` globs that `--policy-from`
  treats as protected inputs. The list always comes from the trusted directory, so a candidate cannot
  unprotect a path; without `--policy-from` it is parsed and ignored. The trusted directory compares
  protected files and globs only, so the caller checks a submodule pin. The example protects `ruff.toml`
  and its Ruff check
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
* An entry and its finding use the adapter's direction for their subject, whether or not a finding
  exists yet. The adapter's per-subject rule, descriptor default or check's configured `direction`
  decides it. Evaluation, pruning and the trusted merge all use that same direction.
* `reason` must be non-empty. An empty or missing reason fails the check even if the value is covered.
* `expires` is optional. A TOML date before today no longer covers its subject and is reported as
  expired. An entry expiring today still covers today.
* Extra informational keys declared by the adapter descriptor are lists of strings and are
  preserved by prune, for example clone `files`. Empty-reason diagnostics list present,
  nonempty extras in the descriptor's declared order.

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

`tools.lock.toml` in the gate repository pins the external check tools: jscpd 5.4.1,
ruff 0.17.0 and coverage 7.16.2, including the archive URL, SHA-256, payload SHA-256,
archive format and binary path.
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
* `verification` uses the `tests` counts and measures inline `# noqa`, file-wide lint suppressions and
  `pragma: no cover` lines in the Python source; `quality-gate-verification.toml` floors the executed
  tests and ceilings the skips and exclusions measured at adoption;
* the `elisp` class lists `elisp-tests`, `elisp-crap`, `elisp-compile` and `elisp-checkdoc`, so this
  repository gates its Emacs Lisp helpers with the gate's own Elisp checks; the ERT suite
  `tests/elisp/qg-elisp-tests.el` exercises the complexity, child and lint helpers, `elisp-crap` scores
  every helper function from that run at or below CRAP 6 with no baseline entries, and the suite's
  `elisp-suite` class lists only `elisp-compile` and `elisp-checkdoc`, so the suite is never instrumented;
* `levels.required_tiers = [1]` makes tier 1 mandatory for every code class; the `tests` check
  provides the Python classes' required `tests` evidence, `elisp-tests` provides it for `elisp`, and the
  `elisp-suite` obligation is exempted because the suite is measured only by its own run.

`make check` is the single entry point and runs only `python3 -I qg.py check`; Ruff, the tests and
CRAP are policy checks, so the Makefile does not duplicate them.

The tests call the gate's command, `quality_gate.cli.main`, in-process on disposable fixture git
repositories. `tests/support.py`'s `run_qg` sets `os.environ`, the working directory and
stdout/stderr for the call, uses a fixture gate copy's lock through `tools.lock_override`, restores
the temporary-directory cache and the run-limit signal handler, and turns an unexpected exception
into exit 1 with its traceback. Tests start `qg.py` as a process through `run_qg_process` only
where the property belongs to the process: the modified gate copies in `tests/test_trust.py`
(`test_gate_new_extension_files_appear_in_identity_with_digests`,
`test_gate_identity_excludes_bytecode_cache_directories` and
`test_gate_elisp_helper_changed_during_check_is_an_identity_error`), whose subject is a gate run
from another directory, and the equivalence test in `tests/test_support.py`, which runs both
paths. A test that needs to patch the gate patches it in-process around `run_qg`; a
`run_qg_process` call on a fixture gate copy starts the original `qg.py` through
`fixture_runner`, so every gate it starts runs the measured `quality_gate` package. The
evidence-cleanup helpers `run_evidence_check` and
`run_worklist_with_evidence` start `qg.py` themselves to run it with fatal resource warnings, and
`tests/test_python_crap.py`'s `test_settings_stay_canonical_after_validation` starts a modified
gate copy directly. `QG_PYTHON` starts the `run_qg_process` and evidence-cleanup subprocesses when
the gate exports it, so the gate's own Python programs are measured by the `crap` check. Clone-gate
tests use a fake jscpd in a temporary
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
It freezes the source and tests once. The probe is the only unmutated run of the complete suite: it
is instrumented so each declared target records a "reached" event naming its decision and the current
test; the marker file records only reached events. The probe must pass with no errors, skipped tests,
expected failures or unexpected successes, and it must run at least one test; otherwise the command
fails before any mutant runs. Its test IDs give suite order and its reached events give each target's
reaching tests. The runner exposes the current test ID through the environment, so hits from child
processes are attributed to the test that started them; a hit that cannot be attributed is recorded
as unattributed. The declared decisions in `tests/mutate_gate.py` cover baseline bounds, threshold
and expiry comparisons, verification floors, prune refusal and exit status, gate decisions, trust-root
identity and protection, and the rule that an ERT run must execute a test. They use comparison flips,
boolean negation, an opposite boolean return, and removal of a raise. This is a selected set of faults,
not an exhaustive measurement of every possible change.

Each mutant's copy is first imported with `python3 -I`, with the copy's root first on `sys.path`; a
module that fails to import makes the mutant `invalid`, which fails the run. A valid mutant then runs
only the tests the probe recorded as reaching its target, in suite order and with failfast. Any of
those tests that fails, errors or unexpectedly succeeds kills the mutant, wherever its assertion
sits: in the test body, a fixture, a cleanup, a subtest or a child process. A run that times out,
writes no valid report, exits inconsistently with its report, skips a test or does not execute the
selected tests in order is an error or timed out, never a kill. All selected tests passing means the
mutant survived. A mutant that no test reached survives with "no test reached its target" and runs no
suite; one with unattributed hits runs the complete suite with the same kill, survival and error
rules.

For every kill, the runner reruns exactly the non-passing test IDs on a fresh pristine copy. If any
of them fails there too, the outcome is `unstable` rather than `killed`: the test is order-dependent
or flaky and must be fixed, and the run fails.

Each mutant's line names the path that decided it: the number of selected tests, "no test reached its
target" or "full suite (unattributed hits)", and the final summary reports the probe time and the
total time. Each suite has a 900-second limit and the process group is killed on timeout. Independent
mutant copies run concurrently with two workers by default, because four on this four-CPU host shared
with agents coincided with swap exhaustion. Results are printed in declaration order. The slow
mutation run is separate from `make check` and uses the same pinned tools cache as the ordinary tests.
The command passes only when every outcome is `killed` and there are no errors.

This design changes these guarantees:

- Dropped: a kill is only a failing assertion, never an error; fixture failures are never kills; each
  selection is checked once unmutated.
- Kept: survivors fail the run; skipped tests fail the run; exact AST target matching; selected tests
  run in suite order.

To protect another decision, add a named `Decision` to the list with its module, function, operator,
exact source expression or statement, and a reason. The target must identify exactly one applicable
node in that function; missing functions, ambiguous targets and decisions that yield no mutation fail
closed. The ordinary suite checks that every declared decision resolves, so a change that moves a
target fails `make check` too. Add a test that would fail for that fault, then run `make mutation` to
confirm the mutant is killed.

## Continuous integration

Every push to `main` and every pull request runs [`.github/workflows/check.yml`](.github/workflows/check.yml)
on GitHub Actions; the workflow can also be dispatched manually. Jobs use the `ubuntu-latest`
runner with the containers below.

The check matrix and separate mutation job use these environments:

| Job | Container | Emacs | Python | Mirrors |
| --- | --- | --- | --- | --- |
| `debian13` | `debian:13` | Debian's 30.1 | Debian's 3.13 | The local Debian 13 machine |
| `ubuntu2604` | `ubuntu:26.04` | GNU release 30.1 | Standalone 3.12.13 | The planned Docker image, using the local default Python version |
| `mutation` | `debian:13` | Debian's 30.1 | Debian's 3.13 | The local environment for mutation testing |

Ubuntu 26.04 ships Emacs 30.2 and Python 3.14, so its job installs both runtimes from pins.
The workflow's top-level `env` holds their versions, download URLs and SHA-256 digests. Each
archive is verified before unpacking; Emacs is built for batch use without GUI or native compilation.
Both installations are cached by image, architecture, version and digest. Every job asserts its
runtime versions before running checks; the standalone Python assertion includes the patch version.
The workflow itself is proven only by the CI run after landing, which the designer checks.

The job setup (packages, pinned runtimes and cache restores) runs as the container's root. Each job
then creates an unprivileged `gate` user and gives it ownership of the checkout and `QG_TOOLS_DIR`;
fetching pinned tools, the gate and the mutation run as that user through `runuser`. A restored
tools cache keeps its modes and changes only ownership, so read-only payloads stay read-only.

The check matrix restores the pinned tools cache keyed on the environment name, architecture and
`tools.lock.toml`, fetches any missing tools (including the coverage wheel), and runs `make -k check`:
Ruff, clones, the test suite under coverage, Python CRAP and the Emacs Lisp checks. The separate
Debian 13 job restores the same Debian tools cache and runs `make mutation`.

Step timeouts are fixed at about five times the longest run observed as of 2026-10-31: 60 minutes
for the gate, 15 for the cold Emacs build and 120 for the mutation step, and each job adds 10 minutes
of setup for packages, checkout, cache operations, Python installation and fetching tools, giving 70
minutes for Debian, 85 for Ubuntu and 130 for mutation. Raise these bounds if the program grows; a
bound comfortably above the normal duration is enough to stop a hung job.

Reproduce it locally with the same tools cache:

    export QG_TOOLS_DIR=/tmp/qg-tools
    python3 -I qg.py tools fetch
    make -k check
    make mutation

## Planned later layers

The core gate is deliberately language-agnostic; adapters measure and the core decides. Tier 1 now
includes the Python and Emacs Lisp tests and CRAP adapters described above. The policy and baseline contract is fixed
at schema 2 (a trust result adds schema 3) so M4 (tier 2 properties/fuzzing) and M5 (tiers 3/4
bounded/proof) add adapters without reworking the core.

Every layer uses the same rule: a new exception is a hand-written baseline entry with a reason, and
pruning only removes resolved entries or tightens bounds.
