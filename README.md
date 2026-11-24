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
* **result** - `check --json` writes one machine-readable schema-3 result that separates execution,
  the adapter's raw outcome and policy satisfaction, and carries diagnostics, obligations and prune
  reporting; `--policy-from` adds a `trust` object and result schema 4.

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
| This repository | Python, with Emacs Lisp helpers | `*.py`, `*.sh`, `*.el`; shebangs `sh`, `bash`, `python*` | `python`, `test`, `elisp`, `elisp-suite`, `config`, `build`, `doc`; `ruff` (`command`), `clones`, `tests` (`python_tests`), `crap` (`python_crap`), `shape` (`python_shape`), `variant-dispatch` (`variant_dispatch`), `verification`, `elisp-tests`, `elisp-crap`, `elisp-compile`, `elisp-checkdoc` | `make check` runs `python3 -I qg.py check`; CI runs `make -k check` with `QG_DIFF_BASE` naming the pushed change |
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
`python_crap.py` joins coverage with `ast` complexity, `python_mutation.py` mutates changed
functions and refuses a change whose tests survive, `variant_dispatch.py` refuses a
vocabulary listed in two places and a format guessed by trial, `elisp_tests.py` and
`elisp/qg-elisp-child.el` run an ERT suite with Edebug coverage, `elisp_crap.py` and
`elisp/qg-elisp-complexity.el` join that coverage with the Emacs Lisp default or policy decision rules,
`elisp_lint.py` and `elisp/qg-elisp-lint.el` run byte compilation and checkdoc,
`verification.py` measures test counts and source exclusions,
`source_chars.py` rejects invisible control characters in selected source,
`coverage_tool.py` loads and combines the pinned wheel's data,
`runner.py` is the one bounded subprocess runner, `checks.py` runs every adapter and assembles the
result, `gate_result.py` computes identity, obligations and the decision, `trust.py` owns
`--policy-from` protected inputs, effective inputs and run identity, and `cli.py` holds the
argument parser and dispatch. `qg.py` is only the entry point.

An adapter is a descriptor, not a branch in the core. It declares its name, configuration keys and
parser, run function, location coverage, number display, subject noun, failure wording,
direction rule, extra baseline keys ("extra trusted inputs"), baseline handling, budget and whether it
runs a test suite (`runs_suite`, described with `check` below). The parser declares each
configured check's evidence; a check produces tests exactly when that evidence includes `tests`.
The registry is the only list of supported adapters. A test adapter reports how many tests ran and
were skipped, and its outcome. A metric adapter returns findings. Verification's
test prerequisite is every earlier check with `tests` evidence: `python_tests`, `elisp_tests`,
and `command` checks with `tests_pattern`; a policy lists every `python_crap` check before its
`verification` check, and checks run in policy order.

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
check fails. Add a new exception by hand, with a reason. A baseline whose entries all resolve keeps
its header and no entries, and prune prints that the baseline is now empty, so the check's `baseline`
key and file can then be deleted by hand.

### Environment access

Use `env_surface` to enforce a policy for environment reads and writes. Give
each allowed name or prefix an owner, such as
`allow = [{ name = "HOME", owner = "POSIX" }]`, and list the check in the
classes it should scan. A computed access has no literal name and always fails.
The Python AST and Emacs Lisp reader handle `.py`, Python shebang scripts, and
`.el` files. Any selected file without a driver, including a shell script,
fails with its path in the report.

The Python reader follows direct local aliases such as `env = os.environ`.
A wildcard import from `os` produces a computed finding at the import line.

The Emacs Lisp reader reports `getenv` reads, `setenv` writes, and one
write per binding in `with-environment-variables`. It reports writes to
`process-environment` through `add-to-list`, `push`, `setq`, and `let` or
`let*` bindings. Other references to `process-environment` are reads. A
literal `NAME=value` supplies the name. A reference to `initial-environment`
produces a computed read of the entire environment.

This command prints the inventory for a policy that declares the check.

```sh
python3 -I qg.py check --only env_surface --json
```

The `measurement.findings` array includes allowed accesses. See the
[policy schema](docs/SCHEMA.md#environment-access-policy) for the full table.

### Source comments

Use the `comments` check to reject comments in all files of the classes that
list it. Python's tokenizer reads `.py` files and Python shebang scripts. Batch
Emacs reads `.el` files. The shell driver reads names ending in `.sh` or `.bash`.
It uses inventory's shebang reader and gives `sh` and `bash` shebangs priority
over filename suffixes. The shared `quality_gate/shell_syntax.py` module sends
source bytes to the pinned shfmt from the gate's tools directory under the
check's remaining deadline. Parser errors, timeouts, and missing drivers fail
the check and name the file. The failure reason lists findings and file errors
in path and line order, with file errors at line 0.

The check matches each exception against the whole physical line. `NAME.el`
must be the file's own base name, and `SUMMARY` is the library summary.

| Language | Position | Exact form | Authority |
| --- | --- | --- | --- |
| Python | Line 1 | `#!` followed by an interpreter path and optional arguments | Kernel shebang |
| Shell | Line 1 | `#!` followed by an absolute interpreter path and optional arguments | Kernel shebang |
| Emacs Lisp | Line 1 | Shebang naming `emacs` directly or as the first argument to `env` | Kernel shebang |
| Emacs Lisp | Line 1, or line 2 after an allowed shebang | `;;; NAME.el --- SUMMARY  -*- lexical-binding: t; -*-` | Emacs library header and file-local cookie |
| Emacs Lisp | Header block | `;;; Commentary:` | `lm-commentary-start` |
| Emacs Lisp | After Commentary | `;;; Code:` | `lm-code-start` and checkdoc |
| Emacs Lisp | Last non-blank line | `;;; NAME.el ends here` | `checkdoc-file-comments-engine` |

Use a docstring for usage and the README or commit message for rationale and
history. See the [policy schema](docs/SCHEMA.md#source-comments-policy) for the
check configuration and result.

### Module graph

The `module_graph` adapter measures Python and Emacs Lisp files in the named inventory classes.
Python imports anywhere in a file count, including function bodies and `TYPE_CHECKING` blocks.
Files with a Python shebang are read as Python even when their names end in `.el`.

Python recognizes two forms for `path-load` edges.

- `import runpy` followed by `runpy.run_path(...)`, with a string literal path passed
  as the first positional argument or as `path_name=`.
- `import importlib.util` followed by `importlib.util.spec_from_file_location(...)`,
  with a string literal path passed as the second positional argument or as `location=`.

The exact import must appear directly in the module body before the call's enclosing
top-level statement. The whole file must have a single binding for the loader's head
name. A star import or a repository module or package that provides the head name also
makes the loader unresolved. Arguments must match the loader's signature and use no
unpacking. Relative paths are resolved from the calling Python file's directory and
can identify a measured module in any language.

Every other name or attribute reference ending in `run_path` or
`spec_from_file_location` produces one unresolved diagnostic in `outside_extractor`,
with the file, the line where the loader is spelled, and the reason. Each
`from ... import` of either name also produces one diagnostic at the import statement,
with or without an alias. References in variable, parameter, and return annotations,
type aliases, and type parameter bounds and defaults are always unresolved. When
code assigns or destructures a loader into an alias, the diagnostic points to the
original loader spelling. Later references using only the alias and dynamic namespace
writes are outside the static analysis.

The batch Emacs reader uses Emacs's load-time coding and line-ending detection and applies
file-local `read-symbol-shorthands`. Emacs's load loop determines when the file ends
cleanly. The extractor reads each top-level form once in sequence and
extracts `(require 'FEATURE)` at the top level or directly inside a top-level
`eval-when-compile`. Locations use the positions of the `require` and `provide` head
symbols from that read. With an omitted filename or explicit `nil`, Emacs matches
interned feature symbols by identity. The target is the unique measured file with a
matching literal `(provide 'FEATURE)` at the top level or directly inside a top-level
`progn`. With no measured provider, the feature is treated as external and produces
neither an edge nor a report entry.

In `(require 'FEATURE "FILE")`, every slash-delimited component of `FILE` must be
nonempty, differ from `.` and `..`, and contain only ASCII letters, digits, `.`, `_`,
`+`, and `-`. The graph compares `FILE.el` and `FILE` exactly against the measured
repository-relative paths. One match produces an edge. Zero or two matches produce
one `outside_extractor` entry with the require's file and line.

Multiple measured providers, computed require operands, and literal filenames
outside the allowlist also produce one located `outside_extractor` entry per require.
Uninterned features in requires or providers are reported there as well.
The Emacs reader refuses reader labels (`#N=` and `#N#`) so each positioned head
identifies a single source occurrence. An error in coding or file-local variable
processing, a reader label, or any other reader error, including EOF inside a form,
refuses the whole file. The graph reports one `outside_extractor` entry naming the file
and the line where Emacs reported the error. It discards the file's outgoing edges and
feature providers and continues measuring the other files.
Requires nested elsewhere, including in functions or quasiquote unquotes, give no edge.
`load` and `load-file` also give no edge. An Emacs launch failure or a Python
syntax error produces a check error that names the affected file.

The graph reports one finding per strongly connected component with at least two modules
and shows a shortest cycle with its edge locations. It also reports dependencies between
distinct test suites. Suite patterns match repository-relative paths, so suites can share
support modules outside those patterns.

Rule 3 reports each dependency from a non-program module to a policy-declared program.
Each finding names both modules and gives the source file and line of the edge.
The optional `programs` list uses the same repository-relative path matching as `suites`.
Only matching modules are programs. Test files are exempt as sources for this rule.

For a repository with `python`, `test`, and `elisp` inventory classes, add this check and list
`module-graph` in those classes' `checks` arrays.

```toml
[checks.module-graph]
adapter = "module_graph"
tier = 1
enforcement = "enforced"
classes = ["python", "test", "elisp"]
suites = ["tests/test_*.py"]
programs = ["tools/*.py"]
```

Run the configured check with

```sh
python3 -I qg.py check --only module-graph
```

The check allows zero findings, so any finding fails the gate under this policy.
The JSON result includes the sorted modules and edges, each edge's kind (`import`, `path-load`, or `require`),
and fan-in and fan-out for each module.

Follow-ups cover subprocess dependencies (`GATE-MODULE-GRAPH-SUBPROCESS`) and
Shell dependency extraction (`GATE-MODULE-GRAPH-SHELL`).

### Source-character checks

    [checks.source-chars]
    adapter = "source_chars"
    tier = 1
    enforcement = "enforced"
    scope = "all"                       # all | changed
    base = "HEAD^"                      # used when scope = "changed"
    include_untracked = true            # used when scope = "changed"
    allow = ["tab", "lf", "crlf", "form-feed-at-line-start"]
    deny = ["nul", "bare-cr", "esc", "del", "c1", "bidi"]
    baseline = "quality-gate-source-chars.toml"  # optional; must name an existing file

`source-chars` reads the files of every class that lists it and scans their actual characters. Only a
regular file is read: a tracked symlink, FIFO, socket or device is reported as `PATH:not-scanned` and is
never followed and never read, and that subject gates like any other.
The table is fixed: TAB, LF, and CR only as part of CRLF are allowed; a form feed is allowed only at
the start of a line as an Emacs page separator. NUL and the other C0 controls, bare CR, ESC, DEL,
C1 controls (`U+0080`–`U+009F`), and bidi controls (`U+202A`–`U+202E`, `U+2066`–`U+2069`) are
rejected. The two-character escape `\r` is text, not a CR byte, and is not flagged. `allow` and `deny`
name the standard table and may be omitted; any other values are a configuration error, so the table
cannot be tuned to one case. `scope = "all"` is the default and scans the whole selected tree; the
scan is cheap enough for every run. `scope = "changed"` limits it to files changed from `base` and,
when enabled, untracked files. An invalid base is a check error, never a pass.

Each finding has a `subject` of `PATH:U+XXXX`, a `value` equal to the number of occurrences, a
`location` of `PATH:LINE:COLUMN` for the first occurrence, and a `measurement` containing that same
path, line, column and code point plus every occurrence. A `PATH:not-scanned` finding has the path as
its `location` and no line, and its `measurement` holds only that path. The threshold is `0`, so a new
subject needs a baseline entry with a reason:

    check = "source-chars"
    metric_version = "source-chars/1"

    [[entry]]
    subject = "tests/fixtures/page-break.el:U+000C"
    bound = 2
    reason = "Emacs page separators in a fixture, not control data"

A file that does not decode as UTF-8 is a finding, never a pass. It uses the subject
`PATH:decode`, reports the first invalid byte offset and its line and column, and can be baselined
like any other subject. Do not baseline a bare CR that changes line-ending behaviour: replace it
with an explicit escape or remove it.

### Python tests

    [checks.tests]
    adapter = "python_tests"
    tier = 1
    enforcement = "enforced"
    run = ["{python}", "code-quality-gate/quality_gate/test_shards.py", "-s", "tests"]
    tests_pattern = "^Ran (\\d+) tests? in"
    skipped_pattern = "skipped=(\\d+)"  # optional; one capture group
    budget_seconds = 900                  # optional; this is the default

The `run` value above uses the shared unittest runner from a gate submodule at
`code-quality-gate/`. Pass `-s DIR` (`--start-directory DIR`) to select the discovery directory
and optionally `-p GLOB` (`--pattern GLOB`) to change unittest's default `test*.py` pattern.
`-j N` (`--workers N`) sets the maximum number of workers. By default the runner uses the smaller
of the process's CPU affinity size and its effective cgroup v2 CPU quota, with a minimum of one
worker. The runner walks from the process's cgroup up to and including the cgroup root and takes
the smallest rounded-up `quota / period` from each `cpu.max`. A missing `cpu.max` or a quota of
`max` sets no limit at that level. With no finite quota or no cgroup v2 entry, the runner uses the
affinity size. An unreadable or unparsable `cpu.max` at any level raises an error naming the file.
If the process's cgroup directory is missing, the error names the directory. An explicit count
bypasses this default. Use `-j 1` to run in-process. The gate's own policy uses the default.

The runner uses standard unittest discovery in every worker. It keeps discovered instances from
`load_tests` and assigns whole classes to workers, keeping tests that share module fixtures
together. Within each worker it runs the assigned tests in discovery order. Tests running in
different workers need to be independent. The runner reports failures and errors with tracebacks
and prints the usual unittest counts. Empty discovery prints `NO TESTS RAN` and exits 5.
The runner refuses suites that override `run` or `__call__`. Each worker uses the gate's coverage
prefix. If a worker crashes or leaves test records missing, the runner lists the unrecorded tests
and shows the last 50 lines of that worker's output.

Pass `--failed-report PATH` to write a UTF-8 JSON object after the run. Its only key is
`"failed"`, whose value is a sorted array of unique unittest IDs, empty when no tests fail.
Failures, errors, and unexpected successes use the test's ID, ordinarily `module.Class.test_name`.
Subtest failures use their parent test's ID. Fixture and import errors use unittest's IDs,
such as `setUpClass (module.Class)` or `unittest.loader._FailedTest.module`.
The runner exits nonzero and names the path if it cannot produce the requested report.
Without the option, it writes no report.

`python_tests` runs the consumer's own test command once from the repository root. The token `{python}`
expands in place to a prefix that starts the current interpreter under coverage: `-I`, the gate's
`covrun.py`, a fresh data directory, the source root, the pinned coverage install, that install's
version and payload digest from the effective tool lock, the gate-owned coverage configuration path,
and the registry directory. The adapter writes and every child uses one
gate-owned coverage configuration (line mode, `branch = False`, `sigterm = true`, `source` the
repository root, `exclude_lines` exactly `#[ \t]*pragma:[ \t]*no cover`) for collection,
combination and analysis. Coverage matches that expression against the whole source text, so the
pattern's whitespace never crosses a line break; because the match is not limited to Python
comment tokens, a string containing the comment form is excluded too. Repository roots containing
spaces or non-ASCII letters are supported.
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

When `run` starts with `{python}` immediately followed by this gate installation's
`test_shards.py` script, the adapter adds `--failed-report` with a path in the check's fresh
data directory. On a completed failure, each reported test ID becomes one finding.
If the report is missing or invalid, the check reason names the report path and the defect.
Other commands produce no per-test findings. Timeouts, signals, and execution errors keep
their existing reasons without reading the report.

Every `python_tests` check runs its command with `TMPDIR` set to a fresh directory the gate creates
directly in the caller's temporary directory with a short `qg-t-` prefix, so the caller's `TMPDIR`
never reaches the suite and the added path stays short. After the command exits, the gate lists every
path left under that directory, relative to it and sorted. A path list holds one path for each entry
left directly in the directory, plus one for each file and each directory inside a left directory at
any depth, so a left directory counts itself and everything under it. Any path left fails the check,
naming the entries left directly in the directory, each with its path count, and the total:
`87 entries (109 paths) left in the suite's TMPDIR: a-dir (17 paths), b.el, ...` lists at most ten
entries, sorted, then `and N more`; an entry with one path is named without a count, and `entry`
and `path` are singular when their count is 1. A command that failed for another reason reports
both reasons. The gate removes the directory whether the suite passed or failed, restoring the
owner's read, write and search bits on every directory before removing its contents. A listing or
removal that still fails is a decision error naming the directory and the operating-system error;
it is never ignored. No policy key enables or disables this rule.

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
Each unexpected result in the child report yields a finding whose subject is the ERT symbol name.

`elisp_tests` gives its suite the same temporary-directory rule as `python_tests`: `TMPDIR` is a
fresh gate-owned directory created in the caller's temporary directory with the same short prefix,
and every path left under it after the child exits fails the check with the same message,
`87 entries (109 paths) left in the suite's TMPDIR: a-dir (17 paths), b.el, ...`, counting and listing
the entries left directly in the directory as `python_tests` does: ten sorted entries at most, then
`and N more`, with a count for an entry holding more than one path. A child that failed for another
reason reports both reasons. The directory is removed afterwards, with every directory given the
owner's read, write and search bits first; a listing or removal that still fails is a decision error
naming the directory and the operating-system error.

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
    baseline = "quality-gate-crap.toml"   # optional; must name an existing file

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

Cyclomatic complexity is 1 plus the decisions in the table below. An irrefutable pattern is a
capture name, `_`, or an or-pattern with an irrefutable alternative, so `case remaining` and
`case 1 | _` add nothing, like `case _`. Nested function and lambda bodies add to the enclosing
function. A function's own CC counts only its executable body: defaults, decorators and annotations
count once, in the owner where they execute (the enclosing function, or the module subject for a
module-level definition). The construct rules and the named-table selections are data tables in
`quality_gate/python_crap.py`.

| Construct | Decisions added |
|---|---|
| `if` (an `elif` is a nested `if`), conditional expression | One per form. |
| `for`, `async for`, `while` | One per loop. |
| comprehension `for` clause, comprehension `if` | One per clause. |
| `except` handler (including `except*`) | One per handler. |
| `match` case | One, except an unguarded irrefutable pattern. |
| `and`/`or` | One per operand after the first. |
| `any`/`all` whose single argument is a tuple or list display | One per element after the first, as for `and`/`or`; a starred element that is itself a tuple or list display expands to its elements, recursively, so an empty one adds none. |
| subscript whose value is a tuple or list display and whose index is not a constant | One per element after the first, a selection among them. A signed numeric constant such as `-1` or `+2` is a constant. |
| subscript of a dict display whose key is not a constant | One per key after the first, a selection among them. Tuple keys of one length that mix booleans with other constants add one per position that holds a boolean constant in every key; string and number positions add nothing. The same subscript of a name counts the most decisions of any such table bound to that name at module level or in the function's body. A binding that is not such a table (an empty dict, a string-keyed dict, anything else) removes that scope's table but never lowers another scope's count, and a binding inside a nested function or class never lowers the count. Names are not scope-resolved: a parameter, local, lambda or comprehension variable, nested binding or default that reuses a module table's name is counted as that table. |
| `.get` on a dict display | One per key after the first, a selection among them, plus one for a default argument, which is a branch. A dict bound to a name is data and adds nothing, unless its keys are all booleans or tuples of booleans, or tuples of one length with a boolean position, when it counts like the display, by the same name rule as the subscript row. |
| `getattr` with three arguments | One, the default is a branch. |
| `next` with two arguments | One, the default is a branch. |
| a string literal or tuple/list display multiplied by a non-constant on either side | One, the repetition chooses a length or count. |
| `map` | One, a loop as a comprehension's `for`. |
| `filter`, `itertools.filterfalse`, `itertools.dropwhile`, `itertools.takewhile` | Two, a loop and its condition. |

Shadowing a table's name is itself a defect, and renaming it is the fix; the count never resolves a name to a scope, and a table of the same name never lowers another scope's count.

A starred element whose length the source does not write counts as one element, and a written
empty display contributes none. In a dict display, each `**` entry counts as one key whatever it
unpacks, the same unwritten-length limit. Calls are recognised
by the called name, so a user function with one of these names counts too; a call imported under
another name, such as `from itertools import filterfalse as reject`, is not recognised. This is the
same name-based limit the `shape` check's rules share.

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

### Python function shape

    [checks.shape]
    adapter = "python_shape"
    tier = 1
    enforcement = "enforced"
    scope = "changed"                     # changed or tree
    base = "HEAD"                         # required; the diff base
    crap_check = "crap"                   # required; the id of a python_crap check
    max_chain = 6                         # optional; this is the default
    clone_min_tokens = 30                 # optional; 20-49; this is the default
    clone_similarity = 0.95               # optional; 0.5-1.0; this is the default

`python_shape` refuses a change that meets a CRAP threshold by fragmenting a function or shattering
a duplicate. One parse of the selected production files feeds five structural rules, and every
finding is enforced with no `baseline` key and no suppression: the check's threshold is `0` and each
finding has value `1`, so any finding fails the check. The five rules are:

* **CPF**, CRAP-payoff fragmentation and an untested single-use helper. A function present before
  and after in a changed file has complexity above the CRAP limit before and at most it after, and
  the commit adds a helper whose only call site is inside that function and which no test
  references. An added method, or an added function whose only call site is in another module, with
  exactly one production caller and no direct test also fails as a single-use helper. Only call
  sites outside test files are production callers: a call from a test file neither makes a helper
  single-use nor prevents it from being reported, a test still counts only by naming the function,
  and a function called only from test files is not single-use (the UNCALLED rule decides it). The
  CRAP limit is the `threshold` of the check named by `crap_check`, so the limit has one source.
* **PTW-SU**, pass-through wrapper, single-use, untested. An added function's body, after an
  optional docstring, is exactly one call (or `return CALL`, with or without `await`) that forwards
  each of its own parameters exactly once and whose other values are constants, the callee is not
  its own parameter, and the function has exactly one call site and no direct test. A method's
  leading `self` or `cls` is not a parameter.
* **SCC**, single-caller chain. Among the added functions, an edge `f -> g` exists when `g`'s only
  call site is inside `f`; a chain deeper than `max_chain` fails, naming every function in it. A
  chain head that branches reports only its deepest path, so each function appears in one finding.
* **LTC**, lower-threshold token clone. Two functions added by the same commit, both production and
  neither an ancestor of the other, whose bodies share a normalised token run of
  `clone_min_tokens` to 49 tokens at similarity at least `clone_similarity`. Tokenising the body
  excludes the docstring and the signature, normalises identifiers to `ID`, numbers to `N` and
  strings to `S`, and keeps keywords and operators; an f-string's data is not structure. The upper
  bound keeps the rule in the gap the 50-token clone check does not cover.
* **UNCALLED**, never called. An added function that no call names outside its own body and that no
  test names directly. Dead code, a handler registered by a decorator such as `singledispatch`, a
  method reached only through `getattr(obj, "handle")`, a descriptor-table entry, a keyword argument
  such as `sorted(key=f)` and a dispatch table called as `TABLE[kind](x)` are all refused unless a
  test names them directly. The remedy is a direct test, a call by name, or the decision kept as data
  in its one owner. Its known limit is the one the other rules share: a call by an unrelated name that
  happens to be spelled the same counts as a call, as it does for the other rules.

A test file is a path with a `tests/` component, a `test_*.py` name or a `*_test.py` name. Test
files are excluded from every rule's scope, and a function is a "direct test" of a name only when a
test function (a `test*` function, or one inside a `Test*`, `*Test` or `*Tests` class) names it.

`scope = "changed"` evaluates the functions whose definition is new or differs from the base
revision's definition with the same qualified name, compared after `ast.dump` with decorators
included, exactly as `python_mutation` selects them: a moved unchanged function is not evaluated and
a deletion inside a function is. UNCALLED, PTW-SU, SCC and LTC still judge only the functions the
commit adds (a new qualified name), not every function it changes. `scope = "tree"`
evaluates every function of the selected production files, so a function the commit does not touch
can fail SCC, LTC or UNCALLED there. CPF is not a tree property, so it compares against `base` in
both scopes (a clean tree with `base = "HEAD"` has no CPF finding). A helper's production call
sites are counted in every enumerated Python file outside test files, with or without a `.py`
suffix, so a caller outside the check's own scope still counts. Python embedded in a shell script is
not read. A missing or invalid input is a configuration error, never a skipped rule: unknown keys,
a `scope` other than `changed` or `tree`, a missing or non-existent `base`, `max_chain` below 1,
`clone_min_tokens` outside 20-49,
`clone_similarity` outside 0.5-1.0, and a `crap_check` naming no check or a check that is not a
`python_crap` check are all rejected. An unparsable changed file or a path Git still quotes is an
error naming it.

The shapes the rules accept are deliberate. A single-use helper with a direct test passes CPF and
PTW-SU; a helper with two call sites passes them too. A refactor that moves decisions into a data
table adds no single-use helper, so CPF does not fire, but each table entry still needs a direct test
or UNCALLED refuses it. A tested decision function plus a thin effect adapter is accepted when the
adapter has a direct test or a second caller. That is the QF12 shape: its helpers are directly
tested, so CPF reports nothing.

Each finding's `subject` names the rule, the functions and the measured values, and the expected
limit. The human report adds the check id and the location:

    check: shape: CPF pkg/app.py:process CC 7 -> 2, helper pkg/app.py:_step (1 call site, no direct test; limit 6 CC; expected the helper to have a direct test or a second caller, or the function to stay unsplit): value 1 exceeds threshold 0 at pkg/app.py:1-5
    check: shape: PTW-SU pkg/app.py:render_json -> json.dumps (forwards data, 2 constants, 1 call site, no direct test; limit 1 call site with no direct test; expected a direct test, a second caller, or no wrapper): value 1 exceeds threshold 0 at pkg/app.py:8-9
    check: shape: SCC chain depth 7: pkg/chain.py:run -> pkg/chain.py:_chain_1 -> pkg/chain.py:_chain_2 -> pkg/chain.py:_chain_3 -> pkg/chain.py:_chain_4 -> pkg/chain.py:_chain_5 -> pkg/chain.py:_chain_6 (limit 6; expected at most 6 consecutive single-caller functions): value 1 exceeds threshold 0 at pkg/chain.py:1-3
    check: shape: LTC pkg/app.py:chip_class <-> pkg/app.py:lane_class (34 normalised tokens, similarity 1.00; limit 30-49 tokens at similarity 0.95; expected no duplicated run below the clone detector's 50-token minimum): value 1 exceeds threshold 0 at pkg/app.py:1-4
    check: shape: UNCALLED pkg/app.py:_run_files (0 call sites, no direct test; limit 0 call sites with no direct test; expected a direct test, a call by name, or the decision kept as data in its one owner): value 1 exceeds threshold 0 at pkg/app.py:5-6

The `measurement` carries the measured values per rule: `rule`, `file`, `name`, `caller`, `helper`,
`call_sites`, `direct_test`, `callee`, `forwarded`, `constants`, `cc_before`, `cc_after`, `limit`,
`chain_depth`, `chain`, `longest`, `ratio` and `tokens`. The check reports
`{"functions": N, "added": M}` in its measurement, so a run shows how much it measured. The metric
version is `python-shape/1`. The adapter itself is 54 functions and scores at most CC 6; no
function of it scores above CRAP 6 measured over its test module, and its own change passes every
rule at `scope = "changed"`.

This repository's own `quality-gate.toml` enables `python_shape` in the `python` class. Its
`base = "HEAD"` judges a local check's uncommitted change; a caller that knows the change's base
sets `QG_DIFF_BASE` instead: a runner gates one item from the item's base commit, a landing check
gives the main commit it lands on, and CI gives the pushed commits. A gate run resolves
`QG_DIFF_BASE` once before any adapter runs, and every check that diffs uses that commit, so a branch
that moves during the run cannot make checks judge different changes. The variable must name a
commit: an existing tree or blob is a configuration error that names the variable and its value,
never a fallback to the policy `base`.

### Variant dispatch

    [checks.variant-dispatch]
    adapter = "variant_dispatch"
    tier = 1
    enforcement = "enforced"
    scope = "tree"                        # tree or changed
    base = "HEAD"                         # optional; the diff base, used with changed

`variant-dispatch` refuses the same vocabulary of names written in two places: two functions
dispatching on it, a function and a table, or two tables, so every vocabulary lives in one declared
table read through one path. It has no baseline, threshold or exemption key: every finding is value
`1` against threshold `0`, its metric version is `variant-dispatch/1` and its evidence is `static`.

Every selected Python file is parsed with `ast`. Shell files are not read yet: a line reader
cannot read bash exactly, and a shell front end needs an exact parser. An owner is a function
(qualified `FILE:Class.method` or `FILE:function`) or a module-level table. An owner's set is the
union of its literal sets, and a literal set is the string literals of one of these:

* Python: the literals one function compares with `==`, `!=`, `in` or `not in` against the same
  subject (the same name, attribute chain or subscript, compared by `ast.dump`), when the other
  operand is not a constant; a literal tuple, list or set display used with `in` or `not in`
  against a non-constant; a `match` statement's literal case patterns; a dict display with at
  least two string-literal keys, other keys ignored, that is subscripted, or read with `.get`,
  by a non-constant.
* A declared table: a module-level assignment (or annotated assignment) to a name whose value is a
  dict display with all string keys, or a tuple, list, set or `frozenset(...)` display of string
  elements, with at least two literals; its set is its keys or elements, and a nested tuple, list or
  set element contributes its string literals.

A literal counts only if it contains a letter, so numbers, exit codes and the empty string never form
a vocabulary. A literal set with fewer than two literals is not a vocabulary and contributes
nothing. Two owners are linked when their sets share at least two literals. Each connected group
of linked owners is one finding, `VSD`, whose subject is the sorted shared literals and whose message
is exactly:

    VSD variant-dispatch: "a", "b", ... are listed in N places: FILE:LINE NAME (function|table), ...
    Declare this vocabulary once, in one table, and read every per-variant difference through it.

The owners appear in file and line order. The JSON `measurement` carries `literals` and `owners`,
each owner with its `path`, `line`, qualified `name`, `kind` and own sorted `literals`.

`scope = "tree"` (the default) reports every finding. `scope = "changed"` reports a finding only when
one of its owners is a function or table the diff from `base` adds or changes; the whole tree is
still read to find the other owners. `base` defaults to `HEAD`. An invalid base is a check error,
never a pass.

This repository's own `quality-gate.toml` enables `variant_dispatch` in the `python` class with
`scope = "tree"`; the gate's own code has no VSD or TRIAL finding. The check landed before the policy
that judges this repository enabled it, which is why the enabling change is separate.

The same adapter reports `TRIAL`, Python only: a function whose body contains one of three exact
statement shapes, with `f` and `g` different module-level functions of the same module called on
the same first argument: `return f(x) or g(x)`; three consecutive statements in one block,
`v = f(x)`, `if v is None:` or `if not v:` whose body is exactly `v = g(x)` and which has no
`else`, then `return v`; or a `try` whose body is exactly `return f(x)` and whose only
handler's body is exactly `return g(x)`, with no `else` or `finally`. Nothing else is a
finding: other fallback chains, guards, handlers and assignments are not read. It is reported only
when the callees have the same return annotation and their names differ only in tokens that are
literals of a declared table of the same module (a format-name table). Its message is exactly:

    TRIAL variant-dispatch: FILE:LINE FUNCTION tries F then G on ARG; select the reader from the table that names the formats, by the record's declared format, instead of trying each.

Two functions that compare a kind with `"alpha"` and `"beta"` are one finding whose remedy is one
table:

    def first(kind):
        if kind == "alpha":
            return 1
        if kind == "beta":
            return 2

    def second(kind):
        return {"alpha": 1, "beta": 2}[kind]

    VSD variant-dispatch: "alpha", "beta" are listed in 2 places: pkg/app.py:1 first (function), pkg/app.py:7 second (function)
    Declare this vocabulary once, in one table, and read every per-variant difference through it.


### Python mutation

    [checks.mutation]
    adapter = "python_mutation"
    tier = 1
    enforcement = "enforced"
    scope = "changed"                     # only changed
    base = "HEAD"                         # required; the diff base
    mutant_seconds = 10                   # optional; one mutant's test run
    function_mutants = 3                  # this repository's policy
    run_seconds = 300                     # optional; the whole check

`python_mutation` refuses a change whose tests survive a mutation of a function the diff adds or
changes. It selects the production functions exactly as `python_shape` does with `scope = "changed"`
and `base`: the selected files the diff touches, and in them each function or method whose
definition is new or differs from the base revision's definition with the same qualified name.
Definitions are compared after `ast.dump`, decorators included, so a moved unchanged function is
not selected and a deletion inside a function selects it. Test files are never mutated. A function
with no mutants is not reported merely for that; a function no test names is a finding (see below).

For each selected function, in source order, the adapter generates these mutants from a fixed
operator set:

* a comparison operator flipped to its complement: `==`/`!=`, `<`/`>=`, `>`/`<=`, `in`/`not in`,
  `is`/`is not`, in both directions;
* `and` and `or` swapped;
* a condition negated: an `if`, `while`, ternary or comprehension `if` test;
* a `return` value replaced by `None`, or `True` and `False` swapped for a boolean constant;
* one whole statement deleted, decorators included, replaced by `pass` when deleting it would
  leave an empty block;
* an integer constant `n` changed to `n + 1`, and a string constant changed to the empty string.
  A signed integer literal is one constant, so `-1` becomes `0`.

The operator label in a finding is the new spelling (`!=`, `>=`, `or`, `return False`, `n+1`,
`empty string`, ...), except that negation is `not` and deletion is `delete`. One table holds each
operator's complement and its display text. Each mutant is produced by applying the change to the
module's syntax tree and printing it with `ast.unparse`, then compiled with
`compile(source, PATH, "exec")`; a mutant that does not compile is not generated. Messages keep
the original line numbers and show the changed expression (`ast.unparse` of the changed node)
substituted into the original source line it came from. Lines are split only on `
`, and the
target's span uses its UTF-8 byte offsets, so non-ASCII text, a form feed, or a Unicode line
separator inside a string before the target cannot shift the shown line. A deleted statement is
shown as `deleted: <first line of the statement's own source segment>`. At most
`function_mutants` mutants are generated per function: the first that many generated mutants
ordered by source position (line, then column), not counting a suppressed candidate.

An equivalent mutant is not generated, and the JSON records it with outcome `not generated` and the
rule that suppressed it:

* `unparsed source unchanged`: `ast.unparse` of the mutated module equals the original's;
* `does not compile`: the mutated source fails `compile`, so the mutant is not counted as killed;
* `self-comparison`: both sides are the same plain name or the same constant, as in `x == x`;
* `constant statement`: a statement that is a bare constant, or a string that is not the first
  statement of a function body, cannot change behaviour and is not mutated;
* `only statement`: deleting it would remove the only non-docstring statement of a function body;
* `docstring`: the mutation would change the first statement's string;
* `return None`: the return is already `return None` or a bare `return`.

There is no suppression list and no baseline: a surviving mutant is answered with a test or by
fixing a generation rule here.

The test files for a function are the Python files under the test directory a `python_tests`
check discovers whose parsed source names the function or imports the function's module in any form:
`import pkg.mod`, `import pkg.mod as m`, `from pkg import mod`, `from pkg.mod import name` and
`from pkg.mod import *` all select it. When the policy configures no `python_tests` check, every
selected test-shaped Python file is considered. A function no such file names is a finding with
`no test names it`: it has no tests, and mutation testing cannot show its tests can fail. Each
mutant is written to a copy of the repository in a temporary directory; the working tree is never
written. The mutant run, and the baseline run of the unmutated copy, get a fresh allowlisted
environment: `PATH`, `LANG` and `LC_ALL` from the gate's own environment, the `QG_PYTHON` and
`PYTHONDONTWRITEBYTECODE` values `_test_environment` adds, and `PWD`, `HOME` and `TMPDIR` set to
directories inside the copy. Every `PATH` entry is resolved with `os.path.realpath` and written as
its absolute path, with an empty entry resolved as the gate's current directory; an entry inside
the source repository is replaced by the same relative path inside the copy. No other allowlisted
value is a path the gate does not set itself, and no
other variable is inherited, so no inherited path or relative traversal can reach the source
tree. The baseline runs once for every changed function that has tests, whether or not any
mutant is generated. A baseline that fails in this environment is a check error naming the
failing test and saying the mutation environment is allowlisted, never a pass. The selected test
files run in that copy with the bounded runner as
`python3 -I -B -m unittest discover -s DIR -p FILE`, one file at a time.

Each run makes the check process a child subreaper (`prctl(PR_SET_CHILD_SUBREAPER)` on Linux). After
the mutant's process group is stopped, every remaining descendant the check adopted is stopped and
reaped, including a child a test started with `start_new_session=True`. A process record counts as
gone only when reading it raises `FileNotFoundError` or `ProcessLookupError`; any other failure to
read a record is a check error naming the pid and the failure. Where the subreaper is unavailable,
or the process table cannot be enumerated to confirm the adopted descendants stopped, the check is
an error naming why, never a pass or a completed run.
Runner tests check that a noisy timeout ends with SIGKILL and no cleanup error, that a group whose
absence cannot be confirmed reports a cleanup error after SIGKILL, and that a permission failure
reading a process record propagates from the reader.

`mutant_seconds` bounds one mutant's test run (default 10), `function_mutants` bounds the generated
mutants per function (default 20), and `run_seconds` bounds the whole check (default 300), covering
generation, copying, test runs and cleanup. The deadline is checked after every copy, run, cleanup
and temporary-directory removal, the last removal included, and each run gets the time remaining
after its copy. A mutant that exceeds its run is `timed out` and counts as killed only when the
original tests passed within `mutant_seconds`; if the original tests fail or exceed their own time,
the check is an error, never a pass. A check whose total time reaches `run_seconds` stops, reports
every function it did not finish as an `over budget` finding, and records every generated mutant
that did not run as `not run (over budget)`; it never passes. An invalid `base` is a check error,
never a pass.

A surviving mutant is one finding, value `1` against threshold `0`, with the exact message:

    python-mutation: FILE:LINE FUNCTION survives OPERATOR (CHANGED EXPRESSION IN ITS ORIGINAL LINE); tests run: FILES. Add a test that fails on this change, or fix the generation rule if the mutant cannot change behaviour.

The parenthetical substitutes the changed expression between the prefix of its first source line
and the suffix of its last. A deletion shows `deleted: ` followed by the statement's exact source
on its first line. For a single-line statement this ends at the statement boundary, excluding
any following statement or trailing comment. For a multi-line statement it extends to the end of
the first line. `FILE:LINE` is the original number of the first line.

For example, a weak test that only asserts the result is one of the possible strings:

    def classify(value):
        if value > 0:
            return "positive"
        return "other"

    class ClassifyTests(unittest.TestCase):
        def test_classify(self):
            self.assertIn(classify(1), ("positive", "other"))

reports the complement that takes the same branch for `1`:

    check: mutation: python-mutation: pkg/app.py:2 classify survives <= (if value <= 0:); tests run: tests/test_app.py. Add a test that fails on this change, or fix the generation rule if the mutant cannot change behaviour.: value 1 exceeds threshold 0 at pkg/app.py:1-3

The finding's `measurement` carries `subject` (`FILE:FUNCTION`), `file`, `function`, `operator`,
`line`, `mutated`, `outcome` and `tests`. The check's JSON `measurement` carries every mutant in
`mutants`, each with those fields plus `rule` (the suppressed rule, otherwise null), and the
`functions` count, the `test_files` considered and the `base` commit. Outcomes are `killed`,
`survived`, `timed out`, `not generated` and `not run (over budget)`. The metric version is
`python-mutation/1`.

### Emacs Lisp CRAP

    [checks.legacy-crap]
    adapter = "elisp_crap"
    tier = 1
    enforcement = "enforced"
    requires = "legacy-tests"                  # an earlier elisp_tests check id
    threshold = 6                              # optional; finite; this is the default
    baseline = "quality-gate-crap-legacy.toml" # optional; must name an existing file

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
    python3 -BI qg.py tools fetch --check
    python3 -I qg.py tools path ruff

`tools fetch` reads the gate's `tools.lock.toml` (or `--lock FILE`) and installs every pinned tool under
`QG_TOOLS_DIR`, which defaults to `~/.local/share/code-quality-gate/tools`, as `NAME-VERSION/`. It
downloads with `urllib`, verifies the archive SHA-256, extracts into a temporary directory inside the
tools directory, and computes the full tree's payload digest before moving it into place. It refuses
an archive hash or payload digest mismatch, or an unsafe archive member (absolute path, `..`, link, or
non-regular file), without installing anything. Tool names and versions must match
`[A-Za-z0-9][A-Za-z0-9._+-]*`, the install destination must resolve inside the tools directory, and a
lock table accepts only `version`, `url`, `sha256`, `payload_sha256`, `binary` and `format`.
The lock rejects unknown keys, a missing `payload_sha256`, and binary paths with empty, `.` or `..`
components, including paths with a trailing slash. Use a canonical relative path such as `bin/shfmt`.
TOML parser failures, including oversized integers and excessive nesting, exit 2 and name the lock.
`tools fetch` keeps an existing install if its payload digest matches the lock and replaces it otherwise.

`python3 -BI qg.py tools fetch --check` verifies every installed payload against the lock offline.
It accepts the same `--lock FILE` option. It traverses cache ancestors with `O_PATH` and `O_NOFOLLOW`,
so search permission is sufficient. It reads each install tree through directory descriptors and walks
it iteratively with a bounded number of open descriptors, including trees 1,000 levels deep. A symbolic
link in the cache path or in the path to the declared binary fails verification. Other links are hashed
as their target text.
The command leaves the cache untouched, and Python's `-B` flag prevents bytecode cache writes in
the checkout. It exits 0 if all installs match, 1 for a missing, unsafe, unreadable, or changed
install, and 2 for a missing, unreadable, or invalid lock. Failures identify the tool and path
or the lock file.

Once a payload matches its pinned digest, `tools fetch` removes every write bit from every directory and
file in the tree and installs it read-only, and a matching existing install is made read-only the same
way. Read and executable bits stay as the archive set them, so the payload digest does not change. A
matching install is not downloaded again, so rerunning `tools fetch` hardens an existing cache without
using the network. The payloads are read-only because the cache is shared: a process that imports from one,
such as coverage, can otherwise leave bytecode files or a `__pycache__` directory behind as the cache's
owner, and a later run as another user cannot read the altered tree. With the write bits removed, such a
process cannot add files, and any install that still matches its pinned payload keeps working. Replacing a
read-only install first restores the owner's write bit on the tree's directories and then removes it.

The lock pins Ruff, jscpd, coverage, and shfmt. The Bash parser for shell checks is shfmt `3.14.1`,
installed as `bin/shfmt` from conda-forge's `linux-64/go-shfmt-3.14.1-hfc2019e_0.conda` artifact.
The archive SHA-256 and size match conda-forge's published package record. On 2026-11-24,
`tools fetch` on main measured the payload SHA-256 from that verified archive, and
`tools fetch --check` passed on the resulting install. The archive digest establishes the version
because this build prints `(devel)` for `--version`. Debian package support has been removed.

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
`format = "conda"` marks a conda v2 artifact. The gate verifies the pinned archive SHA-256 before
opening the ZIP with Python's `zipfile`. The ZIP must contain exactly three regular members:
`metadata.json` and matching `info-<stem>.tar.zst` and `pkg-<stem>.tar.zst` tarballs. A matching stem
can start with an underscore. The reader rejects and names ZIP members with the DOS volume-label or
directory attribute. The JSON marker requires the integer `conda_pkg_format_version` of 2 and rejects
duplicate keys and non-JSON constants. The gate uses the host `libzstd.so.1` runtime to decompress the tarballs
and checks the paths and member types reported by `tarfile`. It rejects a PAX `path` containing an
embedded NUL before writing any payload files. It discards the info tarball and
extracts only the payload with `tarfile`'s `data` filter into a temporary directory in the
user-owned cache. It omits pre-link, post-link, and pre-unlink hooks under `bin/` and `Scripts/`
and runs no package scripts or installer. The full installed tree must match the pinned payload
digest before the gate moves it into place. The extraction requires no root privileges.

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
    QG_AGENT=1 python3 -I qg.py check --only ruff

`check` runs inventory and hygiene (built in, always), then every configured check in policy order. It
prints progress on stdout and failures on stderr. When inventory fails, configured checks are reported
as skipped and the combined check still fails; hygiene still runs. Configuration errors exit 2 before
any check starts.

A rejected run's stderr summary lists only its **root** failures. A failure is a consequence when the
gate itself can name its cause: an unsatisfied check whose dependency is unsatisfied, or an
unsatisfied obligation for which at least one of the class's checks declares the tier's required
evidence and every such candidate check is unsatisfied. A check's dependency is its `requires`
check; a test-measuring check without `requires` depends on every earlier check that produces
`tests` evidence. An obligation with no candidate check is a root, because that is a policy gap.
Chains resolve to their roots, and a consequence can name several, deduplicated in summary order:
the order of the checks in the policy.
The rule is decided from the policy and the results' satisfied status, never from message text.
The summary line `check: failed (...)` names the roots in the usual order. When consequences exist, the next line is
`check: consequences (ENTRY because CAUSE[, CAUSE...]; ...)`, where each entry is spelled as the
summary spells it and `CAUSE` is a root check id. A consequence still rejects and still exits 1.

`check --only CHECK [CHECK ...]` runs inventory and hygiene, then exactly those checks and the checks
they require, in policy order. Nothing else runs. An unknown or repeated check id is a usage error
(exit 2) naming it, before any check runs. A partial run never prunes and never runs under a trusted
directory: `--only` with `--prune` or with `--policy-from` is a usage error (exit 2) naming both
options, before any check runs. A partial run is never a verdict on the tree; use the full `check` for
that.

`QG_AGENT=1` marks an agent sandbox. `check` selects the whole policy by default, or the
`--only` check IDs and their requirements. If any selected adapter declares `runs_suite`,
the command exits 2 before running any checks and prints one message to stderr.
For example, `--only crap` can produce this message:

    qg.py: check: refused inside an agent sandbox (QG_AGENT=1): selected checks run a test suite: tests (python_tests), crap (python_crap). the runner's gate runs the test suites once per candidate and returns its log; run focused tests directly, or a static check with --only NAME; allowed here: ruff

The message names each refused check and its adapter. The `allowed here` list contains
the policy's static check IDs. Select a static check with `--only` to run it inside the
sandbox. Leave `QG_AGENT` unset or set it to another value for normal check behavior.

`check --json` writes exactly one JSON result to stdout and sends all human-readable lines to stderr.
The result schema is `3`; a `--policy-from` result is schema `4` and adds `trust` (see below). Its
top-level keys are `schema`, `gate_version`, `revision`, `dirty`, `policy_sha256`, `decision`,
`checks`, `obligations` and `prune`; a `decision = "error"` document also has `error`, and a
`check --only` document has `selected`.

`checks` contains inventory, hygiene and every configured check, in that order. Each check has `id`,
`kind` (`inventory`, `hygiene` or `check`), `tier` (null for built-ins), `enforcement`, `adapter`,
`evidence` (the evidence names the adapter produces), `metric_version`, `execution`, `outcome`,
`satisfied`, `caused_by`, `duration_seconds`, `budget_seconds`, `diagnostics`, `findings`,
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
SIGKILL. An interrupt that ends the run kills the group immediately and reaps the leader while it
waits, so the leader's unreaped zombie never keeps the group looking alive. That wait is bounded: when
a normal run's group cannot be shown gone within one second, the run still returns, with
`execution = "error"`, `timed_out = true` and an `error` that says cleanup did not confirm the group
gone. An interrupt is always re-raised; if its cleanup cannot be shown gone, the interrupt carries a
note naming the process group and saying the cleanup was not confirmed, and the runner prints that
note on stderr. Cleanup therefore never succeeds silently. A group whose remaining members are all
zombies counts as stopped, because a zombie cannot run and a container's PID 1 may never reap it.
Termination and reaping can add a small amount of time after the budget. Check output is captured
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

Test failure findings use value `1` and threshold `0` and are blocking, with no baseline.
Their display location is `unittest` for Python or the configured suite path for ERT.
Source spans are unavailable, so `locations` is null. Failure details stay in the check's log.

### worklist

    python3 -I qg.py worklist
    python3 -I qg.py worklist --json
    python3 -I qg.py worklist crap
    python3 -I qg.py --repo /path/to/repo worklist crap elisp-crap

`worklist` ranks the debt a reasoned baseline still carries. With no `CHECK` it covers every
configured check that has a baseline and a threshold; with ids it covers exactly those checks. For
each selected check it runs the check and every check it requires, with each prerequisite before
the check that needs it, using the same policy order and producer selection as `check`: every
earlier test producer verification needs (all of them when `requires` is omitted), with every
`python_crap` check listed before verification. The checks run in the repository itself, as with `check`,
and may write what `check` writes.
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

### debt

    python3 -I qg.py debt
    python3 -I qg.py debt --json
    python3 -I qg.py --repo /path/to/repo debt --revision HEAD~5

`debt` lists every baseline entry that still excuses a finding, without running a check, tool or test.
Without `--revision` it reads `quality-gate.toml` once and takes both the configuration and the baseline
names from those bytes, then reads each baseline from the working tree; with `--revision REV` it reads
the policy and baselines from that commit through `git show REV:PATH` and stages the baselines in a
temporary directory, never checking anything out. Neither mode reads source files, suites or load paths,
so a result depends only on the policy and the baselines it reads. An entry is debt when its direction is
`max` and either its check has no threshold or its bound is above the threshold; a `min` floor is not
debt. Clones use a threshold of 0, so every clone entry with a positive bound counts.

The human report prints `CHECK: N debt entries of M` for every check with a baseline, in policy order,
then `debt: N entries`. `--json` writes one document whose schema is in `docs/SCHEMA.md`; `revision` is
the commit's SHA, or null for the working tree. A policy with no baseline reports `debt: 0` and no
checks. An input that cannot be read or staged exits 2 with nothing on stdout: an unreadable revision, a
policy or baseline that cannot be read or parsed, a baseline that cannot be staged, or a baseline named
by the policy that is missing at that revision, and the message names the revision and path. A baseline
path with an embedded NUL is rejected the same way in either mode. The staging area itself is covered
too: a temporary directory that cannot be created or removed is the same usage error, naming the staging
area and the error, so a full temporary filesystem exits 2 with nothing on stdout instead of exiting 1
with a traceback.

### Locations

The `python_crap`, `python_mutation`, `variant_dispatch`, `elisp_crap` and `clones` adapters provide
complete locations: respectively the entire function range (including Python decorators), the mutated
function's range, every owner range of a vocabulary and a trial reader's caller, and both ranges of
every clone in a fingerprint group.
CRAP's module subject uses the span from its first to last outside-function node; that conservative
span can include intervening functions. Verification supplies every inline and file-wide suppression
line, one location per directive, but its test-count metrics have no source location. Command checks,
Python test results, inventory and hygiene have no complete source locations.

Each result's `location_coverage` is `complete`, `partial` or `none`. A finding's `locations` is an
array of `{path, start_line, end_line}` ranges, or null when its locations are incomplete.
`covered_by_baseline` describes the whole-tree ratchet.

`obligations` has one entry per code class and required tier with `class`, `tier`, `status`
(`satisfied`, `exempted` or `unsatisfied`), `required` (the evidence names the tier demands), `checks`
(the checks that counted), `caused_by` (see below) and `reason` (for an exemption; otherwise null).
Tier 1 needs a satisfied
enforced check producing `tests` evidence with at least one executed test, so a lint-only class leaves
tier 1 unsatisfied and rejects. Tier 2 needs `properties` or `fuzzing`; tiers 3 and 4 reserve
`bounded` and `proof`. No version-2 adapter produces those evidence names yet, so a required tier above
1 is exempted by a `[[not_applicable]]` entry until its adapter lands.

Every check and every obligation carries `caused_by`: the list of root check ids for a consequence, or
null for a root and for a satisfied entry. A satisfied check has null there even when it has a
`requires` check.

`prune` reports `requested` (the supplied ids or `all`), `performed` and `reason`. Repeat
`--prune ID` to tighten several baselines in one run, or use `--prune all` to select every configured
baseline. Each selected check must be satisfied; `all` also requires every other check to be satisfied.
The gate validates the entire request before writing, so a failed check refuses all requested prunes.
An unknown id or a check without a baseline exits 2. A refused or failed prune makes the command exit 1
and leaves `decision` reporting the gate evaluation. If a write itself fails, earlier writes in the
same request may already have completed. `--prune` with `--policy-from` is a usage error (exit 2)
naming both options, before any check runs; `--prune` without `--policy-from` is unchanged.

The decision is `error` (exit 2) for invalid policy, usage or configuration, when the run exceeds
its limit, when the run directory cannot be removed, or when a test check cannot remove its temporary
suite directory, `rejected` (exit 1) when
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
A policy that names a baseline file the candidate lacks is refused (exit 2) naming the check, the key
and the repository-relative path, with or without `--allow-protected` for that file, as it is without a
trust root; an authorized candidate policy that removes the key may delete the file in the same change.
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
* `2` - missing or invalid configuration (including a `baseline` key naming a file that does not
  exist, a baseline header that does not match the policy, or two checks sharing a baseline path),
  invalid command line, a repository that is not the top level of a
  git work tree, an unknown inventory class or check id for pruning, a malformed tool lock, a missing
  `--policy-from` trusted directory, a trusted directory inside the candidate, a gate program inside
  the candidate, a protected input, tool payload or gate file that changed during the run, a run or
  test temporary directory that cannot be removed, or a `check` refused under `QG_AGENT=1` because a
  selected check runs a test suite.

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
    baseline = "quality-gate-clones.toml" # optional; must name an existing file

    [checks.source-chars]
    adapter = "source_chars"
    tier = 1
    enforcement = "enforced"
    scope = "all"                         # optional; all or changed
    base = "HEAD^"                        # optional; used with changed
    include_untracked = true              # optional; used with changed
    # allow = ["tab", "lf", "crlf", "form-feed-at-line-start"]
    # deny = ["nul", "bare-cr", "esc", "del", "c1", "bidi"]
    baseline = "quality-gate-source-chars.toml"  # optional; must name an existing file

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
    baseline = "quality-gate-crap.toml"   # optional; must name an existing file

    [checks.shape]
    adapter = "python_shape"
    tier = 1
    enforcement = "enforced"
    scope = "changed"                     # optional; changed or tree
    base = "HEAD"                         # required; the diff base
    crap_check = "crap"                   # required; the id of a python_crap check
    max_chain = 6                         # optional; this is the default
    clone_min_tokens = 30                 # optional; 20-49; this is the default
    clone_similarity = 0.95               # optional; 0.5-1.0; this is the default

    [checks.mutation]
    adapter = "python_mutation"
    tier = 1
    enforcement = "enforced"
    scope = "changed"                     # only changed
    base = "HEAD"                         # required; the diff base
    mutant_seconds = 10                   # optional; this is the default
    function_mutants = 20                 # optional; this is the default
    run_seconds = 300                     # optional; this is the default

    [checks.variant-dispatch]
    adapter = "variant_dispatch"
    tier = 1
    enforcement = "enforced"
    scope = "tree"                        # optional; tree or changed
    base = "HEAD"                         # optional; used with changed

    [checks.verification]
    adapter = "verification"
    tier = 1
    enforcement = "enforced"
    requires = "tests"                    # optional; an earlier test-producing check
    baseline = "quality-gate-verification.toml"  # optional; must name an existing file

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
* A `source_chars` check may name a `baseline` path, which must exist; without one it accepts no
  baseline entries. Its files come from the classes that list it. The character table is fixed;
  `allow` and `deny` may restate it but cannot change it. `scope` defaults
  to `all`; `changed` uses `base` (default `HEAD^`) and includes untracked files unless
  `include_untracked = false`. A file that is not valid UTF-8 reports `PATH:decode`. For a
  `changed` scope, `QG_DIFF_BASE` replaces `base`, and the check's measurement names the commit
  it judged and whether `QG_DIFF_BASE` or the policy key named it.
* A `python_tests` check needs `run` and a one-group `tests_pattern`; `skipped_pattern` is optional
  with one group. Its `{python}` token and `QG_PYTHON` export are described above.
* A `python_crap` check needs `requires`, naming one `python_tests` check declared earlier in the
  policy, and may name a `baseline` path, which must exist; without one it accepts no baseline
  entries. Its `threshold` defaults to 6 and must be finite. Its files come from the classes that
  list it.
* An `elisp_tests` check needs a repository-relative `suite` file; `load_path`, `emacs` and
  `budget_seconds` are optional. Its measured files come from the classes that list it.
* `elisp_compile` and `elisp_checkdoc` select files from the classes that list them. Their `load_path`,
  `emacs` and `budget_seconds` settings are optional and independent for each check.
* An `elisp_crap` check needs `requires`, naming an earlier `elisp_tests` check, and may name a
  `baseline` path, which must exist; without one it accepts no baseline entries. Its `threshold`
  defaults to 6 and must be finite. Every selected file's class must list both checks.
* A `python_shape` check takes no `baseline` key: every finding is enforced. It requires `base`
  and `crap_check`, and accepts `scope` (`changed` or `tree`, default `changed`), `max_chain`
  (default 6), `clone_min_tokens` (20-49, default 30) and `clone_similarity` (0.5-1.0, default
  0.95). Its files come from the classes that list it, minus test files, and CPF's limit is the
  `threshold` of the `python_crap` check `crap_check` names. `QG_DIFF_BASE` replaces `base` in
  both scopes, and the check's measurement names the commit it judged and whether `QG_DIFF_BASE`
  or the policy key named it.
* A `python_mutation` check takes no `baseline` key: every finding is enforced. `scope` is
  `changed`; `base` is required. `mutant_seconds` (default 10), `function_mutants` (default 20)
  and `run_seconds` (default 300) are positive integers. Its files come from the classes that list
  it, minus test files; its test files are what the policy's `python_tests` checks select.
* A `variant_dispatch` check takes no `baseline` key: every finding is enforced. `scope` is
  `tree` (the default) or `changed`; `base` defaults to `HEAD` and is used with `changed`.
* A `verification` check may name a `baseline` path, which must exist; without one it accepts no
  baseline entries. Its optional `requires` names an earlier check with `tests` evidence:
  `python_tests`, `elisp_tests`, or a `command` with `tests_pattern`.
  A reference to a check without test evidence is a configuration error; for a command the error
  identifies its missing `tests_pattern`. Without `requires` every earlier test-producing check is used. It
  measures executed tests (a `min` floor) and skipped tests from those results, and inline `# noqa`
  comments and file-wide lint suppressions for the selected Python files, without running the tests
  again. The `no-cover` count is the lines CRAP's coverage excluded in the measured functions of the
  policy's `python_crap` checks: one `exclusions:FILE:no-cover` subject per file, with each distinct
  excluded line counted once even when several CRAP checks measure the file. It comes from the
  `excluded_lines` those checks reported, not from matching text and not from verification's file
  selection, so a file a CRAP check measures but verification's classes do not select is counted too.
  A policy must list every `python_crap` check before every `verification` check: loading one
  that does not is a configuration error naming both checks, because verification counts the
  exclusions of every CRAP check. Checks run in policy order, so a run and `--only verification`
  run every `python_crap` check before verification. A `python_crap` check
  that ran without a measurement leaves the exclusion count unmeasured: the check is an error
  naming that check, never 0. With no `python_crap` check there are no `no-cover` subjects. The
  noqa and file-wide counts still scan the selected files. A selected file is Python when its name
  ends in `.py`, or when it is a regular file whose shebang interpreter is `python`, `python3` or
  `python3.N` for one or more digits N (as `env` and its options resolve), so an executable Python
  program without the suffix is measured too; `python3-config` and `pythonw` are not Python
  interpreters here. Any other selected file stays out of the scan. An empty Python selection has
  nothing to scan, but the test counts still come from every producer; without valid producer
  results the counts are not measured and the check is unsupported. File-wide directives are
  counted separately as `exclusions:FILE:file-suppression`: Ruff's `# ruff: noqa`, with or without
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
extra occurrences) and, for measuring adapters, an optional `baseline` path. A check with no debt
needs no `baseline` key: without it the check accepts no baseline entries. A baseline begins with the
check's identity and then holds `[[entry]]` tables:

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
* A `baseline` key must name a real file; one naming a missing file is a configuration error when
  the policy loads, naming the check, the key and the path. A check with no debt has no `baseline`
  key, so a refusal means the path is wrong rather than the debt gone. A consumer whose policy still
  names a missing file must first update to a gate where the key is optional, then delete the key,
  and only then take this version. An existing file may start with only its header.
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
nothing) while that check is not satisfied. A baseline whose entries all resolve keeps its header and
no entries, and prune says the baseline is now empty. A new exception enters a baseline only by hand,
with a reason. Because the clone fingerprint covers the clone's
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
  requires `tests`; the gate's own CRAP check has no baseline, because every measured subject is at
  or below CRAP 6;
* `verification` uses the `tests` counts and measures inline `# noqa` and file-wide lint suppressions
  in its selected Python files; its `no-cover` subjects are the lines the `crap` check's coverage
  excluded in measured functions, one subject per file; `quality-gate-verification.toml` floors the
  executed tests and ceilings the skips and exclusions measured at adoption;
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
tests build local tarballs, wheels, and conda archives and fetch them via `file://`
URLs. They cover wrong hashes, unknown keys, archive reader failures, unsafe members, and payload
mismatches. Offline check tests seed local installs, verify descriptor-relative reads and symlink
handling, and exercise the write-free `-BI` invocation from a fresh copy of the gate.
Tool-use tests prove that a tampered Ruff or coverage install is `unsupported` before it runs
and that a full run leaves the coverage install unchanged. Contract tests cover result typing,
obligations and exemptions, diagnostics, baseline identity and domain rules, prune reporting and
round-trips, the bounded runner's group kill and output cap, JSON usage errors, and the trust root's
baseline, policy, protected-path, prune and identity rules.

## Mutation-testing the gate

The regular gate and CI runs on push and pull request omit mutation testing. During debt-cleanup
sessions, run `make mutation` locally or manually dispatch the CI workflow to run its mutation
job. Record surviving mutants as backlog items.

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
identity and protection, the rule that an ERT run must execute a test, and the rule that a test suite
may not leave temporary paths. They use comparison flips, boolean negation, an opposite boolean return,
and removal of a raise. This is a selected set of faults,
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
with agents coincided with swap exhaustion. Results are printed in declaration order. The mutation
run uses the same pinned tools cache as the ordinary tests.
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
after that handover, resolving the judged change, fetching pinned tools, the gate and the mutation
run as that user through `runuser`. A restored tools cache keeps its modes and changes only ownership,
so read-only payloads stay read-only.

The check matrix checks out the full history, restores the pinned tools cache keyed on the environment
name, architecture and `tools.lock.toml`, fetches any missing tools (including the coverage wheel),
and runs `make -k check`: Ruff, clones, the test suite under coverage, Python CRAP, Python function
shape and the Emacs Lisp checks. A checkout of one commit has no base to diff against, so a step
resolves `QG_DIFF_BASE` and prints it: on a push the event's `before` commit when it is present,
non-empty and in the history, otherwise (a new branch or a force push whose old commit is not
fetched) the merge base with the default branch, and on a pull request the event's own base commit,
which must be present, non-empty and in the fetched history. A value is looked up only when it is set
and not empty, so even a branch named `none` cannot stand in for a missing base. A failed push
lookup stays inside a shell condition so the fallback is still reached; a pull request without a
usable base fails, and a push fails only when the fallback also fails. The gate step passes the
variable through `runuser`, so every check that diffs judges that one change. On manual dispatch
only, the separate Debian 13 job restores the same Debian tools cache and runs `make mutation`.

Step timeouts are fixed at about five times the longest run observed as of 2026-10-31: 60 minutes
for the gate, 15 for the cold Emacs build and 120 for the mutation step, and each job adds 10 minutes
of setup for packages, checkout, cache operations, Python installation and fetching tools, giving 70
minutes for Debian, 85 for Ubuntu and 130 for mutation. Raise these bounds if the program grows; a
bound comfortably above the normal duration is enough to stop a hung job.

Reproduce it locally with the same tools cache:

    export QG_TOOLS_DIR=/tmp/qg-tools
    python3 -I qg.py tools fetch
    make -k check

For a debt-cleanup session, use the same cache and run:

    make mutation

## Planned later layers

The core gate is deliberately language-agnostic; adapters measure and the core decides. Tier 1 now
includes the Python and Emacs Lisp tests and CRAP adapters described above. The policy and baseline contract is fixed
at policy schema 2 (result schema 3, or 4 with a trust object) so M4 (tier 2 properties/fuzzing) and
M5 (tiers 3/4 bounded/proof) add adapters without reworking the core.

Every layer uses the same rule: a new exception is a hand-written baseline entry with a reason, and
pruning only removes resolved entries or tightens bounds.
