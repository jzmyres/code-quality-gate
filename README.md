# code-quality-gate

A reusable, offline code-quality gate for repositories that want every file classified, every
reason recorded, every check declared by policy, and every metric exception explicit and ratcheted.
It is one standard-library Python 3.12 command plus pinned external tools. A consuming repository
pins it as a git submodule and keeps its own `quality-gate.toml` and baselines.

The gate is deliberately narrow. It owns the orchestration no maintained tool owns end to end:

* **inventory** - every tracked or stageable file matches exactly one class rule, with a reason, and
  every code class has the checks its tier requires;
* **hygiene** - no tracked file is ignored, no file is oversized, enumeration never lies;
* **checks** - checks are declared in policy and run in policy order; adapters measure, the core decides;
* **one reasoned ratchet** - command and clone checks fail by default, and a baseline entry can accept a
  measured subject above its threshold only with a non-empty reason and an optional expiry;
* **tools** - external tools are pinned by version, URL and SHA-256, and fetched explicitly;
* **result** - `check --json` writes one machine-readable result that agents and CI can consume.

Later layers add language adapters for tests and CRAP scores, in this order: a Python CRAP adapter first,
then an Emacs Lisp CRAP adapter.

## Requirements

* Python 3.12 (the command uses `tomllib`).
* Git.
* The pinned jscpd binary in the tools cache for clone checks.
* The pinned ruff binary in the tools cache for this repository's own command check.

`tools fetch` downloads every pinned tool once; checks never download. No third-party Python packages
are needed. The command is intended to run as `python3 -I qg.py`, so the consuming repository's modules
cannot leak into it.

The implementation lives in the `quality_gate/` package next to `qg.py`: `policy.py` loads and validates
the configuration, `files.py` resolves the repository and runs inventory and hygiene, `tools.py` owns the
pinned tool lock, `ratchet.py` owns baseline decisions and pruning, `clones.py` measures jscpd clones,
`checks.py` runs command and clone adapters and assembles the result, `gate_result.py` computes gate and
consumer identity and the decision, and `cli.py` holds the argument parser and dispatch. `qg.py` is only
the entry point.

## Quick start in a consuming repository

Add the gate as a submodule at `code-quality-gate/`, fetch the pinned tools once, write the configuration,
and run the gate:

    git submodule add https://github.com/jzmyres/code-quality-gate.git code-quality-gate
    python3 -I code-quality-gate/qg.py tools fetch
    $EDITOR quality-gate.toml
    python3 -I code-quality-gate/qg.py check

`check` never downloads a tool. If a configured check needs a pinned tool and it is missing, the check's
outcome is `unsupported` and the message names `python3 -I code-quality-gate/qg.py tools fetch`.

## Commands

All commands accept the repository selector before the command:

    python3 -I qg.py [--repo DIR] COMMAND

`DIR` defaults to the current directory and must be the top level of a git work tree. Configuration is
`DIR/quality-gate.toml`. Files are enumerated with
`git ls-files -z -co --exclude-standard`, so tracked and stageable untracked files are checked and
ignored files are not.

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

Inventory also fails when a code class lists no check, lists an id with no `[checks.ID]` table, has no
enforced check of a required tier, and has no matching `[[not_applicable]]` entry. A code file is
detected by fnmatch against `[code].patterns` or by the basename of its shebang interpreter after `env`
matching `[code].shebangs`.

### hygiene

    python3 -I qg.py hygiene

Hygiene fails (exit 1) when a tracked file matches the repository's ignore rules
(`git ls-files -z -c -i --exclude-standard` returns it), an enumerated file is larger than
`[hygiene].max_bytes` (default `10485760`), or enumeration or a size measurement fails. It prints every
offending path and, for oversized files, the actual and allowed sizes.

### clones

    python3 -I qg.py clones
    python3 -I qg.py clones --prune

`clones` runs every configured check whose adapter is `clones`. It takes the files of the classes that
list that check from the inventory, runs jscpd with the SARIF reporter in a temporary directory, groups
the SARIF clone fingerprints into subjects, and sends every fingerprint occurrence count through the
generic ratchet. A clone fingerprint is a subject; its value is how many reported clones have that
fingerprint; the threshold is `0`, so any occurrence needs a baseline entry.

`clones --prune` lowers each surviving bound to the measured occurrence count and drops resolved entries.
It never adds an entry and never raises a bound, and it refuses (exit 1, writing nothing) while that
check fails. Add a new exception by hand, with a reason. A baseline that would be empty is removed
instead of written.

### tools

    python3 -I qg.py tools fetch
    python3 -I qg.py tools fetch --lock /path/to/tools.lock.toml
    python3 -I qg.py tools path ruff

`tools fetch` reads the gate's `tools.lock.toml` (or `--lock FILE`) and installs every pinned tool under
`QG_TOOLS_DIR`, which defaults to `~/.local/share/code-quality-gate/tools`, as `NAME-VERSION/`. It
downloads with `urllib`, verifies the SHA-256 before extracting, and refuses a mismatch or an unsafe
archive member (absolute path, `..`, link, or non-regular file) without installing anything. An existing
install whose binary is present is kept and not downloaded again. Extraction is staged in the tools
directory and moved into place atomically.

`tools path NAME` prints the expected binary path, whether or not the tool is installed, so scripts can
locate the cache. An unknown tool name exits 2.

The default tools directory is shared by every repository using the gate on this machine. Set
`QG_TOOLS_DIR` to use a different cache (for example in a container or a test).

### check

    python3 -I qg.py check
    python3 -I qg.py check --json
    python3 -I qg.py check --prune clones

`check` runs inventory and hygiene (built in, always), then every configured check in policy order. It
prints progress on stdout and failures on stderr. When inventory fails, configured checks are reported
as skipped and the combined check still fails; hygiene still runs. Configuration errors exit 2 before
any check starts.

`check --json` writes exactly one JSON result to stdout and sends all human-readable lines to stderr.
The result has:

* `schema` - always `1`;
* `gate_version` - the gate's own git revision, or `unknown: ...` with the reason it is unavailable;
* `revision` and `dirty` - the consumer's HEAD (or null when there is no commit) and whether its tree
  has changes;
* `policy_sha256` - the SHA-256 of the policy file;
* `decision` - `accepted`, `accepted_with_exceptions`, `rejected` or `error`;
* `checks` - one object per configured check with `id`, `tier`, `enforcement`, `adapter`,
  `metric_version`, `outcome` (`pass`, `fail`, `unsupported` or `error`), `duration_seconds`,
  `budget_seconds`, `termination` (`exit`, `budget` or `signal`), `findings` and
  `resolved_baseline_entries`.

A finding has `subject`, `value`, `bound` (or null when no baseline entry exists), `threshold`,
`baseline_reason` (or null), `blocking` and `location`; expired findings also carry `expired` and
baseline errors carry `error`. Missing evidence is `unsupported`, never `pass`. Unrounded values are
compared: exactly at a bound passes, and a value `0.1` above the bound fails.

The decision is `error` (exit 2) for invalid policy or usage, `rejected` (exit 1) when inventory,
hygiene or any enforced check does not pass, `accepted_with_exceptions` (exit 0) when every enforced
check passes but at least one finding passes only through a baseline entry or an advisory check does not
pass, and `accepted` (exit 0) otherwise. `check --prune ID` runs the same checks, then prunes only check
`ID` if that check passed; an unknown id or a check without a baseline exits 2.

### Exit codes

* `0` - the command passed, possibly with exceptions;
* `1` - a check failed, a missing tool made a check unsupported, a baseline was malformed, or pruning was
  refused because the check failed;
* `2` - missing or invalid configuration, invalid command line, a repository that is not the top level
  of a git work tree, an unknown inventory class or check id for pruning, or a malformed tool lock.

## Configuration

`quality-gate.toml` is read with `tomllib`. A missing file or an invalid value exits 2, naming the
file, the key, and expected versus actual. Unknown keys anywhere are configuration errors naming the key
and the allowed keys. The complete shape is:

    schema = 1

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
    checks = ["ruff", "clones"]           # ids of [checks.ID] tables

    [classes.config]
    code = false
    description = "Configuration and pinned data"

    [checks.ruff]
    adapter = "command"                   # command or clones
    tier = 1                              # 1-4
    enforcement = "enforced"              # enforced or advisory
    run = ["{tool:ruff}", "check", "--no-cache", "{files}"]
    budget_seconds = 600                  # optional; this is the default
    must_match = "Success"                # optional regular expression on combined output

    [checks.clones]
    adapter = "clones"
    tier = 1
    enforcement = "enforced"
    min_tokens = 50                       # optional; this is the default
    baseline = "quality-gate-clones.toml"

    [[not_applicable]]
    class = "python"                      # a configured class
    tier = 2                              # a required tier it has no enforced check for
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
* Every code class must list at least one check. Every code class needs at least one enforced check of
  each `[levels].required_tiers` entry, unless a `[[not_applicable]]` entry names the class and tier with
  a non-empty reason.
* A command check's `run` is an argument list. The token `{files}` expands in place to the sorted files
  of every class that lists this check, as separate arguments. The token `{tool:NAME}` expands to the
  binary of a tool pinned in `tools.lock.toml`; an unknown or unfetched tool makes the check
  `unsupported` and names `qg.py tools fetch`. A check using `{files}` with no selected files fails:
  zero inputs is not a pass.
* A clone check's files come from the classes that list it. Clone baselines use the generic ratchet
  format below; the old top-level `[clones]` table and the old `[[clone]]` baseline are gone.

## The generic ratchet

An adapter that measures subjects returns findings with a `subject`, a numeric `value` and a
`location`. The policy gives the check's `threshold` (clones use `0`, so the value is the number of
extra occurrences) and, for measuring adapters, a `baseline` path. A baseline is a TOML file of
`[[entry]]` tables:

    [[entry]]
    subject = "76c7cbddc2677be2"
    bound = 1
    files = ["src/a.el", "src/b.el"]
    reason = "the two front ends deliberately mirror each other"
    expires = 2026-12-31

* `subject` identifies the measured thing (a clone fingerprint now; later a function identity).
* `bound` is the largest value this entry accepts. It is compared unrounded; exactly at the bound passes.
* `reason` must be non-empty. An empty or missing reason fails the check even if the value is covered.
* `expires` is optional. A TOML date before today no longer covers its subject and is reported as
  expired. An entry expiring today still covers.
* Adapter-specific informational keys are preserved, for example clone `files`.

A finding passes when `value <= threshold`, or when a baseline entry for its subject exists, has not
expired, and `value <= bound`. A finding above both fails, naming subject, value, threshold or bound, and
location. An entry whose subject was not measured, or that now passes the threshold, is reported as
resolved. A baseline that is absent means no exception is accepted; an empty baseline file is allowed.

`--prune` only lowers each bound to the measured value and drops resolved entries. It never raises a
bound or adds an entry, and it refuses (exit 1, writing nothing) while that check fails. A new exception
enters a baseline only by hand, with a reason. Because the clone fingerprint covers the clone's token
sequence, changing the duplicated code makes the old entry resolve and the new clone fail until a human
accepts it.

## Pinned tools and this repository

`tools.lock.toml` in the gate repository is the only place tool versions live. It pins jscpd 5.4.1 and
ruff 0.17.0, including the archive URL, SHA-256 and binary path. `tools fetch` accepts `--lock FILE` for
testing or for a private mirror; `file://` URLs exercise installation without a network.

This repository gates itself with `quality-gate.toml`:

* the `python` and `test` classes list the `ruff` command check and the `clones` check;
* `ruff` runs the pinned binary through `{tool:ruff}` with `--no-cache` on the inventory's Python files;
* `clones` uses jscpd with `min_tokens = 50` and the generic baseline format;
* `levels.required_tiers = [1]` makes tier 1 mandatory for both code classes.

`make check` runs the gate's lint, the test suite and `python3 -I qg.py check`. Lint resolves ruff with
`python3 -I qg.py tools path ruff`, so the Makefile and the policy use the same pinned binary. `make
RUFF=/path/to/ruff check` still overrides it for a local experiment.

The tests execute `qg.py` as a subprocess on disposable fixture git repositories. Clone-gate tests use a
fake jscpd in a temporary `QG_TOOLS_DIR`; one test runs the real pinned jscpd and fails, rather than
skipping, when the tool is not installed. Command-check tests use the real command; the real ruff test
runs only when the pinned ruff binary exists. `tools fetch` tests use fixture tarballs with `file://`
URLs, including wrong hashes and unsafe archive members.

## Planned later layers

The core gate is deliberately language-agnostic; adapters measure and the core decides. The planned order
for the metric adapters is:

1. **Python tests and CRAP adapter** - run the consumer's tests under the pinned coverage tool, join
   coverage with cyclomatic complexity per function, then gate on a reasoned CRAP baseline.
2. **Emacs Lisp CRAP adapter** - reuse the same baseline and reporting model, but compute complexity and
   coverage through an Emacs batch helper, since Emacs Lisp has no maintained standalone CRAP tool.

Both layers use the same rule: a new exception is a hand-written baseline entry with a reason, and
pruning only removes resolved entries or lowers bounds.
