# code-quality-gate

A reusable, offline code-quality gate for repositories that want every file classified, every
reason recorded, and every duplicate-code exception explicit and ratcheted. It is one standard-library
Python 3.12 command, plus one pinned external tool (jscpd) for clone detection. A consuming repository
pins it as a git submodule and keeps its own `quality-gate.toml` and clone baseline.

The gate is deliberately narrow. It owns the checks that no maintained tool owns end to end:

* **inventory** - every tracked or stageable file matches exactly one class rule, with a reason;
* **hygiene** - no tracked file is ignored, no file is oversized, enumeration never lies;
* **clones** - jscpd finds duplicate code, and a reasoned baseline makes the ratchet lower only;
* **tools** - external tools are pinned by version, URL and SHA-256, and fetched explicitly.

Later layers add language adapters for CRAP scores, in this order: a Python CRAP adapter first, then
an Emacs Lisp CRAP adapter.

## Requirements

* Python 3.12 (the command uses `tomllib`).
* Git.
* The pinned jscpd binary in the tools cache for the `clones` command and for `check` when
  `[clones]` is configured. `tools fetch` downloads it once; checks never download.

No third-party Python packages are needed. The command is intended to run as `python3 -I qg.py`, so
the consuming repository's modules cannot leak into it.

## Quick start in a consuming repository

Add the gate as a submodule at `code-quality-gate/`, fetch the pinned tool once, write the configuration,
and run the gate:

    git submodule add https://github.com/jzmyres/code-quality-gate.git code-quality-gate
    python3 -I code-quality-gate/qg.py tools fetch
    $EDITOR quality-gate.toml
    python3 -I code-quality-gate/qg.py check

`check` never downloads a tool. If a configured check needs jscpd and it is missing, it fails and tells you to run
`python3 -I code-quality-gate/qg.py tools fetch`.

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
    python3 -I qg.py inventory --list test

Inventory fails (exit 1) and prints every violation when a file matches no rule, a file matches more
than one rule, a rule matches no file, a rule has an empty reason, a rule names a class that does not
exist, or a code file (by pattern or shebang) is placed in a class whose `code` is not true. A code file
is detected by fnmatch against `[code].patterns` or by the basename of its shebang interpreter after
`env` matching `[code].shebangs`.

### hygiene

    python3 -I qg.py hygiene

Hygiene fails (exit 1) when:

* a tracked file matches the repository's ignore rules
  (`git ls-files -z -c -i --exclude-standard` returns it);
* an enumerated file is larger than `[hygiene].max_bytes` (default `10485760`);
* enumeration or a size measurement fails.

It prints every offending path and, for oversized files, the actual and allowed sizes.

### clones

    python3 -I qg.py clones
    python3 -I qg.py clones --prune

`clones` takes the files of the classes named in `[clones].classes` from the inventory, runs the pinned
jscpd with the SARIF reporter in a temporary directory, and compares the SARIF clone fingerprints with
the baseline. It fails (exit 1) when jscpd exits non-zero, writes no report, analyzes no files
(`--fail-on-empty` is always passed), a fingerprint is absent from the baseline, a fingerprint occurs
more often than its accepted `count`, or a baseline entry has an empty reason. Each offending clone is
listed with its files and line ranges.

`--prune` rewrites the baseline without entries that no longer occur and lowers each surviving count to
the number of clones that actually occur. It never adds an entry and never raises a count. New clones
still fail; add an exception by hand, with a reason. A baseline that would be empty is removed instead
of written, so the file may be absent when there is nothing to accept.

`clones` requires the pinned jscpd binary. It never downloads implicitly and never skips the check.

### tools

    python3 -I qg.py tools fetch
    python3 -I qg.py tools fetch --lock /path/to/tools.lock.toml
    python3 -I qg.py tools path jscpd

`tools fetch` reads the gate's `tools.lock.toml` (or `--lock FILE`) and installs every pinned tool under
`QG_TOOLS_DIR`, which defaults to `~/.local/share/code-quality-gate/tools`, as `NAME-VERSION/`. It downloads
with `urllib`, verifies the SHA-256 before extracting, and refuses a mismatch or an unsafe archive
member (absolute path, `..`, link, or non-regular file) without installing anything. An existing install
whose binary is present is kept and not downloaded again. Extraction is staged in the tools directory and
moved into place atomically.

`tools path NAME` prints the expected binary path, whether or not the tool is installed, so scripts can
locate the cache. An unknown tool name exits 2.

The default tools directory is shared by every repository using the gate on this machine. Set
`QG_TOOLS_DIR` to use a different cache (for example in a container or a test).

### check

    python3 -I qg.py check
    python3 -I qg.py --repo /path/to/repo check

`check` runs `inventory`, then `hygiene`, then `clones` when `[clones]` is configured. It prints a
header for each check and a final `check: passed (...)` or `check: failed (...)`. It exits 1 if any
check failed. When inventory fails, clones are reported as skipped and the combined check still fails;
hygiene still runs. Configuration errors exit 2 before any check starts.

### Exit codes

* `0` - the command passed.
* `1` - a check failed (inventory, hygiene, clones, tool installation, or a malformed baseline).
* `2` - missing or invalid configuration, invalid command line, a repository that is not the top level
  of a git work tree, an unknown inventory class, or a malformed tool lock.

## Configuration

`quality-gate.toml` is read with `tomllib`. A missing file or an invalid value exits 2, naming the
file, the key, and the expected versus actual value. The complete shape is:

    [code]
    patterns = ["*.py", "*.sh", "*.el"]   # fnmatch on the repository-relative path
    shebangs = ["sh", "bash", "python*"]  # fnmatch on the first-line interpreter basename, after env

    [hygiene]
    max_bytes = 10485760                  # optional; this is the default

    [classes.python]
    code = true                           # may hold code files
    description = "Python programs and tests"

    [classes.shell]
    code = true
    description = "Shell scripts"

    [classes.config]
    code = false
    description = "Configuration and pinned data"

    [classes.build]
    code = false
    description = "Build orchestration"

    [classes.doc]
    code = false
    description = "Documentation"

    [[rule]]
    pattern = "*.py"                      # fnmatch on the repository-relative path
    class = "python"
    reason = "Python source and tests"

    [[rule]]
    pattern = "*.sh"
    class = "shell"
    reason = "Shell scripts"

    [[rule]]
    pattern = "*.toml"
    class = "config"
    reason = "configuration and the clone baseline"

    [[rule]]
    pattern = ".gitignore"
    class = "config"
    reason = "ignore rules"

    [[rule]]
    pattern = "Makefile"
    class = "build"
    reason = "build orchestration"

    [[rule]]
    pattern = "*.md"
    class = "doc"
    reason = "documentation"

    [clones]                              # optional; omit it to skip clone checks
    classes = ["python", "shell"]         # files to scan, from the inventory
    min_tokens = 50                       # optional; this is the default
    baseline = "quality-gate-clones.toml"

This example is a shape, not a universal inventory: delete a rule if your repository has no matching
file, and add a rule for every other file it does have (for example a README, a Makefile, or the clone
baseline). The configuration file itself is enumerated, so it needs a rule too.

Notes:

* `pattern` is matched with `fnmatch.fnmatchcase` against the repository-relative path. `*` matches
  slashes too, so `*.py` matches Python files at any depth.
* Every enumerated file must match exactly one rule, and every rule must match at least one file.
  The configuration file itself is enumerated, so give it a rule too.
* `reason` is mandatory and must be non-empty for every rule. `description` is mandatory and
  non-empty for every class.
* A class with `code = true` may hold code files. A code file may not be placed in a class with
  `code = false`, even if the rule's reason says it is documentation or configuration.
* Every class named by a rule must exist in `[classes]`. A class may exist without any file.
* `[clones].classes` must name configured classes. The baseline path is resolved relative to the
  repository root.

## Clone baseline and ratchet semantics

The baseline is a TOML file (usually `quality-gate-clones.toml`, committed next to the configuration)
with one array-of-tables entry per accepted fingerprint:

    [[clone]]
    fingerprint = "76c7cbddc2677be2"
    count = 1
    files = ["src/a.el", "src/b.el"]
    reason = "the two front ends deliberately mirror each other"

    [[clone]]
    fingerprint = "2747b38a91d89fbd"
    files = ["bin/a.sh", "bin/b.sh"]
    reason = "paired installers kept in sync by hand"

* `fingerprint` is the clone's `partialFingerprints["jscpdCloneHash/v1"]` from the SARIF report.
* `count` is how many reported clones with that fingerprint the baseline accepts. It defaults to `1`.
* `files` records the files for humans and is preserved by `--prune`.
* `reason` must be non-empty. An empty or missing reason is a failure even if the clone matches.

The ratchet only lowers:

* A fingerprint that is not in the baseline fails. Add a new entry by hand, with a reason.
* A fingerprint that occurs more times than its `count` fails. Raise a count only by hand, with a
  reason; `--prune` will never do it for you.
* A baseline entry whose fingerprint no longer occurs is reported as `resolved` and is not a failure.
  `clones --prune` removes resolved entries and lowers counts to what occurs. It never adds an entry
  and never raises a count.
* An absent baseline means no clone is accepted. An empty baseline file is allowed and is removed by
  `--prune`.

Because the fingerprint covers the clone's token sequence, changing the duplicated code makes the old
entry resolve and the new clone fail until a human accepts it. That is the intended ratchet: code
quality can improve automatically, but accepting a new exception is always an explicit, reasoned edit.

## Pinned tools

`tools.lock.toml` in the gate repository is the only place tool versions live:

    [jscpd]
    version = "5.4.1"
    url = "https://github.com/kucherenko/jscpd/releases/download/v5.4.1/jscpd-linux-x64-gnu.tar.gz"
    sha256 = "f2017a17de2a8d5708f8354c6e7223f82da3dc6489675bce543ba00d9d529468"
    binary = "jscpd"

`tools fetch` accepts `--lock FILE` for testing or for a private mirror. The file uses `file://` URLs
just as readily as `https://` URLs, which is how the test suite exercises installation without a
network.

## This repository gates itself

The gate repository classifies its own files with `quality-gate.toml`, pins jscpd in
`tools.lock.toml`, and runs the same command a consumer runs. `make check` performs:

* Ruff (`ruff.toml`: Python 3.12, line length 110, rules `E`, `F`, `W`, `B`) on the files of the
  inventory's `python` and `test` classes;
* `py_compile` on the same files, with `PYTHONPYCACHEPREFIX` in a temporary directory;
* `python3 -I -m unittest discover -s tests`, failing when the run selects no tests;
* `python3 -I qg.py check` on this repository.

The Makefile's Ruff path can be overridden with `make RUFF=/path/to/ruff check`.

The tests execute `qg.py` as a subprocess on disposable fixture git repositories. Clone-gate tests use a
fake jscpd in a temporary `QG_TOOLS_DIR`; one test runs the real pinned jscpd on a fixture with a known
Emacs Lisp clone pair and a known Bash clone pair and fails, rather than skipping, when the tool is not
installed. `tools fetch` tests use fixture tarballs with `file://` URLs, including wrong hashes and
unsafe archive members.

## Planned later layers

The core gate is deliberately language-agnostic. The planned order for the metric adapters is:

1. **Python CRAP adapter** - join Python coverage with cyclomatic complexity per function, then gate on
   a reasoned CRAP baseline. Python's tooling makes the first adapter the shortest path to a working
   metric ratchet.
2. **Emacs Lisp CRAP adapter** - reuse the same baseline and reporting model, but compute complexity and
   coverage through an Emacs batch helper, since Emacs Lisp has no maintained standalone CRAP tool.

Both layers will use the same rule: a new exception is a hand-written baseline entry with a reason, and
pruning only removes resolved entries or lowers counts.
