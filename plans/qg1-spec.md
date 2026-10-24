# QG1: the reusable gate's core (inventory, hygiene, duplicate-code ratchet, pinned tools)

Repository: `~/quality-gate`. Work only in the clone `/home/work/quality-gate/.worktrees/qg1`. Read its
`CLAUDE.md` first. You run as an unprivileged user in a sandbox with no network and no sudo.

Reference implementations, to read and generalize, not copy blindly:
- `/home/work/agent-harness/tests/inventory.py`, `/home/work/agent-harness/Makefile` (lint, hygiene and
  inventory targets) and `/home/work/agent-harness/tests/test_inventory.py`.

jscpd 5.4.1 is installed at `~/.local/share/quality-gate/tools/jscpd-5.4.1/jscpd`. Its documentation is in
`/tmp/claude-1000/-home-work-spacemacs-config/cc02e3ce-dc97-491e-8364-7ba7beb6fcbd/scratchpad/jscpd-docs/rust.md`
(the docs describe HEAD, so check behaviour against the binary). Ruff 0.16.0 is at
`/home/work/.local/share/spacemacs-tools/venv/bin/ruff`.

## 1. `qg.py`: one standard-library Python 3.12 command

Usage: `python3 -I qg.py [--repo DIR] COMMAND`, where DIR (default: the current directory) must be the top
level of a git work tree.
- Configuration is `DIR/quality-gate.toml`, read with `tomllib`. A missing file or an invalid value exits 2,
  naming the file, the key, and expected versus actual.
- Files are enumerated with `git ls-files -z -co --exclude-standard` (tracked or stageable). Git is run
  with `-c safe.directory=<real path of DIR>`, since the sandbox can give the checkout to another user. An
  enumeration failure fails the command.

### `inventory` and `inventory --list CLASS`

Configuration:
```toml
[code]
patterns = ["*.py", "*.sh", "*.el"]   # fnmatch on the repository-relative path
shebangs = ["sh", "bash", "python*"]  # fnmatch on the first-line interpreter's basename, after env

[classes.python]
code = true                            # may hold code files
description = "Python programs: lint, test"

[[rule]]
pattern = "tools/*.py"                 # fnmatch on the repository-relative path
class = "python"
reason = "..."
```
- Every enumerated file matches exactly one rule, every rule matches at least one file, every reason is
  non-empty, every class exists, and a code file (by pattern or shebang) is only in a class with
  `code = true`.
- On failure, print every violation and exit 1. On success, print `inventory: N files match M rules`.
- `--list CLASS` prints the class's files one per line, so a consuming repository's checks take their file
  lists from the inventory. It exits 2 for an unknown class.

### `hygiene`

Fails when a tracked file matches the ignore rules (`git ls-files -ci --exclude-standard`), when an
enumerated file exceeds `[hygiene] max_bytes` (default 10485760), or when enumeration or size measurement
fails.

### `clones` and `clones --prune`

Configuration:
```toml
[clones]
classes = ["python", "shell"]               # files to scan, from the inventory
min_tokens = 50
baseline = "quality-gate-clones.toml"
```
- `clones` runs the pinned jscpd on those files with the SARIF reporter into a temporary directory. A
  clone's fingerprint is its `partialFingerprints["jscpdCloneHash/v1"]`.
- The baseline holds `[[clone]]` entries `fingerprint`, `count` (how many reported clones with that
  fingerprint it accepts, default 1), `files` and a non-empty `reason`. It may be absent when it would be
  empty.
- The command fails, listing each offending clone's files and line ranges, when:
  - a clone's fingerprint is not in the baseline;
  - a fingerprint occurs more times than its `count`;
  - a baseline entry has an empty reason.
- It also fails when jscpd exits non-zero, writes no report, or analyzes no files (`--fail-on-empty`).
- A baseline entry whose fingerprint no longer occurs is reported as `resolved`; that is not a failure.
- `clones --prune` rewrites the baseline without resolved entries, and lowers `count` to what occurs. It
  never adds or raises an entry: a new exception is added by hand, with a reason.

### `tools fetch` and `tools path NAME`

`tools.lock.toml` in this repository pins every external tool. Use exactly these values:
```toml
[jscpd]
version = "5.4.1"
url = "https://github.com/kucherenko/jscpd/releases/download/v5.4.1/jscpd-linux-x64-gnu.tar.gz"
sha256 = "f2017a17de2a8d5708f8354c6e7223f82da3dc6489675bce543ba00d9d529468"
binary = "jscpd"
```
- `tools fetch` downloads each tool with `urllib` into `QG_TOOLS_DIR` (default
  `~/.local/share/quality-gate/tools`), as `NAME-VERSION/`.
- It verifies the SHA-256 before extracting and refuses on a mismatch, installing nothing.
- It extracts only regular-file members with safe relative names (no absolute paths, no `..`, no links).
- It keeps an existing install whose binary is present.
- `tools path NAME` prints the binary's path.
- Any command that needs a missing tool fails with a message saying to run `qg.py tools fetch`. It never
  downloads implicitly and never skips the check.

### `check`

Runs `inventory`, `hygiene` and, when `[clones]` is configured, `clones`; reports each, and exits 1 if any
failed.

## 2. This repository gates itself

- `quality-gate.toml` classifies this repository's own files.
- `ruff.toml`: `target-version = "py312"`, `line-length = 110`, `select = ["E", "F", "W", "B"]`.
- `Makefile`: `check` runs Ruff and `py_compile` (with `PYTHONPYCACHEPREFIX` in a temporary directory) on
  the files of the inventory's Python and test classes, `python3 -I -m unittest discover -s tests` (failing
  when it selects no tests), and `python3 -I qg.py check` on this repository.

## 3. Tests: `tests/test_*.py`

The tests execute `qg.py` as a subprocess on disposable fixture git repositories. Every pass case and
every failure mode named in section 1 is a test, including each exit-2 configuration error.
- Clone gate logic: use a fake jscpd, an executable script writing a fixture SARIF report, placed as
  `jscpd-5.4.1/jscpd` in a temporary `QG_TOOLS_DIR`. Add no other test-only switch.
- The real binary: one test runs the real jscpd from the default tools directory on a fixture that holds
  a known Emacs Lisp clone pair and a known Bash clone pair, and asserts both are reported. If the tool is
  not installed, the test fails with a message naming `qg.py tools fetch`; it is never skipped.
- `tools fetch` uses `file://` URLs to fixture tarballs, in a temporary lock and tools directory, to cover:
  a correct hash installs; a wrong hash refuses and installs nothing; an unsafe member refuses; an existing
  install is kept. To make the lock path testable, `tools fetch` takes an optional `--lock FILE`.

## 4. README.md

Cover:
- what the gate is for;
- every command, with exact runnable examples;
- the configuration format;
- the ratchet semantics;
- how a repository consumes it: a git submodule at `quality-gate/`, running
  `python3 -I quality-gate/qg.py check` and `python3 -I quality-gate/qg.py tools fetch`;
- the order planned for later layers: Python CRAP adapter, Emacs Lisp CRAP adapter.

ACCEPT: make -k check
