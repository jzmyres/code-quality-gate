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
* Optional top-level `python_import_roots` configures Python import analysis. See
  [Python import roots](#python-import-roots).
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
* Optional `[capabilities.NAME]` tables declare a nonblank capability name and exactly two
  required fields. `owner` is a nonblank string naming a declared module. `entry_points` is a
  nonempty array of distinct, exact, case-sensitive repository-relative paths. The paths reject
  glob syntax, empty, `.` and `..` components, and NUL characters. Declaring any capability
  requires `[checks.module-contracts]`. An omitted or empty `[capabilities]` declares none.
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
  `run_seconds` (default 300) are positive integers. `test_runner` is `unittest` by default.
  Set it to `pytest` to require verified collection and test execution in both copied trees.
  A strict subset ranked by explicit module and symbol use can run first. References to the exact
  changed function rank ahead of references to other symbols. A mutant that passes the preferred
  tests runs against the full selection with its own verified original. Within a pytest mutation
  measurement, functions in the same module can reuse a passing original for the identical ordered
  cohort. Pytest originals and mutants run in fresh copies from the same snapshot. Source bytes used
  for selection must match the snapshot. `mutant_seconds`
  bounds each child invocation, and `run_seconds` includes both cohorts, copying and cleanup.
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

### Python import roots

Set the top-level key `python_import_roots = ["src"]` when `src/pkg/mod.py` is imported as
`pkg.mod`. It takes a nonempty ordered array of unique, canonical repository-relative directory
paths. Use `.` for the repository root. It defaults to `["."]`. Roots must exist as directories
without symlink components when the analysis runs.

The module graph, module contracts, and affected dependency selection search those directories
in order for absolute imports and then search the importing file's directory. A relative import
starts from the package containing the importing file under its most specific configured root.
Python mutation uses names relative to the same roots to associate test imports with changed
production functions. This setting controls static analysis. Test imports at run time use the
suite's own setup.

A package initializer has its package's dotted name and its explicit `.__init__` import name.
A file can also have multiple dotted names when configured roots overlap. Graph extraction and
mutation fail when two files in their inputs provide the same dotted name. If affected selection
cannot extract the graph, it selects full inputs according to the affected-scope rules.

### Python module graph policy

The `module_graph` adapter requires `classes`, a nonempty array of inventory class
names. It reads the Python files in those classes. The optional `suites` array
contains case-sensitive `fnmatch` patterns for repository-relative paths. It defaults
to an empty array. The adapter uses a fixed maximum threshold of zero findings.

A `from P import N` edge points to `P.N` when that module is in scope and otherwise points to
`P` when it is in scope. Only edges between measured files are recorded.

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

### SHA-256 provenance policy

A `secrets` adapter can declare an array of `sha256_provenance` tables. For
example, this policy is for a JSON record whose first pack records the digest
of a four-byte payload containing `abc` and a newline.

```toml
[checks.secrets]
adapter = "secrets"
tier = 1
enforcement = "enforced"

[[checks.secrets.sha256_provenance]]
record = "evidence/report.json"
pointer = "/packs/0/tokens_sha256"
payload = "evidence/pack.raw"
payload_sha256 = "edeaaff3f1774ad2888673770c6d64097e391bc362d7d6fb34982ddf0efd18cb"
```

Choose the payload and independently verify its digest before adding the
declaration to the policy used by `--policy-from`. Use exact repository-relative
paths to separate regular files. With a string `payload`, the gate hashes the
captured working-tree bytes of a Git-tracked file.

A compressed payload uses an inline table for the same `payload` field.

```toml
payload = { path = "evidence/pack.gz", compressed_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", decoded_size = 4 }
```

Replace the sample `compressed_sha256` with the 64 lowercase hex digits of
the captured Git-tracked archive's SHA-256. The archive can be up to 16 MiB
and must contain one complete gzip member with a valid checksum and no
trailing bytes. `decoded_size` is the exact decoded byte count, from zero
through 32 MiB. `payload_sha256` is the SHA-256 of the decoded bytes. The
archive remains a regular input to the standard scanner. These fields belong
inside the `payload` table and are independent of the pins on a gzip record.

A historical payload uses an inline table for the same `payload` field:

```toml
payload = { path = "evidence/pack.raw", commit = "1111111111111111111111111111111111111111", blob = "2222222222222222222222222222222222222222", size = 4 }
```

Replace the sample IDs with full lowercase hexadecimal commit and blob IDs in
the repository's object format. The commit must be an ancestor of the
candidate HEAD captured by the check, or equal to it. Git lookups ignore
replacement references and grafts and do not fetch. Repositories configured
for promisor lookups leave historical proofs unresolved. The literal path
must identify exactly one regular blob at that commit, no larger than 16 MiB.
The gate verifies its object ID, byte length and `payload_sha256` within the
check's budget. This lookup does not add its historical contents to the
working-tree scan. The rest of the declaration uses the same record and
pointer fields.

A plain `.json` record can contain up to 16 MiB of UTF-8 JSON. The JSON
Pointer uses `~0` and `~1` escapes and zero-based array indices. Each
record and pointer pair can appear once.

A Git-tracked `.py` record can contain up to 16 MiB of UTF-8 Python source.
Use `/ASSIGNMENT/literal-key` for a key in a single top-level assignment
such as `DIGESTS = {"token_config.json": "…"}`. Use a separate tracked
payload path or a bounded gzip payload table. The assignment uses one ASCII
identifier and a dictionary of unique, unescaped string literal keys and values. The selected
value must be one single- or double-quoted lowercase digest on the scanner's
reported line. The gate parses the source without executing it and compares
the literal's byte span against the scanner's match. The proof covers that
literal occurrence. Findings on later dictionary mutations follow standard
enforcement.

For a Git-tracked `.json.gz` record, add `compressed_sha256` for the exact
captured gzip bytes and `decoded_sha256` for the exact UTF-8 JSON bytes. Both
fields require 64 lowercase hex digits and belong only on `.json.gz` rows.
Compressed and decoded bytes each have a 16 MiB limit. The record must have
one complete gzip member with a valid checksum and no trailing bytes.

Use the exact bytes the producer hashed. For example, when a producer hashes
the contents of a tensor, a serialized tensor container with a header is a
different payload. Both the policy pin and the selected scalar must equal the
recomputed digest.

The pinned scanner scans every selected input under its standard rules.
Betterleaks v1.10.1 can report columns relative to a fragment that starts
mid-line. The gate requires exactly one location on the reported line at or
after the reported start column with the same byte width and redacted match
template. It then checks that the location identifies the declared lowercase
digest string. A verified finding counts in
`measurement.verified_sha256_provenance`. For gzip and Python proof
candidates, the gate reruns the pinned scanner on the same captured file
with secondary decoding disabled. The replay reads one archive layer for
gzip and zero for Python. The original scan and this replay must each
report exactly one identical finding at that coordinate. Python requires a
unique matching shape across the entire physical line.
The standard scan retains its usual archive and decoding settings. Other
findings, including adjacent credentials and findings in secondary decoded
content, retain their normal enforcement.

A check without `--policy-from` scans without applying these declarations.
Missing payloads, changed bytes, duplicate JSON member names, and findings
whose location cannot be verified leave the scanner finding in place. A
failed, incomplete, or invalid replay leaves the original finding in
place. The check rejects a failed standard scan or an incomplete or invalid
standard scanner report.

### Published tokenizer vocabulary integers

A trusted policy can opt in to exact integer proof for a published tokenizer
asset. This example uses a synthetic release address and illustrative pins.

```toml
[[checks.secrets.public_vocabulary]]
path = "assets/tokenizer.json.gz"
published_url = "https://example.invalid/releases/1111111111111111111111111111111111111111/tokenizer.json"
published_revision = "1111111111111111111111111111111111111111"
published_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
published_size = 4000
compressed_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
compressed_size = 1200
pointers = ["/model/vocab/example-password-label", "/model/vocab/example-username-label"]
```

Independently retrieve the exact revision and verify the published bytes
before adding the declaration to the directory used by `--policy-from`. The
gate uses the pinned size and SHA-256 offline. It accepts vocabulary
declarations from that trusted directory. If a run authorizes a candidate
policy replacement, the replacement's vocabulary declarations take effect
after they are included in a trusted directory for a subsequent run.

Declare up to 16 exact Git-tracked regular file paths, with up to 256 distinct
`/model/vocab/<key>` JSON Pointers per path. Use the JSON Pointer escapes
`~0` and `~1` for literal tilde and slash. For an uncompressed `.json` file,
omit both compressed fields. The published JSON size is capped at 32 MiB.
A `.json.gz` file is capped at 16 MiB and must contain one complete gzip
member without extra bytes. The published pins apply to its exact inflated
bytes. The captured input is scanned with the standard flags.

The gate parses the complete UTF-8 document with unique object names and
requires a BPE, WordLevel, or WordPiece model with nonnegative integer
vocabulary IDs. Each proof requires a single physical member line with a
trailing comma and a unique redacted match at the exact reported byte
coordinates. The redacted span must cover the complete canonical decimal
integer at the declared pointer. The supported finding is
`generic-password` with zero or one optional `generic-username` component.
An attached component needs its own declared pointer and exact integer
proof. The standard scan and the decoding-disabled replay must each produce
the same unique row. For gzip, a second decoding-disabled replay reads the
already verified inflated bytes directly.

The measurement `verified_public_vocabulary` counts verified findings.
`public_vocabulary_locations` reports each verified row's redacted
coordinates, with the primary location first and any attached location
second. Findings with inconsistent bytes, unknown shape, incomplete
component proof, or ambiguous or failed replay remain unresolved. A tokenizer
asset with more than 256 candidate rows leaves all of them unresolved. The
16 MiB JSON record bound for SHA-256 assignment proof still applies.

### Public hardware model labels

Use `[[checks.secrets.public_hardware_model_v1]]` in the existing trusted
directory for `--policy-from`. Each declaration covers one finding in a
Git-tracked regular `.json` or `.json.gz` file. Review the public model entry
independently and pin the separate catalogue commit in the trusted policy.
An authorized candidate policy replacement can supply these declarations
once it is included in a trusted directory for a subsequent run.

| Field | Meaning |
| --- | --- |
| `record` | Exact repository-relative path to the record |
| `pointer` | Non-root JSON Pointer for the one model string |
| `match_start`, `match_end` | Zero-based, half-open byte interval of the whole scanner match in the decoded record, including the matched assignment prefix and closing quote |
| `decoded_sha256` | SHA-256 of the complete decoded JSON bytes, including for uncompressed records |
| `compressed_sha256` | SHA-256 of the complete captured archive for `.json.gz` records |
| `catalogue.payload` | Separate historical Git payload table with literal path, full commit and blob IDs, and exact byte size |
| `catalogue.sha256` | SHA-256 of the entire catalogue blob |
| `catalogue.literal_start`, `catalogue.literal_end` | Zero-based, half-open byte interval inside the quotes of the complete unescaped string literal in a UTF-8 Python catalogue |

Only gzip records use `compressed_sha256`. A gzip record contains one
complete member, and its compressed and decoded bytes each have a 16 MiB
limit. Raw JSON records also have a 16 MiB limit. Each record and pointer
pair and each record and match interval pair can occur only once. The Git
operand follows the size, reachability and regular-file checks for a
historical SHA-256 payload. The gate parses the catalogue without executing
it and compares its exact string to the declared strict JSON scalar.

The proof requires an untransformed `fs.content` `generic-api-key` finding
with exact physical byte coordinates and one matching assignment shape
across the entire line. The normal report and a direct replay must each
produce one identical row at that coordinate. The replay disables secondary
decoding and reads zero archive layers for raw JSON and one for gzip.
`measurement.verified_public_hardware_models` counts verified findings when
the trusted policy enables this proof. Other findings retain normal
enforcement, including adjacent findings in the same record.

### Published tokenizer Git revisions

Use `[[checks.secrets.public_git_revision_v1]]` in the trusted
`--policy-from` directory. Each declaration covers one scanner occurrence
in an exact Git-tracked regular `.json` or `.md` file. Declare up to 16
distinct record paths. An authorized candidate policy replacement can supply
these declarations after inclusion in a trusted directory for a subsequent run.

| Field | Meaning |
| --- | --- |
| `record` | Exact repository-relative record path |
| `record_sha256` | SHA-256 of the complete captured UTF-8 file |
| `pointer` | JSON Pointer ending in `tokenizer_revision` |
| `match_start`, `match_end` | Zero-based, half-open byte interval of the whole scanner match in the complete file |
| `publication.repository_url` | Exact public Hugging Face model repository in the form `https://huggingface.co/owner/repository` |
| `publication.revision` | Full 40-digit lowercase Git commit ID |
| `publication.commit.payload`, `publication.tree.payload` | Historical Git payload tables, each with a separate literal path, full local commit and blob IDs, and exact byte size |
| `publication.commit.sha256`, `publication.tree.sha256` | SHA-256 of the exact archived public commit and root tree object bodies |

Before trusting the declaration, independently acquire the commit at the
declared public repository and archive the raw commit and root tree bodies.
Use the bodies returned by `git cat-file commit` and `git cat-file tree`.
Public origin is a trusted-policy decision based on that acquisition. The
gate uses the existing offline historical Git lookup to authenticate the
two archive blobs, each bounded by 64 KiB. It recomputes the typed public
Git object IDs, checks the commit's root tree link and verifies that the
root tree contains regular `tokenizer.json` and `tokenizer_config.json`
entries. The commit must have exactly one `author` and one `committer`
header. Each raw header value must fully match `name <email> timestamp
timezone`, with ASCII space separators. The name must contain a nonblank
byte and may contain non-ASCII bytes. The email field must be nonempty
and contain no ASCII whitespace. Name and email cannot contain angle
brackets. Neither identity can contain CR, NUL, or trailing bytes. The
Unix timestamp is `0` or an unsigned ASCII decimal without leading zeros.
The timezone is `+` or `-` followed by exactly four ASCII digits.

The value at the pointer must be the exact unescaped revision. A sibling
`tokenizer` string must exactly match the publication's repository name.
Records are bounded by 16 MiB and parsed as strict JSON with unique keys.
A `.json` record uses the complete file as its JSON region. A Markdown
record uses a single unindented fence with an exact ` ```json ` opener
and an exact ` ``` ` closer. The opener starts at byte zero or immediately
after two consecutive LF bytes. The opener must end with an LF line break.
The closer must follow an LF line break and end with LF or end of file.

The gate checks the whole Markdown record for marker lines at byte zero
and after every LF, bare CR, or CRLF line break. CRLF counts as one break.
A marker line starts, after any ASCII spaces or tabs, with three or more
backticks, three or more tildes, or `<`. The opener and closer must be the
only marker lines. The JSON region spans the bytes after the opener's LF
up to the start of the closer. The scanner uses LF-based coordinates in
the original file, and the declared half-open byte interval must lie inside
the JSON region.

The untransformed `fs.content` `generic-api-key` finding must match the
declared bytes and the exact pointer. The standard scan and a replay with
archive and secondary decoding disabled must return one identical row at
that coordinate. The check reports the count in
`measurement.verified_public_git_revisions` and redacted coordinates in
`public_git_revision_locations`. Changed bytes, unknown or ambiguous
documents, failed object proofs and failed or ambiguous replay make the
occurrence ineligible for this revision proof. The original finding remains
unresolved unless another proof verifies it. Adjacent and undeclared
findings retain normal enforcement.

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
Capability entry points are validated during the same ownership pass, including in a single-module
map. Each must be an inventoried code file uniquely owned by the capability's `owner`. The file
can be private to that module, and multiple capabilities can name the same file with that owner.

A cross-module direct edge must satisfy both requirements. The source must list the destination
in `allowed_dependencies`, and the target must appear in the destination's `entry_points`. The
enabled check runs after inventory and hygiene and before the other configured checks in full,
`--only` and `--base` runs, including an empty diff.
With successful inventory and a valid map declaring at least two modules, it extracts the full
owned-code graph using the existing Python, Emacs Lisp and shell extractors. Required extraction
failures, including Emacs preparation and reader errors, reject with exit 1, as do ownership,
interface and capability violations. Ordinary outside-extractor records are nonblocking. A valid zero- or
one-module map requires no extraction. `worklist` omits the built-in.

Only the declared owner can invoke a capability entry point. The `capability-owner` rule matches
the exact resolved target on `path-load` edges from Python `runpy.run_path` and
`importlib.util.spec_from_file_location`, `require` edges from Emacs Lisp, and `source` and
`execute` edges from the shell. Python `import` edges follow the module interface rule. The rule
uses only resolved graph edges, so an unresolved operand produces no capability finding. Capability
violations are checked across the full graph, regardless of the diff, `shared_base`, allowed
dependencies or module entry points. A call can violate both the interface and capability rules.

With `shared_base` enabled, `--base` takes precedence and supplies the same affected path union
used for check selection, Python shape, and `changed_paths`. Without `--base`, the check compares the
run's resolved `QG_DIFF_BASE` commit to `HEAD` when set, or the configured `shared_base` revision to
`HEAD` when unset. Use `shared_base = "HEAD"` to check staged and unstaged tracked edits on a
plain local run. Both forms include committed, staged, and unstaged tracked changes, with rename
detection disabled to include both names. The affected union also includes the inventory's standard
exclusion listing of untracked paths. Invalid bases and failed Git enumeration are command errors
even when inventory reports violations.

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
* `obligations` - one entry per effective policy code class and required tier.
  In finalized partial runs, every pair, including each configured exemption,
  has `status: "not_evaluated"`, the tier's evidence names in `required`,
  `checks: []`, `caused_by: null`, and `reason: "partial run"`.
  Preflight error documents have an empty array.
* `selected` - present only on a `check --only` result. Lists the requested check IDs and
  prerequisites in policy order, with `module-contracts` first when requested by ID.
* `scope`, `base`, `changed_paths` - present on finalized `check --base REV` results,
  including trusted runs. Scope is `affected`, base is the requested revision, and
  changed paths are the sorted union of merge-base-to-HEAD, index, and worktree
  comparisons and every inventory-visible untracked path. Both names of a rename are included.
  For a nonempty union, each selected test suite that reaches execution runs the full
  configured command or discovery suite. The graph remains an input to per-file selection.
  Affected unittest uses the shard runner's standard-suite admission and validates one
  terminal record per scheduled occurrence. Its report uses distinct labels for duplicate
  IDs and retains completed records and outstanding positions after interruption.
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
* `test_results` - optional native test results in ascending position order. Each row has a
  zero-based `position` in unittest discovery or ERT selection, an `id`, a native `outcome`,
  and `duration_seconds`. The duration is a finite, nonnegative number for an invoked test
  (including a skip) and null for a unittest occurrence prevented from starting by a fixture.
  Unittest outcomes are `passed`, `skipped`, `expected failure`, `unexpected success`,
  `failure`, `error`, `blocked`, and `fixture skipped`. ERT outcomes are `ert-test-passed`,
  `ert-test-failed`, `ert-test-skipped`, `ert-test-quit`, or `ert-test-aborted-with-non-local-exit`.
  ERT rows also have boolean `expected` and include a string `condition` for unexpected results.
  Native ERT totals exclude quits and non-local exits from the completed and skipped counts.
  Positions distinguish repeated unittest IDs.
  The affected unittest journal can retain the validated terminal prefix after an interruption.
  An empty array represents a validated report with zero terminal occurrences. The field is
  absent if evidence is unavailable or the adapter cannot supply native per-test evidence.

A test check reports its `outcome` and `reason` and keeps the command's output tail in
`diagnostics`; the executed count is in `measurement`. It records the executed and skipped counts
for verification, which reports them as `tests:ID:executed` and `tests:ID:skipped`.
Configured summary patterns supply the aggregate counts for ordinary Python and command suites.

A finding has `subject`, its raw `value`, `bound` (or null), `threshold`,
`baseline_reason` (or null), `covered_by_baseline`, `blocking`, `location`,
`locations` and `expired`. `locations` is an array of objects with `path`,
`start_line` and `end_line`, or null when the source locations are incomplete.
Baseline errors carry `error`.

`module-contracts` uses matching `id`, `kind` and `adapter`, `enforcement = "enforced"`,
and `metric_version = "module-contracts/1"`. Failed inventory makes the contract unsatisfied
with `caused_by = ["inventory"]`. Its `findings` array retains ownership, extraction,
interface, capability and shared entry point diagnostics. Reader errors include `file`, `stage`,
`line` and `message`.
Each distinct violating edge produces a `module-interface` finding ordered by source path, line,
target path and edge kind. It has `rule`, `edge` (`source`, `line`, `target`, `kind`),
`source_module`, `target_module`, `failed_conditions` and `permitted_entry_points`.
`failed_conditions` lists each applicable condition, `dependency-not-allowed` and
`target-not-entry-point`. `permitted_entry_points` is sorted and can be empty.
Invalid capability paths report `invalid-entry-point` with `key` set to
`capabilities.NAME.entry_points[INDEX]`, `file`, `module` (the declared owner), `reason` and
`message`. Each `capability-owner` finding has the caller `file` and one-based `line`, `capability`,
`owner`, `source_module`, `edge` (`source`, `line`, `target`, `kind`), and `message` naming the
capability and owner. Findings are unique and sorted by caller path, line, target path, edge kind
and capability name. Stderr includes the caller location.
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
the existing order. When consequences exist, the line before the verdict is
`check: consequences (ENTRY because CAUSE[, CAUSE...]; ...)`, where each entry
is spelled as the summary spells it: a check id or `obligation CLASS tier
TIER`. A consequence still rejects and still exits 1.

The decision is `rejected` when inventory, hygiene or module contracts fail, when an enforced
check is not satisfied, or when any evaluated obligation is `unsatisfied`. A run scoped by
`--base`, `--only`, or both skips obligation evaluation. Its result is `rejected` when a built-in
or any enforced check that ran is unsatisfied and `partial` (exit 0) otherwise. The text summary
lists the unevaluated class and tier pairs for both decisions. `accepted_with_exceptions` means
every obligation and enforced check is satisfied, but a baseline exception or a non-passing
advisory check exists. Attempt consumers requiring full assurance must use an unscoped result with
`decision` equal to `accepted` or `accepted_with_exceptions`.
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

## Check ledger file

With `check --ledger PATH`, the gate attempts one append of a compact JSON
record with `schema: 1` when a check invocation returns or unwinds after engine
preflight. Relative paths use the invocation's working directory, independently
of `--repo`. The parent directory must exist. An existing destination must be a
regular file. Without `--ledger`, the gate skips ledger collection, destination
inspection, and endpoint sampling.

The gate decides the verdict and exit status, writes the ledger, and flushes
pending progress and forwarded tool output. It writes the JSON result when
requested, prints final notices for unevaluated obligations and consequences
when applicable, and prints the verdict as its last line. A trust block ends
with `check: blocked: ...` after the protected-input details. A trust identity
error ends with `check: error: ...` describing the drift. Text stdout and the
schema-3 and schema-4 result documents keep their existing formats.

| Field | Evidence recorded |
|---|---|
| `run_id` | A new UUID for each invocation that passes engine preflight. |
| `start`, `end` | Consumer Git samples with `revision` (HEAD resolved as a commit) and `dirty` (a boolean), each nullable when unknown. |
| `attribution_revision` | The common commit when both samples resolve to that commit and explicitly report clean. Otherwise null. |
| `gate_version`, `policy_sha256` | The gate revision and the SHA-256 of the policy bytes decoded for this run. |
| `scope`, `selected` | `full`, `partial` for `--only`, or `affected` for `--base`. `selected` lists the IDs from `--only` with their prerequisites, or is null. Built-ins run according to the effective policy. |
| `base`, `resolved_base`, `changed_paths` | The requested `--base` spelling, the resolved shared diff base, and the affected path set, respectively. The resolved base for an affected run is the merge base. The ledger also records a valid `QG_DIFF_BASE` override once resolved. Unavailable or inapplicable values are null. |
| `decision`, `exit_status` | The final decision and command status, including overrides from trusted-input checks. An unwind records `error` and the status when handled by the CLI, or null if no command status has been selected. |
| `complete`, `termination` | A normal engine return has `complete: true`, including rejected, blocked, and errored decisions. An unwind has `complete: false` and the exception class in `termination`. Otherwise `termination` is null. |
| `checks` | Rows in scheduler order, including inventory, hygiene, enabled module contracts, and any configured result or explicit skip. |
| `exemptions` | Evaluated policy exemptions identified by `class` and `tier`, from the finalized obligations. |

Each returned check contributes exactly one row with `id`, `adapter`,
`metric_version`, `execution`, raw `outcome`, `duration_seconds`, and
`satisfied`. Duration is the result's wall time with six decimal places
of precision, including time spent on adapter discovery when its result is
`not_run`. A scheduler skip without adapter work contributes zero seconds.
Returned rows also retain the enforcement setting, the result's
`location_coverage` and baseline resolution lists, and a per-check
`resolved_base` when available.
`selection` carries the `selected` and `left_out` input or test identifiers
when the check reports them, and is null otherwise.
When check JSON includes `test_results`, its ledger row includes the same array with the
same ordering and duration precision.

The `findings` array carries reported subjects and structured evidence,
including the paths and line ranges available from the result. A finding
with a path and no line has null line bounds. A finding without structured
ranges has `locations: null` and retains any available result location
label, such as the known spans of a partially located clone. Ratchet findings
retain `covered_by_baseline`, `blocking`, `expired` and the baseline expiry
date in `baseline_expires` when available. The ledger leaves out command
output, diagnostic arguments, free-form reasons, and comment text.

If a dispatched check raises before producing its result, the last row
has `execution: "interrupted"`, null outcome and satisfaction, the exception
class in `termination`, and monotonic elapsed time from dispatch until the
attempt unwound. Earlier results survive a failed run-directory cleanup.
Checks the scheduler never reached have no row. A preflight refusal
produces no ledger record. A process killed without unwinding may leave the
file without one. A new destination receives its first complete record only when
the gate publishes it without replacement. A dangling final symlink is refused.
For an existing file, the gate validates the open descriptor and checks that any
existing content ends in a newline before appending. A refusal before writing
preserves existing records and leaves an absent destination absent. A failed
write to an existing file can leave a partial tail. Later appends refuse that
file until the incomplete tail is removed.

A failed ledger append on normal return is a command error with exit status 2.
The error names the supplied path and the underlying OS error and takes the
place of the verdict. JSON mode emits one error document. When the command is
already unwinding, the original exception and status take precedence, and the
append failure is attached as an exception note.

The two Git samples describe Git-visible state at the endpoints. Porcelain
status includes untracked files and disables submodule ignore settings.
Visible changes report `dirty: true`. A failed status probe or an otherwise
clean status with a failed index probe or a change-hiding index flag, such
as assume-unchanged or skip-worktree, reports `dirty: null`. Changes reverted
between samples can escape detection. Ignored untracked files, external inputs,
and recursive content verification are outside the scope of the endpoint
claim. The effective policy digest is recorded separately. The schema-4 stdout
document carries the trusted-input evidence for trusted runs.

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
