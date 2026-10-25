# M1b: policy checks, the command adapter, one generic ratchet, and a JSON result

Repository: `~/code-quality-gate`. Work only in the clone `/home/work/code-quality-gate/.worktrees/qg1`. Read
`CLAUDE.md`, `README.md`, the package `quality_gate/` (M1a), `quality-gate.toml`, `tools.lock.toml`, the tests,
and `plans/review-fable-tiered-design-2026-10-24.md` sections 3-5 first. Fable's schema is the approved design;
where this spec is more specific, follow this spec.

Why (user approval 2026-10-24): the gate becomes one tiered gate any repository adopts by policy. M1b adds the
core that every later adapter plugs into: declared checks, measurement in adapters and decisions in the core,
one reasoned ratchet, and a machine-readable result that agents read.

## Policy (`quality-gate.toml`)

- A required top-level `schema = 1`. Any other value, or a missing key, is a configuration error.
- Unknown keys anywhere are a configuration error naming the key and the allowed keys.
- `[classes.NAME]` gains `checks`, a list of check ids. Inventory fails when a code class lists no check, or
  lists an id that has no `[checks.ID]` table.
- `[checks.ID]` with `adapter`, `tier` (1-4), `enforcement` (`enforced` or `advisory`) and adapter-specific keys:
  - `adapter = "command"`: `run` (argument list, required), `budget_seconds` (default 600), optional
    `must_match` (a regular expression the combined output must match). Tokens in `run`: `{files}` expands to
    the sorted files of every class that lists this check (in place, as separate arguments); `{tool:NAME}`
    expands to the binary of a tool pinned in `tools.lock.toml`, which must already be fetched (missing:
    outcome `unsupported`, naming `qg.py tools fetch`). A check using `{files}` whose classes have no files
    fails ("no files selected"): zero inputs is not a pass.
  - `adapter = "clones"`: the existing clone check, keyed by `min_tokens` and `baseline`; the old top-level
    `[clones]` table is removed (no compatibility path).
- `[levels]` with `required_tiers`, a list of tiers that must contain 1 (default `[1]`). Every code class must
  list at least one enforced check of each required tier, or have a `[[not_applicable]]` entry (`class`,
  `tier`, non-empty `reason`) for it; otherwise inventory fails. (M4 raises the minimum to include tier 2 once
  tier-2 adapters exist.)

## The generic ratchet (core)

An adapter that measures subjects returns findings: `subject`, a numeric `value` and a `location`. The policy
gives the check's `threshold` (clones: 0 extra occurrences, so the clone count is the value with threshold 0;
later CRAP: 6) and `baseline`, a TOML file of `[[entry]]` tables with `subject`, `bound`, a non-empty `reason`,
optional `expires` (a TOML date) and adapter-specific informational keys (clones keep `files`). The core
decides, for every adapter alike:
- a finding passes when `value <= threshold`, or when a baseline entry for its subject exists, has not expired
  and `value <= bound`. Compare unrounded; exactly at the bound passes;
- a finding above both fails, naming subject, value, bound or threshold and location;
- an entry with an empty reason fails; an expired entry no longer covers its subject and is reported as
  expired;
- an entry whose subject was not measured, or now passes the threshold, is reported as resolved;
- `--prune` (on `qg.py check --prune ID` and the existing `clones --prune`) only lowers each bound to the
  measured value and drops resolved entries; it never raises a bound or adds an entry, and it refuses (exit 1,
  writing nothing) while that check fails. **Behaviour change:** clones prune used to write while failing.

Move the clone baseline onto this format. The gate has no clone baseline file today, so nothing converts.

## The result

- `qg.py check` runs inventory and hygiene (built in, always) and then every configured check, in policy order.
  Human-readable lines stay as today (progress on stdout, failures on stderr).
- `qg.py check --json` prints exactly one JSON document on stdout and the human lines on stderr:
  `schema` (1), `gate_version` (the gate's git revision, or "unknown" with a reason when unavailable),
  `revision` and `dirty` (the consumer's HEAD and whether its tree has changes), `policy_sha256`, `decision`,
  and `checks`: one object per check with `id`, `tier`, `enforcement`, `adapter`, `metric_version`, `outcome`
  (`pass`, `fail`, `unsupported` or `error`), `duration_seconds`, `budget_seconds`, `termination`
  (`exit`, `budget` or `signal`) and `findings` (`subject`, `value`, `bound`, `threshold`, `baseline_reason`,
  `blocking`, `location`), plus `resolved_baseline_entries`.
- Decision: `error` (exit 2) when the policy or a usage is invalid; `rejected` (exit 1) when any enforced
  check's outcome is not `pass`; `accepted_with_exceptions` (exit 0) when everything enforced passes but some
  finding passes only through a baseline entry or an advisory check failed; otherwise `accepted` (exit 0).
  Missing evidence is `unsupported`, never `pass`.

## Self-policy and tools

- Pin ruff 0.17.0 (the newest release at least two weeks old) in `tools.lock.toml`:
  url `https://github.com/astral-sh/ruff/releases/download/0.17.0/ruff-x86_64-unknown-linux-gnu.tar.gz`,
  sha256 `c94fc1dc71f054d06d9f1149442dcb471516aa2b7d4b7e8124e05d082d4c91d3` (GitHub's asset digest),
  binary `ruff-x86_64-unknown-linux-gnu/ruff`. Make `tools fetch` handle it like jscpd. The tools cache is
  read-only inside your sandbox and you have no network, so you cannot fetch it: write the tests so that the real
  ruff run is exercised only when the binary exists, and say in your final message that Claude must run
  `python3 -I qg.py tools fetch` before the gate. (Claude fetches it after your run; the gate then must pass.)
- The gate's own `quality-gate.toml` declares `schema = 1`, a `ruff` command check (`{tool:ruff}`, `check`,
  `--no-cache`, `{files}`) for its Python classes, and the clones check; the Makefile's lint uses the pinned
  ruff through `qg.py tools path ruff` instead of the venv path.

## Tests (each failure mode must be made to fail)

Fixture-repository tests through the real command, as the existing tests do, covering at least: schema missing
or wrong; an unknown key; a code class with no checks; an unknown check id; `required_tiers` without 1; a missing
tier with and without `not_applicable`; a command check passing, failing, timing out (`termination` `budget`),
missing `must_match`, and selecting no files; `{tool:NAME}` unknown and unfetched; ratchet: new subject above
threshold fails, exactly at bound passes, 0.1 above fails, empty reason fails, expired entry fails, resolved entry
reported, prune lowers and never raises, prune refuses while failing; an advisory failure yields
`accepted_with_exceptions` and exit 0; `--json` emits one parseable document with every field above; exit codes
0, 1 and 2.

## Docs

README (policy reference, ratchet, result schema, exit codes), `CLAUDE.md` (orientation). Commit label
`behaviour change (policy checks and generic ratchet)`.

ACCEPT: make -k check
