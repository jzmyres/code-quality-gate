# QF2: the result and ratchet contract (Astra's gate review, second fix set)

Repository: `~/code-quality-gate`. Work only in the clone `~/code-quality-gate/.worktrees/qg1`. Read
`CLAUDE.md`, `README.md`, `quality_gate/`, the tests, and `plans/review-astra-gate-2026-10-25.md` (the "QF2" line of
Claude's triage: findings 1, 3, 4, 5, 15, 20, 21, 22, 24) first. QF1 has landed before this item.

Why: the result and the ratchet are what agents and later tiers depend on. Decide them now so M4 (tier 2) and M5
(tiers 3/4) add adapters without reworking the core, and so absence of evidence never reads as success.

## Changes

1. **Separate execution, measurement and policy (3).** The result schema becomes `schema = 2`. Each check reports
   `execution` (`completed`, `budget`, `signal`, `error`), `outcome` (the adapter's raw verdict: `pass`, `fail`,
   `unsupported`, `error`; tier 3 later adds `proved`, `no_counterexample`, `unknown`), and `satisfied` (whether the
   policy obligation is met after baselines and enforcement). Findings keep their raw value and say
   `covered_by_baseline`. Inventory and hygiene appear in `checks` like any other check.
2. **Diagnostics in JSON (20).** Each check carries `diagnostics`: the argv it ran, exit code or signal, output byte
   count and a bounded tail (4 KiB), so a consumer never parses stderr to learn why a check failed.
3. **Obligations, not labels (1).** A check's adapter declares the evidence it produces: `tests` (python_tests, and
   the command adapter only when its policy gives `tests_pattern`, counting executed tests as in QF1), `crap`,
   `duplication`, `static` (any other command). Tier 1 is satisfied for a code class only by a passing enforced
   check producing `tests` evidence with at least one executed test (lint alone does not satisfy it); tier 2 (M4)
   will require `properties` or `fuzzing` evidence. The result has `obligations`: one entry per code class and
   required tier with `status` (`satisfied`, `exempted` with its reason, `unsatisfied`) and the checks that
   counted. An unsatisfied obligation rejects.
4. **Resolution needs a complete scan (4).** An adapter reports the subject domain it measured completely (for
   example the selected files); the ratchet resolves or prunes an entry only when its subject lies in that domain
   and was not found above threshold. Entries outside the measured domain are reported `unmeasured` and kept. Each
   baseline file starts with `check = "ID"` and `metric_version = "..."`; a mismatch with the policy is a
   configuration error (migration is a hand edit). Two checks naming the same baseline path is a configuration
   error. Expiry: an entry that expires today still covers today (expires after the date); test it.
5. **Prune is reported (22).** The result has `prune`: the requested check ids, whether it was performed, and the
   refusal reason; a refused or failed prune makes the command exit 1, and the decision field still reports the
   gate evaluation (documented).
6. **One bounded runner (15).** Every subprocess the gate starts (command checks, jscpd, test runs) goes through one
   runner: its own process group, terminated as a group at the budget (SIGTERM, then SIGKILL after 5 s) and reaped,
   output captured up to 1 MiB with the rest counted and discarded, and the whole evaluation (including pattern
   matching on the captured output) inside the deadline.
7. **JSON on every path (21).** With `--json`, usage errors (unknown options, bad arguments) still print one JSON
   document with `decision = "error"` and exit 2; argv elements containing NUL are configuration errors.
8. **One authoritative schema reference (5).** `docs/SCHEMA.md` defines the policy, baseline and result schemas
   (version 2) and lists the superseded proposals (mandatory tier 3, a separate waiver table, MCP and SARIF before
   a consumer, `python-lines-branches/1`); the plans stay as historical records. README points to it.

## Tests (24)

Each change is made to fail first: schema 2 fields present and typed; a lint-only class leaves tier 1 unsatisfied
and rejects; an exempted tier appears with its reason; a baseline entry outside the measured domain stays and is
reported unmeasured; mismatched baseline `check`/`metric_version` and a shared baseline path are configuration
errors; expiry on today covers, yesterday does not; a refused prune exits 1 with `prune.performed = false`; a
command that spawns a long-lived child is killed with its whole group at the budget; output over 1 MiB is capped
with the count; `check --json --unknown-option` prints one JSON document and exits 2; round-trip of `expires` and
adapter metadata through prune.

Commit label `behaviour change (result and ratchet contract, schema 2)`.

ACCEPT: make -k check
