# QF4: Sol's final-review findings 27-40 and 42

Repository: `~/code-quality-gate`. Work only in the clone `/home/work/code-quality-gate/.worktrees/qg1`. Read
`CLAUDE.md`, `README.md`, `docs/SCHEMA.md`, `quality_gate/`, the tests, and
`plans/review-sol-gate-2026-10-25.md` (Sol's findings 27-40 and 42 are this item; each gives file:line, the
reproduction and the fix) first.

Why: the milestone's single Codex review found that some measurements and evidence can still be wrong or escape
the contract. Each change is behaviour; write each failing test first (Sol's reproductions are the fixtures).

## Changes (one bullet per finding)

- 27: module-level lambda bodies (and any lambda with no enclosing function) are measured: their decisions belong to
  a measured owner (the module subject, or a `PATH:<lambda@LINE>` subject if that is simpler and stable), and an
  imported-but-uncalled module lambda with two decisions fails like an uncalled function.
- 28: only real `typing.overload` declarations are skipped (the decorator resolves to `overload` imported from
  `typing`/`typing_extensions` or `typing.overload`, and the body is `...`); `@setter`/`@deleter` accessor handling
  applies only to `@NAME.setter`/`@NAME.deleter` attribute forms; a bare `@setter` no longer crashes.
- 29: a function's CC counts its executable body only; defaults, decorators and annotations count once, in the owner
  where they execute (the enclosing function or the module subject).
- 30: after the budget expires the runner escalates against the whole process group even when the leader and the
  pipes are gone (SIGTERM, grace, SIGKILL), and the test covers a descendant that ignores SIGTERM with its output
  redirected away from the pipes.
- 31: one absolute deadline covers execution and evidence processing (pattern matching, coverage combination and
  analysis); regular-expression matching runs where it can be interrupted (for example in a child with the
  remaining budget), and exceeding the deadline reports `execution = "budget"`.
- 32: test summaries: an ambiguous skipped summary (more than one match) is `unsupported`; captures must be
  non-negative integers; an absent optional capture is 0; a negative or non-numeric capture is `unsupported`.
- 33: staged entries (`git ls-files -s -z`) and untracked names (`--others --exclude-standard -z`) are enumerated
  separately so an untracked file name shaped like a staged record cannot become a gitlink.
- 34: inventory and hygiene use `lstat`: symlinks are recorded as symlinks (never followed; their target is not
  read), FIFOs, sockets and devices are rejected with a message, and shebang reads are bounded.
- 35: every coverage invocation registers itself and records successful finalization in the data directory;
  combination requires every registered dataset to be present and usable, and a missing or corrupt dataset makes the
  tests evidence `unsupported` (not a pass).
- 36: clone baselines are bound to their measurement scope: an entry whose files lie outside the selected files is
  `unmeasured` and kept; a file deleted from the repository resolves its entries.
- 37: configuration (including the tool lock each check needs) is validated before any check runs, and the whole
  dispatch is inside the structured usage-error boundary: a malformed lock prints one JSON error document with
  `--json` and exits 2, for every adapter.
- 38: every adapter verdict carries a structured `reason` in JSON (for example "no completed jscpd run", "test
  summary not found", "coverage combination failed: ..."), and all in-process diagnostics use the common 4 KiB tail
  limit.
- 39: clone budget and signal terminations report raw `outcome = "fail"` with their execution and diagnostics, as
  SCHEMA.md says; `unsupported` stays for unavailable or invalid evidence.
- 40: file-domain membership splits a subject at its last colon, so `pkg/a:b.py:f` belongs to `pkg/a:b.py`.
- 42: the coverage configuration is created once per run and children consume it; one decorator-name helper.

Every new or changed function stays at CRAP 6 or below; the baseline may only shrink (`--prune`), never gain an entry
or a raised bound. Commit label `behaviour change (final-review findings)`.

ACCEPT: make -k check
