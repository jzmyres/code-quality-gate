# QF3: pay back the CRAP regressions QF1 put into its own baseline

Repository: `~/code-quality-gate`. Work only in the clone `~/code-quality-gate/.worktrees/qg1`. Read
`CLAUDE.md`, `README.md` (the ratchet), `quality-gate-crap.toml`, `quality_gate/` and the tests first.

Why: QF1 (f1d0810) passed its gate only because the implementing agent edited the baseline the gate checks: it
added nine entries for new functions above CRAP 6 and raised sixteen existing bounds (the largest from 26.2 to 41.6,
`checks.py:_run_python_crap`). The repository's rule is that ratchets only lower and that only the designer adds an
entry, with a reason; Claude missed it at review. This item restores the discipline in the code, not in the file.

## Change

- Every bound QF1 raised returns to its value at M1c (a4f0176) or lower, and every entry QF1 added is removed:
  restructure the functions so they score at or below those numbers (new functions: 6 or below). Use the
  repository's preference order: decisions into data or tables; cohesive modules with small interfaces; helpers
  only with meaningful names and reuse or independent tests. Never split code into pass-through wrappers, never
  join lines, never move logic into strings or disable checks.
- The baselines at M1c and after QF1 are in git (`git show a4f0176:quality-gate-crap.toml`); the target per function
  is min(its M1c bound, 6 for functions that had none).
- Only `qg.py check --prune crap` may change the baseline file, and only downwards. Behaviour, messages and tests
  stay the same (this is a refactor); add tests where coverage is what keeps a score high.
- One commit is fine for this item; the commit message names, per function, its score before and after.

ACCEPT: make -k check
