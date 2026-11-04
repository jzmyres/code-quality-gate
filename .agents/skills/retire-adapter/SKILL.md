---
name: retire-adapter
description: Checklist for removing an adapter with its registration, tests, mutation decisions and docs.
verified: 2026-11-04
commit: 3169f1d6d9a2
paths: quality_gate/adapters.py, quality_gate/policy.py, quality_gate/clones.py, quality_gate/runner.py, tests/mutate_gate.py, tests/test_adapters.py, tests/test_policy.py, tests/test_runner.py, docs/SCHEMA.md, README.md, CLAUDE.md
---

# Retiring an adapter

QF112 removed the unused `owners` adapter (about 1,600 package lines and about 800 test lines) in commit
5a07ff4. The recovery note in README names `archive/owners-2026-10-31`; this clone has no tags
(`git tag -l` is empty) and its `.git` is read-only, so the implementer cannot create or exercise that tag
and the `git show archive/owners-2026-10-31:PATH` path must be checked in the landing repository.

1. **Follow every registration.** `quality_gate/adapters.py` owns the descriptor, `adapter_for`, the registry
   list and the policy keys. Removing the descriptor changes `tests/test_adapters.py`'s expected adapter names
   and makes `adapter = "NAME"` in a policy fail with the existing config error that lists the remaining
   adapter names (`expected one of ...`); keep that refusal test, which fails against the base commit where the
   adapter still exists. Remove the adapter from `docs/SCHEMA.md`, README and CLAUDE.md's module and check
   lists.
2. **Delete the tests with the code, then find what only they covered.** The trusted gate scores CRAP over the
   whole tree, not just changed files, and a baseline entry does not waive the spec's 6. QF112's first attempt
   failed on four runner process-group helpers (`_proc_member_command`, `_live_member` and
   `_live_group_members` at CRAP 30.0; `_pending_errors` at 6.6) and policy's `_validate_fixed_header`
   (11.1) because the owners tests were their only coverage. The validator had no remaining caller and went
   with its descriptor field; the runner helpers had callers and gained focused tests in
   `tests/test_runner.py`. QF118 later deleted those helpers and their tests with the worker machinery, and
   its gate reported 751 functions within threshold. Delete the dead helper with its last caller or add the
   focused test; never add a CRAP baseline entry. Restoring code from before the retirement brings
   the same debt back: QF120 restored `runner._proc_group_member` from `561a044`, the gate scored it 8.1,
   and file-based subtests in `ProcGroupMemberTests` supplied the vanished, unreadable and short-line
   branches its deleted tests used to reach.
3. **Remove the adapter's mutation decisions.** `tests/mutate_gate.py` carried five owners `Decision`s; the list
   has 24 at this stamp, and the mutation report must match the list. Recount `DECISIONS` after the deletion.
4. **Move a helper the removed module exported.** `clones._read_regular` and `_parent_fd` moved from
   `owners.py` into `clones.py` with their bounded `O_NOFOLLOW|O_NONBLOCK` open and `GateError`; a shared
   helper moves to a remaining module instead of disappearing with the adapter.
5. **Verify.** Run the adapter, mutation and policy focused tests (`tests/test_adapters.py`,
   `tests/test_mutation.py`, `tests/test_policy.py`, plus the tests that cover any moved helper) and lint only
   the changed files; the runner runs the full gate.