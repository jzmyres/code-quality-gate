# Astra (gpt-6-astra, max) review, 2026-10-26, stopped at the Codex weekly reset after about four minutes

Astra's progress messages as printed, unedited; it reviewed only the first commits of the range. Claude verifies each finding before it becomes a spec.

-----
I’ll read the review rules and specs, then inspect each commit in order and review the architecture at HEAD. I’ll make no edits and report findings after each commit or design area, checking the earlier reviews to avoid duplicates.

-----
There are eight commits in the range. I’ve read the specs and repository rules, and I’m reviewing payload authentication first. I’ll distinguish new findings from issues already recorded in the earlier reviews.

-----
Finished `0c553c4` (M2a).

1. **Nit — `tests/test_tools.py:783`**: The stability test compares the digest function with itself, and fetch fixtures derive their expected digest using that same function. An encoding regression could pass these tests while invalidating published pins. **Fix:** add a fixed digest oracle covering ordering, Unicode escaping, directories, symlinks and executable bits.

The import-shadowing bug introduced here is addressed by QF7 later in this range; I’ll check that fix separately.

-----
The trust-root review has exposed two likely gaps: malformed candidate baselines appear to discard the trusted entries, and the after-run identity check only revisits paths found before execution. I’m checking both against the documented contract and tests before reporting them as findings.

-----
Finished `7656cd7` (M2b).

2. **Blocker — `quality_gate/trust.py:124`**: Trusted Git reads honor candidate-controlled replacement refs. A replacement for the caller’s trusted commit can substitute weakened policy while the result still names the original SHA. **Fix:** use `git --no-replace-objects` for trusted revision resolution and reads; add a replacement-ref rejection fixture.

3. **Should-fix — `quality_gate/trust.py:515`**: A malformed candidate baseline becomes an empty entry list, deleting every trusted entry, although its status says `ignored`. An in-memory probe confirmed this. **Fix:** retain REV’s entries when candidate parsing fails.

4. **Should-fix — `quality_gate/trust.py:610`**: Identity checking freezes the initial protected-path list, so it misses files created under protected globs during checks. Initial enumeration also excludes ignored untracked files. **Fix:** enumerate the full protected scope before and after execution and compare membership as well as content.

5. **Should-fix — `quality_gate/trust.py:188` and `:521`**: Protected reads follow candidate symlinks, and prune destinations can traverse symlinked parent directories outside the candidate. A protected symlink to a FIFO can also hang the unbounded read. **Fix:** validate file types and parent components, reject escapes, and confine prune writes to the candidate.

The new tests do not cover these cases.

