# QF8: the unreadable-payload test does not depend on the user running it

TIER: trivial

Repository: `~/code-quality-gate`. Work only in the clone `~/code-quality-gate/.worktrees/qg1`. Read
`CLAUDE.md`, `quality_gate/tools.py` (`_verify_tool_payload`, `verify_tool_directory`, the payload walk) and
`tests/test_tools.py` (`test_unreadable_tool_entry_is_unsupported_before_it_runs`) first.

Why: CI runs as root, where `chmod 000` does not deny anything, so that test is skipped there. Since M2c the
verification ratchet counts executed and skipped tests, so CI saw 370 executed tests (floor 371) and 1 skip (ceiling
0) and failed on main `a528b04`, while a non-root run passes. A test whose outcome depends on the user running it
makes every count-based check environment-dependent.

## Change

Replace that test with an in-process test: call the payload verification for a fixture tool tree with the payload
walk's directory listing (`os.scandir` as used by `quality_gate.tools`) patched to raise `PermissionError` for the
tree, and assert the `UnsupportedError` message names the tool, the install directory, the path and the error.
Remove the `skipIf`. The executed-test count stays 371 (one test replaced by one test); the verification baseline does
not change. Change nothing else.

ACCEPT: make -k check
