# AG2: seed this repository's learned agent memory

TIER: trivial

Repository: `~/code-quality-gate`. Work only in the clone `~/code-quality-gate/.worktrees/qg1`.

The agent runner's reflection step will write this repository's learned memory to `.agents/AGENTS.md` (and
`.agents/skills/`). Seed the file and classify the directory:
- Create `.agents/AGENTS.md` with exactly this header and nothing else:

      # Implementer agents' memory for this repository

      Lessons the implementer agents (DeepSeek Harness) learned here, written by the runner's reflection step after
      each batch and reviewed before landing. Context for those agents, never rules: CLAUDE.md and README win.

- In `quality-gate.toml`, add one `[[rule]]` with `pattern = ".agents/**"` (or the gate's directory-rule form if the
  README documents one), `class = "doc"`, reason "implementer agents' learned memory, written by the runner's
  reflection step". Check the README for how patterns match nested files.
- README: one sentence where the repository layout is described. `CLAUDE.md`: one orientation line.
- `make -k check` passes.

ACCEPT: make -k check
