# CI1: GitHub Actions runs the gate's own check

TIER: trivial

Repository: `~/code-quality-gate`. Work only in the clone `~/code-quality-gate/.worktrees/qg1`. Read
`CLAUDE.md`, `README.md`, `Makefile`, `quality-gate.toml` and `tools.lock.toml` first. This item runs after M1b,
so the Makefile already takes ruff from the pinned tools cache.

Why (user, 2026-10-24: "set up the CI"): the repository is public at `jzmyres/code-quality-gate`; every push to
`main` and every pull request must run the same `make -k check` that gates commits locally.

## Change

- `.github/workflows/check.yml`, modelled on the editor's workflow (`~/spacemacs-config/.github/workflows/check.yml`
  is read-only reference; copy its conventions, not its steps):
  - triggers `push` to `main`, `pull_request`, `workflow_dispatch`; `permissions: contents: read`;
  - `runs-on: ubuntu-latest` with `container: debian:13` (Python 3.13 satisfies the 3.12 minimum);
  - install `python3 make git ca-certificates` with `apt-get install -y --no-install-recommends`, then print
    `python3 --version`;
  - `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1` and
    `actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0` (the editor's pinned commits; pin by full
    SHA with the version comment);
  - trust the checkout: `git config --global --add safe.directory "$GITHUB_WORKSPACE"`;
  - `env: QG_TOOLS_DIR: /tmp/qg-tools`; restore the cache at that path keyed on
    `debian13-${{ runner.arch }}-${{ hashFiles('tools.lock.toml') }}`;
  - `python3 -I qg.py tools fetch` (downloads only what is missing and verifies every checksum);
  - `make -k check`;
  - `timeout-minutes`: the smallest multiple of 5 that is at least three times the measured local `make -k check`
    time; state the measurement in a comment, as the editor's workflow does.
- `quality-gate.toml`: classify `.github/workflows/check.yml` (class `build`, reason: CI runs the self-check).
- README: a short "Continuous integration" section with what CI runs and how to reproduce it locally (exact
  commands).

You cannot run GitHub Actions; Claude pushes and watches the first run.

ACCEPT: make -k check
