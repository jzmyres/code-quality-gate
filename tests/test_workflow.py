"""The CI step that finds the base commit for every event."""
from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

from support import GATE, FixtureCase


WORKFLOW = GATE / ".github" / "workflows" / "check.yml"
STEP = "      - name: Resolve the judged change"
RUN = "        run: |"


def workflow_script() -> str:
    """Read the workflow script without its Git user wrapper because the test uses its own user."""
    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
    start = lines.index(STEP)
    run_at = lines.index(RUN, start)
    body: list[str] = []
    for line in lines[run_at + 1:]:
        if not line.startswith("          "):
            break
        body.append(line[10:])
    return "\n".join(body).replace("runuser -u gate -- ", "") + "\n"


class ResolveChangeStepTests(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        self.script = workflow_script()
        self.base_commit = self.commit({}, "base")
        self.publish_main()
        self.invocations = 0

    def commit(self, files: dict[str, str], message: str) -> str:
        for relative, content in files.items():
            self.add_file(relative, content)
        self.commit_all(message)
        return self.git("rev-parse", "HEAD").stdout.strip()

    def publish_main(self) -> None:
        origin = self.base / "origin.git"
        if not origin.exists():
            self.git("init", "--bare", "-q", str(origin))
            self.git("remote", "add", "origin", str(origin))
        self.git("push", "-q", "origin", "main:main")

    def run_step(
        self,
        *,
        event: str,
        before: str | None = None,
        pr_base: str | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], str | None]:
        self.invocations += 1
        env_file = self.base / f"github-env-{self.invocations}"
        env_file.touch()
        env = self.env({
            "GITHUB_EVENT_NAME": event,
            "GITHUB_ENV": str(env_file),
            "GITHUB_BASE_REF": "main",
            "DEFAULT_BRANCH": "main",
        })
        if before is not None:
            env["BEFORE"] = before
        if pr_base is not None:
            env["PR_BASE_SHA"] = pr_base
        result = subprocess.run(
            ["bash", "-e", "-c", self.script],
            cwd=self.repo,
            env=env,
            capture_output=True,
            text=True,
        )
        return result, self.written_base(env_file)

    def written_base(self, path: Path) -> str | None:
        if not path.exists():
            return None
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("QG_DIFF_BASE="):
                return line.split("=", 1)[1]
        return None

    def test_a_push_with_an_existing_before_uses_it(self) -> None:
        self.commit({"pkg/change.py": "VALUE = 1\n"}, "change")
        result, written = self.run_step(
            event="push", before=self.base_commit
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(written, self.base_commit)

    def test_a_push_without_a_usable_before_uses_the_merge_base(self) -> None:
        self.commit({"pkg/change.py": "VALUE = 1\n"}, "change")
        expected = self.git("merge-base", "HEAD", "origin/main").stdout.strip()
        for name, before in (
            ("all zeros", "0" * 40),
            ("an old force-pushed commit", "a" * 40),
        ):
            with self.subTest(case=name):
                result, written = self.run_step(event="push", before=before)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(written, expected)

    def test_a_push_with_neither_lookup_succeeds_fails(self) -> None:
        self.git("checkout", "-q", "--orphan", "unrelated")
        self.commit({"pkg/other.py": "VALUE = 4\n"}, "unrelated")
        result, written = self.run_step(event="push", before="a" * 40)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIsNone(written)
        self.assertIn("no base commit for push", result.stderr)

    def test_a_manual_run_without_a_before_uses_the_merge_base(self) -> None:
        self.commit({"pkg/change.py": "VALUE = 1\n"}, "change")
        result, written = self.run_step(event="workflow_dispatch")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(written, self.base_commit)

    def test_a_manual_run_on_a_branch_named_none_uses_the_merge_base(self) -> None:
        self.commit({"pkg/change.py": "VALUE = 1\n"}, "change")
        self.git("checkout", "-q", "-b", "none")
        expected = self.git("merge-base", "HEAD", "origin/main").stdout.strip()
        result, written = self.run_step(event="workflow_dispatch")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(written, expected)
        self.assertNotEqual(written, self.git("rev-parse", "HEAD").stdout.strip())

    def test_a_pull_request_keeps_its_event_base_when_the_branch_moved(self) -> None:
        self.git("checkout", "-q", "-b", "feature")
        self.commit({"pkg/feature.py": "VALUE = 2\n"}, "feature")
        self.git("checkout", "-q", "main")
        moved = self.commit({"pkg/main.py": "VALUE = 3\n"}, "main moves")
        self.publish_main()
        self.git("checkout", "-q", "feature")
        self.assertNotEqual(moved, self.base_commit)
        result, written = self.run_step(
            event="pull_request", pr_base=self.base_commit
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(written, self.base_commit)

    def test_a_pull_request_base_missing_from_history_fails(self) -> None:
        self.git("checkout", "-q", "-b", "feature")
        self.commit({"pkg/feature.py": "VALUE = 2\n"}, "feature")
        result, written = self.run_step(
            event="pull_request", pr_base="a" * 40
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(written)
        self.assertIn("no base commit for pull_request", result.stderr)

    def test_a_pull_request_without_a_base_on_a_branch_named_none_fails(self) -> None:
        self.git("checkout", "-q", "-b", "none")
        self.commit({"pkg/none.py": "VALUE = 5\n"}, "none branch")
        for name, pr_base in (
            ("unset", None),
            ("empty", ""),
        ):
            with self.subTest(case=name):
                result, written = self.run_step(
                    event="pull_request", pr_base=pr_base
                )
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIsNone(written)
                self.assertIn("no base commit for pull_request", result.stderr)


if __name__ == "__main__":
    unittest.main()
