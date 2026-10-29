"""End-to-end tests for the churn x current-value worklist."""
from __future__ import annotations

import os
import shutil
import unittest
from pathlib import Path

from support import FixtureCase, PYTHON_TEST_HEADER, baseline_text, output
from test_python_crap import crap_config


ALPHA = """def alpha(value):
    if value:
        if value > 1:
            if value > 2:
                return 3
    return 0
"""

BETA = """def beta(value):
    if value:
        if value > 1:
            return 2
    return 0
"""

SIMPLE = """def simple():
    return 0
"""

GHOST = """def ghost(value):
    if value:
        if value > 1:
            return 2
    return 0
"""

PASSING_TEST = (
    PYTHON_TEST_HEADER
    + "\nclass Sample(unittest.TestCase):\n"
    "    def test_ok(self):\n"
    "        self.assertTrue(True)\n"
)

FAILING_TEST = (
    PYTHON_TEST_HEADER
    + "\nclass Sample(unittest.TestCase):\n"
    "    def test_fails(self):\n"
    "        self.fail('boom')\n"
)

ELISP_MODULE = """;;; core.el --- fixture -*- lexical-binding: t -*-
(defun alpha-elisp (x)
  (when x
    (when (> x 1)
      2)))
(provide 'core)
"""

ELISP_SUITE = """(require 'ert)
(ert-deftest fixture () (should t))
(ert-run-tests-batch-and-exit t)
"""


def python_baseline(entries: list[dict[str, object]]) -> str:
    return baseline_text(
        entries, check="crap", metric_version="python-lines/1"
    )


def elisp_baseline(entries: list[dict[str, object]]) -> str:
    return baseline_text(
        entries, check="elisp-crap", metric_version="elisp-edebug/1"
    )


def write_debt_fixture(case: FixtureCase, *, test_body: str = PASSING_TEST) -> None:
    (case.repo / "a.py").unlink()
    case.write_config(crap_config())
    case.add_file("pkg/alpha.py", ALPHA)
    case.add_file("pkg/beta.py", BETA)
    case.add_file("tests/test_sample.py", test_body)
    case.add_file(
        "quality-gate-crap.toml",
        python_baseline(
            [
                {"subject": "pkg/alpha.py:alpha", "bound": 25, "reason": "alpha debt"},
                {"subject": "pkg/beta.py:beta", "bound": 15, "reason": "beta debt"},
            ]
        ),
    )
    case.commit_all("initial")
    case.add_file("pkg/alpha.py", ALPHA + "# alpha churn\n")
    case.commit_all("alpha change")
    case.add_file("pkg/beta.py", BETA + "# beta churn\n")
    case.commit_all("beta change one")
    case.add_file("pkg/beta.py", BETA + "# beta churn\n# beta churn again\n")
    case.commit_all("beta change two")


def combined_config() -> str:
    text = crap_config().replace('patterns = ["*.py"]', 'patterns = ["*.py", "*.el"]')
    extra = '''\
[classes.elisp]
code = true
description = "Emacs Lisp source"
checks = ["legacy-tests", "elisp-crap"]

[classes.elisp-suite]
code = true
description = "Emacs Lisp suite"
checks = ["smoke"]

[checks.legacy-tests]
adapter = "elisp_tests"
tier = 1
enforcement = "enforced"
suite = "tests/suite.el"
load_path = ["src"]

[checks.smoke]
adapter = "command"
tier = 1
enforcement = "enforced"
run = ["python3", "-c", "print(1)"]
tests_pattern = '(\\d+)'

[checks.elisp-crap]
adapter = "elisp_crap"
tier = 1
enforcement = "enforced"
requires = "legacy-tests"
threshold = 6
baseline = "quality-gate-elisp-crap.toml"

[[rule]]
pattern = "src/*.el"
class = "elisp"
reason = "Emacs Lisp source"

[[rule]]
pattern = "tests/*.el"
class = "elisp-suite"
reason = "Emacs Lisp suite"
'''
    return text + "\n" + extra


def run_worklist(
    case: FixtureCase, *args: str, env: dict[str, str] | None = None
):
    return case.run_qg(
        "worklist", *args, env=env or case.default_tool_env()
    )


def snapshot_tree(repo: Path) -> dict[str, bytes]:
    snapshot: dict[str, bytes] = {}
    for path in sorted(repo.rglob("*")):
        relative = path.relative_to(repo)
        if ".git" in relative.parts or not path.is_file():
            continue
        snapshot[str(relative)] = path.read_bytes()
    return snapshot


class WorklistOrderTests(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        write_debt_fixture(self)

    def test_rows_ranked_by_unrounded_product(self) -> None:
        result = run_worklist(self, "--json", "crap")
        self.assertEqual(result.returncode, 0, output(result))
        document = self.parse_json(result)
        self.assertEqual(document["schema"], 1)
        self.assertEqual(document["notes"], [])
        rows = document["rows"]
        self.assertEqual(
            [row["subject"] for row in rows],
            ["pkg/alpha.py:alpha", "pkg/beta.py:beta"],
        )
        self.assertEqual(rows[0]["check"], "crap")
        self.assertEqual(rows[0]["churn"], 2)
        self.assertEqual(rows[0]["bound"], 25)
        self.assertEqual(rows[0]["value"], 20.0)
        self.assertEqual(rows[0]["churn_x_value"], 40.0)
        self.assertTrue(rows[0]["location"].startswith("pkg/alpha.py:"))
        self.assertEqual(rows[1]["churn"], 3)
        self.assertEqual(rows[1]["bound"], 15)
        self.assertEqual(rows[1]["value"], 12.0)
        self.assertEqual(rows[1]["churn_x_value"], 36.0)
        self.assertTrue(rows[1]["location"].startswith("pkg/beta.py:"))


class WorklistElispTests(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        (self.repo / "a.py").unlink()
        self.write_config(combined_config())
        self.add_file("pkg/alpha.py", SIMPLE)
        self.add_file("tests/test_sample.py", PASSING_TEST)
        self.add_file("quality-gate-crap.toml", python_baseline([]))
        self.add_file("src/core.el", ELISP_MODULE)
        self.add_file("tests/suite.el", ELISP_SUITE)
        self.add_file(
            "quality-gate-elisp-crap.toml",
            elisp_baseline(
                [
                    {
                        "subject": "src/core.el:alpha-elisp",
                        "bound": 15,
                        "reason": "elisp debt",
                    }
                ]
            ),
        )
        self.commit_all()

    def test_elisp_debt_appears_in_the_same_report(self) -> None:
        result = run_worklist(self, "--json")
        self.assertEqual(result.returncode, 0, output(result))
        document = self.parse_json(result)
        rows = document["rows"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["check"], "elisp-crap")
        self.assertEqual(rows[0]["subject"], "src/core.el:alpha-elisp")
        self.assertEqual(rows[0]["churn"], 1)
        self.assertEqual(rows[0]["bound"], 15)
        self.assertEqual(rows[0]["value"], 12.0)
        self.assertEqual(rows[0]["churn_x_value"], 12.0)


class WorklistNoteTests(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        (self.repo / "a.py").unlink()
        self.write_config(crap_config())
        self.add_file("pkg/alpha.py", SIMPLE)
        self.add_file("tests/test_sample.py", PASSING_TEST)
        self.add_file(
            "quality-gate-crap.toml",
            python_baseline(
                [
                    {
                        "subject": "pkg/alpha.py:removed",
                        "bound": 25,
                        "reason": "removed debt",
                    },
                    {
                        "subject": "pkg/ghost.py:ghost",
                        "bound": 15,
                        "reason": "untracked debt",
                    },
                ]
            ),
        )
        self.commit_all()
        self.add_file("pkg/ghost.py", GHOST)

    def test_removed_subject_and_untracked_file_are_notes(self) -> None:
        result = run_worklist(self, "--json", "crap")
        self.assertEqual(result.returncode, 0, output(result))
        document = self.parse_json(result)
        self.assertEqual(document["rows"], [])
        notes = {
            (note["subject"], note["reason"]): note
            for note in document["notes"]
        }
        self.assertIn(
            ("pkg/alpha.py:removed", "no longer exists"), notes
        )
        self.assertIn(
            ("pkg/ghost.py:ghost", "churn not measured"), notes
        )
        self.assertEqual(notes[("pkg/ghost.py:ghost", "churn not measured")]["file"],
                         "pkg/ghost.py")


class WorklistUnreliableTests(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        (self.repo / "a.py").unlink()
        self.write_config(crap_config())
        self.add_file("pkg/alpha.py", ALPHA)
        self.add_file("tests/test_sample.py", FAILING_TEST)
        self.add_file(
            "quality-gate-crap.toml",
            python_baseline(
                [
                    {
                        "subject": "pkg/alpha.py:alpha",
                        "bound": 25,
                        "reason": "alpha debt",
                    }
                ]
            ),
        )
        self.commit_all()

    def test_failing_required_check_exits_one_and_ranks_nothing(self) -> None:
        result = run_worklist(self, "crap")
        self.assertEqual(result.returncode, 1, output(result))
        self.assertIn("worklist: tests:", result.stderr)
        self.assertIn("expected a passing check", result.stderr)
        self.assertIn("got fail", result.stderr)
        self.assertNotIn("CHURN", result.stdout)
        self.assertNotIn("pkg/alpha.py:alpha", result.stdout)


class WorklistGitFailureTests(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        write_debt_fixture(self)

    def fake_git_failing_log(self) -> dict[str, str]:
        bin_dir = self.base / "fake-bin-log"
        bin_dir.mkdir()
        real_git = shutil.which("git")
        assert real_git is not None
        script = bin_dir / "git"
        script.write_text(
            "#!/bin/bash\n"
            'for arg in "$@"; do\n'
            '  if [ "$arg" = "log" ]; then\n'
            '    echo "fatal: simulated log failure" >&2\n'
            "    exit 128\n"
            "  fi\n"
            "done\n"
            f'exec "{real_git}" "$@"\n',
            encoding="utf-8",
        )
        script.chmod(0o755)
        env = self.default_tool_env()
        env["PATH"] = f"{bin_dir}:{os.environ['PATH']}"
        return env

    def test_failed_git_invocation_exits_one_and_names_command(self) -> None:
        result = run_worklist(
            self, "--json", "crap", env=self.fake_git_failing_log()
        )
        self.assertEqual(result.returncode, 1, output(result))
        self.assertIn("git log --follow --format=%H --", result.stderr)
        self.assertIn("expected exit status 0", result.stderr)
        self.assertIn("128", result.stderr)
        self.assertNotIn("CHURN", result.stdout)


class WorklistArgumentTests(FixtureCase):
    def test_unknown_check_id_exits_two(self) -> None:
        result = self.run_qg("worklist", "nope")
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn("unknown check 'nope'", result.stderr)

    def test_check_without_baseline_exits_two(self) -> None:
        result = self.run_qg("worklist", "smoke")
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn("expected a baseline, got none", result.stderr)

    def test_check_without_max_metric_exits_two(self) -> None:
        self.write_config(
            crap_config().replace(
                "[checks.crap]\n",
                '[checks.crap]\ndirection = "min"\n',
            )
        )
        result = self.run_qg("worklist", "crap")
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn("expected a max metric, got 'min'", result.stderr)


class WorklistJsonTests(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        write_debt_fixture(self)

    def test_json_rows_match_human_rows(self) -> None:
        human = run_worklist(self)
        self.assertEqual(human.returncode, 0, output(human))
        machine = run_worklist(self, "--json")
        self.assertEqual(machine.returncode, 0, output(machine))
        document = self.parse_json(machine)
        self.assertEqual(len(document["rows"]), 2)
        for row in document["rows"]:
            line = (
                f"{row['churn']:>5} {row['bound']:>7.1f} "
                f"{row['value']:>7.1f} {row['churn_x_value']:>12.1f}  "
                f"{row['check']}  {row['subject']}  {row['location']}"
            )
            self.assertIn(line, human.stdout)
        self.assertEqual(document["notes"], [])
        self.assertNotIn("Not ranked:", human.stdout)


class WorklistReadOnlyTests(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        write_debt_fixture(self)

    def test_tree_and_baselines_are_byte_identical(self) -> None:
        before = snapshot_tree(self.repo)
        result = run_worklist(self)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(snapshot_tree(self.repo), before)


if __name__ == "__main__":
    unittest.main()
