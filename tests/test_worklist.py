"""End-to-end tests for the churn x current-value worklist."""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import unittest
from pathlib import Path

from support import GATE, FixtureCase, PYTHON_TEST_HEADER, baseline_text, output
from test_python_crap import crap_config
from test_verification import (
    executed_entry, exclusion_entry, verification_baseline, verification_config,
)


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
        if not path.is_file():
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

    def test_equal_displayed_products_are_sorted_by_their_actual_values(self) -> None:
        (self.repo / "pkg/alpha.py").unlink()
        (self.repo / "pkg/beta.py").unlink()
        assignments = "".join(f"    value += {number}\n" for number in range(10))
        source = (
            "def smaller(flag):\n    value = 0\n" + assignments
            + "    if flag:\n        value += 1\n    return value\n\n"
            + "def bigger(flag):\n    value = 0\n" + assignments
            + "    if flag:\n        value += 1\n        value += 2\n    return value\n"
        )
        self.add_file("pkg/fractions.py", source)
        self.add_file("tests/test_sample.py", PYTHON_TEST_HEADER
                      + "\nfrom pkg.fractions import smaller, bigger\n"
                      + "\nclass Sample(unittest.TestCase):\n"
                      + "    def test_both(self):\n"
                      + "        smaller(False)\n        bigger(False)\n")
        self.add_file("quality-gate-crap.toml", python_baseline([
            {"subject": "pkg/fractions.py:smaller", "bound": 7, "reason": "smaller"},
            {"subject": "pkg/fractions.py:bigger", "bound": 7, "reason": "bigger"},
        ]))
        self.commit_all("fractional scores")
        result = run_worklist(self, "--json", "crap")
        self.assertEqual(result.returncode, 0, output(result))
        rows = self.parse_json(result)["rows"]
        self.assertEqual([row["subject"] for row in rows], [
            "pkg/fractions.py:bigger", "pkg/fractions.py:smaller",
        ])
        self.assertGreater(rows[0]["churn_x_value"], rows[1]["churn_x_value"])
        self.assertEqual(f"{rows[0]['churn_x_value']:.1f}", f"{rows[1]['churn_x_value']:.1f}")


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

    def test_outside_selected_files_is_unmeasured_and_deleted_subject_is_absent(self) -> None:
        config = crap_config().replace(
            'checks = ["tests"]\n\n[classes.config]',
            'checks = ["tests"]\n\n[classes.other]\ncode = true\n'
            'description = "Other Python"\nchecks = ["tests"]\n\n[classes.config]',
        )
        config += ('\n[[rule]]\npattern = "other/*.py"\nclass = "other"\n'
                   'reason = "outside the crap selection"\n')
        self.write_config(config)
        (self.repo / "pkg/ghost.py").unlink()
        self.add_file("other/existing.py", GHOST)
        self.add_file("quality-gate-crap.toml", python_baseline([
            {"subject": "other/existing.py:ghost", "bound": 15, "reason": "outside scope"},
            {"subject": "pkg/alpha.py:removed", "bound": 25, "reason": "removed"},
        ]))
        check, document = self.run_json(env=self.default_tool_env())
        self.assertEqual(check.returncode, 0, output(check))
        crap = self.check_by_id(document, "crap")
        self.assertIn("other/existing.py:ghost", crap["unmeasured_baseline_entries"])
        self.assertIn("pkg/alpha.py:removed", crap["resolved_baseline_entries"])
        result = run_worklist(self, "--json", "crap")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(self.parse_json(result)["notes"], [
            {"check": "crap", "subject": "other/existing.py:ghost", "reason": "unmeasured"},
            {"check": "crap", "subject": "pkg/alpha.py:removed", "reason": "no longer exists"},
        ])


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

    def fake_git_failing(self, argument: str) -> dict[str, str]:
        bin_dir = self.base / "fake-bin-log"
        bin_dir.mkdir(exist_ok=True)
        real_git = shutil.which("git")
        assert real_git is not None
        script = bin_dir / "git"
        script.write_text(
            "#!/bin/bash\n"
            'for arg in "$@"; do\n'
            f'  if [ "$arg" = "{argument}" ]; then\n'
            '    echo "fatal: simulated Git failure" >&2\n'
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
            self, "--json", "crap", env=self.fake_git_failing("log")
        )
        self.assertEqual(result.returncode, 1, output(result))
        self.assertIn("log --follow --format=%H --", result.stderr)
        self.assertIn("expected exit status 0", result.stderr)
        self.assertIn("128", result.stderr)
        self.assertNotIn("CHURN", result.stdout)

    def test_failure_to_prepare_the_copy_ranks_nothing_and_preserves_the_tree(self) -> None:
        for argument, message in (("clone", "cannot copy Git repository"),
                                  ("--git-path", "cannot locate Git index"),
                                  ("pack-objects", "cannot copy staged Git objects")):
            with self.subTest(argument=argument):
                before = snapshot_tree(self.repo)
                result = run_worklist(self, "--json", "crap", env=self.fake_git_failing(argument))
                self.assertEqual(result.returncode, 1, output(result))
                self.assertIn(message, result.stderr)
                self.assertIn("simulated Git failure", result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertEqual(snapshot_tree(self.repo), before)

    def test_failure_to_copy_working_files_ranks_nothing(self) -> None:
        os.mkfifo(self.repo / "blocked-pipe")
        result = self.run_qg("worklist", "--json", "crap", timeout=10,
                             env=self.default_tool_env())
        self.assertEqual(result.returncode, 1, output(result))
        self.assertIn("cannot copy repository", result.stderr)
        self.assertIn("blocked-pipe", result.stderr)
        self.assertIn("FIFO", result.stderr)
        self.assertNotIn("check: tests", result.stderr)
        self.assertEqual(result.stdout, "")


class WorklistChurnTests(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        (self.repo / "a.py").unlink()
        self.write_config(crap_config())
        self.add_file("tests/test_sample.py", PASSING_TEST)

    def test_metacharacters_in_paths_are_literal(self) -> None:
        self.add_file("pkg/a[1].py", ALPHA)
        self.add_file("pkg/a1.py", BETA)
        self.add_file("quality-gate-crap.toml", python_baseline([
            {"subject": "pkg/a[1].py:alpha", "bound": 25, "reason": "brackets"},
            {"subject": "pkg/a1.py:beta", "bound": 15, "reason": "plain"},
        ]))
        self.commit_all()
        for number in range(3):
            self.add_file("pkg/a1.py", BETA + f"# change {number}\n")
            self.commit_all(f"plain {number}")
        result = run_worklist(self, "--json", "crap")
        self.assertEqual(result.returncode, 0, output(result))
        rows = self.parse_json(result)["rows"]
        self.assertEqual(len(rows), 2)
        plain, bracketed = rows
        self.assertEqual((plain["subject"], plain["churn"], plain["churn_x_value"]),
                         ("pkg/a1.py:beta", 4, 48))
        self.assertEqual((bracketed["subject"], bracketed["churn"], bracketed["churn_x_value"]),
                         ("pkg/a[1].py:alpha", 1, 20))

    def test_history_over_capture_limit_is_complete_or_reports_truncation(self) -> None:
        self.add_file("pkg/alpha.py", ALPHA)
        self.add_file("quality-gate-crap.toml", python_baseline([
            {"subject": "pkg/alpha.py:alpha", "bound": 25, "reason": "debt"},
        ]))
        self.commit_all()
        touches = 26_002
        parent = self.git("rev-parse", "HEAD").stdout.strip()
        records = []
        for number in range(touches - 1):
            content = ALPHA + f"# change {number}\n"
            records.append(
                "commit refs/heads/main\n"
                "committer qg test <qg@example.invalid> 1700000000 +0000\n"
                "data 1\nx\n"
                + (f"from {parent}\n" if number == 0 else "")
                + f"M 100644 inline pkg/alpha.py\ndata {len(content.encode())}\n"
                f"{content}\n"
            )
        imported = subprocess.run(
            ["git", "fast-import", "--quiet"], cwd=self.repo, env=self.env(),
            input="".join(records), text=True, capture_output=True,
        )
        self.assertEqual(imported.returncode, 0, output(imported))
        result = run_worklist(self, "--json", "crap")
        if result.returncode == 1:
            self.assertIn("truncat", result.stderr.lower(), output(result))
            self.assertEqual(result.stdout, "")
        else:
            self.assertEqual(result.returncode, 0, output(result))
            self.assertEqual(self.parse_json(result)["rows"][0]["churn"], touches)


class WorklistEmptyHistoryTests(FixtureCase):
    def test_uncommitted_repository_reports_git_failure_without_changing_tree(self) -> None:
        (self.repo / "a.py").unlink()
        self.write_config(crap_config())
        self.add_file("pkg/alpha.py", ALPHA)
        self.add_file("tests/test_sample.py", PASSING_TEST)
        self.add_file("quality-gate-crap.toml", python_baseline([
            {"subject": "pkg/alpha.py:alpha", "bound": 25, "reason": "new debt"},
        ]))
        before = snapshot_tree(self.repo)
        result = run_worklist(self, "--json", "crap")
        self.assertEqual(result.returncode, 1, output(result))
        self.assertIn("expected exit status 0", result.stderr)
        self.assertIn("pkg/alpha.py", result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(snapshot_tree(self.repo), before)


class WorklistArgumentTests(FixtureCase):
    def test_unknown_check_id_exits_two(self) -> None:
        result = self.run_qg("worklist", "nope")
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn("unknown check 'nope'", result.stderr)

    def test_check_without_baseline_exits_two(self) -> None:
        result = self.run_qg("worklist", "smoke")
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn("expected a baseline, got none", result.stderr)

    def test_no_eligible_checks_produces_an_empty_report(self) -> None:
        result = run_worklist(self, "--json")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(self.parse_json(result), {"schema": 1, "rows": [], "slack": [], "notes": []})

    def test_repeated_check_id_exits_two_and_names_the_id(self) -> None:
        write_debt_fixture(self)
        result = run_worklist(self, "--json", "crap", "crap")
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn("crap", result.stderr)
        self.assertIn("duplicate", result.stderr)
        self.assertNotIn("rows", self.parse_json(result))


class WorklistMinimumTests(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        (self.repo / "a.py").unlink()
        self.write_config(verification_config(requires=None))
        self.add_file("pkg/mod.py", "VALUE = 1  # noqa: E501\n")
        self.add_file(
            "tests/test_sample.py",
            PYTHON_TEST_HEADER + "\nclass Sample(unittest.TestCase):\n"
            "    def test_one(self): self.assertTrue(True)\n"
            "    def test_two(self): self.assertTrue(True)\n"
            "    def test_three(self): self.assertTrue(True)\n",
        )
        self.add_file(
            "quality-gate-verification.toml",
            verification_baseline([
                executed_entry(1), exclusion_entry("pkg/mod.py", "noqa", 2),
            ]),
        )
        self.commit_all()

    def test_later_prerequisite_with_an_embedded_original_path_prevents_all_runs(self) -> None:
        argument = f"--output={self.repo / 'written.txt'}"
        second = ('[checks.second-tests]\nadapter = "python_tests"\ntier = 1\n'
                  'enforcement = "enforced"\n'
                  f'run = ["{{python}}", "-c", "print(1)", {json.dumps(argument)}]\n'
                  "tests_pattern = '(\\d+)'\n\n")
        self.write_config(verification_config(requires=None).replace(
            "[checks.verification]", second + "[checks.verification]"))
        before = snapshot_tree(self.repo)
        result = run_worklist(self, "--json", "verification")
        self.assertEqual(result.returncode, 1, output(result))
        self.assertIn("check 'second-tests'", result.stderr)
        self.assertIn(argument, result.stderr)
        self.assertIn("repository-relative path", result.stderr)
        self.assertNotIn("check: ", result.stderr)
        self.assertEqual(snapshot_tree(self.repo), before)

    def test_implicit_verification_runs_every_earlier_producer(self) -> None:
        second = ('[checks.second-tests]\nadapter = "python_tests"\ntier = 1\n'
                  'enforcement = "enforced"\n'
                  'run = ["{python}", "-m", "unittest", "discover", "-s", "tests"]\n'
                  "tests_pattern = '^Ran (\\d+) tests? in'\n\n")
        self.write_config(verification_config(requires=None).replace(
            "[checks.verification]", second + "[checks.verification]"))
        self.add_file("quality-gate-verification.toml", verification_baseline([
            executed_entry(1),
            {"subject": "tests:second-tests:executed", "bound": 1, "reason": "second producer"},
            exclusion_entry("pkg/mod.py", "noqa", 2),
        ]))
        check, _document = self.run_json(env=self.default_tool_env())
        self.assertEqual(check.returncode, 0, output(check))
        result = run_worklist(self, "--json", "verification")
        self.assertEqual(result.returncode, 0, output(result))
        slack = self.parse_json(result)["slack"]
        self.assertEqual({item["subject"]: item["value"] for item in slack}, {
            "tests:tests:executed": 3, "tests:second-tests:executed": 3,
        })

    def test_explicit_verification_runs_only_its_named_producer(self) -> None:
        second = ('[checks.second-tests]\nadapter = "python_tests"\ntier = 1\n'
                  'enforcement = "enforced"\n'
                  'run = ["{python}", "-c", "raise SystemExit(1)"]\n'
                  "tests_pattern = '^Ran (\\d+) tests? in'\n\n")
        self.write_config(verification_config(requires="tests").replace(
            "[checks.verification]", second + "[checks.verification]"))
        result = run_worklist(self, "--json", "verification")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertNotIn("check: second-tests", result.stderr)
        self.assertEqual(self.parse_json(result)["slack"][0]["value"], 3)

    def test_a_selected_producer_also_runs_its_own_prerequisite(self) -> None:
        gate = self.fixture_gate()
        adapters = gate / "quality_gate/adapters.py"
        with adapters.open("a", encoding="utf-8") as stream:
            stream.write('''
def _bridge_parse(raw, root, path, full_key):
    from types import SimpleNamespace
    return ParsedSpec(SimpleNamespace(requires=raw["requires"]), "bridge/1", ("tests",),
                      requires=raw["requires"])

def _bridge_run(root, config, check, files, classes, *, prefix, prior):
    import time
    from .checks import _check_result
    required = prior[check.spec.requires]
    return _check_result(check, time.monotonic(), required.outcome,
                         tests_ran=required.tests_ran, tests_skipped=required.tests_skipped)

register_adapter(AdapterDescriptor("bridge", ("requires",), _bridge_parse, _bridge_run,
                                   requires_adapter="python_tests"))
''')
        self.fixture_runner = lambda: gate / "qg.py"
        bridge = ('[checks.bridge]\nadapter = "bridge"\ntier = 1\n'
                  'enforcement = "enforced"\nrequires = "tests"\n\n')
        self.write_config(verification_config(requires="bridge").replace(
            "[checks.verification]", bridge + "[checks.verification]"))
        self.add_file("quality-gate-verification.toml", verification_baseline([
            {"subject": "tests:bridge:executed", "bound": 1, "reason": "bridge producer"},
            exclusion_entry("pkg/mod.py", "noqa", 2),
        ]))
        result = run_worklist(self, "--json", "verification")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(self.parse_json(result)["slack"][0]["value"], 3)
        self.assertIn("check: tests (python_tests)", result.stderr)
        self.assertIn("check: bridge (bridge)", result.stderr)

    def test_minimum_slack_is_reported_beside_maximum_debt(self) -> None:
        human = run_worklist(self, "verification")
        self.assertEqual(human.returncode, 0, output(human))
        self.assertIn("SLACK", human.stdout)
        self.assertIn("1.0     3.0     2.0  verification  tests:tests:executed", human.stdout)
        self.assertIn("exclusions:pkg/mod.py:noqa", human.stdout)
        machine = run_worklist(self, "--json")
        self.assertEqual(machine.returncode, 0, output(machine))
        document = self.parse_json(machine)
        self.assertEqual(document["slack"], [{
            "check": "verification", "subject": "tests:tests:executed",
            "bound": 1, "value": 3, "slack": 2,
        }])
        self.assertEqual(document["rows"][0]["subject"], "exclusions:pkg/mod.py:noqa")
        self.assertEqual(document["rows"][0]["bound"], 2)
        self.assertEqual(document["rows"][0]["value"], 1)

    def test_unmeasured_minimum_is_a_note_without_fabricated_slack(self) -> None:
        missing = {"subject": "tests:missing:executed", "bound": 5, "reason": "old producer"}
        self.add_file(
            "quality-gate-verification.toml",
            verification_baseline([executed_entry(1), missing]),
        )
        self.add_file("pkg/mod.py", "VALUE = 1\n")
        result = run_worklist(self, "--json", "verification")
        self.assertEqual(result.returncode, 0, output(result))
        document = self.parse_json(result)
        self.assertEqual(len(document["slack"]), 1)
        self.assertEqual(document["notes"], [{
            "check": "verification", "subject": "tests:missing:executed", "reason": "not measured",
        }])


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


class WorklistSchemaTests(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        (self.repo / "a.py").unlink()
        config = crap_config(threshold=6).replace(
            '[classes.config]',
            '[classes.other]\ncode = true\ndescription = "Outside CRAP"\n'
            'checks = ["tests"]\n\n[classes.config]',
        ).replace('checks = ["tests", "crap"]', 'checks = ["tests", "crap", "verification"]')
        config += ('\n[checks.verification]\nadapter = "verification"\ntier = 1\n'
                   'enforcement = "enforced"\nrequires = "tests"\n'
                   'baseline = "quality-gate-verification.toml"\n'
                   '\n[[rule]]\npattern = "other/*.py"\nclass = "other"\nreason = "outside CRAP"\n')
        self.write_config(config)
        self.add_file("pkg/alpha.py", ALPHA + "\n" + SIMPLE)
        self.add_file("other/existing.py", GHOST)
        self.add_file("tests/test_sample.py", PASSING_TEST)
        self.add_file("quality-gate-crap.toml", python_baseline([
            {"subject": subject, "bound": bound, "reason": "schema fixture"}
            for subject, bound in (
                ("pkg/alpha.py:alpha", 25), ("pkg/alpha.py:simple", 6),
                ("other/existing.py:ghost", 15), ("pkg/alpha.py:removed", 25),
                ("pkg/ghost.py:ghost", 15),
            )
        ]))
        self.add_file("quality-gate-verification.toml", verification_baseline([
            executed_entry(1),
            {"subject": "tests:missing:executed", "bound": 1, "reason": "outside domain"},
        ]))
        self.commit_all()
        self.add_file("pkg/ghost.py", GHOST)

    def test_json_keys_and_states_agree_with_schema(self) -> None:
        schema = (GATE / "docs/SCHEMA.md").read_text(encoding="utf-8")
        section = schema.split('## Result: `worklist --json`', 1)[1]
        example = json.loads(section.split("```json\n", 1)[1].split("```", 1)[0])
        result = run_worklist(self, "--json")
        self.assertEqual(result.returncode, 0, output(result))
        document = self.parse_json(result)
        self.assertEqual(set(document), set(example))
        self.assertEqual(document["schema"], example["schema"])
        for name in ("rows", "slack"):
            self.assertTrue(document[name], name)
            for item in document[name]:
                with self.subTest(array=name, subject=item["subject"]):
                    self.assertEqual(set(item), set(example[name][0]))
        self.assertEqual([row["subject"] for row in document["rows"]], ["pkg/alpha.py:alpha"])
        self.assertEqual([item["subject"] for item in document["slack"]], ["tests:tests:executed"])
        documented_notes = {note["reason"]: set(note) for note in example["notes"]}
        self.assertEqual({note["reason"] for note in document["notes"]}, set(documented_notes))
        for note in document["notes"]:
            with self.subTest(reason=note["reason"]):
                self.assertEqual(set(note), documented_notes[note["reason"]])
        self.assertEqual({note["subject"]: note["reason"] for note in document["notes"]}, {
            "other/existing.py:ghost": "unmeasured",
            "tests:missing:executed": "not measured",
            "pkg/alpha.py:removed": "no longer exists",
            "pkg/ghost.py:ghost": "churn not measured",
        })


class WorklistReadOnlyTests(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        writer = (PYTHON_TEST_HEADER + "\nclass Sample(unittest.TestCase):\n"
                  "    def test_write(self):\n"
                  "        pathlib.Path('test-results.json').write_text('{}')\n"
                  "        source = pathlib.Path('pkg/alpha.py')\n"
                  "        source.write_text(source.read_text() + '# changed by test\\n')\n")
        write_debt_fixture(self, test_body=writer)

    def test_tree_and_baselines_are_byte_identical(self) -> None:
        before = snapshot_tree(self.repo)
        result = run_worklist(self)
        self.assertEqual(result.returncode, 0, output(result))
        self.assertFalse((self.repo / "test-results.json").exists(), "test wrote into the original tree")
        self.assertEqual(snapshot_tree(self.repo), before)

    def test_copy_preserves_staged_contents_for_checks_that_use_git(self) -> None:
        self.add_file("pkg/alpha.py", ALPHA + "# staged\n")
        self.git("add", "pkg/alpha.py")
        self.add_file("pkg/alpha.py", ALPHA + "# unstaged\n")
        self.add_file("tests/test_sample.py", PYTHON_TEST_HEADER
                      + "\nimport subprocess\n\nclass Sample(unittest.TestCase):\n"
                      + "    def test_index(self):\n"
                      + "        cmd = ['git', 'show', ':pkg/alpha.py']\n"
                      + "        staged = subprocess.check_output(cmd, text=True)\n"
                      + "        self.assertIn('# staged', staged)\n"
                      + "        self.assertNotIn('# unstaged', staged)\n")
        before = snapshot_tree(self.repo)
        result = run_worklist(self, "--json", "crap")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(snapshot_tree(self.repo), before)

    def test_linked_worktree_runs_without_writing_its_shared_git_directory(self) -> None:
        linked = self.base / "linked"
        self.git("worktree", "add", "--detach", str(linked))
        before_repo = snapshot_tree(self.repo)
        before_linked = snapshot_tree(linked)
        result = self.run_qg("worklist", "--json", "crap", repo=linked,
                             env=self.default_tool_env())
        self.assertEqual(result.returncode, 0, output(result))
        self.assertFalse((linked / "test-results.json").exists())
        self.assertEqual(snapshot_tree(linked), before_linked)
        self.assertEqual(snapshot_tree(self.repo), before_repo)

    def test_writing_through_a_relative_link_stays_in_the_copy(self) -> None:
        self.add_file(".gitignore", "__pycache__/\npkg/data-link\n")
        (self.repo / "pkg/data-link").symlink_to("alpha.py")
        self.add_file("tests/test_sample.py", PYTHON_TEST_HEADER
                      + "\nclass Sample(unittest.TestCase):\n"
                      + "    def test_link(self):\n"
                      + "        link = pathlib.Path('pkg/data-link')\n"
                      + "        link.write_text(link.read_text() + '# from link\\n')\n")
        before = snapshot_tree(self.repo)
        result = run_worklist(self, "--json", "crap")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(snapshot_tree(self.repo), before)


class WorklistOriginalArgumentTests(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        write_debt_fixture(self)
        self.add_file("tests/absolute_writer.py",
                      "from pathlib import Path\n"
                      "Path(__file__).with_name('written.txt').write_text('changed')\n"
                      "print('Ran 1 test in 0.0s')\n")
        self.alias = self.base / "alias"
        self.alias.symlink_to(self.repo, target_is_directory=True)

    def writer_command(self, *arguments: str) -> None:
        self.write_config(crap_config().replace(
            '["{python}", "-m", "unittest", "discover", "-s", "tests"]',
            json.dumps(["{python}", *arguments]),
        ))

    def assert_argument_refused(self, argument: str, *, repo: Path | None = None) -> None:
        before = snapshot_tree(self.repo)
        result = self.run_qg("worklist", "--json", "crap", repo=repo,
                             env=self.default_tool_env())
        self.assertEqual(result.returncode, 1, output(result))
        self.assertIn("check 'tests'", result.stderr)
        self.assertIn(argument, result.stderr)
        self.assertIn("resolves into the original repository", result.stderr)
        self.assertIn(str(self.repo / "tests/absolute_writer.py"), result.stderr)
        self.assertIn("repository-relative path", result.stderr)
        self.assertNotIn("check: ", result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertFalse((self.repo / "tests/written.txt").exists())
        self.assertEqual(snapshot_tree(self.repo), before)

    def test_repo_alias_script_is_refused_before_any_check(self) -> None:
        argument = str(self.alias / "tests/absolute_writer.py")
        self.writer_command(argument)
        self.assert_argument_refused(argument, repo=self.alias)

    def test_unrelated_alias_script_is_refused_before_any_check(self) -> None:
        elsewhere = self.base / "elsewhere"
        elsewhere.mkdir()
        other_alias = elsewhere / "another-alias"
        other_alias.symlink_to(self.repo, target_is_directory=True)
        argument = str(other_alias / "tests/absolute_writer.py")
        self.writer_command(argument)
        self.assert_argument_refused(argument)

    def test_option_value_through_alias_is_refused_before_any_check(self) -> None:
        argument = f"--output={self.alias / 'tests/absolute_writer.py'}"
        self.writer_command("tests/absolute_writer.py", argument)
        self.assert_argument_refused(argument)

    def test_absolute_paths_outside_repository_are_accepted(self) -> None:
        interpreter = shutil.which("python3")
        self.assertIsNotNone(interpreter)
        for argument in (interpreter, f"--interpreter={interpreter}"):
            with self.subTest(argument=argument):
                self.writer_command("tests/absolute_writer.py", argument)
                before = snapshot_tree(self.repo)
                result = run_worklist(self, "--json", "crap")
                self.assertEqual(result.returncode, 0, output(result))
                self.assertIn("check: tests", result.stderr)
                self.assertEqual(snapshot_tree(self.repo), before)


class WorklistCopyTests(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        write_debt_fixture(self)

    def test_repository_symlinks_keep_their_targets_under_check_and_worklist(self) -> None:
        self.add_file(".gitignore", "__pycache__/\nlinks/\n")
        links = self.repo / "links"
        links.mkdir()
        (links / "relative").symlink_to("../pkg/alpha.py")
        (links / "absolute").symlink_to(self.repo / "pkg/alpha.py")
        (links / "directory").symlink_to("../pkg", target_is_directory=True)
        (self.repo / "links.md").symlink_to("README.md")
        self.git("add", "links.md")
        targets = {"relative": "../pkg/alpha.py", "absolute": str(self.repo / "pkg/alpha.py"),
                   "directory": "../pkg"}
        self.add_file("tests/test_sample.py", PYTHON_TEST_HEADER
                      + "\nimport os\n\nclass Sample(unittest.TestCase):\n"
                      + "    def test_links(self):\n"
                      + "        self.assertTrue(pathlib.Path('links.md').is_symlink())\n"
                      + "        self.assertEqual(os.readlink('links.md'), 'README.md')\n"
                      + f"        targets = {targets!r}\n"
                      + "        for name, target in targets.items():\n"
                      + "            link = pathlib.Path('links') / name\n"
                      + "            self.assertTrue(link.is_symlink(), str(link))\n"
                      + "            self.assertEqual(os.readlink(link), target)\n")
        check = self.run_qg("check", env=self.default_tool_env())
        self.assertEqual(check.returncode, 0, output(check))
        before = snapshot_tree(self.repo)
        result = run_worklist(self, "--json", "crap")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(snapshot_tree(self.repo), before)

    def test_dangling_link_is_copied_without_opening_its_target(self) -> None:
        self.add_file(".gitignore", "__pycache__/\nbroken-link\n")
        (self.repo / "broken-link").symlink_to("missing-target")
        self.add_file("tests/test_sample.py", PYTHON_TEST_HEADER
                      + "\nimport os\n\nclass Sample(unittest.TestCase):\n"
                      + "    def test_dangling(self):\n"
                      + "        self.assertTrue(pathlib.Path('broken-link').is_symlink())\n"
                      + "        self.assertEqual(os.readlink('broken-link'), 'missing-target')\n")
        result = run_worklist(self, "--json", "crap")
        self.assertEqual(result.returncode, 0, output(result))

    def test_ignored_link_to_external_fifo_is_never_opened(self) -> None:
        fifo = self.base / "external-fifo"
        os.mkfifo(fifo)
        self.add_file(".gitignore", "__pycache__/\nfifo-link\n")
        (self.repo / "fifo-link").symlink_to(fifo)
        self.add_file("tests/test_sample.py", PYTHON_TEST_HEADER
                      + "\nimport os\n\nclass Sample(unittest.TestCase):\n"
                      + "    def test_fifo_link(self):\n"
                      + "        self.assertTrue(pathlib.Path('fifo-link').is_symlink())\n"
                      + f"        self.assertEqual(os.readlink('fifo-link'), {str(fifo)!r})\n")
        result = self.run_qg("worklist", "--json", "crap", timeout=15,
                             env=self.default_tool_env())
        self.assertEqual(result.returncode, 0, output(result))

    def test_ignored_special_files_stop_before_any_check(self) -> None:
        self.add_file(".gitignore", "__pycache__/\nblocked\n")
        path = self.repo / "blocked"
        with socket.socket(socket.AF_UNIX) as server:
            server.bind(str(path))
            self.assert_special_file_refused("socket")
        path.unlink()
        os.mkfifo(path)
        self.assert_special_file_refused("FIFO")

    def assert_special_file_refused(self, kind: str) -> None:
        result = self.run_qg("worklist", "--json", "crap", timeout=10,
                             env=self.default_tool_env())
        self.assertEqual(result.returncode, 1, output(result))
        self.assertIn("blocked", result.stderr)
        self.assertIn(kind, result.stderr)
        self.assertNotIn("check: tests", result.stderr)
        self.assertEqual(result.stdout, "")

    def local_excludes_fixture(self, excludes_path: str) -> None:
        excludes = self.repo / ".git" / "local-excludes"
        excludes.write_text("private-data\n", encoding="utf-8")
        self.git("config", "core.excludesFile", excludes_path)
        self.add_file("private-data", "ignored only by local configuration\n")

    def test_local_excludes_file_is_preserved_as_an_absolute_path(self) -> None:
        for excludes_path in (".git/local-excludes", str(self.repo / ".git/local-excludes")):
            with self.subTest(excludes_path=excludes_path):
                self.local_excludes_fixture(excludes_path)
                self.add_file("tests/test_sample.py", PASSING_TEST)
                check = self.run_qg("check", env=self.default_tool_env())
                self.assertEqual(check.returncode, 0, output(check))
                self.add_file("tests/test_sample.py", PYTHON_TEST_HEADER
                              + "\nimport subprocess\n\nclass Sample(unittest.TestCase):\n"
                              + "    def test_excludes(self):\n"
                              + "        value = subprocess.check_output(\n"
                              + "            ['git', 'config', '--path', 'core.excludesFile'],\n"
                              + "            text=True).strip()\n"
                              + "        self.assertTrue(pathlib.Path(value).is_absolute())\n")
                before = snapshot_tree(self.repo)
                result = run_worklist(self, "--json", "crap")
                self.assertEqual(result.returncode, 0, output(result))
                self.assertEqual(snapshot_tree(self.repo), before)

    def test_missing_config_carry_over_reports_enumeration_difference(self) -> None:
        self.local_excludes_fixture(".git/local-excludes")
        gate = self.fixture_gate()
        module = gate / "quality_gate/worklist.py"
        with module.open("a", encoding="utf-8") as stream:
            stream.write("\n_copy_enumeration_config = lambda root, destination: None\n")
        self.fixture_runner = lambda: gate / "qg.py"
        before = snapshot_tree(self.repo)
        result = run_worklist(self, "--json", "crap")
        self.assertEqual(result.returncode, 1, output(result))
        self.assertIn("copy inventory differs from original", result.stderr)
        self.assertIn("private-data", result.stderr)
        self.assertNotIn("check: tests", result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(snapshot_tree(self.repo), before)

    def test_local_case_matching_is_preserved(self) -> None:
        self.git("config", "core.ignoreCase", "true")
        self.add_file(".gitignore", "__pycache__/\nPRIVATE-DATA\n")
        self.add_file("private-data", "ignored with local case matching\n")
        check = self.run_qg("check", env=self.default_tool_env())
        self.assertEqual(check.returncode, 0, output(check))
        result = run_worklist(self, "--json", "crap")
        self.assertEqual(result.returncode, 0, output(result))

    def test_original_paths_in_prerequisite_arguments_stop_all_checks(self) -> None:
        script = self.add_file("tests/absolute_writer.py",
                               "from pathlib import Path\n"
                               "Path(__file__).with_name('written.txt').write_text('changed')\n"
                               "print('1 test')\n")
        config = crap_config().replace(
            '["{python}", "-m", "unittest", "discover", "-s", "tests"]',
            json.dumps(["{python}", str(script)]),
        )
        self.write_config(config)
        before = snapshot_tree(self.repo)
        result = run_worklist(self, "--json", "crap")
        self.assertEqual(result.returncode, 1, output(result))
        self.assertIn("check 'tests'", result.stderr)
        self.assertIn(str(script), result.stderr)
        self.assertIn("use a repository-relative path", result.stderr)
        self.assertNotIn("check: tests", result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(snapshot_tree(self.repo), before)


if __name__ == "__main__":
    unittest.main()
