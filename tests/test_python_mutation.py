"""Tests for the python_mutation adapter: operators, selection, budgets and findings."""
from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock

from support import BASE_CONFIG, FixtureCase, _add_check_to_class, output

from quality_gate import python_mutation
from quality_gate.files import DiffBase
from quality_gate.runner import RunResult


TEST_CHECK = (
    "\n[checks.tests]\n"
    'adapter = "python_tests"\n'
    "tier = 1\n"
    'enforcement = "enforced"\n'
    'run = ["{python}", "-m", "unittest", "discover", "-s", "tests"]\n'
    'tests_pattern = "^Ran ([0-9]+) tests? in"\n'
)


def mutation_config(*, tests_check: bool = True, **values: Any) -> str:
    text = _add_check_to_class(BASE_CONFIG, "python", "mutation")
    if tests_check:
        text = _add_check_to_class(text, "python", "tests")
    base = values.pop("base", "HEAD^")
    lines = [
        "",
        "[checks.mutation]",
        'adapter = "python_mutation"',
        "tier = 1",
        'enforcement = "enforced"',
        'scope = "changed"',
        f'base = "{base}"',
    ]
    for key, value in values.items():
        if isinstance(value, str):
            lines.append(f'{key} = "{value}"')
        else:
            lines.append(f"{key} = {value}")
    return text + (TEST_CHECK if tests_check else "") + "\n".join(lines) + "\n"


WEAK_TEST = """\
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from pkg.app import always, never, sample


class WeakTests(unittest.TestCase):
    def test_sample(self):
        sample(2, 3, [2], True)

    def test_always(self):
        always()

    def test_never(self):
        never()
"""


SAMPLE = """\
def sample(a, b, items, flag):
    if a == b:
        a = 1
    if a != b:
        a = 2
    if a < b:
        a = 3
    if a >= b:
        a = 4
    if a > b:
        a = 5
    if a <= b:
        a = 6
    if a in items:
        a = 7
    if a not in items:
        a = 8
    if a is b:
        a = 9
    if a is not b:
        a = 10
    if flag and a:
        a = 11
    if flag or a:
        a = 12
    value = 1 if flag else 2
    return "text"


def always():
    return True


def never():
    return False
"""


class MutationCase(FixtureCase):
    """A fixture repository with a base commit and a change commit."""

    def setUp(self) -> None:
        super().setUp()
        self.write_config(mutation_config())

    def base_commit(self, files: dict[str, str] | None = None) -> None:
        self.commit_files(files, "base")

    def commit(self, files: dict[str, str]) -> None:
        self.commit_files(files, "change")

    def commit_files(self, files: dict[str, str] | None, message: str) -> None:
        for relative, content in (files or {}).items():
            self.add_file(relative, content)
        self.commit_all(message)

    def run_mutation(
        self, env: dict[str, str] | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, Any], dict[str, Any]]:
        result, document = self.run_json("--only", "mutation", env=env)
        return result, document, self.check_by_id(document, "mutation")

    def mutants(self, check: dict[str, Any]) -> list[dict[str, Any]]:
        return check["measurement"]["mutants"]

    def assert_function_was_mutated(
        self, result: subprocess.CompletedProcess[str], check: dict[str, Any]
    ) -> None:
        self.assertTrue(self.mutants(check), output(result))
        self.assertFalse(any(
            "no test names it" in finding["subject"]
            for finding in check["findings"]
        ), check["findings"])

    def assert_check_error(self) -> dict[str, Any]:
        result, document, check = self.run_mutation()
        self.assertEqual(result.returncode, 2, output(result))
        self.assertEqual(document["decision"], "error")
        self.assertEqual(check["outcome"], "error")
        return check

    def assert_over_budget(
        self, result: subprocess.CompletedProcess[str], check: dict[str, Any]
    ) -> None:
        self.assertNotEqual(result.returncode, 0, output(result))
        self.assertTrue(any(
            "over budget" in finding["subject"]
            for finding in check["findings"]
        ), check["findings"])


class OperatorTests(MutationCase):
    def test_each_operator_generates_its_mutant(self) -> None:
        self.write_config(mutation_config(function_mutants=100))
        self.base_commit()
        self.commit({"pkg/app.py": SAMPLE, "tests/test_app.py": WEAK_TEST})
        result, _document, check = self.run_mutation()
        records = self.mutants(check)
        generated = {
            record["operator"]
            for record in records
            if record["outcome"] != "not generated"
        }
        self.assertTrue(
            {
                "!=", "==", ">=", "<", "<=", ">", "not in", "in",
                "is not", "is", "or", "and", "not", "return None",
                "return False", "return True", "n+1", "empty string",
                "delete",
            }
            <= generated,
            sorted(generated),
        )
        self.assertTrue(records, result.stdout + result.stderr)
        for record in records:
            self.assertIn(record["outcome"], {
                "killed", "survived", "timed out", "not generated",
            })
            self.assertTrue(record["line"] >= 1)
            self.assertEqual(record["tests"], ["tests/test_app.py"])
            self.assertTrue(record["mutated"])

    def test_at_most_function_mutants_generated_in_source_order(self) -> None:
        self.write_config(mutation_config(function_mutants=3))
        self.base_commit()
        self.commit({
            "pkg/app.py": (
                "def many():\n"
                "    return (1, 2, 3, 4, 5)\n"
            ),
            "tests/test_app.py": (
                "import pathlib\n"
                "import sys\n"
                "import unittest\n"
                "sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))\n"
                "from pkg.app import many\n\n"
                "class ManyTests(unittest.TestCase):\n"
                "    def test_many(self):\n"
                "        many()\n"
            ),
        })
        _result, _document, check = self.run_mutation()
        generated = [
            record for record in self.mutants(check)
            if record["outcome"] != "not generated"
        ]
        self.assertEqual(len(generated), 3, generated)
        self.assertEqual([record["line"] for record in generated], [2, 2, 2])


EQUIVALENT = """\
def only(value):
    return value


def returns(value):
    if value:
        return None
    return


def same(value):
    if value == value:
        return 1
    return 2


def documented(value):
    'A docstring.'
    return value


def pass_block(value):
    if value:
        pass
    return 0
"""


EQUIVALENT_TEST = """\
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from pkg.app import documented, only, pass_block, returns, same


class NamingTests(unittest.TestCase):
    def test_names(self):
        only(1)
        returns(1)
        same(1)
        documented(1)
        pass_block(1)
"""


class EquivalenceTests(MutationCase):
    def records_by_function(self, check: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
        records: dict[str, list[dict[str, Any]]] = {}
        for record in self.mutants(check):
            records.setdefault(record["function"], []).append(record)
        return records

    def test_each_equivalence_rule_suppresses_its_mutant(self) -> None:
        self.write_config(mutation_config(function_mutants=100))
        self.base_commit()
        self.commit({
            "pkg/app.py": EQUIVALENT,
            "tests/test_app.py": EQUIVALENT_TEST,
        })
        _result, _document, check = self.run_mutation()
        records = self.records_by_function(check)
        only = records["only"]
        self.assertTrue(any(
            record["operator"] == "delete"
            and record["outcome"] == "not generated"
            and record["rule"] == "only statement"
            for record in only
        ), only)
        same = records["same"]
        self.assertTrue(any(
            record["operator"] == "!="
            and record["outcome"] == "not generated"
            and record["rule"] == "self-comparison"
            for record in same
        ), same)
        returns = records["returns"]
        self.assertTrue(any(
            record["operator"] == "return None"
            and record["outcome"] == "not generated"
            and record["rule"] == "return None"
            for record in returns
        ), returns)
        documented = records["documented"]
        self.assertTrue(any(
            record["operator"] in ("delete", "empty string")
            and record["outcome"] == "not generated"
            and record["rule"] == "docstring"
            for record in documented
        ), documented)
        pass_block = records["pass_block"]
        self.assertTrue(any(
            record["operator"] == "delete"
            and record["outcome"] == "not generated"
            and record["rule"] == "unparsed source unchanged"
            for record in pass_block
        ), pass_block)

CLASSIFY = """\
def classify(value):
    if value > 0:
        return "positive"
    return "other"
"""


WEAK_CLASSIFY = """\
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from pkg.app import classify


class WeakTests(unittest.TestCase):
    def test_classify(self):
        classify(1)
"""


STRONG_CLASSIFY = """\
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from pkg.app import classify


class StrongTests(unittest.TestCase):
    def test_positive(self):
        self.assertEqual(classify(1), "positive")

    def test_other(self):
        self.assertEqual(classify(0), "other")
        self.assertEqual(classify(-1), "other")
"""


CALL_COMPARISON = """\
def calling(it):
    if next(it) == next(it):
        return 1
    return 2
"""

CONSTANT_STATEMENT = """\
def constants():
    0
    "later"
    return 1
"""

FIRST_STRING = """\
def documented():
    "first"
    "later"
    return 1
"""


class EquivalenceAndSelectionTests(MutationCase):
    def records_for(self, source: str) -> list[Any]:
        function = ast.parse(source).body[0]
        return python_mutation._mutations(function, source, 100)

    def test_a_call_compared_with_itself_is_generated(self) -> None:
        records = self.records_for(CALL_COMPARISON)
        flips = [record for record in records if record.operator == "!="]
        self.assertEqual(len(flips), 1, records)
        self.assertIsNone(flips[0].rule)
        self.assertEqual(
            flips[0].mutated_line, "if next(it) != next(it):"
        )

    def test_a_plain_name_compared_with_itself_is_suppressed(self) -> None:
        source = "def same(value):\n    if value == value:\n        return 1\n    return 2\n"
        records = self.records_for(source)
        flips = [record for record in records if record.operator == "!="]
        self.assertEqual(
            [record.rule for record in flips], ["self-comparison"], records
        )

    def test_a_bare_constant_statement_is_not_mutated(self) -> None:
        records = self.records_for(CONSTANT_STATEMENT)
        on_statement = [
            record for record in records if record.line == 2
        ]
        self.assertTrue(on_statement, records)
        self.assertEqual(
            {record.rule for record in on_statement},
            {"constant statement"},
            on_statement,
        )
        self.assertFalse(
            [record for record in on_statement if record.rule is None]
        )

    def test_only_the_first_string_statement_is_a_docstring(self) -> None:
        records = self.records_for(FIRST_STRING)
        first = [record for record in records if record.line == 2]
        later = [record for record in records if record.line == 3]
        self.assertTrue(first, records)
        self.assertTrue(later, records)
        self.assertEqual({record.rule for record in first}, {"docstring"})
        self.assertEqual(
            {record.rule for record in later}, {"constant statement"}, later
        )

    def test_each_module_import_form_selects_the_test_file(self) -> None:
        forms = {
            "import pkg.app\n": True,
            "import pkg.app as application\n": True,
            "from pkg import app\n": True,
            "from pkg.app import helper\n": True,
            "from pkg.app import *\n": True,
            "from pkg import other\n": False,
        }
        node = ast.parse("def classify(value):\n    return value\n").body[0]
        function = python_mutation.python_shape.ShapeFunction(
            "pkg/app.py:classify", "pkg/app.py", "classify", node, 1, 2, 1,
            "classify",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "tests").mkdir()
            for source, selected in forms.items():
                with self.subTest(source=source):
                    relative = "tests/test_form.py"
                    (root / relative).write_text(source, encoding="utf-8")
                    tests = python_mutation._tests_by_function(
                        root, [function], [relative],
                    )
                    self.assertEqual(
                        bool(tests[function.identity]), selected, tests
                    )

    def test_a_from_pkg_import_test_selects_the_function(self) -> None:
        self.base_commit()
        self.commit({
            "pkg/app.py": CLASSIFY + "\nRESULT = classify(1)\n",
            "tests/test_app.py": (
                "import pathlib\n"
                "import sys\n"
                "import unittest\n"
                "sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))\n"
                "from pkg import app\n\n"
                "class ModuleTests(unittest.TestCase):\n"
                "    def test_result(self):\n"
                "        self.assertIn(app.RESULT, ('positive', 'other'))\n"
            ),
        })
        result, _document, check = self.run_mutation()
        self.assert_function_was_mutated(result, check)


class SelectionTests(MutationCase):
    def test_a_weak_test_reports_a_survivor(self) -> None:
        self.base_commit()
        self.commit({
            "pkg/app.py": CLASSIFY,
            "tests/test_app.py": WEAK_CLASSIFY,
        })
        result, document, check = self.run_mutation()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "rejected")
        survived = [
            finding for finding in check["findings"]
            if "survives" in finding["subject"]
        ]
        self.assertTrue(survived, check["findings"])
        subject = survived[0]["subject"]
        self.assertIn("python-mutation: pkg/app.py:", subject)
        self.assertIn("classify survives", subject)
        self.assertIn("tests run: tests/test_app.py", subject)
        self.assertIn(
            "Add a test that fails on this change, or fix the generation rule "
            "if the mutant cannot change behaviour.",
            subject,
        )
        self.assertTrue(any(
            record["outcome"] == "survived"
            for record in self.mutants(check)
        ))

    def test_a_strong_test_kills_every_mutant(self) -> None:
        self.base_commit()
        self.commit({
            "pkg/app.py": CLASSIFY,
            "tests/test_app.py": STRONG_CLASSIFY,
        })
        result, _document, check = self.run_mutation()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(check["outcome"], "pass")
        self.assertEqual(check["findings"], [])
        self.assertTrue(any(
            record["outcome"] == "killed"
            for record in self.mutants(check)
        ))

    def test_a_function_no_test_names_it_reports_that_finding(self) -> None:
        self.base_commit()
        self.commit({
            "pkg/app.py": (
                "def lonely():\n"
                "    return 1\n"
            ),
            "tests/test_app.py": (
                "import pathlib\n"
                "import sys\n"
                "import unittest\n"
                "sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))\n\n"
                "class UnrelatedTests(unittest.TestCase):\n"
                "    def test_unrelated(self):\n"
                "        self.assertTrue(True)\n"
            ),
        })
        result, _document, check = self.run_mutation()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertTrue(any(
            "no test names it" in finding["subject"]
            for finding in check["findings"]
        ), check["findings"])

    def test_an_unchanged_function_is_not_mutated(self) -> None:
        self.base_commit({"pkg/app.py": (
            "def first(value):\n"
            "    return value + 1\n"
            "\n"
            "\n"
            "def second(value):\n"
            "    return value + 2\n"
        )})
        self.commit({
            "pkg/app.py": (
                "def first(value):\n"
                "    return value + 1\n"
                "\n"
                "\n"
                "def second(value):\n"
                "    return value + 3\n"
            ),
            "tests/test_app.py": (
                "import pathlib\n"
                "import sys\n"
                "import unittest\n"
                "sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))\n"
                "from pkg.app import first, second\n\n"
                "class BothTests(unittest.TestCase):\n"
                "    def test_both(self):\n"
                "        self.assertEqual(first(1), 2)\n"
                "        self.assertEqual(second(1), 4)\n"
            ),
        })
        result, _document, check = self.run_mutation()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(
            {record["function"] for record in self.mutants(check)},
            {"second"},
        )

    def test_a_test_that_only_imports_the_module_selects_the_function(self) -> None:
        self.base_commit()
        self.commit({
            "pkg/app.py": CLASSIFY,
            "tests/test_app.py": (
                "import pathlib\n"
                "import sys\n"
                "import unittest\n"
                "sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))\n"
                "import pkg.app\n\n"
                "class ModuleTests(unittest.TestCase):\n"
                "    def test_unrelated(self):\n"
                "        pkg.app.classify(1)\n"
            ),
        })
        result, _document, check = self.run_mutation()
        self.assert_function_was_mutated(result, check)

    def test_a_policy_without_a_tests_check_uses_test_shaped_files(self) -> None:
        self.write_config(mutation_config(tests_check=False))
        self.base_commit()
        self.commit({
            "pkg/app.py": CLASSIFY,
            "tests/test_app.py": WEAK_CLASSIFY,
        })
        result, _document, check = self.run_mutation()
        self.assert_function_was_mutated(result, check)


DELETION_BASE = """\
def process(value):
    total = value + 1
    total = total * 2
    return total
"""

DELETION_CHANGE = """\
def process(value):
    total = value + 1
    return total
"""

PROCESS_TEST = """\
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from pkg.app import process


class ProcessTests(unittest.TestCase):
    def test_process(self):
        self.assertEqual(process(1), 2)
"""

MOVE_BASE = """\
def first(value):
    return value + 1


def second(value):
    return value + 2
"""

MOVE_CHANGE = """\
def second(value):
    return value + 2


def first(value):
    return value + 1
"""

MOVE_TEST = """\
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from pkg.app import first, second


class MoveTests(unittest.TestCase):
    def test_both(self):
        self.assertEqual(first(1), 2)
        self.assertEqual(second(1), 3)
"""

RENAME_BASE = """\
def before(value):
    return value + 1
"""

RENAME_CHANGE = """\
def after(value):
    return value + 1
"""

DECORATOR_BASE = """\
def marker(function):
    return function


def decorated(value):
    return value + 1
"""

DECORATOR_CHANGE = """\
def marker(function):
    return function


@marker
def decorated(value):
    return value + 1
"""

NESTED_BASE = """\
def outer(value):
    def inner(item):
        return item + 1

    return inner(value)
"""

NESTED_CHANGE = """\
def outer(value):
    def inner(item):
        return item + 2

    return inner(value)
"""


class ChangedSelectionTests(MutationCase):
    def selected(self) -> tuple[Any, Any, dict[str, Any]]:
        return self.run_mutation()

    def test_a_deletion_only_change_selects_the_function(self) -> None:
        self.base_commit({
            "pkg/app.py": DELETION_BASE, "tests/test_app.py": PROCESS_TEST,
        })
        self.commit({"pkg/app.py": DELETION_CHANGE})
        result, _document, check = self.selected()
        self.assertEqual(
            {record["function"] for record in self.mutants(check)},
            {"process"},
        )
        self.assert_function_was_mutated(result, check)

    def test_a_moved_unchanged_function_is_not_changed(self) -> None:
        self.base_commit({
            "pkg/app.py": MOVE_BASE, "tests/test_app.py": MOVE_TEST,
        })
        self.commit({"pkg/app.py": MOVE_CHANGE})
        result, _document, check = self.selected()
        self.assertEqual(self.mutants(check), [])
        self.assertEqual(check["measurement"]["functions"], 0)
        self.assertEqual(result.returncode, 0, output(result))

    def test_a_rename_changes_the_function(self) -> None:
        self.base_commit({"pkg/app.py": RENAME_BASE})
        self.commit({
            "pkg/app.py": RENAME_CHANGE,
            "tests/test_app.py": PROCESS_TEST.replace("process", "after"),
        })
        _result, _document, check = self.selected()
        self.assertEqual(
            {record["function"] for record in self.mutants(check)},
            {"after"},
        )

    def test_a_decorator_change_changes_the_function(self) -> None:
        self.base_commit({"pkg/app.py": DECORATOR_BASE})
        self.commit({
            "pkg/app.py": DECORATOR_CHANGE,
            "tests/test_app.py": PROCESS_TEST.replace("process", "decorated"),
        })
        _result, _document, check = self.selected()
        self.assertEqual(
            {record["function"] for record in self.mutants(check)},
            {"decorated"},
        )

    def test_a_nested_function_change_changes_both_definitions(self) -> None:
        self.base_commit({"pkg/app.py": NESTED_BASE})
        self.commit({
            "pkg/app.py": NESTED_CHANGE,
            "tests/test_app.py": PROCESS_TEST.replace(
                "process", "outer"
            ).replace("(outer(1), 2)", "(outer(1), 3)"),
        })
        _result, _document, check = self.selected()
        self.assertEqual(
            {record["function"] for record in self.mutants(check)},
            {"outer", "outer.inner"},
        )


COUNTDOWN = """\
def countdown(value):
    while value > 0:
        value -= 1
    return value
"""


COUNTDOWN_TEST = """\
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from pkg.app import countdown


class CountdownTests(unittest.TestCase):
    def test_one(self):
        self.assertEqual(countdown(1), 0)

    def test_zero(self):
        self.assertEqual(countdown(0), 0)
"""


class BudgetTests(MutationCase):
    def test_a_hanging_mutant_times_out_and_counts_as_killed(self) -> None:
        self.write_config(mutation_config(
            mutant_seconds=1, function_mutants=2,
        ))
        self.base_commit()
        self.commit({
            "pkg/app.py": COUNTDOWN,
            "tests/test_app.py": COUNTDOWN_TEST,
        })
        started = time.monotonic()
        result, _document, check = self.run_mutation()
        elapsed = time.monotonic() - started
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(check["outcome"], "pass")
        self.assertLess(elapsed, 6, elapsed)
        self.assertTrue(any(
            record["outcome"] == "timed out"
            for record in self.mutants(check)
        ), self.mutants(check))

    def test_a_run_over_run_seconds_reports_over_budget(self) -> None:
        self.write_config(mutation_config(
            mutant_seconds=5, run_seconds=1, function_mutants=2,
        ))
        self.base_commit()
        self.commit({
            "pkg/app.py": (
                COUNTDOWN
                + "\n\ndef second(value):\n    return value + 1\n"
            ),
            "tests/test_app.py": (
                COUNTDOWN_TEST
                + "\n    def test_second(self):\n"
                "        from pkg.app import second\n"
                "        self.assertEqual(second(1), 2)\n"
            ),
        })
        started = time.monotonic()
        result, _document, check = self.run_mutation()
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 6, elapsed)
        self.assertNotEqual(result.returncode, 0, output(result))
        subjects = [
            finding["subject"] for finding in check["findings"]
        ]
        self.assertEqual(
            sum("over budget" in subject for subject in subjects), 2,
            subjects,
        )

    def test_generation_past_run_seconds_is_over_budget_with_no_mutants(self) -> None:
        self.write_config(mutation_config(run_seconds=1))
        self.base_commit()
        self.commit({
            "pkg/app.py": CLASSIFY,
            "tests/test_app.py": WEAK_CLASSIFY,
        })

        def slow_generation(*_args: Any) -> list[Any]:
            time.sleep(1.2)
            return []

        with mock.patch.object(
            python_mutation, "_mutations", slow_generation
        ):
            result, _document, check = self.run_mutation()
        self.assertNotEqual(result.returncode, 0, output(result))
        subjects = [finding["subject"] for finding in check["findings"]]
        self.assertTrue(
            any("over budget" in subject for subject in subjects), subjects
        )

    def test_a_cutoff_records_every_generated_mutant(self) -> None:
        self.write_config(mutation_config(mutant_seconds=5, run_seconds=1))
        self.base_commit()
        self.commit({
            "pkg/app.py": COUNTDOWN,
            "tests/test_app.py": SLOW_TEST,
        })
        result, _document, check = self.run_mutation()
        self.assertNotEqual(result.returncode, 0, output(result))
        records = [
            record for record in self.mutants(check)
            if record["outcome"] != "not generated"
        ]
        self.assertEqual(len(records), 8, records)
        self.assertEqual(
            {record["outcome"] for record in records},
            {"not run (over budget)"},
            records,
        )
        self.assertTrue(any(
            "over budget" in finding["subject"]
            for finding in check["findings"]
        ), check["findings"])

    def test_an_invalid_base_is_a_check_error(self) -> None:
        self.write_config(mutation_config(base="no-such-revision"))
        self.base_commit()
        self.commit({
            "pkg/app.py": CLASSIFY,
            "tests/test_app.py": STRONG_CLASSIFY,
        })
        check = self.assert_check_error()
        self.assertNotIn("pass", check.get("outcome"))

    def test_a_delayed_final_descendant_cleanup_is_over_budget(self) -> None:
        self.write_config(mutation_config(
            mutant_seconds=5, run_seconds=1, function_mutants=1,
        ))
        self.base_commit()
        self.commit({
            "pkg/app.py": COUNTDOWN,
            "tests/test_app.py": COUNTDOWN_TEST,
        })
        real_run = python_mutation.run
        calls = {"count": 0}

        def delayed(*args: Any, **options: Any) -> RunResult:
            calls["count"] += 1
            result = real_run(*args, **options)
            if calls["count"] == 2:
                time.sleep(1.2)
            return result

        with mock.patch.object(
            python_mutation, "run", side_effect=delayed
        ):
            result, _document, check = self.run_mutation()
        self.assert_over_budget(result, check)

    def test_a_delayed_temporary_directory_removal_is_over_budget(self) -> None:
        self.write_config(mutation_config(
            mutant_seconds=5, run_seconds=1, function_mutants=1,
        ))
        self.base_commit()
        self.commit({
            "pkg/app.py": COUNTDOWN,
            "tests/test_app.py": COUNTDOWN_TEST,
        })
        real = tempfile.TemporaryDirectory

        class Delayed:
            def __init__(self, *args: Any, **options: Any) -> None:
                self.directory = real(*args, **options)

            def __getattr__(self, name: str) -> Any:
                return getattr(self.directory, name)

            def __enter__(self) -> str:
                return self.directory.__enter__()

            def __exit__(self, *exc: Any) -> Any:
                name = self.directory.name
                try:
                    return self.directory.__exit__(*exc)
                finally:
                    if Path(name).name.startswith("qg-mutation-"):
                        time.sleep(1.2)

        with mock.patch.object(tempfile, "TemporaryDirectory", Delayed):
            result, _document, check = self.run_mutation()
        self.assert_over_budget(result, check)


class FindingTests(MutationCase):
    def test_the_survivor_message_is_exact(self) -> None:
        self.base_commit()
        self.commit({
            "pkg/app.py": CLASSIFY,
            "tests/test_app.py": WEAK_CLASSIFY,
        })
        _result, _document, check = self.run_mutation()
        expected = (
            "python-mutation: pkg/app.py:2 classify survives <= "
            "(if value <= 0:); tests run: tests/test_app.py. Add a test that "
            "fails on this change, or fix the generation rule if the mutant "
            "cannot change behaviour."
        )
        self.assertIn(expected, [finding["subject"] for finding in check["findings"]])
        finding = next(
            finding for finding in check["findings"]
            if finding["subject"] == expected
        )
        self.assertEqual(finding["value"], 1)
        self.assertEqual(finding["threshold"], 0)
        self.assertEqual(finding["measurement"]["rule"], "SURVIVED")
        self.assertEqual(finding["measurement"]["subject"], "pkg/app.py:classify")

    def test_the_json_carries_every_mutant_with_its_outcome(self) -> None:
        self.write_config(mutation_config(function_mutants=100))
        self.base_commit()
        self.commit({
            "pkg/app.py": EQUIVALENT,
            "tests/test_app.py": EQUIVALENT_TEST,
        })
        _result, document, check = self.run_mutation()
        records = self.mutants(check)
        self.assertTrue(records)
        outcomes = {record["outcome"] for record in records}
        self.assertIn("survived", outcomes)
        self.assertIn("not generated", outcomes)
        suppressed = [
            record for record in records
            if record["outcome"] == "not generated"
        ]
        self.assertTrue(suppressed)
        for record in suppressed:
            self.assertTrue(record["rule"], record)
        for record in records:
            self.assertEqual(
                set(record),
                {
                    "subject", "file", "function", "operator", "line",
                    "mutated", "outcome", "rule", "tests",
                },
            )
        self.assertEqual(document["decision"], "rejected")

    def test_the_working_tree_is_unchanged_after_the_check(self) -> None:
        self.base_commit()
        self.commit({
            "pkg/app.py": CLASSIFY,
            "tests/test_app.py": WEAK_CLASSIFY,
        })
        before = self.git("status", "--porcelain").stdout
        before_app = self.read_file("pkg/app.py")
        before_tests = self.read_file("tests/test_app.py")
        self.run_mutation()
        self.assertEqual(self.git("status", "--porcelain").stdout, before)
        self.assertEqual(self.read_file("pkg/app.py"), before_app)
        self.assertEqual(self.read_file("tests/test_app.py"), before_tests)

ALLOWLIST_TEST = """\
import os
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from pkg.app import classify


class AllowlistTests(unittest.TestCase):
    def test_the_environment_is_allowlisted(self):
        for name in ("QG_LEXICAL_ESCAPE", "QG_RELATIVE_TRAVERSAL"):
            self.assertNotIn(name, os.environ)
        self.assertEqual(classify(1), "positive")
        self.assertEqual(classify(0), "other")
        self.assertEqual(classify(-1), "other")
"""


UNLISTED_ENVIRONMENT_TEST = """\
import os
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from pkg.app import classify


class UnlistedTests(unittest.TestCase):
    def test_reads_unlisted_variable(self):
        os.environ["QG_FIXTURE_UNLISTED"]
        self.assertEqual(classify(1), "positive")
"""


SPIN = """\
def spin(value):
    while value > 0:
        value -= 1
    return value
"""


DETACHED_TEST = """\
import os
import pathlib
import subprocess
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from pkg.app import spin


class DetachedTests(unittest.TestCase):
    def test_a_detached_child(self):
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            start_new_session=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        with open(
            "__PIDS_FILE__", "a", encoding="utf-8"
        ) as stream:
            stream.write(f"{child.pid}\\n")
        self.assertEqual(spin(0), 0)
"""


def _process_running(pid: int) -> bool:
    try:
        state = Path(f"/proc/{pid}/stat").read_text(
            encoding="utf-8"
        ).rpartition(")")[2].split()[0]
    except (FileNotFoundError, IndexError):
        return False
    return state not in ("Z", "X")


class IsolationTests(MutationCase):
    def test_the_mutant_and_baseline_environment_is_allowlisted(self) -> None:
        self.base_commit()
        self.commit({
            "pkg/app.py": CLASSIFY,
            "tests/test_app.py": ALLOWLIST_TEST,
        })
        result, _document, check = self.run_mutation(env={
            "QG_LEXICAL_ESCAPE": (
                f"{self.repo}-sibling/../{self.repo.name}"
            ),
            "QG_RELATIVE_TRAVERSAL": f"../{self.repo.name}",
        })
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(check["outcome"], "pass", output(result))

    def test_an_unlisted_variable_is_an_allowlisted_baseline_error(self) -> None:
        self.base_commit()
        self.commit({
            "pkg/app.py": CLASSIFY,
            "tests/test_app.py": UNLISTED_ENVIRONMENT_TEST,
        })
        result, document, check = self.run_mutation(env={
            "QG_FIXTURE_UNLISTED": "1",
        })
        self.assertEqual(result.returncode, 2, output(result))
        self.assertEqual(document["decision"], "error")
        self.assertEqual(check["outcome"], "error")
        self.assertIn("test_reads_unlisted_variable", check["reason"])
        self.assertIn("allowlisted", check["reason"])

    def test_a_detached_child_is_gone_after_the_mutant_times_out(self) -> None:
        pids_file = self.base / "detached-pids.txt"
        self.write_config(mutation_config(
            mutant_seconds=1, function_mutants=2,
        ))
        self.base_commit()
        self.commit({
            "pkg/app.py": SPIN,
            "tests/test_app.py": DETACHED_TEST.replace(
                "__PIDS_FILE__", str(pids_file)
            ),
        })
        result, _document, check = self.run_mutation()
        self.assertTrue(any(
            record["outcome"] == "timed out" for record in self.mutants(check)
        ), self.mutants(check))
        self.assertTrue(pids_file.exists(), output(result))
        recorded = [
            int(line) for line in pids_file.read_text().split()
        ]
        self.assertTrue(recorded, output(result))
        deadline = time.monotonic() + 3
        while (
            any(_process_running(pid) for pid in recorded)
            and time.monotonic() < deadline
        ):
            time.sleep(0.05)
        self.assertEqual(
            [pid for pid in recorded if _process_running(pid)],
            [], output(result),
        )


DECORATED_NESTED = """\
def outer():
    def plain():
        return 1

    @first
    @second
    def decorated():
        return 2

    return plain() + decorated()
"""


PARENTHESIZED_DECORATOR = """\
def outer():
    @(
        marker
    )
    def decorated():
        return 1

    return decorated()
"""


NONLOCAL = """\
def outer():
    x = 1
    def inner():
        nonlocal x
        return x
    return inner()
"""


NONLOCAL_TEST = """\
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from pkg.app import outer


class NonlocalTests(unittest.TestCase):
    def test_outer(self):
        self.assertEqual(outer(), 1)
"""


class GeneratorTests(unittest.TestCase):
    def generated(
        self, source: str, limit: int = 100,
    ) -> tuple[ast.FunctionDef, list[Any]]:
        function = ast.parse(source).body[0]
        records = python_mutation._mutations(function, source, limit)
        return function, records

    def test_every_comparison_flips_to_its_complement(self) -> None:
        _function, records = self.generated(SAMPLE)
        expected = {
            2: ("!=", "if a != b:"),
            4: ("==", "if a == b:"),
            6: (">=", "if a >= b:"),
            8: ("<", "if a < b:"),
            10: ("<=", "if a <= b:"),
            12: (">", "if a > b:"),
            14: ("not in", "if a not in items:"),
            16: ("in", "if a in items:"),
            18: ("is not", "if a is not b:"),
            20: ("is", "if a is b:"),
        }
        by_line = {
            record.line: record for record in records
            if record.line in expected
            and record.operator in {text for text, _line in expected.values()}
        }
        self.assertEqual(sorted(by_line), sorted(expected))
        for line, (operator, text) in expected.items():
            record = by_line[line]
            self.assertEqual(record.operator, operator, record)
            self.assertEqual(record.mutated_line, text, record)

    def test_a_signed_integer_literal_is_one_constant(self) -> None:
        source = "def signed():\n    return -1\n"
        _function, records = self.generated(source)
        constants = [
            record for record in records if record.operator == "n+1"
        ]
        self.assertEqual(len(constants), 1, records)
        self.assertEqual(constants[0].mutated_line, "return 0")

    def test_the_cap_takes_constants_in_source_order(self) -> None:
        pairs = ", ".join(
            f"{number}: {number + 1}" for number in range(1, 24, 2)
        )
        source = (
            "def mapping():\n"
            f"    value = {{{pairs}}}\n"
            "    return value\n"
        )
        _function, records = self.generated(source, 20)
        generated = [record for record in records if record.rule is None]
        self.assertEqual(len(generated), 20, records)
        constants = [
            int(record.replacement) - 1
            for record in generated if record.operator == "n+1"
        ]
        self.assertEqual(constants, list(range(1, 20)), constants)

    def test_deleting_a_decorated_definition_removes_its_decorators(self) -> None:
        _function, records = self.generated(DECORATED_NESTED)
        deletion = next(
            record for record in records
            if record.operator == "delete"
            and (
                record.line == 5
                or "decorated" in DECORATED_NESTED.splitlines()[record.line - 1]
            )
        )
        mutated = deletion.mutated_source
        self.assertNotIn("@first", mutated)
        self.assertNotIn("@second", mutated)
        self.assertNotIn("def decorated", mutated)
        compile(mutated, "pkg/app.py", "exec")

    def test_a_parenthesized_multi_line_decorator_is_removed_with_its_function(
        self,
    ) -> None:
        function = ast.parse(PARENTHESIZED_DECORATOR).body[0]
        records = python_mutation._mutations(
            function, PARENTHESIZED_DECORATOR, 100
        )
        removed = [
            record for record in records
            if record.operator == "delete"
            and "def decorated" not in record.mutated_source
        ]
        self.assertTrue(removed, records)
        self.assertNotIn("@(", removed[0].mutated_source)
        self.assertNotIn("marker", removed[0].mutated_source)
        compile(removed[0].mutated_source, "pkg/app.py", "exec")

    def test_a_mutant_that_does_not_compile_is_not_generated(self) -> None:
        function = ast.parse(NONLOCAL).body[0]
        records = python_mutation._mutations(function, NONLOCAL, 1)
        deletion = next(
            record for record in records if record.operator == "delete"
        )
        self.assertEqual(deletion.rule, "does not compile")
        generated = [record for record in records if record.rule is None]
        self.assertEqual(
            [record.operator for record in generated], ["n+1"], records
        )


class ContractTests(unittest.TestCase):
    """Direct tests of the adapter's helpers, one contract each."""

    def function(
        self, source: str, path: str = "pkg/app.py",
    ) -> Any:
        node = ast.parse(source).body[0]
        return python_mutation.python_shape.ShapeFunction(
            f"{path}:{node.name}", path, node.name, node, node.lineno,
            node.end_lineno or node.lineno, 1, node.name,
        )

    def source_tree(self, source: str) -> tuple[Path, Path]:
        source_root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        work_root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (source_root / "pkg").mkdir()
        (source_root / "pkg/app.py").write_text(source, encoding="utf-8")
        return source_root, work_root

    def work_mutation(self) -> tuple[str, Any, Any]:
        source = "def work():\n    return 1\n"
        function = self.function(source)
        mutation = next(
            item for item in python_mutation._mutations(
                function.node, source, 10
            ) if item.operator == "n+1"
        )
        return source, function, mutation

    def work_ast_change(self) -> tuple[Any, ...]:
        source = "def work():\n    return 1\n"
        module = ast.parse(source)
        function = module.body[0]
        index = python_mutation._function_index(module, function)
        parents = python_mutation._parents(function)
        change = next(
            item for item in python_mutation._raw_changes(function)
            if item.operator == "n+1"
        )
        return module, function, index, parents, change

    def test_self_comparison_needs_a_plain_name_or_a_constant(self) -> None:
        self.assertTrue(python_mutation._self_comparison(
            ast.parse("value", mode="eval").body,
            ast.parse("value", mode="eval").body,
        ))
        self.assertTrue(python_mutation._self_comparison(
            ast.Constant(value=1), ast.Constant(value=1)
        ))
        self.assertFalse(python_mutation._self_comparison(
            ast.parse("next(it)", mode="eval").body,
            ast.parse("next(it)", mode="eval").body,
        ))

    def test_negation_wraps_the_test(self) -> None:
        change = python_mutation._negation(
            ast.parse("flag", mode="eval").body
        )
        self.assertEqual(change.operator, "not")
        self.assertEqual(change.replacement, "not (flag)")

    def test_signed_constant_and_its_change(self) -> None:
        signed = ast.parse("-1", mode="eval").body
        self.assertEqual(python_mutation._signed_constant(signed), -1)
        self.assertIsNone(python_mutation._signed_constant(
            ast.parse("1", mode="eval").body
        ))
        changes = python_mutation._signed_constant_changes(signed)
        self.assertEqual(len(changes), 1)
        self.assertEqual(
            (changes[0].operator, changes[0].replacement), ("n+1", "0")
        )

    def test_node_changes_adds_a_delete_for_a_statement(self) -> None:
        change = python_mutation._node_changes(
            ast.parse("value = 1").body[0]
        )[0]
        self.assertEqual(change.operator, "delete")
        self.assertTrue(change.delete)

    def test_skip_children_stops_at_definitions_and_signed_literals(self) -> None:
        self.assertTrue(python_mutation._skip_children(
            ast.parse("def inner():\n    pass\n").body[0]
        ))
        self.assertTrue(python_mutation._skip_children(
            ast.parse("-1", mode="eval").body
        ))
        self.assertFalse(python_mutation._skip_children(
            ast.parse("value = 1").body[0]
        ))

    def test_walk_keeps_source_order_and_skips_a_nested_body(self) -> None:
        source = (
            "def outer():\n"
            "    first = 1\n"
            "    def inner():\n"
            "        hidden = 2\n"
            "    return first\n"
        )
        function = ast.parse(source).body[0]
        walked = list(python_mutation._walk(function))
        self.assertTrue(any(
            isinstance(node, ast.FunctionDef) for node in walked
        ))
        self.assertEqual(
            [node.lineno for node in walked if isinstance(node, ast.Assign)],
            [2],
        )

    def test_raw_changes_follow_source_position(self) -> None:
        source = (
            "def mapping():\n"
            "    value = {1: 2, 3: 4}\n"
            "    return value\n"
        )
        function = ast.parse(source).body[0]
        positions = [
            (change.target.lineno, change.target.col_offset)
            for change in python_mutation._raw_changes(function)
        ]
        self.assertEqual(positions, sorted(positions))

    def test_child_nodes_keeps_ast_children_only(self) -> None:
        names = [ast.Name(id="a"), ast.Name(id="b")]
        self.assertEqual(
            python_mutation._child_nodes([*names, "text"]), names
        )
        children = python_mutation._child_nodes(ast.Constant(value=1))
        self.assertEqual(len(children), 1)
        self.assertIsInstance(children[0], ast.Constant)
        self.assertEqual(python_mutation._child_nodes("text"), [])

    def test_is_function_only_statement_needs_one_statement(self) -> None:
        one = ast.parse("def only(value):\n    return value\n").body[0]
        self.assertTrue(python_mutation._is_function_only_statement(
            one, one.body[0], python_mutation._parents(one)
        ))
        two = ast.parse(
            "def pair(value):\n    value = 1\n    return value\n"
        ).body[0]
        self.assertFalse(python_mutation._is_function_only_statement(
            two, two.body[0], python_mutation._parents(two)
        ))

    def test_statement_and_docstring_and_constant_statement(self) -> None:
        source = (
            "def documented():\n"
            "    'first'\n"
            "    'later'\n"
            "    return 1\n"
        )
        function = ast.parse(source).body[0]
        parents = python_mutation._parents(function)
        first, later = function.body[0], function.body[1]
        self.assertIs(python_mutation._statement(first, parents), first)
        self.assertIs(python_mutation._statement(first.value, parents), first)
        self.assertTrue(
            python_mutation._docstring_change(function, first, parents)
        )
        self.assertFalse(
            python_mutation._docstring_change(function, later, parents)
        )
        self.assertTrue(
            python_mutation._constant_statement_change(later.value, parents)
        )

    def test_suppression_names_each_rule(self) -> None:
        source = "def empty():\n    0\n"
        function = ast.parse(source).body[0]
        parents = python_mutation._parents(function)
        delete = python_mutation._node_changes(function.body[0])[0]
        self.assertEqual(
            python_mutation._suppression(function, delete, parents),
            "constant statement",
        )
        rule = python_mutation._Change(
            "delete", function.body[0], "", rule="a rule"
        )
        self.assertEqual(
            python_mutation._suppression(function, rule, parents), "a rule"
        )
        only = ast.parse("def only():\n    return 1\n").body[0]
        only_parents = python_mutation._parents(only)
        only_delete = python_mutation._node_changes(only.body[0])[0]
        self.assertEqual(
            python_mutation._suppression(only, only_delete, only_parents),
            "only statement",
        )

    def test_ast_mutated_replaces_the_target(self) -> None:
        source = "def only():\n    return 1\n"
        module = ast.parse(source)
        function = module.body[0]
        index = python_mutation._function_index(module, function)
        self.assertEqual(index, 1)
        change = python_mutation._raw_changes(function)[0]
        mutated = python_mutation._ast_mutated(module, index, change)
        self.assertEqual(ast.unparse(mutated), "def only():\n    pass")

    def test_enclosing_statement_finds_the_containing_statement(self) -> None:
        source = "def work():\n    return 1 + 2\n"
        function = ast.parse(source).body[0]
        parents = python_mutation._parents(function)
        statement = function.body[0]
        change = python_mutation._Change(
            "n+1", statement.value, "3", ast.Constant(value=3)
        )
        self.assertIs(
            python_mutation._enclosing_statement(change, parents), statement
        )

    def test_mutated_line_and_generated_rule_use_the_ast(self) -> None:
        module, _function, index, parents, change = self.work_ast_change()
        self.assertEqual(
            python_mutation._mutated_line(change, parents, False),
            "return 2",
        )
        mutated = ast.unparse(
            python_mutation._ast_mutated(module, index, change)
        )
        self.assertIn("return 2", mutated)
        self.assertIsNone(python_mutation._generated_rule(
            mutated, ast.unparse(module), "pkg/app.py"
        ))

    def test_generated_rule_names_unchanged_and_uncompilable(self) -> None:
        source = (
            "def block(value):\n"
            "    if value:\n"
            "        pass\n"
            "    return 1\n"
        )
        module = ast.parse(source)
        function = module.body[0]
        index = python_mutation._function_index(module, function)
        original = ast.unparse(module)
        delete = next(
            item for item in python_mutation._raw_changes(function)
            if item.operator == "delete"
            and isinstance(item.target, ast.Pass)
        )
        self.assertEqual(
            python_mutation._generated_rule(
                ast.unparse(
                    python_mutation._ast_mutated(module, index, delete)
                ),
                original,
                "pkg/app.py",
            ),
            "unparsed source unchanged",
        )
        self.assertEqual(
            python_mutation._generated_rule(
                "def broken(:\n", original, "pkg/app.py"
            ),
            "does not compile",
        )

    def test_mutation_records_the_line_and_the_rule(self) -> None:
        module, function, index, parents, change = self.work_ast_change()
        mutation = python_mutation._mutation(
            function, change, parents, module, index,
            "pkg/app.py", ast.unparse(module),
        )
        self.assertEqual((mutation.operator, mutation.line), ("n+1", 2))
        self.assertIsNone(mutation.rule)
        self.assertEqual(mutation.mutated_line, "return 2")
        self.assertIn("return 2", mutation.mutated_source)

    def test_test_references_reads_names_and_imports(self) -> None:
        names, modules = python_mutation._test_references(
            "tests/test_app.py",
            "from pkg import app\napp.classify()\n",
        )
        self.assertIn("classify", names)
        self.assertIn("pkg.app", modules)

    def test_imported_from_and_imported_modules_build_names(self) -> None:
        self.assertEqual(
            python_mutation._imported_from(
                ast.parse("from pkg import app").body[0]
            ),
            {"pkg", "pkg.app"},
        )
        modules: set[str] = set()
        python_mutation._imported_modules(
            ast.parse("import pkg.app").body[0], modules
        )
        self.assertEqual(modules, {"pkg.app"})

    def test_copy_directory_makes_a_directory_inside_the_copy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = python_mutation._copy_directory(root, "home")
            self.assertEqual(path, root / "home")
            self.assertTrue(path.is_dir())

    def test_environment_is_the_allowlist_with_paths_inside_the_copy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            copy_root = Path(directory)
            with mock.patch.dict(os.environ, {
                "PATH": "/bin",
                "LANG": "C",
                "LC_ALL": "C.UTF-8",
                "PWD": "/src",
                "MY_DIR": "/src/pkg",
                "OTHER": "/tmp",
                "QG_PYTHON": "inherited",
            }, clear=True):
                environment = python_mutation._environment(copy_root)
            self.assertEqual(set(environment), {
                "PATH", "LANG", "LC_ALL", "QG_PYTHON",
                "PYTHONDONTWRITEBYTECODE", "PWD", "HOME", "TMPDIR",
            })
            self.assertEqual(environment["PATH"], "/bin")
            self.assertEqual(
                json.loads(environment["QG_PYTHON"]),
                [sys.executable, "-I", "-B"],
            )
            self.assertEqual(environment["PYTHONDONTWRITEBYTECODE"], "1")
            self.assertEqual(environment["PWD"], str(copy_root))
            for name in ("HOME", "TMPDIR"):
                path = Path(environment[name])
                self.assertTrue(path.is_dir(), path)
                self.assertEqual(path.parent, copy_root)

    def test_changed_functions_uses_the_shared_definition_selection(self) -> None:
        source = (
            "def first():\n    return 1\n\n\ndef second():\n    return 2\n"
        )
        previous = python_mutation.python_shape._file_index(
            "pkg/app.py", "def first():\n    return 1\n"
        )
        before = {"pkg/app.py": {
            function.identity: function for function in previous.functions
        }}
        diff = python_mutation.python_shape.Diff(
            frozenset({"pkg/app.py"}), {}, frozenset()
        )
        spec = python_mutation.MutationSpec("changed", "HEAD", 10, 20, 10)
        with mock.patch.multiple(
            python_mutation.python_shape,
            _diff_lines=mock.Mock(return_value=diff),
            _measured_paths=mock.Mock(return_value=["pkg/app.py"]),
            _read_source=mock.Mock(return_value=source),
            _base_functions=mock.Mock(return_value=before),
        ):
            found = python_mutation._changed_functions(
                SimpleNamespace(root=Path(".")), spec, DiffBase("HEAD", "base")
            )
        self.assertEqual([function.name for function in found], ["second"])

    def test_selected_test_files_reads_python_tests_checks(self) -> None:
        check = SimpleNamespace(adapter="python_tests")
        context = SimpleNamespace(
            config=SimpleNamespace(checks={"tests": check}),
            files=["pkg/app.py"], classes={},
        )
        with mock.patch(
            "quality_gate.checks._select_files",
            return_value=(["tests/test_app.py"], []),
        ):
            self.assertEqual(
                python_mutation._selected_test_files(context),
                ["tests/test_app.py"],
            )

    def test_test_directories_reads_the_discover_directory(self) -> None:
        check = SimpleNamespace(
            adapter="python_tests",
            spec=SimpleNamespace(run=(
                "python", "-m", "unittest", "discover", "-s", "tests",
            )),
        )
        context = SimpleNamespace(
            config=SimpleNamespace(checks={"tests": check})
        )
        self.assertEqual(python_mutation._test_directories(context), ["tests"])

    def test_in_any_directory_checks_each_directory(self) -> None:
        self.assertTrue(python_mutation._in_any_directory(
            "tests/test_app.py", ["tests"]
        ))
        self.assertFalse(python_mutation._in_any_directory(
            "pkg/app.py", ["tests"]
        ))

    def test_fallback_test_paths_keeps_test_shaped_files(self) -> None:
        context = SimpleNamespace(
            files=["pkg/app.py", "tests/test_app.py", "tests/helper.py"]
        )
        with mock.patch.object(
            python_mutation, "_selected_test_files",
            return_value=["pkg/app.py", "tests/test_app.py"],
        ):
            self.assertEqual(
                python_mutation._fallback_test_paths(context),
                ["tests/test_app.py"],
            )

    def test_selected_test_paths_uses_the_directory_or_the_fallback(self) -> None:
        context = SimpleNamespace(
            files=["pkg/app.py", "tests/test_app.py", "other/test_other.py"]
        )
        with mock.patch.object(
            python_mutation, "_fallback_test_paths",
            return_value=["fallback"],
        ):
            self.assertEqual(
                python_mutation._selected_test_paths(context, []), ["fallback"]
            )
        self.assertEqual(
            python_mutation._selected_test_paths(context, ["tests"]),
            ["tests/test_app.py"],
        )

    def test_test_file_paths_keeps_python_files_sorted(self) -> None:
        context = SimpleNamespace(
            files=[], config=SimpleNamespace(checks={})
        )
        with mock.patch.object(
            python_mutation, "_selected_test_paths",
            return_value=["tests/test_b.py", "tests/helper.txt", "tests/test_a.py"],
        ):
            self.assertEqual(
                python_mutation._test_file_paths(context),
                ["tests/test_a.py", "tests/test_b.py"],
            )

    def test_module_name_is_the_dotted_path(self) -> None:
        self.assertEqual(
            python_mutation._module_name("pkg/app.py"), "pkg.app"
        )

    def test_discover_argv_runs_one_discovered_file(self) -> None:
        self.assertEqual(
            python_mutation._discover_argv("tests/test_app.py"),
            [
                sys.executable, "-I", "-B", "-m", "unittest", "discover",
                "-s", "tests", "-p", "test_app.py",
            ],
        )

    def test_budget_result_is_a_timed_out_run(self) -> None:
        result = python_mutation._budget_result(["python"])
        self.assertEqual((result.execution, result.timed_out), ("budget", True))
        self.assertIsNone(result.returncode)
        self.assertEqual(result.argv, ("python",))

    def test_run_one_test_past_its_deadline_is_a_budget_result(self) -> None:
        result = python_mutation._run_one_test(
            Path("."), "tests/test_app.py", time.monotonic() - 1
        )
        self.assertEqual(result.execution, "budget")
        self.assertEqual(result.argv, tuple(
            python_mutation._discover_argv("tests/test_app.py")
        ))

    def test_first_failure_keeps_the_earliest_failure(self) -> None:
        passed = RunResult((), execution="completed", returncode=0)
        failed = RunResult((), execution="completed", returncode=1)
        self.assertIsNone(python_mutation._first_failure(None, passed))
        self.assertIs(
            python_mutation._first_failure(failed, passed), failed
        )
        self.assertIs(python_mutation._first_failure(None, failed), failed)

    def test_baseline_copies_the_tree_and_reports_its_budget_cut(self) -> None:
        source = "def work():\n    return 1\n"
        function = self.function(source)
        spec = python_mutation.MutationSpec("changed", "HEAD", 10, 20, 10)
        root, work = self.source_tree(source)
        with mock.patch.object(
            python_mutation, "_run_unittest",
            return_value=RunResult(
                (), execution="completed", returncode=0
            ),
        ):
            self.assertTrue(python_mutation._baseline(
                function, ("tests/test_app.py",), root, work,
                0, spec, time.monotonic(),
            ))
        self.assertTrue((work / "copy-0000/pkg/app.py").exists())
        self.assertFalse(python_mutation._baseline(
            function, ("tests/test_app.py",), root, work,
            1, spec, time.monotonic() - 11,
        ))

    def test_a_slow_baseline_copy_leaves_no_time_for_its_run(self) -> None:
        source = "def work():\n    return 1\n"
        function = self.function(source)
        spec = python_mutation.MutationSpec("changed", "HEAD", 5, 20, 1)
        root, work = self.source_tree(source)
        real_copy = python_mutation._fresh_copy

        def slow_copy(source_root: Path, destination: Path, number: int) -> Path:
            copied = real_copy(source_root, destination, number)
            time.sleep(1.1)
            return copied

        with mock.patch.object(
            python_mutation, "_fresh_copy", side_effect=slow_copy
        ), mock.patch.object(
            python_mutation, "_run_unittest",
            return_value=RunResult(
                (), execution="completed", returncode=0
            ),
        ) as run_tests:
            self.assertFalse(python_mutation._baseline(
                function, ("tests/test_app.py",), root, work,
                0, spec, time.monotonic(),
            ))
        run_tests.assert_not_called()

    def test_result_or_failure_prefers_the_first_failure(self) -> None:
        result = RunResult((), execution="completed", returncode=0)
        failure = RunResult((), execution="budget", returncode=None)
        self.assertIs(
            python_mutation._result_or_failure(result, None), result
        )
        self.assertIs(
            python_mutation._result_or_failure(result, failure), failure
        )

    def test_passed_needs_a_completed_zero_exit(self) -> None:
        self.assertTrue(python_mutation._passed(
            RunResult((), execution="completed", returncode=0)
        ))
        self.assertFalse(python_mutation._passed(
            RunResult((), execution="completed", returncode=1)
        ))
        self.assertFalse(python_mutation._passed(
            RunResult((), execution="budget", returncode=None)
        ))

    def test_baseline_passed_names_a_cut_and_a_failure(self) -> None:
        function = self.function("def work():\n    return 1\n")
        self.assertTrue(python_mutation._baseline_passed(
            function, RunResult((), execution="completed", returncode=0), 1, 10
        ))
        self.assertFalse(python_mutation._baseline_passed(
            function, RunResult((), execution="budget", returncode=None), 1, 10
        ))
        with self.assertRaises(python_mutation.GateError):
            python_mutation._baseline_passed(
                function,
                RunResult((), execution="completed", returncode=1), 1, 10,
            )
        with self.assertRaisesRegex(python_mutation.GateError, "boom"):
            python_mutation._baseline_passed(
                function,
                RunResult((), execution="error", returncode=None, error="boom"),
                1, 10,
            )

    def test_outcome_maps_the_execution_and_failures(self) -> None:
        function = self.function("def work():\n    return 1\n")
        self.assertEqual(python_mutation._outcome(
            RunResult((), execution="budget", returncode=None), function
        ), "timed out")
        self.assertEqual(python_mutation._outcome(
            RunResult((), execution="completed", returncode=0), function
        ), "survived")
        self.assertEqual(python_mutation._outcome(
            RunResult((), execution="completed", returncode=1), function
        ), "killed")
        with self.assertRaises(python_mutation.GateError):
            python_mutation._outcome(
                RunResult((), execution="error", returncode=None, error="x"),
                function,
            )

    def test_the_findings_name_their_rule(self) -> None:
        _source, function, mutation = self.work_mutation()
        survived = python_mutation._survived_finding(
            function, mutation, ("tests/test_app.py",)
        )
        self.assertTrue(
            survived.subject.startswith(
                "python-mutation: pkg/app.py:2 work survives n+1"
            ),
            survived.subject,
        )
        self.assertIn("no test names it", python_mutation._no_test_finding(
            function
        ).subject)
        over = python_mutation._over_budget_finding(
            function, python_mutation.MutationSpec(
                "changed", "HEAD", 10, 20, 10
            )
        )
        self.assertIn("over budget", over.subject)

    def test_records_split_suppressed_and_generated_mutants(self) -> None:
        source = (
            "def documented():\n"
            "    'first'\n"
            "    return 1\n"
        )
        function = self.function(source)
        mutations = python_mutation._mutations(
            function.node, source, 10
        )
        self.assertTrue(python_mutation._suppressed_records(
            function, mutations, ("tests/test_app.py",)
        ))
        self.assertTrue(python_mutation._generated_mutations(mutations))

    def test_run_mutant_copies_and_reports_the_outcome(self) -> None:
        source, function, mutation = self.work_mutation()
        spec = python_mutation.MutationSpec("changed", "HEAD", 10, 20, 10)
        root, work = self.source_tree(source)
        numbers = [0]
        with mock.patch.object(
            python_mutation, "_run_unittest",
            return_value=RunResult(
                (), execution="completed", returncode=1
            ),
        ):
            outcome, over_budget = python_mutation._run_mutant(
                function, mutation, ("tests/test_app.py",),
                spec, time.monotonic(), root, work, numbers,
            )
        self.assertEqual((outcome, over_budget), ("killed", False))
        self.assertEqual(numbers, [1])

    def test_run_generated_records_a_survivor_and_a_cutoff(self) -> None:
        source, function, mutation = self.work_mutation()
        spec = python_mutation.MutationSpec("changed", "HEAD", 10, 20, 10)
        records: list[Any] = []
        with mock.patch.object(
            python_mutation, "_run_mutant",
            return_value=("survived", False),
        ):
            records, findings, finished = python_mutation._run_generated(
                function, [mutation], ("tests/test_app.py",), spec,
                time.monotonic(), Path("."), Path("."), [0], records,
            )
        self.assertTrue(finished)
        self.assertEqual(records[0]["outcome"], "survived")
        self.assertEqual(len(findings), 1)
        cut = python_mutation.MutationSpec("changed", "HEAD", 10, 20, 1)
        records, findings, finished = python_mutation._run_generated(
            function, [mutation], ("tests/test_app.py",), cut,
            time.monotonic() - 2, Path("."), Path("."), [0], [],
        )
        self.assertFalse(finished)
        self.assertEqual(records[0]["outcome"], "not run (over budget)")
        self.assertEqual(findings, [])

    def test_run_function_without_generated_mutants_finishes(self) -> None:
        source = "def empty():\n    0\n"
        function = self.function(source)
        records, findings, finished = python_mutation._run_function(
            function, ("tests/test_app.py",), source,
            python_mutation.MutationSpec("changed", "HEAD", 10, 20, 10),
            time.monotonic(), Path("."), Path("."), [0],
        )
        self.assertTrue(finished)
        self.assertTrue(records)
        self.assertEqual(findings, [])

    def test_source_for_reads_once_and_caches(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pkg").mkdir()
            path = root / "pkg/app.py"
            path.write_text("first", encoding="utf-8")
            sources: dict[str, str] = {}
            self.assertEqual(
                python_mutation._source_for(root, "pkg/app.py", sources),
                "first",
            )
            path.write_text("second", encoding="utf-8")
            self.assertEqual(
                python_mutation._source_for(root, "pkg/app.py", sources),
                "first",
            )

    def test_unfinished_after_cleanup_adds_the_last_function_on_an_overrun(
        self,
    ) -> None:
        function = self.function("def work():\n    return 1\n")
        finished = python_mutation.MutationSpec(
            "changed", "HEAD", 10, 20, 10
        )
        self.assertEqual(python_mutation._unfinished_after_cleanup(
            [function], [], time.monotonic(), finished
        ), [])
        self.assertEqual(python_mutation._unfinished_after_cleanup(
            [], [], time.monotonic(), finished
        ), [])
        unfinished = [function]
        self.assertIs(python_mutation._unfinished_after_cleanup(
            [function], unfinished, time.monotonic(), finished
        ), unfinished)
        over = python_mutation.MutationSpec("changed", "HEAD", 10, 20, 0)
        self.assertEqual(python_mutation._unfinished_after_cleanup(
            [function], [], time.monotonic(), over
        ), [function])

    def test_measure_runs_each_function_and_reports_none_unfinished(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context = SimpleNamespace(root=Path(directory))
            function = self.function("def empty():\n    0\n")
            with mock.patch.object(
                python_mutation, "_source_for", return_value=(
                    "def empty():\n    0\n"
                ),
            ):
                records, findings, unfinished = python_mutation._measure(
                    context,
                    python_mutation.MutationSpec(
                        "changed", "HEAD", 10, 20, 10
                    ),
                    [function],
                    {function.identity: ("tests/test_app.py",)},
                    time.monotonic(),
                )
        self.assertTrue(records)
        self.assertEqual(findings, [])
        self.assertEqual(unfinished, [])

    def test_the_entry_point_reports_a_configuration_error(self) -> None:
        spec = python_mutation.MutationSpec("changed", "no-such", 10, 20, 10)
        check = SimpleNamespace(spec=spec)
        context = SimpleNamespace(
            root=Path("."), check=check, base_override=None, prefix="check"
        )
        stub = SimpleNamespace(configuration_error=False, budget_seconds=None)
        with mock.patch.object(
            python_mutation, "diff_base",
            side_effect=python_mutation.GateError("no such revision"),
        ), mock.patch(
            "quality_gate.checks._ratchet_error", return_value=stub
        ):
            result = python_mutation._run_python_mutation(context)
        self.assertIs(result, stub)
        self.assertTrue(result.configuration_error)
        self.assertEqual(result.budget_seconds, spec.run_seconds)

    def test_mutation_result_records_the_run_budget(self) -> None:
        spec = python_mutation.MutationSpec("changed", "HEAD", 10, 20, 10)
        check = SimpleNamespace(spec=spec)
        context = SimpleNamespace(prefix="check", check=check)
        measured = python_mutation.Domain.of_files(
            ["pkg/app.py"], "the measured production files"
        )
        stub = SimpleNamespace(budget_seconds=None)
        with mock.patch(
            "quality_gate.checks._evaluate_ratchet",
            return_value=(None, "failure"),
        ), mock.patch(
            "quality_gate.checks._ratchet_result", return_value=stub
        ):
            result = python_mutation._mutation_result(
                context, check, time.monotonic(), [], [], [],
                DiffBase("HEAD", "base"), measured, [],
            )
        self.assertIs(result, stub)
        self.assertEqual(result.budget_seconds, spec.run_seconds)


class AdapterUnitTests(unittest.TestCase):
    def test_the_spec_defaults_match_the_documented_budgets(self) -> None:
        parsed = python_mutation._python_mutation_spec(
            {"base": "HEAD"}, Path("."), Path("quality-gate.toml"),
            "checks.mutation",
        )
        spec = parsed.spec
        self.assertEqual(spec.scope, "changed")
        self.assertEqual(spec.mutant_seconds, 10)
        self.assertEqual(spec.function_mutants, 20)
        self.assertEqual(spec.run_seconds, 300)
        self.assertEqual(python_mutation._budget(spec), 300)
        self.assertEqual(parsed.threshold, 0)

    def test_the_check_entry_point_is_callable(self) -> None:
        self.assertTrue(callable(python_mutation._run_python_mutation))

    def test_the_generator_respects_its_limit(self) -> None:
        source = "def many():\n    return (1, 2, 3)\n"
        function = ast.parse(source).body[0]
        records = python_mutation._mutations(function, source, 2)
        generated = [
            record for record in records if record.rule is None
        ]
        self.assertEqual(len(generated), 2)
        self.assertEqual(generated[0].operator, "return None")
        self.assertEqual(generated[1].operator, "n+1")

    def test_the_policy_test_directory_comes_from_discover(self) -> None:
        self.assertEqual(
            python_mutation._discover_directory(
                ("python", "-m", "unittest", "discover", "-s", "tests")
            ),
            "tests",
        )
        self.assertEqual(
            python_mutation._discover_directory(
                ("python", "-m", "unittest", "discover", "-s", "./tests")
            ),
            "tests",
        )
        self.assertEqual(
            python_mutation._discover_directory(("python", "-m", "unittest")),
            "",
        )
        self.assertTrue(
            python_mutation._in_test_directory("tests/test_app.py", "tests")
        )
        self.assertFalse(
            python_mutation._in_test_directory("pkg/app.py", "tests")
        )

    def test_each_change_builder_produces_its_operator(self) -> None:
        comparisons = python_mutation._comparison_changes(
            ast.parse("a == b").body[0].value
        )
        self.assertEqual([change.operator for change in comparisons], ["!="])
        booleans = python_mutation._boolean_changes(
            ast.parse("a and b").body[0].value
        )
        self.assertEqual([change.operator for change in booleans], ["or"])
        conditions = python_mutation._condition_changes(
            ast.parse("if a:\n    pass\n").body[0]
        )
        self.assertEqual([change.operator for change in conditions], ["not"])
        comprehensions = python_mutation._comprehension_changes(
            ast.parse("[x for x in y if x]").body[0].value.generators[0]
        )
        self.assertEqual(
            [change.operator for change in comprehensions], ["not"]
        )
        returns = python_mutation._return_changes(
            ast.parse("def f():\n    return 1\n").body[0].body[0]
        )
        self.assertEqual([change.operator for change in returns], ["return None"])
        constants = python_mutation._constant_changes(
            ast.parse("1").body[0].value
        )
        self.assertEqual([change.operator for change in constants], ["n+1"])

FAILING_TEST = """\
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from pkg.app import classify


class FailingTests(unittest.TestCase):
    def test_fails_on_the_original(self):
        self.fail("the original tests must pass")
"""


SLOW_TEST = """\
import pathlib
import sys
import time
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from pkg.app import countdown


class SlowTests(unittest.TestCase):
    def test_slow(self):
        time.sleep(3)
        self.assertEqual(countdown(1), 0)
"""


class BaselineTests(MutationCase):
    def test_an_uncompilable_deletion_does_not_fill_the_cap(self) -> None:
        self.write_config(mutation_config(function_mutants=1))
        self.base_commit()
        self.commit({
            "pkg/app.py": NONLOCAL,
            "tests/test_app.py": NONLOCAL_TEST,
        })
        _result, _document, check = self.run_mutation()
        records = [
            record for record in self.mutants(check)
            if record["function"] == "outer"
        ]
        deletion = next(
            record for record in records if record["operator"] == "delete"
        )
        self.assertEqual(deletion["rule"], "does not compile", records)
        generated = [
            record for record in records
            if record["outcome"] != "not generated"
        ]
        self.assertEqual(
            [record["operator"] for record in generated], ["n+1"], records
        )
        self.assertEqual(generated[0]["outcome"], "killed", records)

    def test_failing_original_tests_are_a_check_error(self) -> None:
        self.base_commit()
        self.commit({
            "pkg/app.py": CLASSIFY,
            "tests/test_app.py": FAILING_TEST,
        })
        check = self.assert_check_error()
        self.assertIn("original tests do not pass", check["reason"])

    def test_a_baseline_cut_by_run_seconds_is_over_budget(self) -> None:
        self.write_config(mutation_config(
            mutant_seconds=5, run_seconds=1, function_mutants=2,
        ))
        self.base_commit()
        self.commit({
            "pkg/app.py": COUNTDOWN,
            "tests/test_app.py": SLOW_TEST,
        })
        result, _document, check = self.run_mutation()
        self.assert_over_budget(result, check)
