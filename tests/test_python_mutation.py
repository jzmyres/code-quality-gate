"""Tests for the python_mutation adapter: operators, selection, budgets and findings."""
from __future__ import annotations

import ast
import subprocess
import time
import unittest
from pathlib import Path
from typing import Any

from support import BASE_CONFIG, FixtureCase, _add_check_to_class, output

from quality_gate import python_mutation


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

    def run_mutation(self) -> tuple[subprocess.CompletedProcess[str], dict[str, Any], dict[str, Any]]:
        result, document = self.run_json("--only", "mutation")
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

    def test_an_invalid_base_is_a_check_error(self) -> None:
        self.write_config(mutation_config(base="no-such-revision"))
        self.base_commit()
        self.commit({
            "pkg/app.py": CLASSIFY,
            "tests/test_app.py": STRONG_CLASSIFY,
        })
        check = self.assert_check_error()
        self.assertNotIn("pass", check.get("outcome"))


class FindingTests(MutationCase):
    def test_the_survivor_message_is_exact(self) -> None:
        self.base_commit()
        self.commit({
            "pkg/app.py": CLASSIFY,
            "tests/test_app.py": WEAK_CLASSIFY,
        })
        _result, _document, check = self.run_mutation()
        expected = (
            "python-mutation: pkg/app.py:2 classify survives >= "
            "(if value >= 0:); tests run: tests/test_app.py. Add a test that "
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
        self.assertNotEqual(result.returncode, 0, output(result))
        self.assertTrue(any(
            "over budget" in finding["subject"]
            for finding in check["findings"]
        ), check["findings"])
