"""Exercise the opt-in mutation runner with real pytest test functions."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest import mock

from support import output
from test_python_mutation import MutationCase, mutation_config

from quality_gate import pytest_mutation_run, python_mutation
from quality_gate.policy import GateError
from quality_gate.runner import RunResult


APP = "def flag():\n    return True\n"
IMPORT = "from pkg.app import flag\n"


class PytestMutationCase(MutationCase):
    def prepare(self, tests: str, **options: object) -> None:
        self.write_config(mutation_config(
            test_runner="pytest", function_mutants=1, **options,
        ).replace('"unittest", "discover", "-s", "tests"', '"pytest", "tests"'))
        self.base_commit()
        self.commit({
            "pkg/app.py": APP,
            "tests/app_test.py": IMPORT + tests,
        })

    def assert_pytest_error(self, stage: str, detail: str) -> None:
        check = self.assert_check_error()
        self.assertIn(f"pytest {stage}", check["reason"])
        self.assertIn(detail, check["reason"])


class PytestMutationTests(PytestMutationCase):
    def test_assertion_kills_with_plain_pytest_function_and_fixture(self) -> None:
        self.prepare(
            "from pathlib import Path\n"
            "import pytest\n"
            "from pkg import app\n"
            "@pytest.fixture\n"
            "def actual():\n"
            "    return flag()\n"
            "def test_flag(actual):\n"
            "    assert Path(app.__file__).resolve() == Path.cwd() / 'pkg/app.py'\n"
            "    assert actual is True\n"
        )
        result, _document, check = self.run_mutation()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual({row["outcome"] for row in self.mutants(check)}, {
            "not generated", "killed",
        })
        self.assertEqual(self.git("status", "--porcelain").stdout, "")

    def test_passing_pytest_function_reports_survivor(self) -> None:
        self.prepare("def test_flag():\n    assert isinstance(flag(), bool)\n")
        result, _document, check = self.run_mutation()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual({row["outcome"] for row in self.mutants(check)}, {
            "not generated", "survived",
        })

    def test_zero_collection_invalidates_original(self) -> None:
        self.prepare("print('1 passed')\nflag()\n")
        self.assert_pytest_error("original tests", "collected zero selected tests")

    def test_zero_collection_invalidates_mutant(self) -> None:
        self.prepare("if flag():\n    def test_flag():\n        assert flag()\n")
        self.assert_pytest_error("mutant run", "collected zero selected tests")

    def test_all_skipped_invalidates_original(self) -> None:
        self.prepare(
            "import pytest\n"
            "@pytest.mark.skip\n"
            "def test_flag():\n"
            "    assert flag()\n"
        )
        self.assert_pytest_error("original tests", "executed zero selected tests")

    def test_original_import_failure_is_a_collection_error(self) -> None:
        self.prepare("import missing_fixture_dependency\ndef test_flag():\n    assert flag()\n")
        self.assert_pytest_error("original tests", "collection error in tests/app_test.py")

    def test_mutant_import_failure_is_a_collection_error(self) -> None:
        self.prepare(
            "if not flag():\n"
            "    import missing_fixture_dependency\n"
            "def test_flag():\n"
            "    assert flag()\n"
        )
        self.assert_pytest_error("mutant run", "collection error in tests/app_test.py")

    def test_import_failure_during_mutated_test_is_a_call_error(self) -> None:
        self.prepare(
            "def test_flag():\n"
            "    if not flag():\n"
            "        import missing_fixture_dependency\n"
        )
        self.assert_pytest_error("mutant run", "call error in tests/app_test.py::test_flag")

    def test_fixture_assertion_cannot_kill(self) -> None:
        self.prepare(
            "import pytest\n"
            "@pytest.fixture\n"
            "def positive():\n"
            "    assert flag() is True\n"
            "def test_flag(positive):\n"
            "    assert flag()\n"
        )
        self.assert_pytest_error("mutant run", "setup error in tests/app_test.py::test_flag")

    def test_mutant_with_different_execution_is_invalid(self) -> None:
        self.prepare(
            "import pytest\n"
            "@pytest.mark.skipif(not flag(), reason='fixture changes with mutant')\n"
            "def test_original_only():\n"
            "    assert flag()\n"
            "def test_always():\n"
            "    assert isinstance(flag(), bool)\n"
        )
        self.assert_pytest_error("mutant run", "collected or executed different tests")

    def test_loaded_source_checkout_is_rejected(self) -> None:
        source = str(self.repo / "pkg/app.py")
        self.prepare(
            "import importlib.util\n"
            "import sys\n"
            f"spec = importlib.util.spec_from_file_location('source_app', {source!r})\n"
            "source_app = importlib.util.module_from_spec(spec)\n"
            "sys.modules[spec.name] = source_app\n"
            "spec.loader.exec_module(source_app)\n"
            "def test_flag():\n"
            "    assert flag() and source_app.flag()\n"
        )
        self.assert_pytest_error("original tests", "imported from the source checkout")

    def test_pytest_config_can_bind_a_relative_import_root(self) -> None:
        self.write_config(mutation_config(test_runner="pytest", function_mutants=1))
        self.base_commit()
        self.commit({
            "src/pkg/app.py": APP,
            "pyproject.toml": '[tool.pytest.ini_options]\npythonpath = ["src"]\n',
            "tests/test_app.py": IMPORT + "def test_flag():\n    assert flag()\n",
        })
        result, _document, check = self.run_mutation()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertIn("killed", {row["outcome"] for row in self.mutants(check)})

    def test_mutant_timeout_cannot_kill(self) -> None:
        self.prepare("def test_flag():\n    assert flag()\n", mutant_seconds=2)
        real_run = python_mutation.run

        def time_out_mutant(argv, *, cwd, **kwargs):
            if cwd.name == "copy-0001":
                return RunResult(tuple(argv), "budget", None, timed_out=True)
            return real_run(argv, cwd=cwd, **kwargs)

        with mock.patch.object(python_mutation, "run", side_effect=time_out_mutant):
            self.assert_pytest_error("mutant run", "timed out after 2 s")


class ReceiptTests(PytestMutationCase):
    def test_mutant_does_not_launch_after_copy_exhausts_budget(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            function = SimpleNamespace(path="app.py")
            mutation = SimpleNamespace(mutated_source="VALUE = 1\n")
            spec = python_mutation.MutationSpec("changed", "HEAD", 10, 1, 10, "pytest")
            with (
                mock.patch.object(python_mutation, "_remaining", side_effect=[1, 0]),
                mock.patch.object(python_mutation, "_fresh_copy", return_value=root),
                mock.patch.object(python_mutation, "_run_pytest") as run_pytest,
            ):
                result = python_mutation._run_mutant(
                    function, mutation, ("tests/test_app.py",), spec, 0, root, root, [0], root,
                )
            self.assertEqual(result, ("not run (over budget)", True))
            run_pytest.assert_not_called()
            self.assertEqual((root / "app.py").read_text(), mutation.mutated_source)

    def test_verified_receipts_drive_adapter_without_pytest(self) -> None:
        self.prepare("def test_flag():\n    assert flag()\n")
        node = "tests/app_test.py::test_flag"

        def complete(argv, *, cwd, **_kwargs):
            assertions = [node] if cwd.name == "copy-0001" else []
            Path(argv[5]).write_text(json.dumps({
                "collected": [node], "executed": [node], "assertions": assertions, "errors": [],
            }), encoding="utf-8")
            return RunResult(tuple(argv), "completed", int(bool(assertions)))

        with mock.patch.object(python_mutation, "run", side_effect=complete):
            result, _document, check = self.run_mutation()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertIn("killed", {row["outcome"] for row in self.mutants(check)})

    def test_receipt_validation_rejects_unsound_results(self) -> None:
        report = self.base / "report.json"
        valid = {"collected": ["selected"], "executed": ["selected"], "assertions": [], "errors": []}
        cases = (
            ({"executed": "not a list"}, 0, "invalid executed"),
            ({"collected": ["selected", "selected"]}, 0, "duplicate collected"),
            ({"errors": ["collection error"]}, 0, "collection error"),
            ({"executed": []}, 0, "executed zero"),
            ({"executed": ["another"]}, 0, "inconsistent collection and execution"),
            ({}, 1, "pytest exited 1"),
        )
        for changed, code, message in cases:
            with self.subTest(changed=changed):
                report.write_text(json.dumps(valid | changed), encoding="utf-8")
                result = RunResult((), "completed", code)
                with self.assertRaisesRegex(GateError, message):
                    python_mutation._pytest_result(result, report, "pytest", 4, False)
        report.write_text("[]", encoding="utf-8")
        with self.assertRaisesRegex(GateError, "invalid pytest evidence"):
            python_mutation._pytest_result(RunResult((), "completed", 0), report, "pytest", 4, False)

    def test_pytest_result_separates_budgets_and_runner_failure(self) -> None:
        report = self.base / "report.json"
        timeout = RunResult((), "budget", None, timed_out=True)
        self.assertIsNone(python_mutation._pytest_result(timeout, report, "pytest", 4, True))
        with self.assertRaisesRegex(GateError, "timed out"):
            python_mutation._pytest_result(timeout, report, "pytest", 4, False)
        with self.assertRaisesRegex(GateError, "could not complete"):
            python_mutation._pytest_result(RunResult((), "signal", -15), report, "pytest", 4, False)

    def test_mutant_outcome_requires_identical_cohort(self) -> None:
        function = SimpleNamespace(identity="pkg/app.py:flag")
        baseline = python_mutation._PytestEvidence(("one",), ("one",), ())
        other = python_mutation._PytestEvidence(("two",), ("two",), ())
        self.assertEqual(python_mutation._pytest_outcome(function, baseline, None), "timed out")
        self.assertEqual(python_mutation._pytest_outcome(function, baseline, baseline), "survived")
        with self.assertRaisesRegex(GateError, "different tests"):
            python_mutation._pytest_outcome(function, baseline, other)


class HookEvidenceTests(unittest.TestCase):
    def report(self, evidence, item, when, exception, *, failed=False, skipped=False):
        hook = evidence.pytest_runtest_makereport(
            item, SimpleNamespace(excinfo=SimpleNamespace(value=exception)),
        )
        next(hook)
        report = SimpleNamespace(when=when, failed=failed, skipped=skipped)
        with self.assertRaises(StopIteration):
            hook.send(SimpleNamespace(get_result=lambda: report))

    def test_hooks_distinguish_assertions_skips_and_fixture_errors(self) -> None:
        test_file = Path("/copied/test_file.py")
        item = SimpleNamespace(
            path=test_file, nodeid="test_file.py::test_one", getparent=lambda _: None,
        )
        evidence = pytest_mutation_run.Evidence({test_file}, object, RuntimeError)
        evidence.pytest_collection_finish(SimpleNamespace(items=[item]))
        self.report(evidence, item, "call", AssertionError(), failed=True)
        self.report(evidence, item, "call", None, skipped=True)
        self.report(evidence, item, "teardown", AssertionError(), failed=True)
        evidence.pytest_collectreport(SimpleNamespace(failed=True, nodeid="another.py"))
        self.assertEqual(evidence.collected, [item.nodeid])
        self.assertEqual(evidence.executed, [item.nodeid])
        self.assertEqual(evidence.assertions, [item.nodeid])
        self.assertEqual(evidence.errors, {
            f"pytest teardown error in {item.nodeid}", "pytest collection error in another.py",
        })

    def test_hooks_require_collection_from_the_selected_copied_paths(self) -> None:
        test_file = Path("/copied/test_file.py")
        item = SimpleNamespace(
            path=test_file, nodeid="test_file.py::test_one",
            getparent=lambda _: SimpleNamespace(obj=SimpleNamespace(__file__="/other/test_file.py")),
        )
        evidence = pytest_mutation_run.Evidence({test_file}, object, AssertionError)
        evidence.pytest_collection_finish(SimpleNamespace(items=[]))
        evidence.pytest_collection_finish(SimpleNamespace(items=[item]))
        evidence.expected_files = {Path("/copied/test_another.py")}
        evidence.pytest_collection_finish(SimpleNamespace(items=[item]))
        self.assertEqual(evidence.errors, {
            "pytest collected zero selected tests",
            "pytest did not collect tests from exactly the selected copied files",
            f"pytest loaded a test module outside its copied file: {item.nodeid}",
        })

    def test_runner_uses_copy_and_writes_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            original = directory / "original"
            copy = directory / "copy"
            target = copy / "pkg.py"
            module = ModuleType("pkg")
            module.__file__ = str(target)
            leaked = ModuleType("leaked")
            leaked.__file__ = str(original / "pkg.py")
            report = directory / "report.json"
            pytest = SimpleNamespace(
                Module=object, fail=SimpleNamespace(Exception=AssertionError),
                hookimpl=mock.Mock(return_value=lambda hook: hook),
                main=mock.Mock(return_value=0),
            )
            modules = {"pytest": pytest, "pkg": module, "leaked": leaked, "empty": None}
            with (
                mock.patch.object(pytest_mutation_run.Path, "cwd", return_value=copy),
                mock.patch.object(sys, "path", [str(original)]),
                mock.patch.dict(sys.modules, modules),
            ):
                code = pytest_mutation_run._main([str(original), str(report), "pkg.py", "test_file.py"])
                self.assertEqual(sys.path, [str(copy)])
            self.assertEqual(code, 0)
            self.assertEqual(pytest.main.call_args.args[0], [f"--rootdir={copy}", "--", "./test_file.py"])
            self.assertIn("pytest imported from the source checkout", report.read_text(encoding="utf-8"))
            missing = pytest_mutation_run.Evidence(set(), object, AssertionError)
            missing.write(report, original, target)
            self.assertIn("pytest did not import the measured module from the copy", missing.errors.pop())


def load_tests(loader, standard_tests, _pattern):
    if importlib.util.find_spec("pytest") is not None:
        return standard_tests
    return unittest.TestSuite(
        loader.loadTestsFromTestCase(case) for case in (ReceiptTests, HookEvidenceTests)
    )
