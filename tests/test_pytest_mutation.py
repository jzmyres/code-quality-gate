"""Exercise the opt-in mutation runner with real pytest test functions."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest import mock

from support import output
from test_python_mutation import MutationCase, mutation_config

from quality_gate import pytest_mutation_run, python_mutation
from quality_gate.policy import GateError
from quality_gate.runner import RunResult


APP = "def flag():\n    return True\n"
IMPORT = "from pkg.app import flag\n"


class PytestMutationCase(MutationCase):
    def prepare(self, tests: str, *, app: str = APP, **options: object) -> None:
        self.write_config(mutation_config(
            test_runner="pytest", function_mutants=1, **options,
        ).replace('"unittest", "discover", "-s", "tests"', '"pytest", "tests"'))
        self.base_commit()
        self.commit({
            "pkg/app.py": app,
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

    def test_pytest_selects_aliased_imports_from_configured_root(self) -> None:
        self.write_config(
            'python_import_roots = ["src"]\n'
            + mutation_config(test_runner="pytest", function_mutants=1)
        )
        self.base_commit()
        self.commit({
            "src/pkg/app.py": APP + "\nRESULT = flag()\n",
            "conftest.py": "from pkg import app\nfrom root_support import marker\nassert marker\n",
            "root_support.py": "marker = True\n",
            "tests/test_app.py": (
                "from pkg import app as helper\n"
                "def test_result():\n"
                "    assert helper.RESULT is True\n"
            ),
        })
        result, _document, check = self.run_mutation()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(check["measurement"]["test_files"], ["tests/test_app.py"])
        self.assertEqual(
            [(row["subject"], row["tests"]) for row in self.mutants(check) if row["outcome"] == "killed"],
            [("src/pkg/app.py:flag", ["tests/test_app.py"])],
        )

    def test_mutant_timeout_cannot_kill(self) -> None:
        self.prepare("def test_flag():\n    assert flag()\n", mutant_seconds=2)
        real_run = python_mutation.run

        def time_out_mutant(argv, *, cwd, **kwargs):
            if cwd.name == "copy-0001":
                return RunResult(tuple(argv), "budget", None, timed_out=True)
            return real_run(argv, cwd=cwd, **kwargs)

        with mock.patch.object(python_mutation, "run", side_effect=time_out_mutant):
            self.assert_pytest_error("mutant run", "timed out after 2 s")


class PreferredCohortTests(PytestMutationCase):
    preferred_file = "tests/app_test.py"
    fallback_file = "tests/test_other.py"

    def stage(
        self, preferred: str, fallback: str, *, app: str = APP,
        original: str = "def flag():\n    return False\n", **options: object,
    ) -> None:
        self.write_config(mutation_config(test_runner="pytest", **options))
        self.base_commit({"pkg/app.py": original, "pkg/other.py": APP})
        self.commit({"pkg/app.py": app, self.preferred_file: preferred, self.fallback_file: fallback})

    def test_direct_bindings_prefer_the_measured_module_over_a_same_name_import(self) -> None:
        forms = (
            ("from pkg.app import flag as target", "target"),
            ("from pkg import app", "app.flag"),
            ("import pkg.app as target", "target.flag"),
            ("import pkg.app", "pkg.app.flag"),
        )
        self.stage("", IMPORT.replace("pkg.app", "pkg.other") + "def test_other():\n    assert flag()\n")
        for declaration, reference in forms:
            with self.subTest(declaration=declaration):
                self.add_file(
                    self.preferred_file, f"{declaration}\ndef test_measured():\n    assert {reference}()\n",
                )
                result, _document, check = self.run_mutation()
                self.assertEqual(result.returncode, 0, output(result))
                self.assertEqual(
                    check["measurement"]["test_files"], [self.preferred_file, self.fallback_file],
                )
                self.assertEqual(self.evaluated(check), [("killed", [self.preferred_file])])

    def test_module_entry_point_can_witness_a_changed_helper(self) -> None:
        entry = "\ndef entry():\n    return flag()\n"
        self.stage(
            "from pkg import app\ndef test_entry():\n    assert app.entry()\n",
            "from pkg.other import flag\ndef test_other():\n    assert flag()\n",
            app=APP + entry, original=APP.replace("True", "False") + entry,
        )
        result, _document, check = self.run_mutation()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(self.evaluated(check), [("killed", [self.preferred_file])])

    def test_only_suppressed_mutations_still_require_a_preferred_original(self) -> None:
        self.stage(
            IMPORT + "def test_preferred():\n    assert flag() is None\n",
            "from pkg.other import flag\ndef test_other():\n    assert flag()\n",
            app="def flag():\n    return None\n",
        )
        check, attempts = self.record_passing_attempts()
        preferred = [self.preferred_file]
        self.assertEqual(attempts, [("original tests", preferred)])
        self.assertTrue(self.mutants(check))
        self.assertEqual(
            [(row["outcome"], row["tests"]) for row in self.mutants(check)],
            [("not generated", preferred)] * len(self.mutants(check)),
        )

    def test_only_preferred_survivors_run_with_the_full_cohort(self) -> None:
        self.stage(
            IMPORT + "def test_result_type():\n    assert isinstance(flag(), int)\n",
            "from pkg import app\ndef test_result():\n    assert getattr(app, 'flag')() == 5\n",
            app="def flag():\n    return 4 + 1\n", function_mutants=3,
        )
        check, attempts = self.record_passing_attempts()
        preferred = [self.preferred_file]
        full = [self.preferred_file, self.fallback_file]
        self.assertEqual(self.evaluated(check), [("killed", preferred), ("killed", full), ("killed", full)])
        self.assertEqual(attempts, [
            ("original tests", preferred), ("mutant run", preferred), ("mutant run", preferred),
            ("original tests", full), ("mutant run", full), ("mutant run", preferred), ("mutant run", full),
        ])

    def test_survival_in_the_full_cohort_rejects(self) -> None:
        self.stage(
            IMPORT + "def test_preferred():\n    assert isinstance(flag(), bool)\n",
            "from pkg import app\ndef test_other():\n    assert isinstance(getattr(app, 'flag')(), bool)\n",
        )
        result, _document, check = self.run_mutation()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(self.evaluated(check), [("survived", [self.preferred_file, self.fallback_file])])

    def test_unusable_mutant_evidence_in_the_full_cohort_rejects(self) -> None:
        self.stage(
            IMPORT + "def test_preferred():\n    assert isinstance(flag(), bool)\n",
            "from pkg import app\ndef test_bad():\n"
            "    if not getattr(app, 'flag')():\n        raise RuntimeError()\n",
        )
        self.assert_pytest_error("mutant run", f"call error in {self.fallback_file}::test_bad")

    def test_invalid_preferred_evidence_does_not_run_the_full_cohort(self) -> None:
        self.stage(
            IMPORT + "def test_preferred():\n    if not flag():\n        raise RuntimeError()\n",
            "from pkg import app\ndef test_other():\n    assert getattr(app, 'flag')()\n",
        )
        with mock.patch.object(python_mutation, "_run_pytest", wraps=python_mutation._run_pytest) as runs:
            self.assert_pytest_error("mutant run", f"call error in {self.preferred_file}::test_preferred")
        preferred = [self.preferred_file]
        self.assertEqual(self.attempts(runs), [("original tests", preferred), ("mutant run", preferred)])

    def record_passing_attempts(self) -> tuple[dict[str, Any], list[tuple[str, list[str]]]]:
        with mock.patch.object(python_mutation, "_run_pytest", wraps=python_mutation._run_pytest) as runs:
            result, _document, check = self.run_mutation()
        self.assertEqual(result.returncode, 0, output(result))
        return check, self.attempts(runs)

    def evaluated(self, check: dict[str, Any]) -> list[tuple[str, list[str]]]:
        return [
            (row["outcome"], row["tests"]) for row in self.mutants(check) if row["outcome"] != "not generated"
        ]

    def attempts(self, runs: mock.Mock) -> list[tuple[str, list[str]]]:
        return [(call.kwargs["stage"], list(call.args[2])) for call in runs.call_args_list]


class OriginalReuseTests(PytestMutationCase):
    def commit_functions(self, changed: dict[str, str]) -> None:
        self.write_config(mutation_config(test_runner="pytest", function_mutants=1))
        self.base_commit()
        self.commit(changed)

    def test_shared_original_is_scoped_to_the_measured_module(self) -> None:
        self.commit_functions({
            "pkg/app.py": APP + "\ndef ready():\n    return True\n",
            "pkg/extra.py": "def active():\n    return True\n",
            "tests/test_apps.py": (
                "from pkg.app import flag, ready\nfrom pkg.extra import active\n"
                "def test_flags():\n    assert flag() and ready() and active()\n"
            ),
        })
        attempts, killed = self.run_and_record_kills()
        cohort = ("tests/test_apps.py",)
        self.assertEqual(attempts, [
            ("original tests", "pkg/app.py", cohort),
            ("mutant run", "pkg/app.py", cohort),
            ("mutant run", "pkg/app.py", cohort),
            ("original tests", "pkg/extra.py", cohort),
            ("mutant run", "pkg/extra.py", cohort),
        ])
        self.assertEqual(killed, ["pkg/app.py:flag", "pkg/app.py:ready", "pkg/extra.py:active"])

    def test_distinct_preferred_cohorts_keep_separate_originals_and_share_fallback(self) -> None:
        self.commit_functions({
            "pkg/app.py": APP + "\ndef ready():\n    return True\n",
            "tests/test_flag.py": IMPORT + "def test_flag():\n    assert isinstance(flag(), bool)\n",
            "tests/test_ready.py": (
                "from pkg.app import ready\ndef test_ready():\n    assert isinstance(ready(), bool)\n"
            ),
            "tests/test_both.py": (
                "from pkg import app\ndef test_both():\n"
                "    assert getattr(app, 'flag')() and getattr(app, 'ready')()\n"
            ),
        })
        attempts, killed = self.run_and_record_kills()
        flag = ("tests/test_flag.py",)
        ready = ("tests/test_ready.py",)
        full = ("tests/test_both.py", *flag, *ready)
        self.assertEqual([(stage, tests) for stage, _, tests in attempts], [
            ("original tests", flag), ("mutant run", flag), ("original tests", full),
            ("mutant run", full), ("original tests", ready), ("mutant run", ready), ("mutant run", full),
        ])
        self.assertEqual(killed, ["pkg/app.py:flag", "pkg/app.py:ready"])

    def run_and_record_kills(self) -> tuple[list[tuple[str, str, tuple[str, ...]]], list[str]]:
        with mock.patch.object(python_mutation, "_run_pytest", wraps=python_mutation._run_pytest) as runs:
            result, _document, check = self.run_mutation()
        self.assertEqual(result.returncode, 0, output(result))
        copy_roots = [call.args[1] for call in runs.call_args_list]
        self.assertEqual(len(copy_roots), len(set(copy_roots)))
        attempts = [(call.kwargs["stage"], call.args[5], call.args[2]) for call in runs.call_args_list]
        killed = [row["subject"] for row in self.mutants(check) if row["outcome"] == "killed"]
        return attempts, killed


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
                    function, mutation, ("tests/test_app.py",), spec, 0, root,
                    python_mutation._Copies(root, root), [0], root,
                )
            self.assertEqual(result, ("not run (over budget)", True))
            run_pytest.assert_not_called()
            self.assertEqual((root / "app.py").read_text(), mutation.mutated_source)

    def test_original_receipt_is_reused_for_two_independently_verified_mutants(self) -> None:
        self.prepare(
            "from pkg import app\ndef test_flag():\n"
            "    assert getattr(app, 'flag')() and getattr(app, 'ready')()\n",
            app=APP + "\ndef ready():\n    return True\n",
        )
        node = "tests/app_test.py::test_flag"
        invocations = []

        def complete(argv, *, cwd, **_kwargs):
            invocations.append(cwd.name)
            assertions = [node] if cwd.name != "copy-0000" else []
            return self.write_receipt(argv, [node], assertions)

        check = self.passing_receipts(complete)
        self.assertEqual(invocations, ["copy-0000", "copy-0001", "copy-0002"])
        kills = [row["subject"] for row in self.mutants(check) if row["outcome"] == "killed"]
        self.assertEqual(kills, ["pkg/app.py:flag", "pkg/app.py:ready"])

    def test_cache_requires_a_successful_original_for_the_exact_order(self) -> None:
        copies = python_mutation._Copies(self.base, self.base / "snapshot")
        spec = python_mutation.MutationSpec("changed", "HEAD", 10, 1, 10, "pytest")
        function = SimpleNamespace(path="pkg/app.py")
        cohort = ("tests/test_first.py", "tests/test_second.py")
        reverse = cohort[::-1]
        receipt = python_mutation._PytestEvidence(("one",), ("one",), ())
        other = python_mutation._PytestEvidence(("two",), ("two",), ())
        copies_used = [0]

        def original(tests):
            return python_mutation._original_baseline(
                function, tests, self.base, copies, copies_used, spec, 0, self.base,
            )

        with (
            mock.patch.object(python_mutation, "_remaining", return_value=5),
            mock.patch.object(python_mutation, "_baseline", side_effect=[False, receipt, other]) as runs,
        ):
            self.assertFalse(original(cohort))
            self.assertIs(original(cohort), receipt)
            self.assertIs(original(cohort), receipt)
            self.assertIs(original(reverse), other)
        self.assertEqual([call.args[1] for call in runs.call_args_list], [cohort, cohort, reverse])
        with mock.patch.object(python_mutation, "_remaining", return_value=0):
            self.assertFalse(original(cohort))

    def test_changed_measured_source_after_snapshot_rejects(self) -> None:
        self.prepare("def test_flag():\n    assert flag()\n")
        real_copy = python_mutation._copy_tree

        def copy_then_change(source, destination):
            copied = real_copy(source, destination)
            (source / "pkg/app.py").write_bytes(APP.replace("\n", "\r\n").encode())
            return copied

        with (
            mock.patch.object(python_mutation, "_copy_tree", side_effect=copy_then_change),
            mock.patch.object(python_mutation, "_run_pytest") as run_pytest,
        ):
            check = self.assert_check_error()
        self.assertIn("measured source changed while copying pkg/app.py", check["reason"])
        run_pytest.assert_not_called()

    def test_measured_source_changed_before_copy_refuses(self) -> None:
        self.assert_selection_change_refused("pkg/app.py")

    def test_test_source_changed_before_copy_refuses(self) -> None:
        self.assert_selection_change_refused("tests/app_test.py")

    def assert_selection_change_refused(self, relative: str) -> None:
        self.prepare("def test_flag():\n    assert flag()\n")
        real_copy = python_mutation._copy_tree

        def change_then_copy(source, destination):
            if destination.name == "original-source":
                path = source / relative
                path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
            return real_copy(source, destination)

        with (
            mock.patch.object(python_mutation, "_copy_tree", side_effect=change_then_copy),
            mock.patch.object(
                python_mutation, "_run_pytest", wraps=python_mutation._run_pytest,
            ) as run_pytest,
        ):
            check = self.assert_check_error()
        self.assertIn(f"selected source differs from snapshot: {relative}", check["reason"])
        run_pytest.assert_not_called()

    def test_verified_receipts_drive_pytest_fallback(self) -> None:
        self.prepare("import pkg.app as app\ndef test_flag():\n    assert isinstance(app.flag(), bool)\n")
        full_only = "tests/test_fallback.py"
        self.add_file(full_only, "from pkg import app\ndef test_flag():\n    assert getattr(app, 'flag')()\n")
        preferred = ["tests/app_test.py"]
        full = [*preferred, full_only]
        invocations = []
        real_baseline = python_mutation._baseline

        def complete(argv, *, cwd, **_kwargs):
            files = argv[8:]
            invocations.append(files)
            nodes = [f"{file}::test_flag" for file in files]
            assertions = [nodes[-1]] if cwd.name == "copy-0003" else []
            return self.write_receipt(argv, nodes, assertions)

        check = self.passing_receipts(complete)
        self.assertEqual(invocations, [preferred, preferred, full, full])
        killed = self.mutants(check)[-1]
        self.assertEqual((killed["outcome"], killed["tests"]), ("killed", full))

        def cutoff(function, tests, *args):
            return real_baseline(function, tests, *args) if list(tests) == preferred else False

        invocations.clear()
        with (
            mock.patch.object(python_mutation, "run", side_effect=complete),
            mock.patch.object(python_mutation, "_baseline", side_effect=cutoff),
        ):
            result, _document, check = self.run_mutation()
        self.assert_over_budget(result, check)
        self.assertEqual(invocations, [preferred, preferred])
        self.assertEqual(self.mutants(check)[-1]["tests"], preferred)

    def passing_receipts(self, complete) -> dict[str, Any]:
        with mock.patch.object(python_mutation, "run", side_effect=complete):
            result, _document, check = self.run_mutation()
        self.assertEqual(result.returncode, 0, output(result))
        return check

    @staticmethod
    def write_receipt(argv: list[str], nodes: list[str], assertions: list[str]) -> RunResult:
        Path(argv[5]).write_text(json.dumps({
            "collected": nodes, "executed": nodes, "assertions": assertions, "errors": [],
        }), encoding="utf-8")
        return RunResult(tuple(argv), "completed", int(bool(assertions)))

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
        collected = ("one", "two")
        executed = ("one",)
        baseline = python_mutation._PytestEvidence(collected, executed, ())
        killed = python_mutation._PytestEvidence(collected, executed, executed)
        self.assertEqual(python_mutation._pytest_outcome(function, baseline, None), "timed out")
        self.assertEqual(python_mutation._pytest_outcome(function, baseline, baseline), "survived")
        self.assertEqual(python_mutation._pytest_outcome(function, baseline, killed), "killed")
        changed_cohorts = (
            python_mutation._PytestEvidence(("one", "three"), executed, executed),
            python_mutation._PytestEvidence(collected, ("two",), ("two",)),
        )
        for other in changed_cohorts:
            with self.subTest(other=other), self.assertRaisesRegex(
                GateError, "collected or executed different tests from the original",
            ):
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

    def test_record_item_checks_the_loaded_module_origin(self) -> None:
        test_file = Path("/copied/test_file.py")
        module = ModuleType("test_file")
        module.__file__ = str(test_file)
        item = SimpleNamespace(
            path=test_file, nodeid="test_file.py::test_one",
            getparent=mock.Mock(return_value=SimpleNamespace(obj=module)),
        )
        evidence = pytest_mutation_run.Evidence({test_file}, object, AssertionError)
        evidence._record_item(item)
        self.assertEqual(evidence.collected, [item.nodeid])
        self.assertEqual(evidence.errors, set())

        module.__file__ = "/other/test_file.py"
        item.nodeid = "test_file.py::test_two"
        evidence._record_item(item)
        self.assertEqual(evidence.collected, ["test_file.py::test_one", item.nodeid])
        self.assertEqual(evidence.errors, {
            f"pytest loaded a test module outside its copied file: {item.nodeid}",
        })

    def test_only_assertions_and_explicit_failures_in_the_call_phase_kill(self) -> None:
        evidence = pytest_mutation_run.Evidence(set(), object, LookupError)
        cases = (
            ("call", AssertionError(), True),
            ("call", LookupError(), True),
            ("call", RuntimeError(), False),
            ("call", None, False),
            ("setup", AssertionError(), False),
            ("teardown", LookupError(), False),
        )
        for phase, exception, expected in cases:
            with self.subTest(phase=phase, exception=exception):
                report = SimpleNamespace(when=phase)
                excinfo = None if exception is None else SimpleNamespace(value=exception)
                call = SimpleNamespace(excinfo=excinfo)
                self.assertIs(evidence._is_assertion(report, call), expected)

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
            interpreter = str(directory / "interpreter")
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
                mock.patch.object(sys, "path", [str(original), interpreter]),
                mock.patch.dict(sys.modules, modules),
            ):
                code = pytest_mutation_run._main(
                    [str(original), str(report), "pkg.py", '["."]', "test_file.py"],
                )
                self.assertEqual(sys.path, [str(copy), interpreter])
            self.assertEqual(code, 0)
            self.assertEqual(pytest.main.call_args.args[0], [f"--rootdir={copy}", "--", "./test_file.py"])
            self.assertIn("pytest imported from the source checkout", report.read_text(encoding="utf-8"))
            missing = pytest_mutation_run.Evidence(set(), object, AssertionError)
            missing.write(report, original, target)
            self.assertIn("pytest did not import the measured module from the copy", missing.errors.pop())

    def test_import_root_cannot_escape_its_copy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            copy = directory / "copy"
            copy.mkdir()
            original = directory / "original"
            original.mkdir()
            (copy / "src").symlink_to(original, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "import root escapes its copy"):
                pytest_mutation_run._import_path(copy, original, ["src"])


def load_tests(loader, standard_tests, _pattern):
    if importlib.util.find_spec("pytest") is not None:
        return standard_tests
    return unittest.TestSuite(
        loader.loadTestsFromTestCase(case) for case in (ReceiptTests, HookEvidenceTests)
    )
