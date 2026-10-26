"""Tests for the python_tests adapter and its QG_PYTHON contract."""
from __future__ import annotations

import contextlib
import importlib
import io
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from support import (
    GATE,
    PYTHON_COMMON_RULE_LINES,
    PYTHON_TEST_HEADER,
    FixtureCase,
    output,
)

sys.path.insert(0, str(GATE))
checks = importlib.import_module("quality_gate.checks")
coverage_tool = importlib.import_module("quality_gate.coverage_tool")
covrun = importlib.import_module("quality_gate.covrun")
gate_tools = importlib.import_module("quality_gate.tools")
policy = importlib.import_module("quality_gate.policy")
python_tests = importlib.import_module("quality_gate.python_tests")
runner = importlib.import_module("quality_gate.runner")


def tests_config(
    *,
    run: str = '["{python}", "-m", "unittest", "discover", "-s", "tests"]',
    tests_pattern: str = r"^Ran (\d+) tests? in",
    skipped_pattern: str | None = None,
    budget: int | None = None,
) -> str:
    lines = [
        "schema = 2",
        "",
        "[code]",
        'patterns = ["*.py"]',
        'shebangs = ["python*"]',
        "",
        "[levels]",
        "required_tiers = [1]",
        "",
        "[classes.test]",
        "code = true",
        'description = "Python tests"',
        'checks = ["tests"]',
        "",
        "[classes.config]",
        "code = false",
        'description = "Configuration"',
        "",
        "[classes.doc]",
        "code = false",
        'description = "Documentation"',
        "",
        "[checks.tests]",
        'adapter = "python_tests"',
        "tier = 1",
        'enforcement = "enforced"',
        f"run = {run}",
        f"tests_pattern = {json.dumps(tests_pattern)}",
    ]
    if skipped_pattern is not None:
        lines.append(f"skipped_pattern = {json.dumps(skipped_pattern)}")
    if budget is not None:
        lines.append(f"budget_seconds = {budget}")
    lines.extend(
        [
            "",
            "[[rule]]",
            'pattern = "tests/*.py"',
            'class = "test"',
            'reason = "tests"',
        ]
    )
    lines.extend(PYTHON_COMMON_RULE_LINES)
    return "\n".join(lines)


class PythonTestsTests(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        (self.repo / "a.py").unlink()
        self.write_config(tests_config())

    def add_test(self, name: str, body: str) -> None:
        self.add_file(
            f"tests/{name}.py",
            PYTHON_TEST_HEADER + "\nclass Sample(unittest.TestCase):\n" + body,
        )

    def run_tests(
        self, *, env: dict[str, str] | None = None
    ) -> tuple[object, dict[str, object]]:
        return self.run_json(env=env or self.default_tool_env())

    def failed_tests(
        self, *needles: str
    ) -> tuple[object, dict[str, object]]:
        result, document = self.run_tests()
        self.assertEqual(result.returncode, 1, output(result))
        check = self.check_by_id(document, "tests")
        self.assertEqual(check["outcome"], "fail")
        for needle in needles:
            self.assertIn(needle, result.stderr)
        return result, check

    def unsupported_tests(
        self,
        *needles: str,
        env: dict[str, str] | None = None,
    ) -> tuple[object, dict[str, object]]:
        result, document = self.run_tests(env=env)
        self.assertEqual(result.returncode, 1, output(result))
        check = self.check_by_id(document, "tests")
        self.assertEqual(check["outcome"], "unsupported")
        self.assertIsInstance(check["reason"], str)
        for needle in needles:
            self.assertIn(needle, result.stderr)
        return result, check

    def test_tests_pass_and_report_the_count(self) -> None:
        self.add_test(
            "test_sample",
            "    def test_one(self):\n        self.assertTrue(True)\n\n"
            "    def test_two(self):\n        self.assertTrue(True)\n",
        )
        result, document = self.run_tests()
        self.assertEqual(result.returncode, 0, output(result))
        check = self.check_by_id(document, "tests")
        self.assertEqual(check["outcome"], "pass")
        self.assertEqual(check["execution"], "completed")
        self.assertEqual(check["measurement"], {"tests": 2})
        self.assertEqual(check["metric_version"], "test-count/1")
        self.assertIn("passed (2 tests", result.stderr)

    def test_zero_tests_fails(self) -> None:
        self.add_file("tests/helper.py", "VALUE = 1\n")
        self.failed_tests(
            "no test executed: 0 ran, 0 skipped",
            "zero tests is not a pass",
        )

    def test_all_skipped_tests_fail_as_no_test_executed(self) -> None:
        self.write_config(
            tests_config(skipped_pattern=r"skipped=(\d+)")
        )
        self.add_test(
            "test_skipped",
            "    @unittest.skip('deliberate')\n"
            "    def test_skipped(self):\n"
            "        self.assertTrue(True)\n",
        )
        self.failed_tests(
            "no test executed: 1 ran, 1 skipped",
            "zero tests is not a pass",
        )

    def test_ambiguous_test_summary_is_unsupported(self) -> None:
        self.add_file(
            "tests/summary.py",
            "print('Ran 1 test in 0.1s')\n"
            "print('Ran 2 tests in 0.2s')\n",
        )
        self.write_config(
            tests_config(run='["{python}", "tests/summary.py"]')
        )
        self.unsupported_tests("ambiguous test summary")

    def test_ambiguous_test_summary_on_failure_is_unsupported(self) -> None:
        self.add_file(
            "tests/failing_summary.py",
            "import sys\n"
            "print('Ran 1 test in 0.1s')\n"
            "print('Ran 2 tests in 0.2s')\n"
            "sys.exit(1)\n",
        )
        self.write_config(
            tests_config(run='["{python}", "tests/failing_summary.py"]')
        )
        self.unsupported_tests("ambiguous test summary")

    def test_failing_test_fails(self) -> None:
        self.add_test(
            "test_failure",
            "    def test_fails(self):\n        self.fail('deliberate')\n",
        )
        self.failed_tests("command exited 1", "deliberate")

    def test_failed_command_without_summary_has_no_measurement(self) -> None:
        self.add_file(
            "tests/failing.py",
            "import sys\nprint('no summary')\nsys.exit(1)\n",
        )
        self.write_config(
            tests_config(run='["{python}", "tests/failing.py"]')
        )
        _result, check = self.failed_tests("command exited 1", "no summary")
        self.assertNotIn("measurement", check)

    def test_failed_command_with_zero_executed_tests_reports_counts(self) -> None:
        self.add_file(
            "tests/failing.py",
            "import sys\n"
            "print('Ran 1 test in 0.1s')\n"
            "print('skipped=1')\n"
            "sys.exit(1)\n",
        )
        self.write_config(
            tests_config(
                run='["{python}", "tests/failing.py"]',
                skipped_pattern=r"skipped=(\d+)",
            )
        )
        _result, check = self.failed_tests(
            "command exited 1 and no test executed: 1 ran, 1 skipped",
            "zero tests is not a pass",
        )
        self.assertEqual(check["measurement"], {"tests": 0})

    def test_timeout_reports_budget(self) -> None:
        self.write_config(tests_config(budget=1))
        self.add_test(
            "test_slow",
            "    def test_slow(self):\n        import time\n"
            "        time.sleep(10)\n",
        )
        result, document = self.run_tests()
        self.assertEqual(result.returncode, 1, output(result))
        check = self.check_by_id(document, "tests")
        self.assertEqual(check["outcome"], "fail")
        self.assertEqual(check["execution"], "budget")
        self.assertEqual(check["budget_seconds"], 1)
        self.assertIn("exceeded its 1 second budget", result.stderr)

    def test_ambiguous_skipped_summary_is_unsupported(self) -> None:
        self.add_file(
            "tests/summary.py",
            "print('Ran 1 test in 0.1s')\n"
            "print('skipped=0')\n"
            "print('skipped=1')\n",
        )
        self.write_config(
            tests_config(
                run='["{python}", "tests/summary.py"]',
                skipped_pattern=r"skipped=(\d+)",
            )
        )
        self.unsupported_tests("ambiguous skipped summary")

    def test_negative_skipped_count_is_unsupported(self) -> None:
        self.add_file(
            "tests/summary.py",
            "print('Ran 1 test in 0.1s')\n"
            "print('skipped=-1')\n",
        )
        self.write_config(
            tests_config(
                run='["{python}", "tests/summary.py"]',
                skipped_pattern=r"skipped=(-?\d+)",
            )
        )
        self.unsupported_tests("not a test count")

    def test_a_child_that_exits_without_saving_is_unsupported(self) -> None:
        # The child registers before it runs and exits before coverage saves.

        self.add_file("tests/abrupt_child.py", "import os\nos._exit(0)\n")
        self.add_test(
            "test_abrupt",
            "    def test_abrupt(self):\n"
            "        import json\n"
            "        import os\n"
            "        import pathlib\n"
            "        import subprocess\n"
            "        prefix = json.loads(os.environ['QG_PYTHON'])\n"
            "        child = (pathlib.Path(__file__).resolve().parent\n"
            "                 / 'abrupt_child.py')\n"
            "        subprocess.run([*prefix, str(child)], check=True,\n"
            "                       env=os.environ.copy())\n"
        )
        _result, check = self.unsupported_tests("abrupt_child.py", "is missing")
        self.assertIn("coverage combination failed", check["reason"])

    def test_unmatched_tests_pattern_is_unsupported(self) -> None:
        self.write_config(tests_config(tests_pattern=r"NEVER (\d+)"))
        self.add_test(
            "test_sample",
            "    def test_one(self):\n        self.assertTrue(True)\n",
        )
        _result, check = self.unsupported_tests(
            "tests_pattern", "did not match"
        )
        self.assertIn("did not match", check["reason"])

    def test_missing_coverage_is_unsupported(self) -> None:
        self.add_test(
            "test_sample",
            "    def test_one(self):\n        self.assertTrue(True)\n",
        )
        result, check = self.unsupported_tests(
            "not installed",
            "tools fetch",
            env={"QG_TOOLS_DIR": str(self.base / "empty-tools")},
        )
        self.assertIn("not installed", check["reason"])

    def test_full_gate_leaves_the_coverage_install_byte_identical(self) -> None:
        source = coverage_tool.coverage_installation()
        tools = self.base / "tools"
        destination = tools / source.name
        shutil.copytree(source, destination, symlinks=True)
        self.fixture_gate()
        self.set_lock_field(
            "coverage",
            "payload_sha256",
            self.payload_digest(destination),
        )
        self.add_test(
            "test_sample",
            "    def test_one(self):\n        self.assertTrue(True)\n",
        )
        config = tests_config().replace(
            'checks = ["tests"]', 'checks = ["tests", "crap"]'
        )
        config += (
            "\n[checks.crap]\n"
            'adapter = "python_crap"\n'
            "tier = 1\n"
            'enforcement = "enforced"\n'
            'requires = "tests"\n'
            "threshold = 6\n"
            'baseline = "quality-gate-crap.toml"\n'
        )
        self.write_config(config)
        before = self.payload_digest(destination)
        result, document = self.run_json(
            env={"QG_TOOLS_DIR": str(tools)}
        )
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(self.payload_digest(destination), before)
        self.assertEqual(list(destination.rglob("__pycache__")), [])
        self.assertEqual(list(destination.rglob("*.pyc")), [])


class AuthorizedCoverageTests(FixtureCase):
    def test_an_authorized_lock_reaches_the_coverage_runner(self) -> None:
        (self.repo / "a.py").unlink()
        self.write_config(tests_config())
        self.add_file(
            "tests/test_sample.py",
            PYTHON_TEST_HEADER
            + "\nclass Sample(unittest.TestCase):\n"
            "    def test_one(self):\n"
            "        self.assertTrue(True)\n",
        )
        lock = (GATE / "tools.lock.toml").read_text(encoding="utf-8")
        self.add_file("tools.lock.toml", lock)
        self.commit_all()
        revision = self.git("rev-parse", "HEAD").stdout.strip()

        source = coverage_tool.coverage_installation()
        tools = self.base / "tools"
        destination = tools / source.name
        shutil.copytree(source, destination, symlinks=True)
        (destination / "authorized-upgrade.txt").write_text(
            "authorized\n", encoding="utf-8"
        )
        payload = self.payload_digest(destination)
        pinned = gate_tools.load_tools(GATE / "tools.lock.toml")["coverage"]
        self.assertNotEqual(payload, pinned.payload_sha256)
        changed = lock.replace(
            f'payload_sha256 = "{pinned.payload_sha256}"',
            f'payload_sha256 = "{payload}"',
        )
        self.assertNotEqual(changed, lock)
        self.add_file("tools.lock.toml", changed)

        result, document = self.run_json(
            "--policy-from",
            revision,
            "--allow-protected",
            "tools.lock.toml",
            env={"QG_TOOLS_DIR": str(tools)},
        )
        self.assertEqual(result.returncode, 0, output(result))
        check = self.check_by_id(document, "tests")
        self.assertEqual(check["outcome"], "pass")
        self.assertEqual(check["measurement"], {"tests": 1})


class CovrunTests(unittest.TestCase):
    def test_usage_and_missing_coverage_are_reported(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(covrun._run([]), 2)
        self.assertIn("expected DATA_DIR", stderr.getvalue())

        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing"
            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                code = covrun._run(
                    [
                        "covrun.py",
                        temporary,
                        temporary,
                        str(missing),
                        "7.16.2",
                        "0" * 64,
                        str(Path(temporary) / "config"),
                        str(Path(temporary) / "registry"),
                        "-c",
                        "pass",
                    ]
                )
            self.assertEqual(code, 2)
            self.assertIn("coverage is not installed", stderr.getvalue())

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="qg-covrun-")
        self.addCleanup(self._temporary.cleanup)
        self.base = Path(self._temporary.name)
        self.data_dir = self.base / "data"
        self.data_dir.mkdir()
        self.source_root = self.base / "root"
        self.source_root.mkdir()
        self.coverage_dir = coverage_tool.coverage_installation()
        self.coverage = gate_tools.load_tools(GATE / "tools.lock.toml")[
            "coverage"
        ]
        self.config_file = coverage_tool.write_coverage_config(
            self.data_dir, self.source_root
        )
        self.registry = coverage_tool.registry_dir(self.data_dir)
        self.runner = GATE / "quality_gate" / "covrun.py"

    def script(self, name: str, text: str) -> Path:
        path = self.source_root / name
        path.write_text(text, encoding="utf-8")
        return path

    def prefix_arguments(self, coverage_dir: Path) -> list[str]:
        return [
            str(coverage_dir),
            self.coverage.version,
            self.coverage.payload_sha256,
            str(self.config_file),
            str(self.registry),
        ]

    def tampered(self, name: str, sentinel_name: str) -> tuple[Path, Path, Path]:
        destination = self.base / name / self.coverage_dir.name
        shutil.copytree(self.coverage_dir, destination, symlinks=True)
        init = destination / "coverage" / "__init__.py"
        init.write_text(init.read_text() + "TAMPERED = 1\n", encoding="utf-8")
        sentinel = self.base / sentinel_name
        script = self.script(
            "probe.py",
            f"open({str(sentinel)!r}, 'w').write('ran\\n')\n",
        )
        return destination, sentinel, script

    def command(self, program: str, *arguments: str) -> list[str]:
        return [
            sys.executable,
            "-I",
            str(self.runner),
            str(self.data_dir),
            str(self.source_root),
            *self.prefix_arguments(self.coverage_dir),
            program,
            *arguments,
        ]

    def run_program(
        self, program: str, *arguments: str, cwd: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            self.command(program, *arguments),
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def registration(self) -> tuple[Path, dict[str, str]]:
        records = list(
            coverage_tool.registry_dir(self.data_dir).glob("*.json")
        )
        self.assertEqual(len(records), 1, records)
        document = json.loads(records[0].read_text(encoding="utf-8"))
        return records[0], document

    def combine(self) -> None:
        coverage_tool.combine_coverage(
            self.data_dir,
            self.base / "combined" / ".coverage",
            self.config_file,
        )

    def test_program_imports_its_own_quality_gate_package(self) -> None:
        package = self.source_root / "quality_gate"
        package.mkdir()
        (package / "__init__.py").write_text("", encoding="utf-8")
        candidate = package / "candidate.py"
        candidate.write_text(
            "def candidate_only():\n    return 'candidate'\n",
            encoding="utf-8",
        )
        script = self.script(
            "prog.py",
            "import pathlib\n"
            "import sys\n"
            "sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))\n"
            "from quality_gate.candidate import candidate_only\n"
            "assert candidate_only() == 'candidate'\n",
        )
        result = self.run_program(str(script), cwd=self.base)
        self.assertEqual(result.returncode, 0, output(result))
        self.combine()
        coverage = coverage_tool.import_coverage()
        data = coverage.CoverageData(str(self.base / "combined" / ".coverage"))
        data.read()
        self.assertIn(2, data.lines(str(candidate)) or [])

    def start(self, program: str) -> subprocess.Popen[str]:
        return subprocess.Popen(
            self.command(program),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def read_ready(self, process: subprocess.Popen[str]) -> None:
        assert process.stdout is not None
        self.assertEqual(process.stdout.readline(), "ready\n")

    def finish(
        self, process: subprocess.Popen[str], *, kill: bool
    ) -> int:
        if kill:
            process.kill()
        else:
            process.terminate()
        try:
            return process.wait(timeout=60)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            process.communicate()

    def test_run_wires_the_gate_configuration_before_execution(self) -> None:
        calls: list[list[str]] = []

        def fake_main(arguments: list[str]) -> int:
            calls.append(arguments)
            for argument in arguments:
                if argument.startswith("--data-file="):
                    Path(argument.split("=", 1)[1]).write_text(
                        "data", encoding="utf-8"
                    )
            return 7

        with mock.patch.dict(
            os.environ, {"COVERAGE_TEST_OVERRIDE": "1"}
        ), mock.patch.object(
            covrun, "_coverage_main", return_value=(fake_main, None)
        ), mock.patch.object(sys, "path", list(sys.path)):
            code = covrun._run(
                [
                    "covrun.py",
                    str(self.data_dir),
                    str(self.source_root),
                    *self.prefix_arguments(self.coverage_dir),
                    "prog.py",
                    "--secret",
                ]
            )
        self.assertEqual(code, 7)
        self.assertNotIn("COVERAGE_TEST_OVERRIDE", os.environ)
        self.assertEqual(calls[0][0], "run")
        self.assertNotIn("--parallel-mode", calls[0])
        self.assertIn(f"--rcfile={self.config_file}", calls[0])
        self.assertEqual(calls[0][-1], "--secret")
        record, document = self.registration()
        self.assertEqual(document["program"], "prog.py")
        self.assertNotIn("--secret", record.read_text(encoding="utf-8"))

    def test_keyboard_interrupt_still_counts(self) -> None:
        script = self.script("prog.py", "x = 1\nraise KeyboardInterrupt\n")
        result = self.run_program(str(script))
        self.assertEqual(result.returncode, -signal.SIGINT, output(result))
        self.assertIn("KeyboardInterrupt", result.stderr)
        _record, document = self.registration()
        self.assertEqual(document["program"], str(script))
        self.assertTrue((self.data_dir / document["dataset"]).is_file())
        self.combine()
        self.assertTrue((self.base / "combined" / ".coverage").is_file())

    def test_sigterm_saves_without_changing_the_signal_status(self) -> None:
        script = self.script(
            "prog.py",
            "import time\nprint('ready', flush=True)\ntime.sleep(60)\n",
        )
        process = self.start(str(script))
        self.read_ready(process)
        self.assertEqual(
            self.finish(process, kill=False), -signal.SIGTERM
        )
        _record, document = self.registration()
        self.assertTrue((self.data_dir / document["dataset"]).is_file())
        self.combine()

    def test_sigkill_before_the_dataset_is_saved_is_unsupported(self) -> None:
        script = self.script(
            "prog.py",
            "import time\nprint('ready', flush=True)\ntime.sleep(60)\n",
        )
        process = self.start(str(script))
        self.read_ready(process)
        self.assertEqual(
            self.finish(process, kill=True), -signal.SIGKILL
        )
        record, document = self.registration()
        with self.assertRaises(policy.UnsupportedError) as raised:
            self.combine()
        message = str(raised.exception)
        self.assertIn(record.stem, message)
        self.assertIn(str(script), message)
        self.assertIn(document["dataset"], message)

    def test_run_refuses_tampered_coverage_before_it_is_imported(self) -> None:
        destination, sentinel, script = self.tampered(
            "tampered-run", "ran-in-process"
        )
        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            code = covrun._run(
                [
                    "covrun.py",
                    str(self.data_dir),
                    str(self.source_root),
                    *self.prefix_arguments(destination),
                    str(script),
                ]
            )
        self.assertEqual(code, 2)
        self.assertIn("payload digest mismatch", stderr.getvalue())
        self.assertIn(str(destination), stderr.getvalue())
        self.assertFalse(sentinel.exists())

    def test_tampered_coverage_is_refused_before_it_is_imported(self) -> None:
        destination, sentinel, script = self.tampered("tampered-tools", "ran")
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                str(self.runner),
                str(self.data_dir),
                str(self.source_root),
                *self.prefix_arguments(destination),
                str(script),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn("payload digest mismatch", result.stderr)
        self.assertIn(str(destination), result.stderr)
        self.assertFalse(sentinel.exists())

    def test_registration_names_the_program_without_its_arguments(
        self,
    ) -> None:
        script = self.script("prog.py", "print('done')\n")
        result = self.run_program(str(script), "--secret", "value")
        self.assertEqual(result.returncode, 0, output(result))
        record, document = self.registration()
        self.assertEqual(document["program"], str(script))
        self.assertTrue((self.data_dir / document["dataset"]).is_file())
        self.assertNotIn("--secret", record.read_text(encoding="utf-8"))

    def test_registration_names_a_module_command(self) -> None:
        self.assertEqual(
            covrun._program(["-m", "prog", "--secret"]), "-m prog"
        )
        self.assertEqual(covrun._program(["prog.py", "--secret"]), "prog.py")


class CoverageRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="qg-registry-")
        self.addCleanup(self._temporary.cleanup)
        self.data_dir = Path(self._temporary.name) / "data"
        self.data_dir.mkdir()
        coverage_tool.write_coverage_config(self.data_dir, self.data_dir)
        self.registry = coverage_tool.registry_dir(self.data_dir)
        self.registry.mkdir()

    def record(
        self,
        *,
        dataset: str = ".coverage.abc",
        program: str = "prog.py",
        text: str | None = None,
    ) -> Path:
        path = self.registry / "abc.json"
        path.write_text(
            text
            if text is not None
            else json.dumps({"dataset": dataset, "program": program}),
            encoding="utf-8",
        )
        return path

    def combine(self) -> None:
        coverage_tool.combine_coverage(
            self.data_dir,
            self.data_dir / "combined" / ".coverage",
            coverage_tool.coverage_config_path(self.data_dir),
        )

    def test_no_registration_is_unsupported(self) -> None:
        with self.assertRaises(policy.UnsupportedError) as raised:
            self.combine()
        self.assertIn("no coverage invocation registered", str(raised.exception))

    def test_missing_dataset_names_the_invocation_program_and_dataset(
        self,
    ) -> None:
        record = self.record()
        with self.assertRaises(policy.UnsupportedError) as raised:
            self.combine()
        message = str(raised.exception)
        self.assertIn(record.stem, message)
        self.assertIn("prog.py", message)
        self.assertIn(".coverage.abc", message)
        self.assertIn("is missing", message)

    def test_a_record_without_a_dataset_is_unsupported(self) -> None:
        record = self.record(text=json.dumps({"program": "prog.py"}))
        with self.assertRaises(policy.UnsupportedError) as raised:
            self.combine()
        message = str(raised.exception)
        self.assertIn("no usable dataset", message)
        self.assertIn(str(record), message)

    def test_unsafe_dataset_names_are_unsupported(self) -> None:
        for name in ("../x", "/absolute/.coverage", ""):
            with self.subTest(name=name):
                record = self.record(dataset=name)
                with self.assertRaises(policy.UnsupportedError) as raised:
                    self.combine()
                message = str(raised.exception)
                self.assertIn("unsafe dataset", message)
                self.assertIn(str(record), message)

    def test_truncated_record_is_unsupported_with_its_path(self) -> None:
        record = self.record(text='{"dataset": ".coverage.abc"')
        with self.assertRaises(policy.UnsupportedError) as raised:
            self.combine()
        message = str(raised.exception)
        self.assertIn("is unreadable", message)
        self.assertIn(str(record), message)

    def test_corrupt_dataset_names_the_invocation_program_and_dataset(
        self,
    ) -> None:
        record = self.record()
        (self.data_dir / ".coverage.abc").write_text(
            "garbage", encoding="utf-8"
        )
        with self.assertRaises(policy.UnsupportedError) as raised:
            self.combine()
        message = str(raised.exception)
        self.assertIn("corrupt", message)
        self.assertIn(record.stem, message)
        self.assertIn("prog.py", message)
        self.assertIn(".coverage.abc", message)


class CoverageDeadlineTests(unittest.TestCase):
    def test_a_combination_after_the_deadline_reports_budget(self) -> None:
        spec = policy.PythonTestsSpec(
            run=(),
            tests_pattern="",
            tests_pattern_re=re.compile(""),
            skipped_pattern=None,
            skipped_pattern_re=None,
            budget_seconds=1,
        )
        check = policy.CheckDef(
            id="tests",
            adapter="python_tests",
            tier=1,
            enforcement="enforced",
            metric_version="test-count/1",
            evidence=("tests",),
            command=None,
            clones=None,
            python_tests=spec,
            python_crap=None,
            threshold=None,
            baseline=None,
        )
        result = checks._combine_tests_evidence(
            check,
            spec,
            0.0,
            "check: tests",
            Path("/nonexistent-data"),
            Path("combined"),
            Path("config"),
            runner.Diagnostics(),
            0.0,
        )
        assert result is not None
        self.assertEqual(result.execution, "budget")
        self.assertEqual(result.outcome, "fail")
        self.assertIn("coverage combination exceeded", result.reason)


class TestSummaryTests(unittest.TestCase):
    def spec(
        self,
        tests_pattern: str = r"^Ran ([0-9]+) tests? in",
        skipped_pattern: str | None = r"skipped=([0-9]+)",
    ) -> policy.PythonTestsSpec:
        return policy.PythonTestsSpec(
            run=(),
            tests_pattern=tests_pattern,
            tests_pattern_re=re.compile(tests_pattern, re.MULTILINE),
            skipped_pattern=skipped_pattern,
            skipped_pattern_re=(
                re.compile(skipped_pattern, re.MULTILINE)
                if skipped_pattern is not None
                else None
            ),
            budget_seconds=600,
        )

    def test_count_subtracts_skipped_and_reports_summary_errors(self) -> None:
        count, error = python_tests.parse_test_count(
            self.spec(), "Ran 3 tests in 0.01s\nskipped=1"
        )
        self.assertEqual((count, error), (2, None))
        count, error = python_tests.parse_test_count(
            self.spec(), "no summary"
        )
        self.assertIsNone(count)
        self.assertIn("did not match", error)

    def test_non_integer_counts_are_rejected(self) -> None:
        ran, skipped, error = python_tests.parse_test_summary(
            self.spec(tests_pattern=r"^Ran ([A-Za-z]+) tests? in"),
            "Ran many tests in 0.01s",
        )
        self.assertEqual((ran, skipped), (None, None))
        self.assertIn("tests_pattern", error)
        self.assertIn("not a test count", error)

        ran, skipped, error = python_tests.parse_test_summary(
            self.spec(skipped_pattern=r"skipped=([A-Za-z]+)"),
            "Ran 1 test in 0.01s\nskipped=many",
        )
        self.assertEqual((ran, skipped), (None, None))
        self.assertIn("skipped_pattern", error)
        self.assertIn("not a test count", error)

    def test_ambiguous_skipped_summary_is_rejected(self) -> None:
        ran, skipped, error = python_tests.parse_test_summary(
            self.spec(), "Ran 2 tests in 0.1s\nskipped=0\nskipped=1"
        )
        self.assertEqual((ran, skipped), (None, None))
        self.assertIn("ambiguous skipped summary", error)

    def test_negative_counts_are_rejected(self) -> None:
        ran, skipped, error = python_tests.parse_test_summary(
            self.spec(skipped_pattern=r"skipped=(-?[0-9]+)"),
            "Ran 2 tests in 0.1s\nskipped=-1",
        )
        self.assertEqual((ran, skipped), (None, None))
        self.assertIn("not a test count", error)
        ran, skipped, error = python_tests.parse_test_summary(
            self.spec(tests_pattern=r"^Ran (-?[0-9]+) tests? in"),
            "Ran -1 test in 0.1s",
        )
        self.assertEqual((ran, skipped), (None, None))
        self.assertIn("not a test count", error)

    def test_an_absent_optional_capture_is_zero(self) -> None:
        ran, skipped, error = python_tests.parse_test_summary(
            self.spec(skipped_pattern=r"skipped(?:=([0-9]+))?"),
            "Ran 1 test in 0.1s\nskipped",
        )
        self.assertEqual((ran, skipped, error), (1, 0, None))

    def test_more_skipped_than_ran_is_rejected(self) -> None:
        ran, skipped, error = python_tests.parse_test_summary(
            self.spec(), "Ran 1 test in 0.01s\nskipped=2"
        )
        self.assertEqual((ran, skipped), (None, None))
        self.assertEqual(error, "skipped 2 tests but only 1 ran")


if __name__ == "__main__":
    unittest.main()
