"""An agent sandbox refuses every check that runs a whole test suite."""
from __future__ import annotations

import os
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from support import PYTHON_TEST_HEADER, FixtureCase, output
from test_python_crap import crap_config

from quality_gate import adapters, checks, cli, policy
from quality_gate.trust import Trust

AGENT = {"QG_AGENT": "1"}


def agent_config() -> str:
    """The CRAP fixture policy, plus a static check that leaves a marker."""
    return crap_config().replace(
        'checks = ["tests", "crap"]', 'checks = ["lint", "tests", "crap"]'
    ).replace(
        "[checks.tests]",
        '[checks.lint]\nadapter = "command"\ntier = 1\n'
        'enforcement = "enforced"\n'
        "run = [\"python3\", \"-c\", "
        "\"open('lint-ran', 'w').write('x'); print(1)\"]\n\n"
        "[checks.tests]",
        1,
    )


def passing_suite(context: adapters.AdapterContext) -> checks.CheckResult:
    """Supply a passing suite result without a tools cache."""
    return checks._check_result(
        context.check, time.monotonic(), "pass", measurement={"tests": 1}
    )


class AgentRefusalTests(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        (self.repo / "a.py").unlink()
        self.add_file("pkg/__init__.py", "")
        self.add_file(
            "quality-gate-crap.toml",
            'check = "crap"\nmetric_version = "python-lines/1"\n',
        )
        self.add_file(
            "tests/test_sample.py",
            PYTHON_TEST_HEADER
            + "pathlib.Path('tests-ran').write_text('x', encoding='utf-8')\n\n"
            "class Sample(unittest.TestCase):\n"
            "    def test_ok(self):\n"
            "        self.assertTrue(True)\n",
        )
        self.write_config(agent_config())

    def marker(self, name: str) -> bool:
        return (self.repo / name).exists()

    def test_a_full_check_is_refused_before_any_check_runs(self) -> None:
        result = self.run_qg("check", env=AGENT)
        self.assertEqual(result.returncode, 2, output(result))
        self.assertEqual(result.stdout, "")
        text = result.stderr
        self.assertEqual(len(text.splitlines()), 1, text)
        self.assertIn(
            "qg.py: check: refused inside an agent sandbox (QG_AGENT=1)", text
        )
        self.assertIn("crap (python_crap)", text)
        self.assertIn("tests (python_tests)", text)
        self.assertIn(
            "the runner's gate runs the test suites once per candidate and "
            "returns its log",
            text,
        )
        self.assertNotIn("check: inventory", text)
        self.assertFalse(self.marker("tests-ran"))
        self.assertFalse(self.marker("lint-ran"))

    def test_only_crap_names_the_tests_check_it_requires(self) -> None:
        result = self.run_qg("check", "--only", "crap", env=AGENT)
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("crap (python_crap)", text)
        self.assertIn("tests (python_tests)", text)
        self.assertNotIn("check: inventory", text)
        self.assertFalse(self.marker("tests-ran"))

    def test_the_message_ends_with_the_checks_that_may_run(self) -> None:
        result = self.run_qg("check", "--only", "crap", env=AGENT)
        text = output(result)
        self.assertIn(
            "run focused tests directly, or a static check with --only NAME; "
            "allowed here:",
            text,
        )
        allowed = text.split("allowed here:", 1)[1]
        self.assertIn("lint", allowed)
        self.assertNotIn("crap", allowed)
        self.assertNotIn("tests", allowed)

    def test_agent_refusal_none_allowed(self) -> None:
        self.write_config(crap_config())
        result = self.run_qg("check", env=AGENT)
        self.assertEqual(result.returncode, 2, output(result))
        self.assertTrue(
            result.stderr.rstrip().endswith("allowed here: none"), output(result)
        )

    def test_a_static_check_runs_alone_under_the_agent_variable(self) -> None:
        result = self.run_qg("check", "--only", "lint", env=AGENT)
        text = output(result)
        self.assertEqual(result.returncode, 0, text)
        self.assertIn("check: partial run passed", text)
        self.assertTrue(self.marker("lint-ran"))
        self.assertFalse(self.marker("tests-ran"))

    def test_a_json_run_writes_one_error_document_and_refuses(self) -> None:
        result, document = self.run_json(env=AGENT)
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn("refused inside an agent sandbox", document["error"])
        self.assertIn("crap (python_crap)", document["error"])
        self.assertEqual(document["decision"], "error")
        self.assertFalse(self.marker("tests-ran"))

    def test_a_trusted_policy_is_refused_too(self) -> None:
        self.commit_all()
        trusted = self.trusted_directory("HEAD")
        result = self.run_qg(
            "check", "--policy-from", str(trusted), env=AGENT
        )
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn(
            "qg.py: check: refused inside an agent sandbox (QG_AGENT=1)", text
        )
        self.assertFalse(self.marker("tests-ran"))

    def test_an_agent_refusal_closes_the_trusted_policy(self) -> None:
        self.commit_all()
        trusted = self.trusted_directory("HEAD")
        with mock.patch.object(
            Trust, "close", autospec=True, side_effect=Trust.close,
        ) as close:
            result = self.run_qg("check", "--policy-from", str(trusted), env=AGENT)
        self.assertEqual(result.returncode, 2, output(result))
        close.assert_called_once()

    def test_without_the_agent_variable_the_full_check_runs(self) -> None:
        environment = os.environ.copy()
        environment.pop("QG_AGENT", None)
        with mock.patch.dict(os.environ, environment, clear=True):
            self.assert_full_check_runs()

    def test_zero_keeps_the_full_check_running(self) -> None:
        self.assert_full_check_runs({"QG_AGENT": "0"})

    def assert_full_check_runs(self, env: dict[str, str] | None = None) -> None:
        tests_run = mock.Mock(side_effect=passing_suite)
        crap_run = mock.Mock(side_effect=passing_suite)
        with mock.patch.dict(adapters.ADAPTERS, {
            "python_tests": replace(adapters.ADAPTERS["python_tests"], run=tests_run),
            "python_crap": replace(adapters.ADAPTERS["python_crap"], run=crap_run),
        }):
            result = self.run_qg("check", env=env)
        text = output(result)
        self.assertEqual(result.returncode, 0, text)
        self.assertIn("check: passed", text)
        self.assertTrue(self.marker("lint-ran"))
        tests_run.assert_called_once()
        crap_run.assert_called_once()


class AgentHelperTests(unittest.TestCase):
    """The refusal helpers read the policy and the registry, and nothing else."""

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="qg-agent-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "quality-gate.toml").write_text(
            agent_config(), encoding="utf-8"
        )
        (self.root / "quality-gate-crap.toml").write_text(
            'check = "crap"\nmetric_version = "python-lines/1"\n',
            encoding="utf-8",
        )
        self.config = policy.load_config(self.root)

    def test_selected_checks_are_the_whole_policy_without_only(self) -> None:
        selected = cli._agent_selected_checks(self.config, None)
        self.assertEqual(
            [check.id for check in selected], ["lint", "tests", "crap"]
        )

    def test_selected_checks_include_what_an_only_id_requires(self) -> None:
        selected = cli._agent_selected_checks(self.config, ["crap"])
        self.assertEqual([check.id for check in selected], ["tests", "crap"])

    def test_the_refusal_names_the_refused_checks_and_the_allowed_ones(self) -> None:
        selected = cli._agent_selected_checks(self.config, ["crap"])
        message = cli._agent_refusal(self.config, selected)
        self.assertIn("crap (python_crap)", message)
        self.assertIn("tests (python_tests)", message)
        self.assertIn("allowed here: lint", message)

    def test_a_static_selection_is_not_refused(self) -> None:
        selected = cli._agent_selected_checks(self.config, ["lint"])
        self.assertIsNone(cli._agent_refusal(self.config, selected))

    def test_the_variable_refuses_only_the_value_one(self) -> None:
        selected = [self.config.checks["tests"]]
        with mock.patch.dict(
            os.environ, {"QG_AGENT": "1"}, clear=False
        ), mock.patch.object(
            cli, "_agent_selected_checks", return_value=selected
        ):
            with self.assertRaises(policy.UsageError) as raised:
                cli._refuse_in_agent_sandbox(self.config, None)
        self.assertIn("refused inside an agent sandbox", str(raised.exception))
        for value in ("0", "yes", ""):
            with self.subTest(value=value), mock.patch.dict(
                os.environ, {"QG_AGENT": value}, clear=False
            ):
                cli._refuse_in_agent_sandbox(self.config, None)


class SuiteAdapterRegistryTests(unittest.TestCase):
    def test_every_registered_adapter_declares_a_boolean_suite_flag(self) -> None:
        for name, descriptor in adapters.ADAPTERS.items():
            with self.subTest(adapter=name):
                self.assertIs(type(descriptor.runs_suite), bool)

    def test_agent_refusal_flag_required(self) -> None:
        command = adapters.ADAPTERS["command"]
        with mock.patch.dict(adapters.ADAPTERS), self.assertRaisesRegex(
            TypeError, "runs_suite"
        ):
            adapters.register_adapter(adapters.AdapterDescriptor(
                "missing-suite-flag", command.keys, command.parse, command.run,
            ))


if __name__ == "__main__":
    unittest.main()
