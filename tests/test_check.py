"""Tests for the combined check command and CLI wiring."""
from __future__ import annotations

import contextlib
import importlib
import io
import json
import signal
import sys
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from support import (
    BASE_CONFIG,
    GATE,
    FixtureCase,
    output,
    sarif_report,
    stub_check_result,
    with_clones,
)

sys.path.insert(0, str(GATE))
adapters = importlib.import_module("quality_gate.adapters")
checks = importlib.import_module("quality_gate.checks")
cli = importlib.import_module("quality_gate.cli")
policy = importlib.import_module("quality_gate.policy")
runner = importlib.import_module("quality_gate.runner")


class _SleepSpec:
    def __init__(self, sleep_seconds: int, budget_seconds: int) -> None:
        self.sleep_seconds = sleep_seconds
        self.budget_seconds = budget_seconds


def _parse_sleep(raw, root, path, full_key):
    return adapters.ParsedSpec(
        _SleepSpec(
            policy._integer(raw, "sleep_seconds", path, f"{full_key}.sleep_seconds"),
            policy._integer(raw, "budget_seconds", path, f"{full_key}.budget_seconds"),
        ),
        "sleep/1",
        ("tests",),
    )


def _run_sleep(context):
    check = context.check
    time.sleep(check.spec.sleep_seconds)
    return stub_check_result(
        check,
        check.spec.budget_seconds,
        measurement={"tests": 1},
        tests_ran=1,
        tests_skipped=0,
    )


SLEEP_STUB = adapters.AdapterDescriptor(
    "sleep-stub",
    ("sleep_seconds", "budget_seconds"),
    _parse_sleep,
    _run_sleep,
    budget=lambda spec: spec.budget_seconds,
)


def _parse_requires(raw, root, path, full_key):
    required = policy._string(raw, "requires", path, f"{full_key}.requires")
    return adapters.ParsedSpec(
        SimpleNamespace(requires=required), "requires/1", ("static",),
        requires=required,
    )


def _run_requires(context):
    return stub_check_result(context.check, 60)


REQUIRES_STUB = adapters.AdapterDescriptor(
    "requires-stub", ("requires",), _parse_requires, _run_requires,
)


def _two_check_config(lint_run: str = '["python3", "-c", "print(1)"]') -> str:
    return BASE_CONFIG.replace(
        'checks = ["smoke"]', 'checks = ["smoke", "lint"]'
    ) + (
        '\n[checks.lint]\nadapter = "command"\ntier = 1\n'
        'enforcement = "enforced"\n'
        f"run = {lint_run}\n"
        "tests_pattern = '(\\d+)'\n"
    )


def _prerequisite_config() -> str:
    return BASE_CONFIG.replace(
        'checks = ["smoke"]', 'checks = ["tests", "verify"]'
    ) + (
        '\n[checks.tests]\nadapter = "command"\ntier = 1\n'
        'enforcement = "enforced"\n'
        'run = ["python3", "-c", "print(1)"]\n'
        "tests_pattern = '(\\d+)'\n\n"
        '[checks.verify]\nadapter = "requires-stub"\ntier = 1\n'
        'enforcement = "enforced"\nrequires = "tests"\n'
    )


def _sleep_config(entries):
    names = ", ".join(json.dumps(name) for name, _sleep, _budget in entries)
    lines = [
        "schema = 2",
        "",
        "[code]",
        'patterns = ["*.py", "*.sh", "*.el"]',
        'shebangs = ["sh", "bash", "python*"]',
        "",
        "[levels]",
        "required_tiers = [1]",
        "",
        "[classes.python]",
        "code = true",
        'description = "Python source"',
        f"checks = [{names}]",
        "",
        "[classes.doc]",
        "code = false",
        'description = "Documentation"',
        "",
        "[classes.config]",
        "code = false",
        'description = "Configuration"',
        "",
        "[[rule]]",
        'pattern = "*.py"',
        'class = "python"',
        'reason = "Python source"',
        "",
        "[[rule]]",
        'pattern = "*.md"',
        'class = "doc"',
        'reason = "Documentation"',
        "",
        "[[rule]]",
        'pattern = "*.toml"',
        'class = "config"',
        'reason = "Configuration"',
        "",
        "[[rule]]",
        'pattern = ".gitignore"',
        'class = "config"',
        'reason = "Ignore rules"',
        "",
    ]
    for name, sleep, budget in entries:
        lines.extend([
            f"[checks.{name}]",
            'adapter = "sleep-stub"',
            "tier = 1",
            'enforcement = "enforced"',
            f"sleep_seconds = {sleep}",
            f"budget_seconds = {budget}",
            "",
        ])
    return "\n".join(lines)


class CheckTests(FixtureCase):
    def test_retired_clones_command_is_rejected(self) -> None:
        for args in (("clones",), ("clones", "--prune")):
            with self.subTest(args=args):
                result = self.run_qg(*args)
                self.assertEqual(result.returncode, 2, output(result))
                self.assertIn("invalid choice: 'clones'", result.stderr)

    def test_retired_option_is_rejected(self) -> None:
        result = self.run_qg("check", "--reuse-store", str(self.base / "store"))
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn("unrecognized arguments", result.stderr)
        self.assertIn("--reuse-store", result.stderr)

    def test_checks_run_again_on_each_invocation(self) -> None:
        marker = self.base / "runs"
        code = f"open({str(marker)!r}, 'a').write('x'); print(1)"
        command = json.dumps([sys.executable, "-I", "-c", code])
        self.write_config(BASE_CONFIG.replace('["python3", "-c", "print(1)"]', command))
        for _ in range(2):
            result = self.run_qg("check")
            self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(marker.read_text(encoding="utf-8"), "xx")

    def test_prune_exit_rejects_refusal_even_when_the_gate_was_accepted(self) -> None:
        self.assertEqual(checks._decision_exit_code("accepted", "clones", {"performed": False}), 1)
        self.assertEqual(checks._decision_exit_code("accepted", "clones", {"performed": True}), 0)

    def test_check_runs_inventory_and_hygiene(self) -> None:
        result = self.run_qg("check")
        text = output(result)
        self.assertEqual(result.returncode, 0, text)
        self.assertIn("check: inventory", text)
        self.assertIn("inventory: 4 files match 4 rules", text)
        self.assertIn("check: hygiene", text)
        self.assertIn("hygiene: 4 files within 10485760 bytes", text)
        self.assertIn("check: smoke (command)", text)
        self.assertIn("check: passed (3 checks)", text)

    def test_check_reports_inventory_failure_and_still_runs_hygiene(self) -> None:
        self.add_file("mystery.txt", "x\n")
        result = self.run_qg("check")
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertIn("inventory: mystery.txt", text)
        self.assertIn("hygiene: 5 files within", text)
        self.assertIn("skipped because inventory failed", text)
        self.assertIn("check: failed (inventory, smoke, obligation python tier 1)", text)

    def test_check_reports_hygiene_failure(self) -> None:
        self.write_config(
            BASE_CONFIG.replace(
                "[classes.python]",
                "[hygiene]\nmax_bytes = 10\n\n[classes.python]",
            )
        )
        result = self.run_qg("check")
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertIn("inventory: 4 files match 4 rules", text)
        self.assertIn("exceeds max_bytes 10", text)
        self.assertIn("check: failed (hygiene)", text)

    def test_check_runs_clones_when_configured(self) -> None:
        self.write_config(with_clones())
        env = self.install_fake_jscpd(sarif_report([]))
        result = self.run_qg("check", env=env)
        text = output(result)
        self.assertEqual(result.returncode, 0, text)
        self.assertIn("check: clones (clones)", text)
        self.assertIn("check: clones: 0 clones", text)
        self.assertIn("check: passed (4 checks)", text)

    def check_failure(self, env: dict[str, str], *needles: str) -> None:
        result = self.run_qg("check", env=env)
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        for needle in needles:
            self.assertIn(needle, text)

    def test_check_reports_clone_failure(self) -> None:
        self.write_config(with_clones())
        env = self.install_fake_jscpd(
            sarif_report([("fp1", [("a.py", 1, 8), ("b.py", 1, 8)])])
        )
        self.add_file("b.py", "print('b')\n")
        self.check_failure(env, "new clone fp1", "check: failed (clones)")

    def test_check_reports_missing_tool(self) -> None:
        self.write_config(with_clones())
        env = {"QG_TOOLS_DIR": str(self.base / "empty-tools")}
        self.check_failure(env, "tools fetch", "check: failed (clones)")

    def test_check_reports_enumeration_failure(self) -> None:
        env = self.fake_git_failing_ls_files()
        result = self.run_qg("check", env=env)
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertIn("file enumeration failed", text)
        self.assertIn("check: failed (inventory, hygiene, smoke, obligation python tier 1)", text)

    def test_check_with_missing_config_exits_2(self) -> None:
        self.config_path.unlink()
        result = self.run_qg("check")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("quality-gate.toml", text)

    def test_failed_builtin_carries_the_structured_reason(self) -> None:
        self.add_file("mystery.txt", "x\n")
        _result, document = self.run_json()
        inventory = self.check_by_id(document, "inventory")
        self.assertEqual(inventory["outcome"], "fail")
        self.assertIn("unclassified", inventory["reason"])
        self.assertNotIn("selected", document)

    def test_in_process_diagnostics_keep_the_last_four_kib(self) -> None:
        messages = [f"{index:04d} " + "x" * 100 for index in range(100)]
        diagnostics = checks._tail_diagnostics(
            messages, argv=None, exit_code=1
        )
        self.assertTrue(diagnostics.output_truncated)
        self.assertLessEqual(
            len(diagnostics.output_tail.encode("utf-8")), 4096
        )
        self.assertTrue(diagnostics.output_tail.endswith("x" * 100))

    def test_check_skips_clones_when_inventory_fails(self) -> None:
        self.add_file("mystery.txt", "x\n")
        self.write_config(with_clones())
        env = {"QG_TOOLS_DIR": str(self.base / "empty-tools")}
        self.check_failure(
            env,
            "check: clones: skipped because inventory failed",
            "check: failed (inventory, smoke, clones, obligation python tier 1)",
        )


class PartialRunTests(FixtureCase):
    def test_only_runs_inventory_hygiene_and_the_named_check(self) -> None:
        self.write_config(_two_check_config())
        result, document = self.run_json("--only", "smoke")
        text = output(result)
        self.assertEqual(result.returncode, 0, text)
        self.assertIn("check: inventory", text)
        self.assertIn("check: hygiene", text)
        self.assertIn("check: smoke (command)", text)
        self.assertNotIn("check: lint (command)", text)
        self.assertEqual(document["decision"], "partial")
        self.assertEqual(document["selected"], ["smoke"])
        self.assertEqual(document["obligations"], [])
        self.assertIn("check: partial run passed (3 checks)", text)

    def test_a_selected_failing_check_is_rejected(self) -> None:
        self.write_config(
            _two_check_config('["python3", "-c", "raise SystemExit(1)"]')
        )
        result, document = self.run_json("--only", "lint")
        text = output(result)
        self.assertEqual(result.returncode, 1, text)
        self.assertEqual(document["decision"], "rejected")
        self.assertEqual(document["selected"], ["lint"])
        self.assertEqual(document["obligations"], [])

    def test_a_selected_check_runs_its_prerequisite_first(self) -> None:
        self.write_config(_prerequisite_config())
        with mock.patch.dict(adapters.ADAPTERS, {REQUIRES_STUB.name: REQUIRES_STUB}):
            result, document = self.run_json("--only", "verify")
        text = output(result)
        self.assertEqual(result.returncode, 0, text)
        self.assertIn("check: tests (command)", text)
        self.assertIn("check: verify (requires-stub)", text)
        self.assertLess(
            text.index("check: tests (command)"),
            text.index("check: verify (requires-stub)"),
        )
        self.assertEqual(document["decision"], "partial")
        self.assertEqual(document["selected"], ["tests", "verify"])


class PartialRunArgumentTests(FixtureCase):
    def test_unknown_check_id_exits_two_before_any_check(self) -> None:
        self.write_config(_two_check_config())
        result = self.run_qg("check", "--only", "nope")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("unknown check 'nope'", text)
        self.assertNotIn("check: inventory", text)

    def test_repeated_check_id_exits_two_before_any_check(self) -> None:
        self.write_config(_two_check_config())
        result = self.run_qg("check", "--only", "smoke", "smoke")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("duplicate check id 'smoke'", text)
        self.assertNotIn("check: inventory", text)

    def test_only_with_prune_exits_two_before_any_check(self) -> None:
        self.write_config(_two_check_config())
        result = self.run_qg("check", "--only", "smoke", "--prune", "smoke")
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("--only", text)
        self.assertIn("--prune", text)
        self.assertNotIn("check: inventory", text)

    def test_only_with_policy_from_exits_two_before_any_check(self) -> None:
        self.write_config(_two_check_config())
        self.commit_all()
        trusted = self.trusted_directory("HEAD")
        result = self.run_qg(
            "check", "--only", "smoke", "--policy-from", str(trusted)
        )
        text = output(result)
        self.assertEqual(result.returncode, 2, text)
        self.assertIn("--only", text)
        self.assertIn("--policy-from", text)
        self.assertNotIn("check: inventory", text)


class EvidenceCleanupTests(FixtureCase):
    def definition(self, identifier, requires=None):
        return policy.CheckDef(
            identifier, "fixture", 1, "enforced", "fixture/1", ("tests",),
            SimpleNamespace(requires=requires), None, None,
        )

    def result(self, context, temporary=None):
        return checks.CheckResult(
            context.check.id, "check", 1, "enforced", "fixture", ("tests",),
            "fixture/1", "pass", "completed", 0.0, 60,
            temporary=temporary,
        )

    def produce(self, context):
        temporary = context.temporary_directory(prefix="qg-evidence-", dir=self.base)
        self.evidence = Path(temporary.name) / "evidence.txt"
        self.evidence.write_text("evidence", encoding="utf-8")
        return self.result(context, temporary)

    def run_checks(self, definitions, adapter, *, implicit_tests=False):
        config = SimpleNamespace(checks={check.id: check for check in definitions})
        descriptor = SimpleNamespace(run=adapter, budget=lambda spec: 60, requires_tests=implicit_tests)
        with mock.patch.object(checks, "_check_descriptor", return_value=descriptor), \
                contextlib.redirect_stdout(io.StringIO()):
            return checks._run_policy_checks(self.repo, config, [], {}, 0)

    def assert_removed(self):
        self.assertFalse(self.evidence.parent.exists(), str(self.evidence.parent))

    def test_evidence_lasts_through_all_consumers_and_is_removed_before_the_next_check(self):
        definitions = [self.definition("producer"), self.definition("first", "producer"),
                       self.definition("gap"), self.definition("last", "producer"),
                       self.definition("unrelated")]

        def adapter(context):
            if context.check.id == "producer":
                return self.produce(context)
            if context.check.id == "unrelated":
                self.assert_removed()
            else:
                self.assertEqual(self.evidence.read_text(encoding="utf-8"), "evidence")
            return self.result(context)

        results = self.run_checks(definitions, adapter)
        self.assert_removed()
        self.assertIsNone(results[0].temporary)

    def test_evidence_with_no_consumers_is_removed_immediately(self):
        def adapter(context):
            if context.check.id == "producer":
                return self.produce(context)
            self.assert_removed()
            return self.result(context)

        self.run_checks([self.definition("producer"), self.definition("unrelated")], adapter)

    def test_an_implicit_test_dependency_keeps_evidence_until_the_consumer_finishes(self):
        def adapter(context):
            if context.check.id == "producer":
                return self.produce(context)
            self.assertEqual(self.evidence.read_text(encoding="utf-8"), "evidence")
            return self.result(context)

        self.run_checks([self.definition("producer"), self.definition("consumer")], adapter,
                        implicit_tests=True)
        self.assert_removed()

    def test_later_error_removes_evidence_waiting_for_a_consumer(self):
        def adapter(context):
            if context.check.id == "producer":
                return self.produce(context)
            self.assertTrue(self.evidence.exists())
            raise policy.GateError("later check failed")

        definitions = [self.definition("producer"), self.definition("error"),
                       self.definition("consumer", "producer")]
        with self.assertRaisesRegex(policy.GateError, "later check failed"):
            self.run_checks(definitions, adapter)
        self.assert_removed()

    def test_error_before_an_adapter_returns_still_removes_its_directory(self):
        def adapter(context):
            self.produce(context)
            raise policy.GateError("producer failed")

        with self.assertRaisesRegex(policy.GateError, "producer failed"):
            self.run_checks([self.definition("producer")], adapter)
        self.assert_removed()

    def assert_cleanup_failure_survives(self, ending):
        def adapter(context):
            result = self.produce(context)
            self.addCleanup(result.temporary.cleanup)
            result.temporary.cleanup = mock.Mock(side_effect=PermissionError("cleanup denied"))
            result.diagnostics = runner.Diagnostics(
                argv=["fixture"], exit_code=1, output_bytes=15,
                output_tail="fixture output", error="original diagnostic",
            )
            if ending == "failure":
                result.outcome = "fail"
            return result

        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            results = self.run_checks([self.definition("producer")], adapter)
        document = results[0].to_json()
        diagnostic = document["diagnostics"]["error"]
        message = f"cannot remove evidence directory {self.evidence.parent}: cleanup denied"
        self.assertIn(message, diagnostic)
        self.assertEqual(diagnostic.count(message), 1)
        self.assertIn(message, stderr.getvalue())
        self.assertTrue(self.evidence.parent.is_dir())
        expected = {
            "success": ("pass", "completed"),
            "failure": ("fail", "completed"),
        }
        self.assertEqual((document["outcome"], document["execution"]), expected[ending])
        self.assertIn("original diagnostic", diagnostic)
        self.assertEqual(document["diagnostics"]["argv"], ["fixture"])
        self.assertEqual(document["diagnostics"]["exit_code"], 1)
        self.assertEqual(document["diagnostics"]["output_tail"], "fixture output")

    def test_cleanup_failure_preserves_completed_outcomes_and_diagnostics(self):
        for ending in ("success", "failure"):
            with self.subTest(ending=ending):
                self.assert_cleanup_failure_survives(ending)

    def test_cleanup_failure_is_reported_and_other_directories_are_still_removed(self):
        paths = []

        def adapter(context):
            result = self.produce(context)
            paths.append(self.evidence.parent)
            if context.check.id == "producer":
                self.addCleanup(result.temporary.cleanup)
                result.temporary.cleanup = mock.Mock(side_effect=OSError("denied"))
                result.diagnostics.error = "original diagnostic"
            return result

        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            results = self.run_checks([self.definition("producer"), self.definition("other")], adapter)
        message = f"cannot remove evidence directory {paths[0]}: denied"
        self.assertIn(message, stderr.getvalue())
        self.assertIn(message, results[0].diagnostics.error)
        self.assertIn("original diagnostic", results[0].diagnostics.error)
        self.assertTrue(paths[0].is_dir())
        self.assertFalse(paths[1].exists())


class RunLimitTests(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        adapters.register_adapter(SLEEP_STUB)
        self.addCleanup(adapters.remove_adapter, SLEEP_STUB.name)

    def run_cli(self, *args: str) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(["--repo", str(self.repo), *args])
        return code, stdout.getvalue(), stderr.getvalue()

    def assert_run_limit(self, entries, limit, step, allowance) -> None:
        self.write_config(_sleep_config(entries))
        started = time.monotonic()
        with mock.patch.object(checks, "RUN_ALLOWANCE_SECONDS", allowance):
            code, _stdout, stderr = self.run_cli("check")
        self.assertEqual(code, 2, stderr)
        self.assertLess(time.monotonic() - started, 10)
        self.assertIn(f"{limit} s limit", stderr)
        self.assertIn(f"during {step}: check setup", stderr)

    def test_a_sleeping_check_ends_the_run_with_exit_two(self) -> None:
        self.assert_run_limit([("sleep", 30, 1)], 1, "sleep", 0)

    def test_a_run_timeout_writes_an_error_document(self) -> None:
        self.write_config(_sleep_config([("sleep", 30, 1)]))
        with mock.patch.object(checks, "RUN_ALLOWANCE_SECONDS", 0):
            code, stdout, stderr = self.run_cli("check", "--json")
        self.assertEqual(code, 2, stderr)
        document = json.loads(stdout)
        self.assertEqual(document["decision"], "error")
        self.assertIn("1 s limit", document["error"])

    def test_the_limit_is_the_sum_of_the_checks_budgets_plus_the_allowance(self) -> None:
        self.assert_run_limit(
            [("first", 0, 1), ("second", 30, 2)], 4, "second", 1
        )

    def test_a_partial_run_limit_sums_only_the_selected_checks(self) -> None:
        self.write_config(
            _sleep_config([("sleep", 30, 1), ("unselected", 0, 100)])
        )
        started = time.monotonic()
        with mock.patch.object(checks, "RUN_ALLOWANCE_SECONDS", 0):
            code, stdout, stderr = self.run_cli("check", "--only", "sleep")
        self.assertEqual(code, 2, stderr)
        self.assertLess(time.monotonic() - started, 10)
        self.assertIn("1 s limit", stderr)
        self.assertNotIn("unselected", stdout)

    @staticmethod
    def _handler(_signum: int, _frame: object) -> None:
        pass

    def test_the_timer_and_handler_are_restored_after_a_run(self) -> None:
        handler = self._handler
        previous = signal.signal(signal.SIGALRM, handler)
        self.addCleanup(signal.setitimer, signal.ITIMER_REAL, 0.0)
        self.addCleanup(signal.signal, signal.SIGALRM, previous)
        self.write_config(_sleep_config([("quick", 0, 1)]))
        with mock.patch.object(checks, "RUN_ALLOWANCE_SECONDS", 0):
            code, _stdout, stderr = self.run_cli("check")
        self.assertEqual(code, 0, stderr)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.assertIs(signal.getsignal(signal.SIGALRM), handler)

        self.write_config(_sleep_config([("sleep", 30, 1)]))
        with mock.patch.object(checks, "RUN_ALLOWANCE_SECONDS", 0):
            code, _stdout, stderr = self.run_cli("check")
        self.assertEqual(code, 2, stderr)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.assertIs(signal.getsignal(signal.SIGALRM), handler)


if __name__ == "__main__":
    unittest.main()
