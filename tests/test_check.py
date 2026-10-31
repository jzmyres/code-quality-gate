"""Tests for the combined check command and CLI wiring."""
from __future__ import annotations

import contextlib
import importlib
import io
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from support import BASE_CONFIG, GATE, FixtureCase, output, sarif_report, with_clones

sys.path.insert(0, str(GATE))
checks = importlib.import_module("quality_gate.checks")
policy = importlib.import_module("quality_gate.policy")
runner = importlib.import_module("quality_gate.runner")


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

    def test_budget_stop_removes_earlier_and_current_evidence(self):
        paths = []

        def adapter(context):
            result = self.produce(context)
            paths.append(self.evidence.parent)
            if context.check.id == "budget":
                raise runner.StepTimeout("fixture work")
            return result

        definitions = [self.definition("producer"), self.definition("budget", "producer")]
        with contextlib.redirect_stderr(io.StringIO()):
            results = self.run_checks(definitions, adapter)
        self.assertEqual(results[1].execution, "budget")
        self.assertTrue(all(not path.exists() for path in paths), paths)

    def test_budget_expiring_after_the_adapter_returns_removes_its_evidence(self):
        with mock.patch.object(checks, "check_time", side_effect=runner.StepTimeout("return")), \
                contextlib.redirect_stderr(io.StringIO()):
            results = self.run_checks([self.definition("producer")], self.produce)
        self.assertEqual(results[0].execution, "budget")
        self.assert_removed()

    def assert_cleanup_failure_survives(self, ending, *, recorded_diagnostics=False,
                                       retain_evidence=True):
        def adapter(context):
            result = self.produce(context)
            self.addCleanup(result.temporary.cleanup)
            result.temporary.cleanup = mock.Mock(side_effect=PermissionError("cleanup denied"))
            if not retain_evidence:
                result.temporary = None
            result.diagnostics = runner.Diagnostics(
                argv=["fixture"], exit_code=1, output_bytes=15,
                output_tail="fixture output", error="original diagnostic",
            )
            if recorded_diagnostics:
                runner.record_diagnostics(result.diagnostics)
            if ending == "timeout before return":
                raise runner.StepTimeout("fixture work")
            if ending == "worker error":
                raise runner.WorkerError("fixture worker failed")
            if ending == "failure":
                result.outcome = "fail"
            return result

        # Fail check_time only after the adapter has returned its evidence.
        check_time = runner.StepTimeout("adapter return") if ending == "timeout after return" else None
        with mock.patch.object(checks, "check_time", side_effect=check_time), \
                contextlib.redirect_stderr(io.StringIO()) as stderr:
            results = self.run_checks([self.definition("producer")], adapter)
        document = results[0].to_json()
        diagnostic = document["diagnostics"]["error"]
        message = f"cannot remove evidence directory {self.evidence.parent}: cleanup denied"
        self.assertIn(message, diagnostic)
        self.assertEqual(diagnostic.count(message), 1)
        self.assertIn(message, stderr.getvalue())
        self.assertTrue(self.evidence.parent.is_dir())
        expected = {
            "timeout before return": ("fail", "budget"),
            "timeout after return": ("fail", "budget"),
            "worker error": ("error", "error"),
            "success": ("pass", "completed"),
            "failure": ("fail", "completed"),
        }
        self.assertEqual((document["outcome"], document["execution"]), expected[ending])
        if recorded_diagnostics or ending in ("success", "failure"):
            self.assertIn("original diagnostic", diagnostic)
            self.assertEqual(document["diagnostics"]["argv"], ["fixture"])
            self.assertEqual(document["diagnostics"]["exit_code"], 1)
            self.assertEqual(document["diagnostics"]["output_tail"], "fixture output")
        else:
            self.assertIn(document["reason"], diagnostic)

    def test_cleanup_failure_survives_a_timeout_before_adapter_return(self):
        self.assert_cleanup_failure_survives("timeout before return")

    def test_cleanup_failure_survives_a_timeout_after_adapter_return(self):
        self.assert_cleanup_failure_survives("timeout after return")

    def test_cleanup_failure_survives_a_worker_error(self):
        self.assert_cleanup_failure_survives("worker error")

    def test_cleanup_failure_preserves_recorded_diagnostics(self):
        for ending in ("timeout before return", "timeout after return", "worker error"):
            for retained in (False, True):
                with self.subTest(ending=ending, retained=retained):
                    self.assert_cleanup_failure_survives(
                        ending, recorded_diagnostics=True, retain_evidence=retained,
                    )

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


if __name__ == "__main__":
    unittest.main()
