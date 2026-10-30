"""Tests for the combined check command and CLI wiring."""
from __future__ import annotations

import importlib
import json
import sys
import unittest

from support import BASE_CONFIG, GATE, FixtureCase, output, sarif_report, with_clones

sys.path.insert(0, str(GATE))
checks = importlib.import_module("quality_gate.checks")


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


if __name__ == "__main__":
    unittest.main()
