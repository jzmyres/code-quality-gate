"""Exercise affected selection through the gate in a disposable repository."""

import json
import subprocess

from support import GATE, PYTHON_TEST_HEADER, FixtureCase, output


CONFIG = r"""
schema = 2

[code]
patterns = ["*.py", "*.sh"]
shebangs = ["python*", "sh", "bash"]

[classes.source]
code = true
description = "Sources"
checks = ["lint", "tests", "chars"]

[classes.test]
code = true
description = "Test sources"
checks = ["tests"]

[classes.data]
code = false
description = "Data and configuration"

[[rule]]
pattern = "pkg/*"
class = "source"
reason = "Source modules"

[[rule]]
pattern = "tests/*.py"
class = "test"
reason = "Tests"

[[rule]]
pattern = "*.toml"
class = "data"
reason = "Configuration"

[[rule]]
pattern = "README.md"
class = "data"
reason = "Fixture data"

[[rule]]
pattern = ".gitignore"
class = "data"
reason = "Ignore rules"

[checks.lint]
adapter = "command"
tier = 1
enforcement = "enforced"
run = ["python3", "-c", "import sys; print(sys.argv[1:])", "{files}"]

[checks.chars]
adapter = "source_chars"
tier = 1
enforcement = "enforced"
scope = "changed"
base = "HEAD"

[checks.tests]
adapter = "python_tests"
tier = 1
enforcement = "enforced"
run = ["{python}", "-m", "unittest", "discover", "-s", "tests"]
tests_pattern = '^Ran (\d+) tests? in'
"""

CRAP = """\
[checks.crap]
adapter = "python_crap"
tier = 1
enforcement = "enforced"
requires = "tests"
threshold = 6
"""

SHAPE_CONFIG = CONFIG.replace('"lint", "tests", "chars"', '"lint", "tests", "chars", "shape"') + CRAP + """\
[checks.shape]
adapter = "python_shape"
tier = 1
enforcement = "enforced"
scope = "changed"
base = "HEAD"
crap_check = "crap"
"""

VERIFICATION = """\
[checks.verification]
adapter = "verification"
tier = 1
enforcement = "enforced"
requires = "tests"
"""

IMPORTING = "test_importing.Example.test_value"
OTHER = "test_other.Example.test_value"


class AffectedScopeTests(FixtureCase):
    def setUp(self):
        super().setUp()
        (self.repo / "a.py").unlink()
        self.write_config(CONFIG)
        self.add_file("pkg/__init__.py", "")
        self.add_file("pkg/a.py", "value = 1\n")
        self.add_file("pkg/b.py", "import pkg.a\n")
        self.write_test("importing", "import pkg.b\n")
        self.write_test("other")

    def write_test(self, name, imports="", body="        self.assertTrue(True)\n", decorator=""):
        self.add_file(
            f"tests/test_{name}.py",
            PYTHON_TEST_HEADER + f"\n{imports}\nclass Example(unittest.TestCase):\n"
            f"{decorator}    def test_value(self):\n{body}",
        )

    def run_gate(self, *args):
        environment = self.default_tool_env()
        environment["QG_AGENT"] = "0"
        return self.run_json(*args, env=environment)

    def affected(self, *args):
        result, document = self.run_gate("--base", "HEAD", *args)
        self.assertEqual(document.get("scope"), "affected", output(result))
        self.assertEqual(document["base"], "HEAD")
        return result, document

    def change(self, relative, content):
        self.commit_all()
        self.add_file(relative, content)

    def checked(self, document, name="tests"):
        return self.check_by_id(document, name)

    def test_transitive_module_selection_and_per_file_dependents(self):
        self.change("pkg/a.py", "value = 2\n")
        result, document = self.affected()
        self.assertEqual(result.returncode, 0, output(result))
        suite = self.checked(document)
        self.assertEqual(suite["executed"], [IMPORTING])
        self.assertEqual(suite["selection"]["selected"], {IMPORTING: "depends on pkg/b.py"})
        self.assertIn(OTHER, suite["selection"]["left_out"])
        lint = self.checked(document, "lint")
        self.assertEqual(lint["diagnostics"]["argv"][-2:], ["pkg/a.py", "pkg/b.py"])
        chars = self.checked(document, "chars")
        self.assertEqual(chars["selection"]["selected"], {"pkg/a.py": "changed"})
        for name in ("inventory", "hygiene"):
            self.assertEqual(self.checked(document, name)["selection"]["reason"], "full run")

    def test_changed_test_runs_itself(self):
        self.commit_all()
        self.write_test("other", body="        self.assertEqual(1, 1)\n")
        _, document = self.affected()
        self.assertEqual(self.checked(document)["executed"], [OTHER])
        lint = self.checked(document, "lint")
        self.assertEqual(lint["execution"], "not_run")
        self.assertEqual(lint["outcome"], "not_run")
        self.assertIn("no changed file", lint["reason"])

    def test_changed_test_also_selects_test_that_imports_its_value(self):
        self.write_test("other", "VALUE = 1\n")
        self.write_test("consumer", "from test_other import VALUE\n", "        self.assertEqual(VALUE, 2)\n")
        self.commit_all()
        self.write_test("other", "VALUE = 2\n")
        result, document = self.affected()
        self.assertEqual(result.returncode, 0, output(result))
        suite = self.checked(document)
        self.assertEqual(suite["executed"], ["test_consumer.Example.test_value", OTHER])
        self.assertEqual(suite["selection"]["selected"]["test_consumer.Example.test_value"],
                         "depends on tests/test_other.py")
        self.assertIn(IMPORTING, suite["selection"]["left_out"])

    def test_imported_case_is_selected_only_in_its_changed_discovery_module(self):
        self.add_file("tests/test_other.py", "from test_importing import Example\n")
        self.change("tests/test_other.py", "from test_importing import Example\nVALUE = 2\n")
        result, document = self.affected()
        self.assertEqual(result.returncode, 0, output(result))
        suite = self.checked(document)
        self.assertEqual(suite["executed"], [f"{IMPORTING} (discovery occurrence 2)"])
        self.assertIn(f"{IMPORTING} (discovery occurrence 1)", suite["selection"]["left_out"])

    def test_runtime_read_of_non_graph_file_runs_suite_in_full(self):
        self.write_test("other", "from pathlib import Path\n",
                       "        self.assertEqual(Path('README.md').read_text(), 'changed\\n')\n")
        self.change("README.md", "changed\n")
        result, document = self.affected()
        self.assertEqual(result.returncode, 0, output(result))
        suite = self.checked(document)
        self.assertEqual(suite["executed"], [IMPORTING, OTHER])
        self.assertIn("unplaced file README.md", suite["selection"]["reason"])

    def test_unknown_base_names_revision(self):
        self.commit_all()
        result, document = self.run_gate("--base", "qg-unknown-revision")
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn("--base 'qg-unknown-revision': expected an existing commit, got no such revision",
                      document["error"])

    def test_full_run_keeps_configured_pattern_and_json_shape(self):
        self.write_config(CONFIG.replace('"-s", "tests"]', '"tests", "-p", "test_other.py"]'))
        self.commit_all()
        result, document = self.run_gate()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertFalse({"scope", "base", "selected", "changed_paths"} & document.keys())
        self.assertTrue(all("selection" not in row for row in document["checks"]))
        suite = self.checked(document)
        self.assertEqual(suite["measurement"], {"tests": 1})
        self.assertEqual(
            suite["diagnostics"]["argv"][-5:], ["unittest", "discover", "tests", "-p", "test_other.py"],
        )

    def test_full_run_keeps_verbose_argument_and_runs_all_tests(self):
        self.write_config(CONFIG.replace('"-s", "tests"]', '"-v", "-s", "tests"]'))
        self.commit_all()
        result, document = self.run_gate()
        self.assertEqual(result.returncode, 0, output(result))
        suite = self.checked(document)
        self.assertEqual(suite["measurement"], {"tests": 2})
        self.assertEqual(suite["diagnostics"]["argv"][-4:], ["discover", "-v", "-s", "tests"])
        self.assertIn(OTHER, suite["diagnostics"]["output_tail"])

    def test_staged_rename_keeps_both_names(self):
        self.commit_all()
        self.git("mv", "pkg/b.py", "pkg/renamed.py")
        self.write_test("importing", "import pkg.renamed\n")
        _, document = self.affected()
        self.assertIn("unplaced file pkg/b.py", self.checked(document)["selection"]["reason"])
        lint = self.checked(document, "lint")
        self.assertEqual(lint["diagnostics"]["argv"][-3:], ["pkg/__init__.py", "pkg/a.py", "pkg/renamed.py"])
        self.assertIn("unplaced file pkg/b.py", lint["selection"]["reason"])

    def test_committed_and_staged_changes_survive_unstaged_reverts(self):
        from quality_gate.files import affected_diff

        self.commit_all()
        self.add_file("pkg/a.py", "value = 2\n")
        self.commit_all("branch change")
        self.add_file("pkg/b.py", "import pkg.a\nvalue = 2\n")
        self.git("add", "pkg/b.py")
        self.add_file("pkg/b.py", "import pkg.a\n")
        base, changed = affected_diff(self.repo, "HEAD^")
        self.assertEqual(base.commit, self.git("rev-parse", "HEAD^").stdout.strip())
        self.assertEqual(changed, {"pkg/a.py", "pkg/b.py"})
        result, document = self.run_gate("--base", "HEAD^")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(self.checked(document, "lint")["selection"]["selected"],
                         {"pkg/a.py": "changed", "pkg/b.py": "changed"})

    def test_lint_config_change_checks_unmodified_file(self):
        command = '["{tool:ruff}", "check", "--config", "ruff.toml", "{files}"]'
        self.write_config(CONFIG.replace('["python3", "-c", "import sys; print(sys.argv[1:])", "{files}"]',
                                         command))
        self.add_file("pkg/b.py", "import pkg.a\n")
        self.add_file("ruff.toml", "[lint]\nselect = []\n")
        self.change("ruff.toml", '[lint]\nselect = ["F401"]\n')
        _, document = self.affected()
        lint = self.checked(document, "lint")
        self.assertEqual(lint["outcome"], "fail")
        self.assertIn("ruff.toml", lint["selection"]["selected"]["pkg/b.py"])
        self.assertIn("F401", lint["diagnostics"]["output_tail"])

    def test_extended_lint_configuration_runs_all_per_file_checks(self):
        self.write_config(CONFIG.replace(
            '["python3", "-c", "import sys; print(sys.argv[1:])", "{files}"]',
            '["{tool:ruff}", "check", "--no-cache", "--config", "ruff.toml", "{files}"]',
        ))
        self.add_file("ruff.toml", 'extend = "lint-options.toml"\n')
        self.add_file("lint-options.toml", "[lint]\nselect = []\n")
        self.change("lint-options.toml", '[lint]\nselect = ["F401"]\n')
        _, document = self.affected()
        lint = self.checked(document, "lint")
        self.assertEqual(lint["outcome"], "fail")
        self.assertIn("F401", lint["diagnostics"]["output_tail"])
        for name in ("lint", "chars"):
            self.assertEqual(
                self.checked(document, name)["selection"]["selected"],
                dict.fromkeys(("pkg/__init__.py", "pkg/a.py", "pkg/b.py"),
                              "full run: unplaced file lint-options.toml"),
            )

    def test_tool_pin_change_runs_full_file_class(self):
        self.write_config(CONFIG.replace(
            '["python3", "-c", "import sys; print(sys.argv[1:])", "{files}"]',
            '["{tool:ruff}", "check", "--no-cache", "{files}"]',
        ))
        self.add_file("tools.lock.toml", '[tool.ruff]\nversion = "1.0"\n')
        self.change("tools.lock.toml", '[tool.ruff]\nversion = "2.0"\n')
        _, document = self.affected()
        lint = self.checked(document, "lint")
        self.assertEqual(lint["diagnostics"]["argv"][-3:], ["pkg/__init__.py", "pkg/a.py", "pkg/b.py"])
        self.assertIn("tools.lock.toml", lint["selection"]["selected"]["pkg/b.py"])

    def test_deleted_path_without_attribution_runs_the_full_gate(self):
        self.add_file("unknown.bin", b"data")
        self.commit_all()
        self.git("rm", "unknown.bin")
        result, document = self.affected()
        self.assertEqual(result.returncode, 0, output(result))
        lint = self.checked(document, "lint")
        self.assertIn("cannot attribute changed file unknown.bin", lint["selection"]["reason"])
        self.assertEqual(self.checked(document)["executed"], [IMPORTING, OTHER])

    def enable_crap(self):
        self.write_config(CONFIG.replace('"lint", "tests", "chars"', '"lint", "tests", "chars", "crap"')
                          + "\n" + CRAP)

    def test_crap_measures_changed_unimported_complexity(self):
        self.enable_crap()
        self.add_file("pkg/unimported.py", "def value(a, b):\n    return a + b\n")
        self.change(
            "pkg/unimported.py", "def value(a, b):\n    if a and b:\n        return 1\n    return 0\n",
        )
        _, document = self.affected()
        crap = self.checked(document, "crap")
        self.assertEqual(crap["outcome"], "fail")
        self.assertEqual(crap["selection"]["selected"], {"pkg/unimported.py": "changed"})
        self.assertGreater(crap["measurement"]["functions"], 0)
        self.assertIn("coverage required", self.checked(document)["selection"]["reason"])

    def test_crap_schedules_coverage_when_affected_file_discovers_zero_cases(self):
        self.enable_crap()
        self.add_file("tests/test_importing.py", PYTHON_TEST_HEADER + "import pkg.a\n")
        self.change("pkg/a.py", "value = 2\n")
        result, document = self.affected()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(self.checked(document)["executed"], [OTHER])
        self.assertGreater(self.checked(document, "crap")["measurement"]["functions"], 0)

    def test_verification_has_full_suppression_scan_and_full_prerequisites(self):
        self.write_config(
            CONFIG.replace('"lint", "tests", "chars"', '"lint", "tests", "chars", "verification"')
            + "\n" + VERIFICATION
        )
        self.change("pkg/a.py", "value = 2  # noqa: F401\n")
        _, document = self.affected()
        verification = self.checked(document, "verification")
        self.assertEqual(verification["outcome"], "fail")
        self.assertEqual(verification["selection"]["selected"]["pkg/b.py"], "full run")
        self.assertTrue(any("pkg/a.py" in row["subject"] for row in verification["findings"]))
        self.assertEqual(self.checked(document)["executed"], [IMPORTING, OTHER])

    def test_load_tests_hook_runs_in_full_even_with_an_empty_diff(self):
        self.add_file(
            "tests/test_hook.py",
            "import unittest\n"
            "def load_tests(loader, suite, pattern):\n"
            "    def registered():\n"
            "        pass\n"
            "    @unittest.skip('hook skip')\n"
            "    def skipped():\n"
            "        pass\n"
            "    class Cases(unittest.TestCase):\n"
            "        test_registered = staticmethod(registered)\n"
            "        test_skipped = staticmethod(skipped)\n"
            "    return loader.loadTestsFromTestCase(Cases)\n",
        )
        self.commit_all()
        result, document = self.affected()
        self.assertEqual(result.returncode, 0, output(result))
        suite = self.checked(document)
        self.assertIn("load_tests", suite["selection"]["reason"])
        self.assertIn("test_hook.load_tests.<locals>.Cases.test_registered", suite["executed"])
        skipped = "test_hook.load_tests.<locals>.Cases.test_skipped"
        self.assertIn(skipped, suite["selection"]["selected"])
        self.assertEqual(suite["skipped"], [skipped])
        self.assertNotIn(skipped, suite["executed"])
        report = self.discover_shards(["-s", "tests", "-j", "1"], {})
        self.assertIn(skipped, report["selection"]["selected"])
        self.assertEqual(report["skipped"], [skipped])

    def write_repeated_hook(self, first_invocation):
        self.add_file("tests/test_hook.py", f"""\
import unittest

class Repeated(unittest.TestCase):
    def test_repeated(self):
        if not hasattr(self, "invoked"):
            self.invoked = True
            {first_invocation}

def load_tests(loader, suite, pattern):
    case = Repeated("test_repeated")
    return unittest.TestSuite([case, case])
""")

    def test_hook_discovery_records_each_occurrence_of_the_same_case(self):
        self.write_repeated_hook('self.skipTest("first occurrence")')
        self.commit_all()
        result, document = self.affected()
        self.assertEqual(result.returncode, 0, output(result))
        suite = self.checked(document)
        first = "test_hook.Repeated.test_repeated (discovery occurrence 1)"
        second = "test_hook.Repeated.test_repeated (discovery occurrence 2)"
        self.assertIn(first, suite["selection"]["selected"])
        self.assertIn(second, suite["selection"]["selected"])
        self.assertIn(first, suite["skipped"])
        self.assertIn(second, suite["executed"])
        self.assertEqual(suite["not_executed"], {})

    def test_only_selected_test_skipped_with_or_without_policy_pattern(self):
        self.commit_all()
        self.write_test("other", decorator="    @unittest.skip('disabled')\n")
        for pattern in ("", r"skipped_pattern = 'skipped=(\d+)'"):
            with self.subTest(pattern=pattern):
                self.write_config(CONFIG + pattern + "\n")
                self.git("add", "quality-gate.toml")
                self.git("commit", "--allow-empty", "-m", "Configure skip reporting")
                _, document = self.affected()
                suite = self.checked(document)
                self.assertEqual(suite["outcome"], "fail")
                self.assertEqual(suite["measurement"], {"tests": 0})
                self.assertEqual(suite["skipped"], [OTHER])
                self.assertIn(IMPORTING, suite["selection"]["left_out"])

    def test_discovery_import_error_is_not_an_executed_test(self):
        self.change("tests/test_other.py", "raise ImportError('fixture discovery error')\n")
        _, document = self.affected()
        suite = self.checked(document)
        self.assertEqual(suite["outcome"], "fail")
        self.assertEqual(suite["executed"], [])
        self.assertIn("ImportError: fixture discovery error", suite["discovery_errors"][0])

    def test_passing_subtest_counts_even_with_a_skipped_subtest(self):
        self.commit_all()
        self.write_test("other", body="        with self.subTest('passes'):\n"
                                     "            self.assertTrue(True)\n"
                                     "        with self.subTest('skips'):\n"
                                     "            self.skipTest('disabled')\n")
        result, document = self.affected()
        self.assertEqual(result.returncode, 0, output(result))
        suite = self.checked(document)
        self.assertEqual(suite["measurement"], {"tests": 1})
        self.assertEqual(suite["executed"], [OTHER])
        self.assertEqual(suite["skipped"], [])

    def test_command_adapter_suite_runs_the_configured_command_in_full(self):
        self.write_config(CONFIG.replace('adapter = "python_tests"', 'adapter = "command"')
                          .replace('"{python}", "-m"', '"python3", "-I", "-m"')
                          .replace('"-s", "tests"]', '"tests", "-p", "test_importing.py", "-v"]')
                          + 'must_match = "test_importing.Example.test_value"\n')
        self.commit_all()
        self.write_test("other", body="        self.fail('outside the configured pattern')\n")
        full_result, full_document = self.run_gate()
        result, document = self.affected()
        self.assertEqual(full_result.returncode, 0, output(full_result))
        self.assertEqual(result.returncode, 0, output(result))
        suite = self.checked(document)
        full_suite = self.checked(full_document)
        self.assertEqual(suite["diagnostics"]["argv"], full_suite["diagnostics"]["argv"])
        self.assertEqual(full_suite["measurement"], {"tests": 1})
        self.assertNotIn("measurement", suite)
        self.assertEqual(suite["selection"], {
            "selected": {}, "left_out": {}, "reason": "full run: command adapter suite is opaque",
        })
        self.assertNotIn("executed", suite)

    def test_opaque_suites_do_not_report_counts_for_skipped_cases(self):
        python_config = CONFIG.replace(
            '"-m", "unittest", "discover", "-s", "tests"', '"pkg/run_tests.py"',
        )
        command_config = python_config.replace('adapter = "python_tests"', 'adapter = "command"')
        command_config = command_config.replace('"{python}"', '"python3"')
        self.add_file("pkg/run_tests.py", (
            "import unittest\n"
            "suite = unittest.defaultTestLoader.discover('tests')\n"
            "raise SystemExit(not unittest.TextTestRunner().run(suite).wasSuccessful())\n"
        ))
        for name in ("importing", "other"):
            self.write_test(name, decorator="    @unittest.skip('disabled')\n")
        configurations = {
            "command adapter suite": command_config,
            "custom Python test command": python_config,
        }
        for description, config in configurations.items():
            for pattern, full_outcome, full_count in (("unmatched", "pass", 2), ("skipped", "fail", 0)):
                with self.subTest(adapter=description, pattern=pattern):
                    self.check_opaque_suite(config, description, pattern, full_outcome, full_count)

    def check_opaque_suite(self, config, description, pattern, full_outcome, full_count):
        self.write_config(config + f"skipped_pattern = '{pattern}=(\\d+)'\n")
        self.commit_all()
        full_result, full_document = self.run_gate()
        result, document = self.affected()
        suite = self.checked(document)
        full_suite = self.checked(full_document)
        self.assertEqual(full_result.returncode, int(full_outcome == "fail"), output(full_result))
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(suite["outcome"], "pass", output(result))
        self.assertEqual(full_suite["outcome"], full_outcome, output(full_result))
        self.assertEqual(suite["diagnostics"]["argv"][-1:], full_suite["diagnostics"]["argv"][-1:])
        self.assertEqual(suite["selection"], {
            "selected": {}, "left_out": {},
            "reason": f"full run: {description} is opaque",
        })
        self.assertFalse({"measurement", "executed", "skipped", "tests"} & suite.keys())
        self.assertEqual(full_suite["measurement"], {"tests": full_count})
        self.assertIn("skipped=2", full_suite["diagnostics"]["output_tail"])
        self.assertNotIn("skipped=2", suite["diagnostics"]["output_tail"])
        self.assertNotIn("skipped=2", result.stderr)
        self.assertNotIn("2 tests", result.stderr)

    def test_retargeted_python_test_symlink_selects_the_discovery_file(self):
        before = self.add_file("pkg/before.py", "import unittest\n")
        after = self.add_file(
            "pkg/after.py",
            "import unittest\n\nclass Cases(unittest.TestCase):\n"
            "    def test_linked(self):\n        self.assertTrue(True)\n",
        )
        link = self.repo / "tests/test_linked.py"
        link.symlink_to("../pkg/" + before.name)
        self.commit_all()
        link.unlink()
        link.symlink_to("../pkg/" + after.name)
        self.git("add", "tests/test_linked.py")

        result, document = self.affected("--only", "tests")
        self.assertEqual(result.returncode, 0, output(result))
        suite = self.checked(document)
        self.assertEqual(suite["executed"], ["test_linked.Cases.test_linked"])
        self.assertEqual(suite["selection"]["selected"], {"test_linked.Cases.test_linked": "changed"})

    def test_interrupted_suite_keeps_selection_and_completed_invocations(self):
        self.write_config(CONFIG + "budget_seconds = 3\n")
        self.write_test("later")
        self.commit_all()
        self.write_test("importing", body="        self.assertTrue(1)\n")
        for body, execution in (
            ("        import time\n        time.sleep(60)\n", "budget"),
            ("        import os, signal\n        os.kill(os.getpid(), signal.SIGTERM)\n", "signal"),
            ("        import os, signal\n        os.kill(os.getpid(), signal.SIGINT)\n", "signal"),
        ):
            with self.subTest(execution=execution):
                self.write_test("later", body=body)
                result, document = self.affected()
                self.assertEqual(result.returncode, 1, output(result))
                suite = self.checked(document)
                later = "test_later.Example.test_value"
                self.assertEqual(suite["execution"], execution)
                self.assertEqual(suite["selection"]["selected"], {IMPORTING: "changed", later: "changed"})
                self.assertIn(OTHER, suite["selection"]["left_out"])
                self.assertEqual(suite["executed"], [IMPORTING])
                self.assertEqual(suite["measurement"], {"tests": 1})
                self.assertEqual(suite["not_executed"], {later: "invocation interrupted"})

    def test_hook_failure_is_attributed_to_its_discovery_occurrence(self):
        self.write_repeated_hook('self.fail("first occurrence")')
        self.commit_all()
        result, document = self.affected()
        self.assertEqual(result.returncode, 1, output(result))
        suite = self.checked(document)
        first = "test_hook.Repeated.test_repeated (discovery occurrence 1)"
        second = "test_hook.Repeated.test_repeated (discovery occurrence 2)"
        self.assertEqual(suite["outcome"], "fail")
        self.assertEqual(suite["executed"][:2], [first, second])
        self.assertEqual([finding["subject"] for finding in suite["findings"]], [first])

    def test_staged_initializer_deletion_expands_package_and_dependents(self):
        self.write_config(CONFIG + """
[[rule]]
pattern = "consumer.py"
class = "source"
reason = "External package consumer"
""")
        self.add_file("pkg/b.py", "value = 1\n")
        self.add_file("consumer.py", "from pkg.b import value\n")
        self.commit_all()
        self.git("rm", "pkg/__init__.py")
        result, document = self.affected()
        self.assertEqual(result.returncode, 0, output(result))
        lint = self.checked(document, "lint")
        self.assertIn("pkg/__init__.py", lint["selection"]["selected"]["pkg/b.py"])
        self.assertIn("consumer.py", lint["diagnostics"]["argv"])
        self.assertIn("unplaced file pkg/__init__.py", lint["selection"]["selected"]["consumer.py"])
        self.assertEqual(self.checked(document)["executed"], [IMPORTING, OTHER])

    def test_shell_source_dependents_reach_file_command(self):
        from quality_gate.adapters import affected_graph
        from quality_gate.files import validate_inventory
        from quality_gate.policy import load_config

        self.add_file("pkg/source.sh", "#!/bin/sh\nVALUE=1\n")
        self.add_file("pkg/consumer.sh", '#!/bin/sh\n. "$(dirname "$0")"/source.sh\n')
        self.change("pkg/source.sh", "#!/bin/sh\nVALUE=2\n")
        result, document = self.affected()
        self.assertEqual(result.returncode, 0, output(result))
        lint = self.checked(document, "lint")
        self.assertEqual(lint["diagnostics"]["argv"][-2:], ["pkg/consumer.sh", "pkg/source.sh"])
        self.assertEqual(lint["selection"]["selected"]["pkg/consumer.sh"], "depends on pkg/source.sh")
        self.assertEqual(self.checked(document)["outcome"], "not_run")
        config = load_config(self.repo)
        files, classes, violations = validate_inventory(self.repo, config)
        self.assertEqual(violations, [])
        _, affected = affected_graph(self.repo, config, files, classes, self.base, {"pkg/source.sh"})
        self.assertEqual(affected["pkg/consumer.sh"], "depends on pkg/source.sh")

    def test_initializer_change_seeds_every_package_module(self):
        from quality_gate.module_graph import Edge, affected_paths

        edges = [Edge("consumer.py", "pkg/mod.py", 1)]
        states = (["consumer.py", "pkg/mod.py"], ["consumer.py", "pkg/mod.py", "pkg/__init__.py"])
        for nodes in states:
            with self.subTest(nodes=nodes):
                affected = affected_paths(nodes, edges, {"pkg/__init__.py"})
                self.assertEqual(affected["pkg/mod.py"], "package initializer pkg/__init__.py changed")
                self.assertEqual(affected["consumer.py"], "depends on pkg/mod.py")

    def test_crap_remains_unsupported_when_entire_suite_executes_nothing(self):
        self.enable_crap()
        self.add_file("tests/test_importing.py", PYTHON_TEST_HEADER + "import pkg.a\n")
        self.add_file("tests/test_other.py", "")
        self.change("pkg/a.py", "value = 2\n")
        _, document = self.affected()
        self.assertEqual(self.checked(document)["outcome"], "fail")
        self.assertEqual(self.checked(document)["executed"], [])
        self.assertIn("coverage required", self.checked(document)["selection"]["reason"])
        crap = self.checked(document, "crap")
        self.assertEqual(crap["outcome"], "unsupported")
        self.assertEqual(crap["reason"], "coverage unreliable: tests did not pass")
        self.assertNotIn("measurement", crap)

    def test_crap_remains_unsupported_when_an_executed_test_fails(self):
        self.enable_crap()
        self.commit_all()
        self.add_file("pkg/a.py", "def changed():\n    return 2\n")
        self.write_test("importing", "import pkg.b\n", body="        self.fail('bad change')\n")
        _, document = self.affected()
        self.assertEqual(self.checked(document)["executed"], [IMPORTING])
        crap = self.checked(document, "crap")
        self.assertEqual(crap["outcome"], "unsupported")
        self.assertEqual(crap["reason"], "coverage unreliable: tests did not pass")
        self.assertNotIn("measurement", crap)

    def test_shard_command_uses_ordinary_discovery_with_the_configured_pattern(self):
        script = GATE / "quality_gate" / "test_shards.py"
        argv = ["-s", "tests", "-p", "test_other.py", "-j", "1"]
        self.add_file("tests/test_importing.py", "raise AssertionError('pattern selected the wrong file')\n")
        configured = json.dumps(["{python}", str(script), *argv])
        self.write_config(CONFIG.replace(
            '["{python}", "-m", "unittest", "discover", "-s", "tests"]', configured,
        ))
        self.commit_all()
        self.write_test("other", body="        self.assertEqual(1, 1)\n")
        result, document = self.affected()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(self.checked(document)["executed"], [OTHER])
        self.assertEqual(self.discover_shards(argv, {"tests/test_other.py": "changed"})["executed"], [OTHER])

    def discover_shards(self, argv, paths):
        from quality_gate.adapters import _read_affected_report

        plan = self.base / "plan.json"
        plan.write_text(json.dumps({
            "argv": argv, "shards": True, "full": None, "coverage": False,
            "paths": paths,
        }), encoding="utf-8")
        child = subprocess.run(
            [*self.python_prefix(), str(GATE / "quality_gate" / "test_shards.py"), "--affected", str(plan)],
            cwd=self.repo,
            env=self.default_tool_env(), capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(child.returncode, 0, output(child))
        return _read_affected_report(plan.with_suffix(".result.jsonl"))

    def test_unchanged_elisp_suite_is_not_run(self):
        self.write_config(CONFIG.replace('"*.py", "*.sh"', '"*.py", "*.sh", "*.el"') + """
[classes.elisp]
code = true
description = "Elisp suites"
checks = ["elisp"]

[[rule]]
pattern = "*.el"
class = "elisp"
reason = "Elisp tests"

[checks.elisp]
adapter = "elisp_tests"
tier = 1
enforcement = "enforced"
suite = "tests/ert.el"
""")
        self.add_file("tests/ert.el", "")
        self.commit_all()
        result, document = self.affected("--only", "elisp")
        self.assertEqual(result.returncode, 0, output(result))
        suite = self.checked(document, "elisp")
        self.assertEqual(suite["outcome"], "not_run")
        self.assertIn("tests/ert.el", suite["selection"]["left_out"])

    def test_changed_elisp_suite_is_selected_with_a_dot_prefix(self):
        self.write_elisp_config()
        self.add_file("lisp/calc.el", "(defun calc (a) a)\n(provide 'calc)\n")
        self.add_file("tests/suite.el", "(require 'ert)\n(ert-run-tests-batch-and-exit)\n")
        self.change(
            "tests/suite.el",
            "(require 'ert)\n(ert-deftest selected () (should t))\n(ert-run-tests-batch-and-exit)\n",
        )
        self.assert_changed_elisp_suite_runs()

    def test_editing_tracked_ert_target_selects_the_linked_suite(self):
        self.write_elisp_config()
        self.add_file("lisp/calc.el", "(defun calc (a) a)\n(provide 'calc)\n")
        target = "tests/ert-target.el"
        self.add_file(target, "(require 'ert)\n(ert-run-tests-batch-and-exit)\n")
        (self.repo / "tests/suite.el").symlink_to("ert-target.el")
        self.change(
            target,
            "(require 'ert)\n(ert-deftest linked () (should t))\n(ert-run-tests-batch-and-exit)\n",
        )
        self.assert_changed_elisp_suite_runs()

    def assert_changed_elisp_suite_runs(self):
        result, document = self.affected("--only", "elisp")
        self.assertEqual(result.returncode, 0, output(result))
        suite = self.checked(document, "elisp")
        self.assertEqual(suite["selection"]["selected"], {"tests/suite.el": "changed"})
        self.assertEqual(suite["measurement"], {"tests": 1})

    def test_elisp_crap_remains_unsupported_for_empty_ert_suite(self):
        suite = self.check_elisp_crap_without_executed_tests("")
        self.assertIn("coverage required", suite["selection"]["reason"])

    def test_elisp_crap_remains_unsupported_for_all_skipped_ert_suite(self):
        suite = self.check_elisp_crap_without_executed_tests(
            "(ert-deftest skipped () (ert-skip \"disabled\"))\n",
        )
        self.assertIn("1 selected, 1 skipped", suite["reason"])

    def check_elisp_crap_without_executed_tests(self, cases):
        self.write_elisp_config()
        self.add_file(
            "tests/suite.el",
            f"(require 'ert)\n{cases}(ert-run-tests-batch-and-exit)\n",
        )
        self.add_file("lisp/calc.el", "(defun calc (a) a)\n(provide 'calc)\n")
        self.change("lisp/calc.el", "(defun calc (a) (if a 1 2))\n(provide 'calc)\n")
        result, document = self.affected("--only", "elisp_crap")
        self.assertEqual(result.returncode, 1, output(result))
        suite = self.checked(document, "elisp")
        self.assertEqual(suite["outcome"], "fail")
        self.assertEqual(suite["measurement"], {"tests": 0})
        crap = self.checked(document, "elisp_crap")
        self.assertEqual(crap["selection"]["selected"], {"lisp/calc.el": "changed"})
        self.assertEqual(crap["outcome"], "unsupported")
        self.assertEqual(crap["reason"], "coverage unreliable: elisp did not pass")
        self.assertNotIn("measurement", crap)
        return suite

    def write_elisp_config(self):
        self.write_config(CONFIG.replace('"*.py", "*.sh"', '"*.py", "*.sh", "*.el"') + """
[classes.elisp]
code = true
description = "Measured Elisp sources"
checks = ["elisp", "elisp_crap"]

[classes.ert]
code = true
description = "ERT suites"
checks = ["lint"]

[[rule]]
pattern = "lisp/*.el"
class = "elisp"
reason = "Elisp sources"

[[rule]]
pattern = "tests/*.el"
class = "ert"
reason = "ERT suite"

[checks.elisp]
adapter = "elisp_tests"
tier = 1
enforcement = "enforced"
suite = "./tests/suite.el"

[checks.elisp_crap]
adapter = "elisp_crap"
tier = 1
enforcement = "enforced"
requires = "elisp"
threshold = 6
""")

    def test_python_shape_uses_requested_diff_and_reports_measured_files(self):
        self.write_config(SHAPE_CONFIG)
        self.commit_all()
        self.add_file("pkg/a.py", "def new_function():\n    return 1\n")
        self.commit_all("Branch change")
        result, document = self.run_gate("--base", "HEAD^", "--only", "shape")
        shape = self.checked(document, "shape")
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(shape["measurement"]["base"], {
            "commit": self.git("rev-parse", "HEAD^").stdout.strip(), "source": "--base",
        })
        self.assertEqual(shape["measurement"]["functions"], 1)
        self.assertEqual(shape["selection"]["selected"], {"pkg/a.py": "in the requested diff"})
        self.assertIn("pkg/b.py", shape["selection"]["left_out"])

    def test_python_shape_is_not_run_with_no_measured_files(self):
        self.write_config(SHAPE_CONFIG)
        self.commit_all()
        result, document = self.affected("--only", "shape")
        self.assertEqual(result.returncode, 0, output(result))
        shape = self.checked(document, "shape")
        self.assertEqual(shape["outcome"], "not_run")
        self.assertEqual(shape["reason"], "no files in the shape measurement")
        self.assertEqual(shape["selection"]["selected"], {})
        self.assertIn("pkg/a.py", shape["selection"]["left_out"])

    def test_python_shape_uses_both_sides_of_a_pure_rename(self):
        self.write_config(SHAPE_CONFIG)
        self.add_file("pkg/a.py", "def moved():\n    return 1\n")
        self.commit_all()
        self.git("mv", "pkg/a.py", "pkg/renamed.py")
        _, document = self.affected("--only", "shape")
        shape = self.checked(document, "shape")
        self.assertEqual(shape["selection"]["selected"], {"pkg/renamed.py": "in the requested diff"})
        self.assertEqual(shape["measurement"]["functions"], 1)
        self.assertEqual(document["changed_paths"], ["pkg/a.py", "pkg/renamed.py"])

    def test_python_shape_lists_a_committed_change_reverted_in_the_worktree(self):
        self.write_config(SHAPE_CONFIG)
        original = "def reverted():\n    return 1\n"
        self.add_file("pkg/a.py", original)
        self.commit_all()
        self.add_file("pkg/a.py", "def reverted():\n    return 2\n")
        self.commit_all("Branch change")
        self.add_file("pkg/a.py", original)
        result, document = self.run_gate("--base", "HEAD^", "--only", "shape")
        self.assertEqual(result.returncode, 0, output(result))
        shape = self.checked(document, "shape")
        self.assertEqual(shape["selection"]["selected"], {"pkg/a.py": "in the requested diff"})
        self.assertEqual(shape["measurement"]["functions"], 0)
        self.assertEqual(document["changed_paths"], ["pkg/a.py"])
