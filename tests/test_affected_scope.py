"""Exercise affected selection through the gate in a disposable repository."""

import json
import subprocess
import tomllib

from support import GATE, PYTHON_TEST_HEADER, FixtureCase, output


SHARD_RUNNER = GATE / "quality_gate" / "test_shards.py"
SHARD_COMMAND = json.dumps(["{python}", str(SHARD_RUNNER), "-s", "tests", "-j", "1"])
UNITTEST_DISCOVER = ["{python}", "-m", "unittest", "discover"]

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
run = @SHARD_COMMAND@
tests_pattern = '^Ran (\d+) tests? in'
""".replace("@SHARD_COMMAND@", SHARD_COMMAND)

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
RUNTIME_REASON = "full run: suite runtime inputs are undeclared"

OBLIGATION_CONFIG = CONFIG + """
[levels]
required_tiers = [1, 2, 3]

[[not_applicable]]
class = "test"
tier = 2
reason = "The fixture has no property-testing adapter"
"""

DISCOVERY_IDS = """\
import json
import sys
import unittest

def ids(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from ids(test)
        else:
            yield test.id()

print(json.dumps(list(ids(unittest.TestLoader().discover(*sys.argv[1:])))))
"""


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
        self.assert_runtime_suite(suite, [IMPORTING, OTHER])
        lint = self.checked(document, "lint")
        self.assertEqual(lint["diagnostics"]["argv"][-2:], ["pkg/a.py", "pkg/b.py"])
        chars = self.checked(document, "chars")
        self.assertEqual(chars["selection"]["selected"], {"pkg/a.py": "changed"})
        for name in ("inventory", "hygiene"):
            self.assertEqual(self.checked(document, name)["selection"]["reason"], "full run")

    def assert_runtime_suite(self, suite, names):
        self.assertEqual(suite["executed"], names)
        self.assertEqual(suite["selection"]["selected"], dict.fromkeys(names, RUNTIME_REASON))
        self.assertEqual(suite["selection"]["left_out"], {})

    def test_changed_test_runs_the_full_suite(self):
        self.commit_all()
        self.write_test("other", body="        self.assertEqual(1, 1)\n")
        _, document = self.affected()
        self.assert_runtime_suite(self.checked(document), [IMPORTING, OTHER])
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
        self.assert_runtime_suite(suite, ["test_consumer.Example.test_value", IMPORTING, OTHER])

    def test_imported_case_runs_in_both_discovery_modules(self):
        self.add_file("tests/test_other.py", "from test_importing import Example\n")
        self.change("tests/test_other.py", "from test_importing import Example\nVALUE = 2\n")
        result, document = self.affected()
        self.assertEqual(result.returncode, 0, output(result))
        suite = self.checked(document)
        self.assert_runtime_suite(
            suite, [f"{IMPORTING} (discovery occurrence {position})" for position in (1, 2)],
        )

    def test_runtime_read_of_graph_node_rejects_and_runs_every_discovery_occurrence(self):
        start, pattern = "tests", "test_*.py"
        configured = json.dumps(["{python}", str(SHARD_RUNNER), "-s", start, "-p", pattern, "-j", "1"])
        self.write_config(CONFIG.replace(SHARD_COMMAND, configured))
        self.add_file("tests/test_alias.py", "from test_importing import Example\n")
        self.write_test("other", "from pathlib import Path\n",
                       "        self.assertEqual(Path('pkg/a.py').read_text(), 'value = 1\\n')\n")
        self.commit_all()
        base, baseline = self.run_gate()
        self.assertEqual(base.returncode, 0, output(base))
        self.assertEqual(self.checked(baseline)["measurement"], {"tests": 3})

        self.add_file("pkg/a.py", "value = 2\n")
        result, document = self.affected()
        suite = self.checked(document)

        discovery_script = self.base / "discover.py"
        discovery_script.write_text(DISCOVERY_IDS, encoding="utf-8")
        discovery = subprocess.run(
            [*self.python_prefix(), str(discovery_script), start, pattern], cwd=self.repo,
            env=self.default_tool_env(), capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(discovery.returncode, 0, output(discovery))
        expected = json.loads(discovery.stdout)
        for occurrences in (suite["selection"]["selected"], suite["executed"]):
            self.assertCountEqual(
                [name.partition(" (discovery occurrence ")[0] for name in occurrences], expected,
            )
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "rejected")
        self.assertEqual(document["changed_paths"], ["pkg/a.py"])
        self.assertEqual(suite["outcome"], "fail")
        self.assertEqual(suite["selection"]["reason"], RUNTIME_REASON)
        self.assertEqual([row["subject"] for row in suite["findings"]], [OTHER])
        self.assertEqual(suite["selection"]["left_out"], {})
        self.assertEqual(suite["not_executed"], {})

    def test_runtime_read_of_non_graph_file_runs_suite_in_full(self):
        self.write_test("other", "from pathlib import Path\n",
                       "        self.assertEqual(Path('README.md').read_text(), 'changed\\n')\n")
        self.change("README.md", "changed\n")
        result, document = self.affected()
        self.assertEqual(result.returncode, 0, output(result))
        suite = self.checked(document)
        self.assertEqual(suite["executed"], [IMPORTING, OTHER])
        self.assertIn("unplaced file README.md", suite["selection"]["reason"])

    def assert_unevaluated_pairs(self, result, document, policy):
        fixture = tomllib.loads(policy)
        evidence = {1: ["tests"], 2: ["properties", "fuzzing"], 3: ["bounded"]}
        expected = [
            (name, tier) for name, definition in fixture["classes"].items() if definition["code"]
            for tier in fixture["levels"]["required_tiers"]
        ]
        self.assertCountEqual(
            [(row["class"], row["tier"]) for row in document["obligations"]], expected,
        )
        for row in document["obligations"]:
            name, tier = row["class"], row["tier"]
            self.assertEqual(row, {
                "class": name, "tier": tier, "status": "not_evaluated",
                "required": evidence[tier], "checks": [], "caused_by": None,
                "reason": "partial run",
            }, f"{name} tier {tier}")
        prefix = "check: obligations not evaluated ("
        summaries = [
            line.removeprefix(prefix).removesuffix(")").split(", ")
            for line in output(result).splitlines() if line.startswith(prefix)
        ]
        self.assertEqual(len(summaries), 1, output(result))
        self.assertCountEqual(summaries[0], [f"{name} tier {tier}" for name, tier in expected])
        return expected

    def test_partial_obligations_cover_every_required_pair_on_pass_and_rejection(self):
        self.write_config(OBLIGATION_CONFIG)
        self.commit_all()
        for fails in (False, True):
            self.write_test("other", body=f"        self.assertFalse({fails!r})\n")
            for args in (("--base", "HEAD"), ("--base", "HEAD", "--only", "tests"), ("--only", "tests")):
                with self.subTest(args=args, fails=fails):
                    result, document = self.run_gate(*args)
                    self.assertEqual(result.returncode, int(fails), output(result))
                    self.assertEqual(document["decision"], "rejected" if fails else "partial")
                    self.assert_unevaluated_pairs(result, document, OBLIGATION_CONFIG)

        self.write_test("other")
        result, document = self.run_gate()
        self.assertEqual(result.returncode, 1, output(result))
        fixture = tomllib.loads(OBLIGATION_CONFIG)
        exemptions = {(row["class"], row["tier"]) for row in fixture["not_applicable"]}
        expected = [
            (name, tier, "exempted" if (name, tier) in exemptions else
             "satisfied" if tier == 1 else "unsatisfied")
            for name, definition in fixture["classes"].items() if definition["code"]
            for tier in fixture["levels"]["required_tiers"]
        ]
        self.assertCountEqual([
            (row["class"], row["tier"], row["status"]) for row in document["obligations"]
        ], expected)
        self.assertNotIn("obligations not evaluated", output(result))

    def test_trusted_affected_obligations_use_the_effective_policy(self):
        self.write_config(OBLIGATION_CONFIG)
        self.commit_all()
        trusted = self.trusted_directory("HEAD")
        self.add_file("pkg/a.py", "value = 2\n")
        result, document = self.affected("--policy-from", str(trusted))
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(document["decision"], "partial")
        self.assert_unevaluated_pairs(result, document, OBLIGATION_CONFIG)

        self.write_config(CONFIG)
        result, document = self.affected("--policy-from", str(trusted))
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "blocked")
        self.assert_unevaluated_pairs(result, document, OBLIGATION_CONFIG)

    def test_unknown_base_names_revision(self):
        self.commit_all()
        result, document = self.run_gate("--base", "qg-unknown-revision")
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn("--base 'qg-unknown-revision': expected an existing commit, got no such revision",
                      document["error"])
        self.assertEqual(document["obligations"], [])
        self.assertEqual(document["checks"], [])

    def test_failed_untracked_enumeration_is_a_preflight_usage_error(self):
        self.commit_all()
        environment = self.default_tool_env() | self.fake_git_failing_ls_files() | {"QG_AGENT": "0"}
        result, document = self.run_json("--base", "HEAD", env=environment)
        self.assertEqual(result.returncode, 2, output(result))
        self.assertEqual(document["decision"], "error")
        self.assertIn("--base 'HEAD': changed-file selection failed", document["error"])
        self.assertIn("simulated enumeration failure", document["error"])
        self.assertEqual(document["checks"], [])
        self.assertEqual(document["obligations"], [])

    def test_clean_diff_omits_ordinary_unittest_invocations(self):
        self.commit_all()
        result, document = self.affected("--only", "tests")
        self.assertEqual(result.returncode, 0, output(result))
        suite = self.checked(document)
        self.assertEqual(suite["outcome"], "not_run")
        self.assertEqual(suite["executed"], [])
        self.assertEqual(suite["selection"]["selected"], {})
        self.assertCountEqual(suite["selection"]["left_out"], [IMPORTING, OTHER])
        report = self.discover_shards(["-s", "tests"])
        self.assertEqual(report["selection"], suite["selection"])

    def test_full_run_keeps_configured_pattern_and_json_shape(self):
        command = [*UNITTEST_DISCOVER, "tests", "-p", "test_other.py"]
        self.write_config(CONFIG.replace(SHARD_COMMAND, json.dumps(command)))
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
        command = [*UNITTEST_DISCOVER, "-v", "-s", "tests"]
        self.write_config(CONFIG.replace(SHARD_COMMAND, json.dumps(command)))
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

    def test_untracked_only_diff_measures_added_tree_shape_helpers(self):
        self.write_config(SHAPE_CONFIG.replace('scope = "changed"\nbase = "HEAD"\ncrap_check',
                                               'scope = "tree"\nbase = "HEAD"\ncrap_check'))
        self.add_file(".gitignore", "__pycache__/\nignored.py\n")
        self.commit_all()
        base, _ = self.affected("--only", "shape")
        self.assertEqual(base.returncode, 0, output(base))

        created = {
            "pkg/new.py": "def added_helper():\n    return 1\n",
            "pkg/second.py": "value = 2\n",
        }
        for path, contents in created.items():
            self.add_file(path, contents)
        self.add_file("ignored.py", "def ignored_helper():\n    return 0\n")
        result, document = self.affected()
        self.assertCountEqual(document["changed_paths"], created.keys())
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(self.checked(document, "lint")["selection"]["selected"],
                         dict.fromkeys(created, "changed"))
        self.assert_runtime_suite(self.checked(document), [IMPORTING, OTHER])
        shape = self.checked(document, "shape")
        self.assertEqual(shape["outcome"], "fail")
        self.assertEqual(shape["measurement"]["added"], 1)
        self.assertEqual(
            [(row["measurement"]["rule"], row["measurement"]["file"]) for row in shape["findings"]],
            [("UNCALLED", "pkg/new.py")],
        )

    def test_committed_and_staged_changes_survive_unstaged_reverts(self):
        from quality_gate.files import affected_diff

        self.commit_all()
        self.add_file("pkg/a.py", "value = 2\n")
        self.commit_all("branch change")
        self.add_file("pkg/b.py", "import pkg.a\nvalue = 2\n")
        self.git("add", "pkg/b.py")
        self.add_file("pkg/b.py", "import pkg.a\n")
        diff = affected_diff(self.repo, "HEAD^")
        self.assertEqual(diff.base.commit, self.git("rev-parse", "HEAD^").stdout.strip())
        self.assertEqual(diff.changed_paths, {"pkg/a.py", "pkg/b.py"})
        self.assertEqual(diff.untracked_paths, set())
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
        self.assertEqual(self.checked(document)["selection"]["reason"], RUNTIME_REASON)

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
        report = self.discover_shards(["-s", "tests", "-j", "1"])
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

    def test_all_discovered_tests_skipped_with_or_without_policy_pattern(self):
        self.add_file("tests/test_importing.py", "")
        self.commit_all()
        self.write_test("other", decorator="    @unittest.skip('disabled')\n")
        for pattern in ("", r"skipped_pattern = 'skipped=(\d+)'"):
            with self.subTest(pattern=pattern):
                self.write_config(CONFIG + pattern + "\n")
                self.git("add", "quality-gate.toml")
                self.git("commit", "--allow-empty", "-m", "Configure skip reporting")
                result, document = self.affected()
                suite = self.checked(document)
                self.assertEqual(suite["outcome"], "fail")
                self.assertEqual(suite["measurement"], {"tests": 0})
                self.assertEqual(suite["skipped"], [OTHER])
                self.assertEqual(suite["selection"]["left_out"], {})
                self.assertNotIn("Ran 1 test", result.stderr)
                self.assertNotIn("Ran 1 test", suite["diagnostics"]["output_tail"])
                self.assertIn(f"skipped {OTHER}: disabled", result.stderr)

    def test_discovery_import_error_is_not_an_executed_test(self):
        self.change("tests/test_other.py", "raise ImportError('fixture discovery error')\n")
        result, document = self.affected()
        suite = self.checked(document)
        self.assertEqual(suite["outcome"], "fail")
        self.assertEqual(suite["executed"], [IMPORTING])
        self.assertEqual(suite["measurement"], {"tests": 1})
        self.assertIn("ImportError: fixture discovery error", suite["discovery_errors"][0])
        self.assertIn("ImportError: fixture discovery error", result.stderr)
        self.assertIn("Traceback (most recent call last)", result.stderr)
        self.assertNotIn("Ran 1 test", result.stderr)
        self.assertNotIn("Ran 1 test", suite["diagnostics"]["output_tail"])

    def test_clean_diff_still_reports_discovery_errors(self):
        self.add_file("tests/test_other.py", "raise ImportError('fixture discovery error')\n")
        self.commit_all()
        result, document = self.affected("--only", "tests")
        self.assertEqual(result.returncode, 1, output(result))
        suite = self.checked(document)
        self.assertEqual(document["changed_paths"], [])
        self.assertEqual(suite["executed"], [])
        self.assertIn("ImportError: fixture discovery error", suite["discovery_errors"][0])
        self.assertIn("fixture discovery error", result.stderr)

    def test_clean_diff_runs_source_less_discoveries(self):
        self.write_test("other", "del __file__\n")
        self.commit_all()
        result, document = self.affected("--only", "tests")
        self.assertEqual(result.returncode, 0, output(result))
        suite = self.checked(document)
        self.assertEqual(
            suite["selection"]["reason"], "full run: discovery returned a test without a source file",
        )
        self.assertEqual(suite["executed"], [IMPORTING, OTHER])
        report = self.discover_shards(["-s", "tests"])
        self.assertEqual(report["selection"], suite["selection"])
        self.add_file("pkg/a.py", "value = 2\n")
        result, document = self.affected("--only", "tests")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(self.checked(document)["selection"], suite["selection"])

    def test_completed_suite_accounts_for_class_and_module_setup_skips(self):
        self.add_file(
            "tests/test_class_skip.py",
            "import unittest\nclass Cases(unittest.TestCase):\n"
            "    @classmethod\n    def setUpClass(cls):\n        raise unittest.SkipTest('class setup')\n"
            "    def test_class_skip(self):\n        self.fail('not reachable')\n",
        )
        self.add_file(
            "tests/test_module_skip.py",
            "import unittest\ndef setUpModule():\n    raise unittest.SkipTest('module setup')\n"
            "class Cases(unittest.TestCase):\n    def test_module_skip(self):\n"
            "        self.fail('not reachable')\n",
        )
        self.change("pkg/a.py", "value = 2\n")
        result, document = self.affected("--only", "tests")
        self.assertEqual(result.returncode, 0, output(result))
        suite = self.checked(document)
        self.assertEqual(suite["executed"], [IMPORTING, OTHER])
        skipped = [
            "test_class_skip.Cases.test_class_skip", "test_module_skip.Cases.test_module_skip",
        ]
        self.assertCountEqual(suite["skipped"], skipped)
        self.assertEqual(suite["not_executed"], {})
        report = self.discover_shards(["-s", "tests"], full=RUNTIME_REASON)
        self.assertCountEqual(report["skipped"], skipped)

    def test_affected_discovery_refuses_a_suite_that_could_hide_a_fixture_skip(self):
        self.add_file("tests/test_incomplete.py", """\
import unittest

class Incomplete(unittest.TestSuite):
    def run(self, result, debug=False):
        first, omitted, passing = list(self)
        return unittest.TestSuite([first, passing]).run(result, debug)

class Blocked(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raise unittest.SkipTest("class setup")

    def test_first(self):
        self.fail("not reachable")

    def test_omitted(self):
        self.fail("not reachable")

class Passing(unittest.TestCase):
    def test_passes(self):
        pass

def load_tests(loader, suite, pattern):
    return Incomplete([Blocked("test_first"), Blocked("test_omitted"), Passing("test_passes")])
""")
        self.change("pkg/a.py", "value = 2\n")
        result, document = self.affected("--only", "tests")
        self.assertEqual(result.returncode, 1, output(result))
        suite = self.checked(document)
        self.assertEqual(suite["outcome"], "fail")
        self.assertIn("suite Incomplete in module test_incomplete", suite["reason"])
        self.assertIn("expected standard unittest suite execution", suite["reason"])
        self.assertEqual(suite["executed"], [])

    def test_affected_execution_rejects_missing_replayed_and_unexpected_occurrences(self):
        self.commit_all()
        case = "test_accounting.Changed.test_case"
        unexpected = "test_accounting.Unexpected.test_unscheduled"
        for invocation, diagnosis, outstanding in (
            ("return result", f"missing position 1 ({case!r})", [case]),
            ("super().run(result); super().run(result)", f"duplicated position 1 ({case!r})", []),
            ("Unexpected('test_unscheduled')(result)", f"unexpected unittest occurrence {unexpected!r}", [
                case, IMPORTING, OTHER,
            ]),
            ("result.stopTest(self)", f"occurrence {case!r} stopped without starting", [
                case, IMPORTING, OTHER,
            ]),
            ("result.startTest(self); result.startTest(self)", f"occurrence {case!r} started again", [
                case, IMPORTING, OTHER,
            ]),
        ):
            with self.subTest(invocation=invocation):
                self.add_file("tests/test_accounting.py", f"""\
import unittest

class Unexpected(unittest.TestCase):
    def test_unscheduled(self):
        pass

class Changed(unittest.TestCase):
    def run(self, result):
        {invocation}

    def test_case(self):
        pass

def load_tests(loader, suite, pattern):
    return unittest.TestSuite([Changed("test_case")])
""")
                result, document = self.affected("--only", "tests")
                self.assertEqual(result.returncode, 1, output(result))
                suite = self.checked(document)
                self.assertEqual(suite["outcome"], "fail")
                self.assertIn(diagnosis, suite["reason"])
                self.assertCountEqual(suite["not_executed"], outstanding)

    def test_affected_execution_accounts_for_fixture_failures(self):
        for scope, fixture in (
            ("class", "    @classmethod\n    def setUpClass(cls):\n"
             "        raise RuntimeError('class setup')\n"),
            ("module", "def setUpModule():\n    raise RuntimeError('module setup')\n"),
        ):
            definition = "class Cases(unittest.TestCase):\n"
            prefix = definition + fixture if scope == "class" else fixture + definition
            self.add_file(f"tests/test_{scope}_error.py", "import unittest\n" + prefix +
                          "    def test_first(self):\n        self.fail('not reachable')\n"
                          "    def test_second(self):\n        self.fail('not reachable')\n")
        self.change("pkg/a.py", "value = 2\n")
        result, document = self.affected("--only", "tests")
        self.assertEqual(result.returncode, 1, output(result))
        suite = self.checked(document)
        self.assertEqual(suite["executed"], [IMPORTING, OTHER])
        self.assertEqual(suite["skipped"], [])
        self.assertEqual(suite["not_executed"], {
            f"test_{scope}_error.Cases.test_{name}": "fixture setup failed"
            for scope in ("class", "module") for name in ("first", "second")
        })
        self.assertCountEqual(
            [finding["subject"] for finding in suite["findings"]],
            ["setUpClass (test_class_error.Cases)", "setUpModule (test_module_error)"],
        )
        for scope in ("class", "module"):
            self.assertIn(f"RuntimeError: {scope} setup", result.stderr)

    def test_duplicate_discovery_labels_cannot_overwrite_a_literal_id(self):
        self.add_file("tests/test_collision.py", """\
import unittest

class Cases(unittest.TestCase):
    def __init__(self, name):
        super().__init__("runTest")
        self.name = name

    def id(self):
        return self.name

    def runTest(self):
        pass

def load_tests(loader, suite, pattern):
    return unittest.TestSuite(Cases(name) for name in (
        "sample", "sample", "sample (discovery occurrence 1)",
        "sample (discovery occurrence 1) (duplicate)",
    ))
""")
        self.change("pkg/a.py", "value = 2\n")
        result, document = self.affected("--only", "tests")
        self.assertEqual(result.returncode, 0, output(result))
        suite = self.checked(document)
        self.assertCountEqual(suite["selection"]["selected"], [
            "sample (discovery occurrence 1) (duplicate) (duplicate)",
            "sample (discovery occurrence 2)",
            "sample (discovery occurrence 1)",
            "sample (discovery occurrence 1) (duplicate)",
            IMPORTING, OTHER,
        ])
        self.assertCountEqual(suite["executed"], suite["selection"]["selected"])
        self.assertEqual(suite["not_executed"], {})

    def test_passing_subtest_counts_even_with_a_skipped_subtest(self):
        self.commit_all()
        self.write_test("other", body="        with self.subTest('passes'):\n"
                                     "            self.assertTrue(True)\n"
                                     "        with self.subTest('skips'):\n"
                                     "            self.skipTest('disabled')\n")
        result, document = self.affected()
        self.assertEqual(result.returncode, 0, output(result))
        suite = self.checked(document)
        self.assertEqual(suite["measurement"], {"tests": 2})
        self.assertEqual(suite["executed"], [IMPORTING, OTHER])
        self.assertEqual(suite["skipped"], [])

    def test_opaque_suites_keep_full_run_verdict_counts_and_verification_findings(self):
        for name in ("other", "disabled"):
            self.write_test(name, decorator="    @unittest.skip('disabled by fixture')\n")
        self.add_file("tests/test_unmatched.py", "raise AssertionError('outside configured pattern')\n")
        argv = ["-m", "unittest", "discover", "tests", "-p", "test_[dio]*.py", "-v"]
        adapters = (
            ("command", ("python3", "-I"), "command adapter suite"),
            ("python_tests", ("{python}",), "custom Python test command"),
        )
        for adapter, executable, description in adapters:
            with self.subTest(adapter=adapter):
                self.assert_opaque_suite_parity(adapter, executable, argv, description)

    def assert_opaque_suite_parity(self, adapter, executable, argv, description):
        self.write_config(
            CONFIG.replace('adapter = "python_tests"', f'adapter = "{adapter}"')
            .replace(SHARD_COMMAND, json.dumps([*executable, *argv]))
            .replace('"lint", "tests", "chars"', '"lint", "tests", "chars", "verification"')
            + "skipped_pattern = 'skipped=(\\d+)'\n" + VERIFICATION
        )
        self.commit_all()
        full_result, full_document = self.run_gate()
        result, document = self.affected()
        suite = self.checked(document)
        full_suite = self.checked(full_document)
        self.assertEqual(result.returncode, full_result.returncode, output(result))
        self.assertEqual(suite["outcome"], full_suite["outcome"], output(result))
        self.assertEqual(suite["outcome"], "pass")
        self.assertEqual(suite["measurement"], full_suite["measurement"])
        self.assertEqual(suite["measurement"], {"tests": 1})
        for report in (suite, full_suite):
            self.assertEqual(report["diagnostics"]["argv"][-len(argv):], argv)
            self.assertIn("skipped=2", report["diagnostics"]["output_tail"])
        self.assertEqual(suite["selection"], {
            "selected": {}, "left_out": {}, "reason": f"full run: {description} is opaque",
        })
        self.assertNotIn("executed", suite)
        self.assertNotIn("skipped", suite)
        verification = self.checked(document, "verification")
        full_verification = self.checked(full_document, "verification")
        self.assertEqual(verification["outcome"], full_verification["outcome"])
        self.assertEqual(verification["findings"], full_verification["findings"])
        skipped = {row["subject"]: row["value"] for row in verification["findings"]}
        self.assertEqual(skipped["tests:tests:skipped"], 2)

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
        self.assert_runtime_suite(suite, [IMPORTING, "test_linked.Cases.test_linked", OTHER])

    def test_interrupted_suite_keeps_selection_and_completed_invocations(self):
        self.write_config(CONFIG + "budget_seconds = 3\n")
        self.add_file("tests/test_fixture.py", """\
import unittest

def setUpModule():
    raise RuntimeError("fixture failure before interruption")

class Blocked(unittest.TestCase):
    def test_blocked(self):
        self.fail("not reachable")
""")
        blocked = "test_fixture.Blocked.test_blocked"
        self.write_test("later")
        self.commit_all()
        self.write_test("importing", body="        self.assertTrue(1)\n")
        for body, execution in (
            ("        import time\n        time.sleep(60)\n", "budget"),
            ("        import os, signal\n        os.kill(os.getpid(), signal.SIGTERM)\n", "signal"),
            ("        import os, signal\n        os.kill(os.getpid(), signal.SIGINT)\n", "signal"),
            ("        import os\n        os._exit(0)\n", "completed"),
        ):
            with self.subTest(execution=execution):
                self.write_test("later", body=body)
                result, document = self.affected()
                self.assertEqual(result.returncode, 1, output(result))
                suite = self.checked(document)
                later = "test_later.Example.test_value"
                self.assertEqual(suite["execution"], execution)
                self.assertEqual(suite["selection"]["selected"], dict.fromkeys(
                    [blocked, IMPORTING, later, OTHER], RUNTIME_REASON,
                ))
                self.assertEqual(suite["selection"]["left_out"], {})
                self.assertEqual(suite["executed"], [IMPORTING])
                self.assertEqual(suite["measurement"], {"tests": 1})
                self.assertIn("RuntimeError: fixture failure before interruption", result.stderr)
                self.assertEqual([finding["subject"] for finding in suite["findings"]], [
                    "setUpModule (test_fixture)",
                ])
                self.assertEqual(suite["not_executed"], {
                    blocked: "fixture setup failed",
                    later: "invocation interrupted",
                    OTHER: "the run did not invoke this selected test",
                })

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

    def test_changed_initializer_reaches_every_per_file_check(self):
        self.enable_crap()
        self.add_file("pkg/a.py", "# \u202e\nvalue = 1\n")
        self.add_file("pkg/b.py", "import pkg.a\n# \u202e\n")
        self.add_file("pkg_consumer.py", "import pkg.b\n")
        self.write_config(self.read_file("quality-gate.toml") + """
[[rule]]
pattern = "pkg_consumer.py"
class = "source"
reason = "Consumer outside the package"
""")
        self.change("pkg/__init__.py", "value = 2\n")
        result, document = self.affected()
        self.assertEqual(document["changed_paths"], ["pkg/__init__.py"])
        self.assertEqual(self.checked(document)["outcome"], "pass", output(result))
        package = {
            "pkg/__init__.py": "changed",
            "pkg/a.py": "package initializer pkg/__init__.py changed",
            "pkg/b.py": "package initializer pkg/__init__.py changed",
        }
        lint = self.checked(document, "lint")
        self.assertEqual(lint["diagnostics"]["argv"][-4:], [*package, "pkg_consumer.py"])
        self.assertEqual(lint["selection"]["selected"], {**package, "pkg_consumer.py": "depends on pkg/b.py"})
        chars = self.checked(document, "chars")
        self.assertEqual(chars["selection"]["selected"], package)
        self.assertEqual(
            {finding["subject"] for finding in chars["findings"]}, {"pkg/a.py:U+202E", "pkg/b.py:U+202E"},
        )
        crap = self.checked(document, "crap")
        self.assertEqual(crap["selection"]["selected"], package)
        self.assertEqual(
            {finding["subject"] for finding in crap["findings"]}, {f"{path}:<module>" for path in package},
        )

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
        self.assert_runtime_suite(self.checked(document), [IMPORTING, OTHER])
        config = load_config(self.repo)
        files, classes, violations = validate_inventory(self.repo, config)
        self.assertEqual(violations, [])
        _, _, affected = affected_graph(self.repo, config, files, classes, self.base, {"pkg/source.sh"})
        self.assertEqual(affected["pkg/consumer.sh"], "depends on pkg/source.sh")

    def test_initializer_change_seeds_every_package_module(self):
        from quality_gate.module_graph import Edge, affected_paths

        edges = [Edge("consumer.py", "pkg/mod.py", 1)]
        states = (["consumer.py", "pkg/mod.py"], ["consumer.py", "pkg/mod.py", "pkg/__init__.py"])
        for nodes in states:
            with self.subTest(nodes=nodes):
                expanded, affected = affected_paths(nodes, edges, {"pkg/__init__.py"})
                self.assertEqual(expanded["pkg/mod.py"], "package initializer pkg/__init__.py changed")
                self.assertEqual(affected["consumer.py"], "depends on pkg/mod.py")

    def test_crap_remains_unsupported_when_entire_suite_executes_nothing(self):
        self.enable_crap()
        self.add_file("tests/test_importing.py", PYTHON_TEST_HEADER + "import pkg.a\n")
        self.add_file("tests/test_other.py", "")
        self.change("pkg/a.py", "value = 2\n")
        _, document = self.affected()
        self.assertEqual(self.checked(document)["outcome"], "fail")
        self.assertEqual(self.checked(document)["executed"], [])
        self.assertEqual(self.checked(document)["selection"]["reason"], RUNTIME_REASON)
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
        self.assertEqual(self.checked(document)["executed"], [IMPORTING, OTHER])
        crap = self.checked(document, "crap")
        self.assertEqual(crap["outcome"], "unsupported")
        self.assertEqual(crap["reason"], "coverage unreliable: tests did not pass")
        self.assertNotIn("measurement", crap)

    def test_shard_command_uses_ordinary_discovery_with_the_configured_pattern(self):
        argv = ["-s", "tests", "-p", "test_other.py", "-j", "1"]
        self.add_file("tests/test_importing.py", "raise AssertionError('pattern selected the wrong file')\n")
        configured = json.dumps(["{python}", str(SHARD_RUNNER), *argv])
        self.write_config(CONFIG.replace(SHARD_COMMAND, configured))
        self.commit_all()
        self.write_test("other", body="        self.assertEqual(1, 1)\n")
        result, document = self.affected()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(self.checked(document)["executed"], [OTHER])
        self.assertEqual(self.discover_shards(argv, full=RUNTIME_REASON)["executed"], [OTHER])

    def discover_shards(self, argv, *, full=None):
        from quality_gate.adapters import _read_affected_report

        plan = self.base / "plan.json"
        plan.write_text(json.dumps({
            "argv": argv, "full": full,
        }), encoding="utf-8")
        child = subprocess.run(
            [*self.python_prefix(), str(SHARD_RUNNER), "--affected", str(plan)],
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

    def test_ert_runtime_read_of_graph_node_rejects(self):
        self.write_elisp_config()
        before = "(defvar calc-value 1)\n"
        self.add_file("lisp/calc.el", before)
        self.add_file(
            "tests/suite.el",
            "(require 'ert)\n"
            "(ert-deftest reads-calc-as-data ()\n"
            "  (with-temp-buffer\n"
            '    (insert-file-contents "lisp/calc.el")\n'
            f"    (should (equal (buffer-string) {json.dumps(before)}))))\n"
            "(ert-run-tests-batch-and-exit)\n",
        )
        self.commit_all()
        base, baseline = self.run_gate("--only", "elisp")
        self.assertEqual(base.returncode, 0, output(base))
        self.assertEqual(self.checked(baseline, "elisp")["measurement"], {"tests": 1})

        self.add_file("lisp/calc.el", "(defvar calc-value 2)\n")
        result, document = self.affected("--only", "elisp")
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "rejected")
        self.assertEqual(document["changed_paths"], ["lisp/calc.el"])
        suite = self.checked(document, "elisp")
        self.assertEqual(suite["selection"]["selected"], {"tests/suite.el": RUNTIME_REASON})
        self.assertEqual(suite["outcome"], "fail")
        self.assertEqual(suite["measurement"], {"tests": 1})
        self.assertEqual([row["subject"] for row in suite["findings"]], ["reads-calc-as-data"])

    def assert_changed_elisp_suite_runs(self):
        result, document = self.affected("--only", "elisp")
        self.assertEqual(result.returncode, 0, output(result))
        suite = self.checked(document, "elisp")
        self.assertEqual(suite["selection"]["selected"], {"tests/suite.el": RUNTIME_REASON})
        self.assertEqual(suite["measurement"], {"tests": 1})

    def test_elisp_crap_remains_unsupported_for_empty_ert_suite(self):
        suite = self.check_elisp_crap_without_executed_tests("")
        self.assertEqual(suite["selection"]["reason"], RUNTIME_REASON)

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
