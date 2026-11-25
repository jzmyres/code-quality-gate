"""Exercise declared module interfaces through the check command."""
from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
from unittest import mock

from support import BASE_CONFIG, FixtureCase, baseline_text, output, with_clones

from quality_gate import adapters, checks, files, module_graph, runner
from quality_gate.files import validate_inventory
from quality_gate.policy import GateError, load_config

CONTRACT_CHECK = """\
[checks.module-contracts]
adapter = "module_contracts"
tier = 1
enforcement = "enforced"

"""
FIXTURE_MAP = """\
[modules.fixture]
files = ["*"]
entry_points = []
allowed_dependencies = []

"""
CONTRACT_MAP = """\
[modules.app]
files = ["app/*.py"]
entry_points = []
allowed_dependencies = ["library"]

[modules.library]
files = ["library/*.py"]
entry_points = ["library/z.py", "library/api.py"]
allowed_dependencies = []

"""
CONTRACT_CONFIG = BASE_CONFIG + CONTRACT_CHECK + CONTRACT_MAP
NO_ALLOWANCE = CONTRACT_CONFIG.replace('allowed_dependencies = ["library"]', "allowed_dependencies = []")
ENTRY_POINTS = ["library/api.py", "library/z.py"]


class ModuleContractTests(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        (self.repo / "a.py").unlink()
        self.add_file("app/main.py", "import app.helper\nimport library.api\n")
        self.add_file("app/helper.py", "value = 1\n")
        self.add_file("library/api.py", "value = 2\n")
        self.add_file("library/private.py", "value = 3\n")
        self.add_file("library/z.py", "value = 4\n")
        self.write_config(CONTRACT_CONFIG)
        self.git("add", "-A")

    def contract(self, code: int, *args: str, stage: bool = True, env: dict[str, str] | None = None):
        if stage:
            self.git("add", "-A")
        result, document = self.run_json(*args, env=env)
        self.assertEqual(result.returncode, code, output(result))
        self.assertEqual(
            [row["id"] for row in document["checks"][:3]], ["inventory", "hygiene", "module-contracts"],
        )
        return result, document, self.check_by_id(document, "module-contracts")

    def assert_interface(self, result, finding, *, target, failed, permitted=ENTRY_POINTS):
        self.assertEqual(finding, {
            "rule": "module-interface",
            "edge": {"source": "app/main.py", "line": 2, "target": target, "kind": "import"},
            "source_module": "app",
            "target_module": "library",
            "failed_conditions": failed,
            "permitted_entry_points": permitted,
        })
        for text in ("module-interface", f"app/main.py:2 -> {target} (import)", "app -> library",
                     *failed, f"permitted entry points: {json.dumps(permitted)}"):
            self.assertIn(text, result.stderr)

    def test_accepts_intra_module_private_and_cross_module_public_edges(self) -> None:
        _, _, check = self.contract(0)
        self.assertEqual(check["findings"], [])
        self.assertEqual(check["budget_seconds"], 600)

    def test_map_alone_does_not_enable_contracts(self) -> None:
        self.write_config(NO_ALLOWANCE.replace(CONTRACT_CHECK, ""))
        self.add_file("orphan.py", "value = 0\n")
        self.git("add", "-A")
        result = self.run_qg_process("check", "--json")
        self.assertEqual(result.returncode, 0, output(result))
        rows = json.loads(result.stdout)["checks"]
        self.assertEqual([row["id"] for row in rows], ["inventory", "hygiene", "smoke"])

    def test_enabled_check_rejects_missing_map_and_unknown_dependencies(self) -> None:
        for config, diagnostic in (
            (BASE_CONFIG + CONTRACT_CHECK, "[modules]: expected a table, got missing"),
            (CONTRACT_CONFIG.replace('["library"]', '["absent"]'),
             "modules.app.allowed_dependencies[0]: expected a declared module, got unknown module 'absent'"),
        ):
            with self.subTest(diagnostic=diagnostic):
                self.write_config(config)
                result = self.run_qg_process("check")
                self.assertEqual(result.returncode, 2, output(result))
                self.assertIn(f"{self.config_path}: {diagnostic}", result.stderr)

    def test_explicit_contract_selection_runs_once_with_builtins(self) -> None:
        self.write_config(NO_ALLOWANCE)
        _, document, check = self.contract(1, "--only", "module-contracts")
        self.assertEqual(document["selected"], ["module-contracts"])
        self.assertEqual(len(document["checks"]), 3)
        self.assertEqual(check["findings"][0]["failed_conditions"], ["dependency-not-allowed"])

    def test_extraction_uses_the_resolved_ownership_map(self) -> None:
        config = load_config(self.repo)
        files, classes, violations = validate_inventory(self.repo, config)
        self.assertEqual(violations, [])
        owners, findings = adapters.module_ownership(config, files, classes)
        self.assertEqual(findings, [])
        self.assertEqual(owners, {
            "app/helper.py": "app",
            "app/main.py": "app",
            "library/api.py": "library",
            "library/private.py": "library",
            "library/z.py": "library",
        })
        graph = adapters.extract_contract_graph(self.repo, config, owners, classes, self.base, findings)
        self.assertEqual(graph.modules, sorted(owners))
        self.assertEqual(findings, [])
        self.assertEqual(
            adapters.module_contract_findings(config, owners, graph, classes.tracked_code_paths), [],
        )

    def test_edge_kind_is_part_of_deduplication_and_ordering(self) -> None:
        config = load_config(self.repo)
        owners, findings = module_graph.resolve_ownership(
            config.modules, ("app/main.py", *ENTRY_POINTS, "library/private.py"),
            frozenset(("app/main.py", *ENTRY_POINTS, "library/private.py")),
        )
        self.assertEqual(findings, [])
        target = "library/private.py"
        path_load = module_graph.Edge("app/main.py", target, 1, "path-load")
        imported = module_graph.Edge("app/main.py", target, 1, "import")
        edges = [path_load, imported, path_load]
        findings = module_graph.interface_findings(config.modules, owners, edges)
        self.assertEqual([finding["edge"] for finding in findings], [imported.to_json(), path_load.to_json()])

    def test_rejects_an_allowed_dependency_on_a_private_file(self) -> None:
        self.add_file("app/main.py", "import app.helper\nimport library.private\n")
        result, _, check = self.contract(1)
        finding, = check["findings"]
        self.assert_interface(result, finding, target="library/private.py", failed=["target-not-entry-point"])

    def test_rejects_a_public_target_without_a_dependency_allowance(self) -> None:
        self.write_config(NO_ALLOWANCE)
        result, _, check = self.contract(1, "--only", "smoke")
        finding, = check["findings"]
        self.assert_interface(result, finding, target="library/api.py", failed=["dependency-not-allowed"])

    def test_reports_both_failures_and_empty_entry_points(self) -> None:
        self.write_config(NO_ALLOWANCE.replace(
            'entry_points = ["library/z.py", "library/api.py"]', "entry_points = []",
        ))
        result, _, check = self.contract(1)
        finding, = check["findings"]
        self.assert_interface(result, finding, target="library/api.py", permitted=[],
                              failed=["dependency-not-allowed", "target-not-entry-point"])

    def test_preserves_distinct_edges_when_the_diagnostic_tail_truncates(self) -> None:
        self.add_file("app/main.py", "import library.private, library.private\n" * 45)
        result, _, check = self.contract(1)
        self.assertTrue(check["diagnostics"]["output_truncated"])
        self.assertNotIn("app/main.py:1 ->", check["diagnostics"]["output_tail"])
        self.assertIn("app/main.py:1 ->", result.stderr)
        self.assertEqual([row["edge"]["line"] for row in check["findings"]], list(range(1, 46)))
        self.assertTrue(all(
            row["failed_conditions"] == ["target-not-entry-point"] for row in check["findings"]
        ))

    def assert_map_failure(self, *, stage=True):
        with mock.patch.object(adapters, "_extract_graph") as extract:
            result, document, check = self.contract(1, stage=stage)
        extract.assert_not_called()
        self.assertTrue(self.check_by_id(document, "inventory")["satisfied"])
        self.assertIsNone(check["budget_seconds"])
        return result, check["findings"]

    def test_staged_code_outside_modules_fails_independently_of_inventory(self) -> None:
        self.add_file("orphan.py", "value = 0\n")
        result, findings = self.assert_map_failure()
        self.assertIn(
            "module-contracts: uncovered-file: orphan.py: no declared module owner",
            result.stderr.splitlines(),
        )
        finding, = findings
        self.assertEqual((finding["rule"], finding["file"]), ("uncovered-file", "orphan.py"))

    def test_untracked_nonignored_code_outside_modules_fails(self) -> None:
        self.add_file("orphan.py", "value = 0\n")
        self.assertEqual(self.git("ls-files", "orphan.py").stdout, "")
        result, findings = self.assert_map_failure(stage=False)
        self.assertIn(
            "module-contracts: uncovered-file: orphan.py: no declared module owner",
            result.stderr.splitlines(),
        )
        self.assertEqual(findings[0]["file"], "orphan.py")

    def test_uncovered_non_utf8_path_is_retained_in_the_finding(self) -> None:
        path = "orphan\udcff.py"
        self.add_file(path, "value = 0\n")
        _, _, check = self.contract(1)
        self.assertEqual(check["findings"][0]["file"], path)
        self.assertIn(r"orphan\udcff.py", check["diagnostics"]["output_tail"])

    def test_distinct_owners_are_reported_in_sorted_order(self) -> None:
        self.write_config(CONTRACT_CONFIG.replace(
            'files = ["library/*.py"]', 'files = ["library/*.py", "app/*.py"]',
        ))
        result, findings = self.assert_map_failure()
        self.assertIn("app/main.py: multiple module owners: app, library", result.stderr)
        self.assertEqual([row["file"] for row in findings], ["app/helper.py", "app/main.py"])
        self.assertTrue(all(row["owners"] == ["app", "library"] for row in findings))

    def test_patterns_may_overlap_within_a_module(self) -> None:
        self.write_config(CONTRACT_CONFIG.replace(
            'files = ["app/*.py"]', 'files = ["app/*.py", "app/main.py"]',
        ))
        self.contract(0)

    def test_patterns_must_match_code_and_are_case_sensitive(self) -> None:
        self.write_config(CONTRACT_CONFIG.replace(
            'files = ["app/*.py"]', 'files = ["app/*.py", "README.md", "APP/*.py"]',
        ))
        result, findings = self.assert_map_failure()
        for index, pattern in enumerate(("README.md", "APP/*.py"), 1):
            key = f"modules.app.files[{index}]"
            self.assertIn(
                f"module-contracts: unused-pattern: {key}: pattern {pattern!r}"
                " matches no inventoried code file",
                result.stderr.splitlines(),
            )
            self.assertEqual(findings[index - 1]["key"], key)
            self.assertEqual(findings[index - 1]["module"], "app")

    def test_entry_points_must_exist_be_code_and_have_the_declared_owner(self) -> None:
        self.write_config(CONTRACT_CONFIG.replace(
            "entry_points = []", 'entry_points = ["missing.py", "README.md", "library/api.py"]', 1,
        ))
        result, findings = self.assert_map_failure()
        self.assertEqual([row["rule"] for row in findings], ["invalid-entry-point"] * 3)
        for row, reason in zip(findings, ("absent from inventory", "not an inventoried code file",
                                          "owned by library"), strict=True):
            self.assertEqual(row["module"], "app")
            self.assertEqual(row["reason"], reason)
            self.assertIn(f"{row['key']}: {row['file']}: {reason}", result.stderr)

    def test_entry_points_require_a_unique_owner(self) -> None:
        self.add_file("orphan.py", "value = 0\n")
        self.write_config(CONTRACT_CONFIG.replace(
            "entry_points = []", 'entry_points = ["orphan.py", "app/main.py"]', 1,
        ).replace('files = ["library/*.py"]', 'files = ["library/*.py", "app/main.py"]'))
        _, findings = self.assert_map_failure()
        self.assertEqual([row["reason"] for row in findings if row["rule"] == "invalid-entry-point"],
                         ["has no module owner", "has multiple module owners: app, library"])

    def test_all_code_requires_ownership_even_without_an_extractor(self) -> None:
        self.add_file("app/data.lua", "return 1\n")
        config = CONTRACT_CONFIG.replace('patterns = ["*.py",', 'patterns = ["*.lua", "*.py",')
        config += '\n[[rule]]\npattern = "*.lua"\nclass = "python"\nreason = "Lua source"\n'
        self.write_config(config)
        _, findings = self.assert_map_failure()
        self.assertEqual(findings[0]["file"], "app/data.lua")
        self.write_config(config.replace('files = ["app/*.py"]', 'files = ["app/*"]'))
        with mock.patch.object(module_graph, "dependencies", wraps=module_graph.dependencies) as extract:
            self.contract(0)
        self.assertNotIn("app/data.lua", extract.call_args.args[1])

    def test_empty_map_requires_a_code_free_tree(self) -> None:
        self.write_config(CONTRACT_CONFIG.replace(CONTRACT_MAP, "[modules]\n\n"))
        _, findings = self.assert_map_failure()
        self.assertEqual(len(findings), 5)
        for directory in ("app", "library"):
            shutil.rmtree(self.repo / directory)
        start = self.read_file("quality-gate.toml").index('[[rule]]\npattern = "*.py"')
        end = self.read_file("quality-gate.toml").index('[[rule]]\npattern = "*.md"')
        config = self.read_file("quality-gate.toml")
        self.write_config(config[:start] + config[end:])
        with mock.patch.object(adapters, "_extract_graph") as extract:
            _, _, check = self.contract(0)
        extract.assert_not_called()
        self.assertEqual(check["findings"], [])
        self.assertIsNone(check["budget_seconds"])

    def test_single_module_has_no_extraction(self) -> None:
        self.write_config(BASE_CONFIG + CONTRACT_CHECK + FIXTURE_MAP)
        with mock.patch.object(adapters, "_extract_graph") as extract, \
                mock.patch.object(checks, "_arm_run_limit", wraps=checks._arm_run_limit) as limit:
            _, _, check = self.contract(0)
        extract.assert_not_called()
        limit.assert_called_once_with(900)
        self.assertIsNone(check["budget_seconds"])

    def test_base_rejects_a_map_only_change_and_a_committed_violation_without_a_diff(self) -> None:
        self.commit_all()
        self.write_config(NO_ALLOWANCE)
        for expected in (["quality-gate.toml"], []):
            with self.subTest(changed=expected):
                result, document, check = self.contract(1, "--base", "HEAD")
                self.assertEqual(document["changed_paths"], expected)
                self.assert_interface(result, check["findings"][0], target="library/api.py",
                                      failed=["dependency-not-allowed"])
                if expected:
                    self.commit_all()

    def test_trusted_check_uses_the_effective_map_over_candidate_files(self) -> None:
        self.write_config(NO_ALLOWANCE)
        self.add_file("app/main.py", "import app.helper\n")
        self.commit_all()
        trusted = str(self.trusted_directory("HEAD"))
        self.write_config(CONTRACT_CONFIG)
        self.add_file("app/main.py", "import app.helper\nimport library.api\n")
        result, document, check = self.contract(1, "--policy-from", trusted)
        self.assertEqual(document["decision"], "blocked")
        self.assert_interface(result, check["findings"][0], target="library/api.py",
                              failed=["dependency-not-allowed"])
        self.contract(0, "--policy-from", trusted, "--allow-protected", "quality-gate.toml")

    def test_authorized_map_cannot_repair_an_invalid_trusted_policy_before_loading(self) -> None:
        self.write_config(BASE_CONFIG + CONTRACT_CHECK)
        self.commit_all()
        trusted = self.trusted_directory("HEAD")
        self.write_config(CONTRACT_CONFIG)
        self.git("add", "-A")
        result = self.run_qg_process(
            "check", "--policy-from", str(trusted), "--allow-protected", "quality-gate.toml",
        )
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn("[modules]: expected a table, got missing", result.stderr)

    def test_inventory_failure_skips_map_resolution_and_extraction(self) -> None:
        self.add_file("unknown.txt", "")
        with mock.patch.object(checks, "module_ownership") as ownership, \
                mock.patch.object(checks, "extract_contract_graph") as extract:
            result, _, check = self.contract(1)
        ownership.assert_not_called()
        extract.assert_not_called()
        self.assertIn("module-contracts: skipped because inventory failed", result.stderr)
        self.assertEqual(check["caused_by"], ["inventory"])
        self.assertIn("inventory", check["reason"])
        self.assertEqual(check["findings"], [])
        self.assertIsNone(check["budget_seconds"])

    def test_worklist_runs_its_configured_check_without_contracts(self) -> None:
        self.write_config(with_clones() + CONTRACT_CHECK + CONTRACT_MAP)
        self.add_file("quality-gate-clones.toml", baseline_text([]))
        self.add_file("orphan.py", "value = 0\n")
        self.git("add", "-A")
        with mock.patch.object(checks, "_run_module_contracts") as contracts:
            result = self.run_qg("worklist", "clones", "--json", env=self.install_fake_jscpd())
        contracts.assert_not_called()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertNotIn("module-contracts", output(result))

    def test_python_extraction_failure_blocks(self) -> None:
        self.add_file("app/main.py", "import (\n")
        result, _, check = self.contract(1)
        finding, = check["findings"]
        self.assertEqual(finding["rule"], "module-extraction")
        self.assertIn("app/main.py: expected readable, valid Python source", finding["message"])
        self.assertIn(finding["message"], result.stderr)

    def test_shell_source_edge_is_checked_with_the_pinned_parser(self) -> None:
        self.add_file("app/use.sh", "source ../library/private.sh\n")
        self.add_file("library/private.sh", "value=3\n")
        self.write_config(CONTRACT_CONFIG.replace('files = ["app/*.py"]', 'files = ["app/*"]')
                          .replace('files = ["library/*.py"]', 'files = ["library/*"]') + """
[[rule]]
pattern = "*.sh"
class = "python"
reason = "Shell source"
""")
        with mock.patch.object(adapters, "run", wraps=runner.run) as run:
            _, _, check = self.contract(1, env=self.default_tool_env())
        self.assertEqual([call.args[0][-1] for call in run.call_args_list],
                         ["app/use.sh"] * 3 + ["library/private.sh"] * 3)
        finding, = check["findings"]
        self.assertEqual(finding["edge"], {
            "source": "app/use.sh", "target": "library/private.sh", "line": 1, "kind": "source",
        })
        self.assertEqual(finding["failed_conditions"], ["target-not-entry-point"])

    def configure_elisp(self, source: str) -> None:
        self.add_file("app/use.el", source)
        self.add_file("library/fixture.el", "(provide 'fixture)\n")
        self.write_config(CONTRACT_CONFIG.replace('files = ["app/*.py"]', 'files = ["app/*"]')
                          .replace('files = ["library/*.py"]', 'files = ["library/*"]') + """
[[rule]]
pattern = "*.el"
class = "python"
reason = "Lisp source"
""")

    def test_elisp_require_uses_the_same_interface_rules(self) -> None:
        self.configure_elisp("(require 'fixture)\n")
        result, _, check = self.contract(1)
        finding, = check["findings"]
        self.assertEqual(finding["edge"], {
            "source": "app/use.el", "target": "library/fixture.el", "line": 1, "kind": "require",
        })
        self.assertEqual(finding["failed_conditions"], ["target-not-entry-point"])
        self.assertIn("app/use.el:1 -> library/fixture.el (require)", result.stderr)

    def test_elisp_reader_and_preparation_errors_block(self) -> None:
        for stage, line, source, detail in (
            ("reader", 3, "(require 'fixture)\n(provide 'use)\n(",
             f"End of file during parsing: {self.repo / 'app/use.el'}"),
            ("preparation", 4, "(require 'fixture)\n(provide 'use)\n;; Local Variables:\n"
             ';; read-symbol-shorthands: #1=(("f-" . "fixture-"))\n;; End:\n',
             'Invalid read syntax: "#1=", 1, 27'),
        ):
            with self.subTest(stage=stage):
                self.configure_elisp(source)
                result, _, check = self.contract(1)
                finding, = check["findings"]
                self.assertEqual(finding["rule"], "module-extraction")
                self.assertEqual(
                    (finding["file"], finding["line"], finding["stage"]), ("app/use.el", line, stage),
                )
                message = f"Emacs Lisp source with a {stage} error ({detail}) is outside the extractor"
                self.assertEqual(finding["message"], message)
                self.assertIn(
                    f"module-contracts: module-extraction: app/use.el:{line}: {message}",
                    result.stderr.splitlines(),
                )

    def test_elisp_reader_finding_survives_python_extraction_failure(self) -> None:
        self.configure_elisp("(provide 'use)\n(")
        self.add_file("app/main.py", "import (\n")
        result, _, check = self.contract(1)
        reader_message = (
            f"Emacs Lisp source with a reader error (End of file during parsing: {self.repo / 'app/use.el'})"
            " is outside the extractor"
        )
        python_message = (
            "app/main.py: expected readable, valid Python source, got invalid syntax (main.py, line 1)"
        )
        self.assertEqual(check["findings"], [
            {"rule": "module-extraction", "file": "app/use.el", "line": 2, "kind": "reader-error",
             "stage": "reader", "message": reader_message},
            {"rule": "module-extraction", "stage": "module graph dependencies", "message": python_message},
        ])
        self.assertIn(
            f"module-contracts: module-extraction: app/use.el:2: {reader_message}",
            result.stderr.splitlines(),
        )
        self.assertIn(f"module-contracts: module-extraction: {python_message}", result.stderr.splitlines())

    def test_elisp_outside_record_is_nonblocking(self) -> None:
        self.configure_elisp("(require (intern \"fixture\"))\n")
        _, _, check = self.contract(0)
        self.assertEqual(check["findings"], [])

    def test_emacs_launch_failure_blocks(self) -> None:
        self.configure_elisp("(provide 'use)\n")
        offline = runner.RunResult((), "error", None, error="offline")
        with mock.patch.object(adapters, "run", return_value=offline):
            _, _, check = self.contract(1)
        finding, = check["findings"]
        self.assertEqual(finding["rule"], "module-extraction")
        self.assertIn("cannot read Emacs Lisp module graph for app/use.el, library/fixture.el: offline",
                      finding["message"])

    def test_invalid_emacs_report_blocks(self) -> None:
        self.configure_elisp("(provide 'use)\n")

        def invalid_report(argv, **_):
            Path(argv[-1]).write_text(json.dumps({
                "app/use.el": [{"kind": "require", "line": 1, "target": "absent.el"}],
                "library/fixture.el": [],
            }), encoding="utf-8")
            return runner.RunResult((), "completed", 0)

        with mock.patch.object(adapters, "run", side_effect=invalid_report):
            _, _, check = self.contract(1)
        self.assertIn("app/use.el: invalid Emacs reader record", check["findings"][0]["message"])

    def test_multi_module_run_allocates_and_uses_the_contract_deadline(self) -> None:
        with mock.patch.object(checks, "check_deadline", wraps=runner.check_deadline) as deadline, \
                mock.patch.object(checks, "_arm_run_limit", wraps=checks._arm_run_limit) as limit:
            self.contract(0, "--only", "smoke")
        self.assertEqual([call.args[0] for call in deadline.call_args_list], ["module-contracts", "smoke"])
        self.assertEqual(deadline.call_args_list[0].args[2], 600)
        limit.assert_called_once_with(1500)

    def test_expiry_during_graph_or_edge_evaluation_blocks(self) -> None:
        for function, stage in (("dependencies", "module graph dependencies"),
                                ("interface_findings", "module interface evaluation")):
            original = getattr(module_graph, function)

            def expire(*args, original=original, **kwargs):
                graph = original(*args, **kwargs)
                deadline = runner._check_deadline.get()
                deadline.started -= deadline.seconds
                return graph

            with self.subTest(stage=stage), mock.patch.object(module_graph, function, side_effect=expire):
                _, _, check = self.contract(1)
                self.assertEqual(check["budget_seconds"], 600)
                self.assertEqual(check["execution"], "budget")
                self.assertEqual(check["findings"][-1]["stage"], stage)
                self.assertIn("deadline: 600 seconds", check["findings"][-1]["message"])

    def test_enclosing_run_timeout_preserves_error_path(self) -> None:
        with mock.patch.object(checks, "_run_limit", return_value=0.2), \
                mock.patch.object(module_graph, "dependencies", side_effect=lambda *_a, **_kw: time.sleep(2)):
            result, document = self.run_json()
        self.assertEqual(result.returncode, 2, output(result))
        self.assertEqual(document["decision"], "error")
        self.assertIn("during module-contracts: module graph dependencies", document["error"])

    def test_affected_selection_reuses_identical_language_inputs(self) -> None:
        self.commit_all()
        self.add_file("library/api.py", "value = 7\n")
        with mock.patch.object(module_graph, "dependencies", wraps=module_graph.dependencies) as extract:
            self.contract(0, "--base", "HEAD")
        extract.assert_called_once()

    def test_affected_selection_extracts_again_for_different_language_inputs(self) -> None:
        self.write_config(CONTRACT_CONFIG.replace(
            'patterns = ["*.py",', 'patterns = ["app/*.py", "library/*.py",',
        ))
        self.add_file("data.py", "value = 0\n")
        self.commit_all()
        self.add_file("data.py", "value = 1\n")
        with mock.patch.object(module_graph, "dependencies", wraps=module_graph.dependencies) as extract:
            _, document, _ = self.contract(0, "--base", "HEAD")
        contract, affected = [call.args[1] for call in extract.call_args_list]
        self.assertEqual(sorted([*contract, "data.py"]), affected)
        self.assertEqual(document["changed_paths"], ["data.py"])


class SharedSurfaceTests(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        (self.repo / "a.py").unlink()
        self.add_file("app/main.py", "import library.api\n")
        self.add_file("library/api.py", "value = 1\n")
        self.add_file("library/z.py", "value = 2\n")
        self.config = CONTRACT_CONFIG.replace(
            CONTRACT_CHECK, CONTRACT_CHECK.rstrip() + '\nshared_base = "HEAD"\n\n',
        ).replace("[modules.app]\n", '[modules.app]\nprotected_paths = ["README.md"]\n')
        self.write_config(self.config)
        self.commit_all()

    def contract(self, code: int, *args: str, env: dict[str, str] | None = None):
        result, document = self.run_json(*args, env=env)
        self.assertEqual(result.returncode, code, output(result))
        return result, document, self.check_by_id(document, "module-contracts")["findings"]

    def assert_shared_entry_point(self, *args: str, env: dict[str, str] | None = None):
        result, document, findings = self.contract(1, *args, env=env)
        finding, = findings
        self.assertEqual(finding["rule"], "shared-entry-point")
        self.assertEqual(finding["file"], "app/main.py")
        self.assertEqual(finding["module"], "app")
        self.assertEqual(finding["protected_path"], "README.md")
        for message in (finding["message"], "app/main.py", "README.md", "in module app"):
            self.assertIn(message, result.stderr)
        return document

    def change_feature(self) -> None:
        self.add_file("app/main.py", "import library.api\nvalue = 2\n")

    def assert_command_error(self, message: str, *args: str, env: dict[str, str] | None = None):
        result, document = self.run_json(*args, env=env)
        self.assertEqual(result.returncode, 2, output(result))
        self.assertEqual(document["decision"], "error")
        self.assertIn(message, document["error"])
        self.assertIn(message, result.stderr)
        return result

    def test_shared_entry_point_blocks_full_only_and_trusted_checks(self) -> None:
        trusted = self.trusted_directory("HEAD")
        self.write_config(self.config.replace('shared_base = "HEAD"\n', ""))
        self.change_feature()
        self.add_file("README.md", "# changed\n")
        self.assert_shared_entry_point("--policy-from", str(trusted))
        self.write_config(self.config)
        self.assert_shared_entry_point()
        self.assert_shared_entry_point("--only", "module-contracts")

    def test_committed_feature_and_staged_protected_edit_block_together(self) -> None:
        self.change_feature()
        self.contract(0)
        self.commit_all("feature")
        self.contract(0, "--base", "HEAD^")
        self.add_file("README.md", "# changed\n")
        self.git("add", "README.md")
        self.contract(0)
        document = self.assert_shared_entry_point("--base", "HEAD^")
        self.assertEqual(document["changed_paths"], ["README.md", "app/main.py"])

    def test_protected_rename_counts_as_an_edit(self) -> None:
        self.git("mv", "README.md", "MOVED.md")
        self.contract(0)
        self.change_feature()
        document = self.assert_shared_entry_point("--base", "HEAD")
        self.assertEqual(document["changed_paths"], ["MOVED.md", "README.md", "app/main.py"])

    def test_protected_deletion_reports_the_pair_when_its_inventory_rule_is_unmatched(self) -> None:
        (self.repo / "README.md").unlink()
        self.change_feature()
        for args in ((), ("--base", "HEAD")):
            with self.subTest(args=args), mock.patch.object(checks, "extract_contract_graph") as extract:
                document = self.assert_shared_entry_point(*args)
                extract.assert_not_called()
                inventory = self.check_by_id(document, "inventory")
                self.assertFalse(inventory["satisfied"])
                self.assertIn("pattern '*.md'): matches no file", inventory["diagnostics"]["output_tail"])

    def test_protected_file_replaced_by_directory_counts_as_an_edit(self) -> None:
        trusted = self.trusted_directory("HEAD")
        (self.repo / "README.md").unlink()
        self.add_file("README.md/description.md", "# replacement\n")
        self.change_feature()
        for args in ((), ("--base", "HEAD"), ("--policy-from", str(trusted))):
            with self.subTest(args=args):
                self.assert_shared_entry_point(*args)

    def test_protected_file_replaced_by_symlink_counts_as_an_edit(self) -> None:
        readme = self.repo / "README.md"
        readme.unlink()
        readme.symlink_to("library/api.py")
        self.change_feature()
        self.assert_shared_entry_point()

    def test_unclassified_code_can_be_a_uniquely_owned_feature(self) -> None:
        config = self.config.replace('pattern = "*.py"', 'pattern = "library/*.py"')
        config = config.replace("[code]", 'module_dirs = ["app", "library"]\n\n[code]')
        self.write_config(config)
        self.change_feature()
        self.add_file("README.md", "# changed\n")
        document = self.assert_shared_entry_point()
        inventory = self.check_by_id(document, "inventory")
        self.assertIn("app/main.py: unclassified", inventory["diagnostics"]["output_tail"])

    def test_pairs_are_ordered_and_protected_code_is_excluded_as_a_feature(self) -> None:
        self.write_config(self.config.replace('["README.md"]', '["library/z.py", "README.md"]'))
        self.add_file("README.md", "# changed\n")
        self.add_file("library/z.py", "value = 3\n")
        self.contract(0)
        self.change_feature()
        self.add_file("app/another.py", "value = 1\n")
        self.git("add", "app/another.py")
        _, _, findings = self.contract(1)
        self.assertEqual(
            [(row["file"], row["protected_path"]) for row in findings],
            [("app/another.py", "README.md"), ("app/another.py", "library/z.py"),
             ("app/main.py", "README.md"), ("app/main.py", "library/z.py")],
        )

    def test_tracked_target_with_two_caller_modules_blocks_on_empty_diff(self) -> None:
        self.add_file("library/z.py", "import library.api\n")
        self.write_config(self.config.replace('protected_paths = ["README.md"]\n', ""))
        self.commit_all("add an internal caller")
        result, document, findings = self.contract(1, "--base", "HEAD")
        self.assertEqual(document["changed_paths"], [])
        finding, = findings
        self.assertEqual(finding["rule"], "multi-module-file")
        self.assertEqual(finding["file"], "library/api.py")
        self.assertEqual(finding["modules"], ["app", "library"])
        self.assertIn(finding["message"], result.stderr)
        self.write_config(self.config.replace('shared_base = "HEAD"\n', ""))
        self.change_feature()
        self.add_file("README.md", "# changed\n")
        self.assertEqual(self.contract(0)[2], [])

    def test_multiple_callers_in_one_module_pass(self) -> None:
        self.add_file("app/another.py", "import library.api\n")
        self.commit_all("add another app caller")
        self.assertEqual(self.contract(0, "--base", "HEAD")[2], [])

    def test_multi_module_findings_excludes_transitive_callers(self) -> None:
        owners = {"app/main.py": "app", "library/z.py": "library", "library/api.py": "library"}
        edges = [
            module_graph.Edge("app/main.py", "library/z.py", 1),
            module_graph.Edge("library/z.py", "library/api.py", 1),
        ]
        self.assertEqual(module_graph.multi_module_findings(owners, edges, frozenset(owners)), [])

    def test_untracked_target_passes_until_added_to_the_index(self) -> None:
        self.add_file("library/z.py", "import library.api\n")
        self.commit_all("add an internal caller")
        self.git("rm", "--cached", "library/api.py")
        self.assertEqual(self.contract(0)[2], [])
        self.git("add", "library/api.py")
        self.assertEqual(self.contract(1)[2][0]["rule"], "multi-module-file")

    def test_base_precedence(self) -> None:
        self.change_feature()
        self.add_file("README.md", "# changed\n")
        self.commit_all("feature and shared edit")
        self.contract(0)
        self.assert_shared_entry_point(env={"QG_DIFF_BASE": "HEAD^"})
        self.contract(0, "--base", "HEAD", env={"QG_DIFF_BASE": "HEAD^"})
        self.assert_shared_entry_point("--base", "HEAD^", env={"QG_DIFF_BASE": "invalid"})
        self.write_config(self.config.replace('shared_base = "HEAD"', 'shared_base = "HEAD^"'))
        self.assert_shared_entry_point()
        self.contract(0, env={"QG_DIFF_BASE": "HEAD"})

    def test_affected_scope_uses_merge_base_and_override_uses_resolved_commit(self) -> None:
        self.git("checkout", "-b", "other")
        self.add_file("README.md", "# changed\n")
        self.commit_all("edit documentation on other branch")
        self.git("checkout", "main")
        self.add_file("README.md", "# changed\n")
        self.change_feature()
        self.commit_all("edit documentation and feature on main")
        self.assert_shared_entry_point("--base", "other")
        self.contract(0, env={"QG_DIFF_BASE": "other"})

    def test_invalid_base_is_a_command_error(self) -> None:
        invalid = "qg-unknown-revision"
        for args, env in ((("--base", invalid), None), ((), {"QG_DIFF_BASE": invalid}), ((), None)):
            with self.subTest(args=args, env=env):
                if not args and env is None:
                    self.write_config(self.config.replace(
                        'shared_base = "HEAD"', f'shared_base = "{invalid}"',
                    ))
                self.assert_command_error(invalid, *args, env=env)

    def test_invalid_base_is_a_command_error_with_an_unclassified_file(self) -> None:
        self.add_file("unknown.txt", "")
        invalid = "qg-unknown-revision"
        for args, env in ((("--base", invalid), None), ((), {"QG_DIFF_BASE": invalid})):
            with self.subTest(args=args, env=env):
                self.assert_command_error(invalid, *args, env=env)

    def test_unreadable_diff_is_a_command_error_with_an_unclassified_file(self) -> None:
        self.add_file("unknown.txt", "")
        original = files._git

        def unreadable_diff(root, args, operation):
            if args[0] == "diff":
                raise GateError(f"{operation} failed: unreadable diff")
            return original(root, args, operation)

        with mock.patch.object(files, "_git", side_effect=unreadable_diff):
            for args in ((), ("--base", "HEAD")):
                with self.subTest(args=args):
                    self.assert_command_error("unreadable diff", *args)

    def test_rejects_a_directory_in_the_base_even_if_the_candidate_removes_it(self) -> None:
        self.write_config(self.config.replace('protected_paths = ["README.md"]',
                                              'protected_paths = ["library"]'))
        self.commit_all("declare a directory as a protected path")
        trusted = self.trusted_directory("HEAD")
        self.change_feature()
        shutil.rmtree(self.repo / "library")
        for args in ((), ("--base", "HEAD"), ("--policy-from", str(trusted))):
            with self.subTest(args=args):
                result = self.assert_command_error("directory 'library'", *args)
                self.assertIn("modules.app.protected_paths[0]", result.stderr)

    def test_rejects_paths_missing_from_the_selected_base(self) -> None:
        self.add_file("docs/registry.md", "# registry\n")
        self.commit_all("add a registry after the comparison base")
        self.write_config(self.config.replace('["README.md"]', '["docs/registry.md"]'))
        self.contract(0)
        self.assert_command_error("no entry for 'docs/registry.md'", "--base", "HEAD^")
        self.assert_command_error("no entry for 'docs/registry.md'", env={"QG_DIFF_BASE": "HEAD^"})
        self.write_config(self.config.replace('["README.md"]', '["readme.md"]'))
        self.assert_command_error("no entry for 'readme.md'")

    def test_validates_paths_against_the_merge_base_in_affected_scope(self) -> None:
        self.git("checkout", "-b", "other")
        (self.repo / "README.md").unlink()
        self.commit_all("remove the protected file on the other branch")
        self.git("checkout", "main")
        self.add_file("README.md", "# changed\n")
        self.change_feature()
        self.commit_all("edit the protected file and a feature on main")
        self.assert_shared_entry_point("--base", "other")
        self.assert_command_error("no entry for 'README.md'", env={"QG_DIFF_BASE": "other"})

    def test_rejects_a_symlink_in_the_base(self) -> None:
        (self.repo / "registry.md").symlink_to("README.md")
        self.commit_all("add a symlink")
        self.write_config(self.config.replace('["README.md"]', '["registry.md"]'))
        self.assert_command_error("symlink 'registry.md'")

    def test_opted_out_policy_does_not_validate_paths_against_a_base(self) -> None:
        config = self.config.replace('shared_base = "HEAD"\n', "")
        self.write_config(config.replace('["README.md"]', '["library", "absent.md"]'))
        self.assertEqual(self.contract(0, "--base", "HEAD")[2], [])

    def test_rejects_invalid_protected_paths(self) -> None:
        for value in ('"README.md"', "[1]", '[""]', '["/README.md"]', '["docs/../README.md"]',
                      '["docs//README.md"]', '["READ*.md"]', '["README.m?"]', '["README.[m]d"]',
                      '["README.md", "README.md"]'):
            with self.subTest(value=value):
                self.write_config(self.config.replace('protected_paths = ["README.md"]',
                                                      f"protected_paths = {value}"))
                result = self.run_qg("check")
                self.assertEqual(result.returncode, 2, output(result))
                self.assertIn("modules.app.protected_paths", result.stderr)
        self.write_config(self.config.replace("[modules.library]\n",
                                              '[modules.library]\nprotected_paths = ["README.md"]\n'))
        result = self.run_qg("check")
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn("modules.library.protected_paths[0]", result.stderr)
        self.assertIn("duplicate 'README.md'", result.stderr)

    def test_rejects_malformed_shared_base(self) -> None:
        for value in ('"  "', '1', r'"HEAD\u0000"'):
            with self.subTest(value=value):
                self.write_config(self.config.replace('shared_base = "HEAD"', f"shared_base = {value}"))
                result = self.run_qg("check")
                self.assertEqual(result.returncode, 2, output(result))
                self.assertIn("checks.module-contracts.shared_base", result.stderr)
