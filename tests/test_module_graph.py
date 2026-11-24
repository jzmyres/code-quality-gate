from __future__ import annotations

import tomllib
from dataclasses import replace
from types import SimpleNamespace
from typing import Any
from unittest import mock

from support import BASE_CONFIG, GATE, FixtureCase

from quality_gate import adapters, module_graph, policy


def edge(source: str, target: str, line: int, kind: str = "import") -> dict[str, str | int]:
    return {"source": source, "target": target, "line": line, "kind": kind}


class ModuleGraphTests(FixtureCase):
    def configure_graph(self, options: str = "", *, elisp: bool = False) -> None:
        config = BASE_CONFIG + """
[checks.module-graph]
adapter = "module_graph"
tier = 1
enforcement = "enforced"
classes = ["python"]
""" + options
        if elisp:
            config += """
[[rule]]
pattern = "*.el"
class = "python"
reason = "Elisp measured by the graph"
"""
        self.write_config(config)

    def graph(self, exit_code: int) -> dict[str, Any]:
        result, document = self.run_json("--only", "module-graph")
        self.assertEqual(result.returncode, exit_code, result.stderr)
        return self.check_by_id(document, "module-graph")

    def test_module_graph_function_local_cycle(self) -> None:
        self.configure_graph()
        fixture = GATE / "tests/fixtures/module_graph/package.toml"
        for path, source in tomllib.loads(fixture.read_text(encoding="utf-8"))["files"].items():
            self.add_file(path, source)
        check = self.graph(1)
        finding, = check["findings"]
        a, b = "pkg/a.py", "pkg/b.py"
        self.assertIn(f"Cyclic import ({a} -> {b} -> {a})", finding["subject"])
        self.assertEqual(finding["measurement"], {
            "component": [a, b],
            "cycle": [edge(a, b, 2), edge(b, a, 1)],
        })
        self.assertEqual(finding["location"], f"{a}:2, {b}:1")
        self.add_file(b, "")
        self.assertEqual(self.graph(0)["findings"], [])

    def test_module_graph_component_and_acyclic_chain(self) -> None:
        self.configure_graph()
        for name, content in {
            "a": "import b\n",
            "b": "import c\n",
            "c": "import a\n",
            "d": "import e\n",
            "e": "import f\n",
            "f": "",
        }.items():
            self.add_file(f"{name}.py", content)
        finding, = self.graph(1)["findings"]
        self.assertEqual(finding["measurement"]["component"], ["a.py", "b.py", "c.py"])
        self.assertEqual(len(finding["measurement"]["cycle"]), 3)
        self.add_file("c.py", "import a\nimport b\n")
        finding, = self.graph(1)["findings"]
        self.assertEqual(finding["measurement"]["cycle"], [edge("b.py", "c.py", 1), edge("c.py", "b.py", 2)])
        self.add_file("b.py", "import c\nimport a\n")
        finding, = self.graph(1)["findings"]
        self.assertEqual(finding["measurement"]["cycle"], [edge("a.py", "b.py", 1), edge("b.py", "a.py", 2)])

    def test_module_graph_import_resolution(self) -> None:
        self.configure_graph()
        self.add_file("lib/__init__.py", "value = 2\n")
        self.add_file("lib/dep.py", "")
        self.add_file("lib/nested/consumer.py", (
            "from .. import dep\n"
            "from lib import dep, value\n"
            "import math\n"
            "from ... import dep\n"
            "import helper\n"
            "if TYPE_CHECKING:\n"
            "    import lib.dep\n"
        ))
        self.add_file("lib/nested/helper.py", "")
        source = "lib/nested/consumer.py"
        self.assertEqual(self.graph(0)["measurement"]["edges"], [
            edge(source, "lib/__init__.py", 2),
            edge(source, "lib/dep.py", 1),
            edge(source, "lib/dep.py", 2),
            edge(source, "lib/dep.py", 7),
            edge(source, "lib/nested/helper.py", 5),
        ])

    def test_module_graph_out_of_scope_submodule_falls_back_to_package(self) -> None:
        self.configure_graph()
        config = self.read_file("quality-gate.toml")
        rule = """
[classes.other]
code = true
description = "Python outside the graph"
checks = ["smoke"]

[[rule]]
pattern = "lib/outside.py"
class = "other"
reason = "excluded from the graph"

"""
        config = config.replace('pattern = "*.py"', 'pattern = "[ac]*.py"')
        self.write_config(config + rule + """
[[rule]]
pattern = "lib/__init__.py"
class = "python"
reason = "package measured by the graph"
""")
        self.add_file("lib/__init__.py", "")
        self.add_file("lib/outside.py", "invalid Python source")
        self.add_file("caller.py", "from lib import outside\nimport lib.outside\nfrom lib import *\n")
        graph = self.graph(0)["measurement"]
        self.assertNotIn("lib/outside.py", graph["modules"])
        self.assertEqual(graph["edges"], [
            edge("caller.py", "lib/__init__.py", 1),
            edge("caller.py", "lib/__init__.py", 3),
        ])

    def test_module_graph_suite_edges(self) -> None:
        self.configure_graph('suites = ["test_*.py"]\n')
        self.add_file("test_alpha.py", "import helper\nimport test_beta\n")
        self.add_file("test_beta.py", "")
        self.add_file("helper.py", "import test_beta\n")
        finding, = self.graph(1)["findings"]
        self.assertEqual(finding["measurement"], {"edge": edge("test_alpha.py", "test_beta.py", 2)})
        self.assertEqual(finding["location"], "test_alpha.py:2")
        self.configure_graph()
        self.assertEqual(self.graph(0)["findings"], [])

    def test_module_graph_syntax_error(self) -> None:
        self.configure_graph()
        self.add_file("broken.py", "def :\n")
        check = self.graph(1)
        self.assertEqual(check["outcome"], "error")
        self.assertIn("broken.py", check["reason"])
        self.assertIn("invalid syntax", check["reason"])
        self.assertNotIn("measurement", check)

    def test_module_graph_measurement(self) -> None:
        self.configure_graph()
        self.add_file("first.py", "import second\nimport second\n")
        self.add_file("second.py", "")
        self.add_file("note.md", "import first\n")
        self.assertEqual(self.graph(0)["measurement"], {
            "modules": ["a.py", "first.py", "second.py"],
            "edges": [edge("first.py", "second.py", 1), edge("first.py", "second.py", 2)],
            "fan_in": {"first.py": 0, "a.py": 0, "second.py": 1},
            "fan_out": {"first.py": 1, "a.py": 0, "second.py": 0},
            "value": 0,
            "threshold": 0,
        })

    def test_module_graph_elisp_top_level_require(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", "\n(require 'b)\n")
        self.add_file("b.el", "(provide 'b)\n")
        self.assertEqual(self.graph(0)["measurement"]["edges"], [edge("a.el", "b.el", 2, "require")])

    def test_module_graph_elisp_compile_time_require(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", "(eval-when-compile\n  (\n   require 'b))\n")
        self.add_file("b.el", "(provide 'b)\n")
        self.assertEqual(self.graph(0)["measurement"]["edges"], [edge("a.el", "b.el", 3, "require")])

    def test_module_graph_elisp_compile_time_shared_reader_label(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", (
            "(eval-when-compile\n"
            "  '#1=(alpha beta)\n"
            "  '#1#\n"
            "  (require 'b))\n"
        ))
        self.add_file("b.el", "(provide 'b)\n")
        self.assertEqual(self.graph(0)["measurement"]["edges"], [edge("a.el", "b.el", 4, "require")])

    def test_module_graph_elisp_compile_time_bare_list_reader_label(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", (
            "(eval-when-compile\n"
            "  #1=(alpha beta)\n"
            "  #1#\n"
            "  (require 'b))\n"
        ))
        self.add_file("b.el", "(provide 'b)\n")
        self.assertEqual(self.graph(0)["measurement"]["edges"], [edge("a.el", "b.el", 4, "require")])

    def test_module_graph_elisp_compile_time_symbol_reader_label(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", (
            "(eval-when-compile\n"
            "  #1=alpha\n"
            "  #1#\n"
            "  (require 'b))\n"
        ))
        self.add_file("b.el", "(provide 'b)\n")
        self.assertEqual(self.graph(0)["measurement"]["edges"], [edge("a.el", "b.el", 4, "require")])

    def test_module_graph_elisp_compile_time_character_literal(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", "(eval-when-compile\n  ?)\n  (require 'b))\n")
        self.add_file("b.el", "(provide 'b)\n")
        self.assertEqual(self.graph(0)["measurement"]["edges"], [edge("a.el", "b.el", 3, "require")])

    def test_module_graph_elisp_literal_filename(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", '(require \'b "c")\n')
        self.add_file("b.el", "(provide 'b)\n")
        self.add_file("c.el", "(provide 'c)\n")
        self.assertEqual(self.graph(0)["measurement"]["edges"], [edge("a.el", "c.el", 1, "require")])

    def test_module_graph_elisp_literal_filename_exact_fallback(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", '(require \'b "nested/target.el")\n(require \'b "missing")\n')
        self.add_file("nested/target.el", "")
        self.add_file("b.el", "(provide 'b)\n")
        measurement = self.graph(0)["measurement"]
        self.assertEqual(measurement["edges"], [edge("a.el", "nested/target.el", 1, "require")])
        self.assertNotIn("outside_extractor", measurement)

    def test_module_graph_elisp_reader_label(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", "(defconst fixture '#1=(alpha beta))\n(require 'b)\n")
        self.add_file("b.el", "(provide 'b)\n")
        self.assertEqual(self.graph(0)["measurement"]["edges"], [edge("a.el", "b.el", 2, "require")])

    def test_module_graph_elisp_top_level_labelled_require(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", "\n#1=\n(require 'b)\n")
        self.add_file("b.el", "(provide 'b)\n")
        self.assertEqual(self.graph(0)["measurement"]["edges"], [edge("a.el", "b.el", 2, "require")])

    def test_module_graph_elisp_dotted_literal_filename(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", '(require \'dotted-fixture "odd.name")\n')
        self.add_file("odd.name.el", "")
        self.add_file("other.el", "(provide 'dotted-fixture)\n")
        self.assertEqual(self.graph(0)["measurement"]["edges"], [edge("a.el", "odd.name.el", 1, "require")])

    def test_module_graph_elisp_literal_filename_prefers_el_suffix(self) -> None:
        self.configure_graph("""
[[rule]]
pattern = "odd.name"
class = "python"
reason = "Python script measured by the graph"
""", elisp=True)
        self.add_file("a.el", '(require \'dotted-fixture "odd.name")\n')
        self.add_file("odd.name", "#!/usr/bin/env python3\n")
        self.add_file("odd.name.el", "(provide 'dotted-fixture)\n")
        context = self.graph_context(["a.el", "odd.name", "odd.name.el"], ("odd.name.el",))
        result = adapters._run_module_graph(context)
        expected_edge = edge("a.el", "odd.name.el", 1, "require")
        self.assertEqual(result.measurement["edges"], [expected_edge])
        self.assertIn("odd.name", result.measurement["modules"])
        self.assertEqual(result.outcome, "fail")
        finding, = result.findings
        self.assertIn("a.el -> odd.name.el", finding.subject)
        self.assertEqual(finding.location, "a.el:1")
        self.assertEqual(finding.measurement, {"edge": expected_edge})

    def test_module_graph_elisp_noncanonical_literal_filenames(self) -> None:
        self.configure_graph(elisp=True)
        sep = chr(47)
        absolute_operand = sep + "program"
        operands = (
            "", "odd.name" + sep, "program.el" + sep, "a" + sep * 2 + "program",
            absolute_operand, sep.join(("dir", ".")), sep.join(("sub", "dir", "..")),
            sep.join((".", "program")), sep.join(("~", "program")),
            sep.join((chr(36) + "HOME", "program")), sep + ":" + absolute_operand,
        )
        program = "odd.name/.el"
        self.add_file(program, "(provide 'dotted-fixture)\n")
        targets = ["odd.name.el", "program.el", "a/program.el"]
        for path in targets:
            self.add_file(path, "")
        context = self.graph_context(["a.el", program, *targets], (program,))
        self.assert_rejected_require_filenames(context, "dotted-fixture", operands)

    def test_module_graph_elisp_literal_filename_allowlist(self) -> None:
        self.configure_graph(elisp=True)
        rejected = ("hold/~/program", "hold/a:b", "hold/\u212a")
        allowed = "hold/a1.b_c+d-e"
        targets = [f"{operand}.el" for operand in (*rejected, allowed)]
        for target in targets:
            self.add_file(target, "")
        context = self.graph_context(["a.el", *targets])
        self.assert_rejected_require_filenames(context, "fixture", rejected)
        self.add_file("a.el", f'\n(require \'fixture "{allowed}")\n')
        measurement = adapters._run_module_graph(context).measurement
        self.assertEqual(measurement["edges"], [edge("a.el", f"{allowed}.el", 2, "require")])
        self.assertNotIn("outside_extractor", measurement)

    def assert_rejected_require_filenames(
        self, context: adapters.AdapterContext, feature: str, operands: tuple[str, ...],
    ) -> None:
        for operand in operands:
            with self.subTest(operand=operand):
                self.add_file("a.el", f'\n(require \'{feature} "{operand}")\n')
                result = adapters._run_module_graph(context)
                self.assertEqual(result.measurement["edges"], [])
                self.assertEqual(result.outcome, "pass")
                self.assertEqual(result.findings, [])
                self.assertEqual(result.measurement.get("outside_extractor"), [
                    {"file": "a.el", "line": 2,
                     "message": "noncanonical require filename is outside the extractor"},
                ])

    def test_module_graph_elisp_top_level_progn_provider(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", "(require 'b)\n")
        self.add_file("b.el", "(progn (provide 'b) (require 'c))\n")
        self.add_file("c.el", "(provide 'c)\n(progn (progn (provide 'b)))\n")
        self.assertEqual(self.graph(0)["measurement"]["edges"], [edge("a.el", "b.el", 1, "require")])

    def test_module_graph_elisp_uninterned_provider_does_not_hide_edge(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", "\n(require 'fixture)\n")
        self.add_file("fixture.el", "(provide 'fixture)\n")
        context = self.graph_context(["a.el", "fixture.el", "decoy.el"], ("fixture.el",))
        expected_edge = edge("a.el", "fixture.el", 2, "require")
        for source, line in (("\n(\n provide '#:fixture)\n", 2),
                             ("(progn\n  (\n   provide '#:fixture))\n", 3)):
            with self.subTest(source=source):
                self.add_file("decoy.el", source)
                result = adapters._run_module_graph(context)
                self.assertEqual(result.measurement["edges"], [expected_edge])
                self.assertEqual(result.outcome, "fail")
                finding, = result.findings
                self.assertIn("a.el -> fixture.el", finding.subject)
                self.assertEqual(finding.location, "a.el:2")
                self.assertEqual(finding.measurement, {"edge": expected_edge})
                self.assertEqual(result.measurement.get("outside_extractor"), [
                    {"file": "decoy.el", "line": line,
                     "message": "uninterned provide feature is outside the extractor"},
                ])

    def test_module_graph_elisp_computed_operands(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", '(require (intern "b"))\n(require \'b (concat "b" ".el"))\n')
        self.add_file("b.el", "(provide 'b)\n")
        measurement = self.graph(0)["measurement"]
        self.assertEqual(measurement["edges"], [])
        self.assertEqual(measurement.get("outside_extractor"), [
            {"file": "a.el", "line": 1, "message": "computed require feature is outside the extractor"},
            {"file": "a.el", "line": 2, "message": "computed require filename is outside the extractor"},
        ])

    def test_module_graph_elisp_uninterned_require(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", (
            "(require '#:fixture)\n"
            "(eval-when-compile\n"
            "  (\n"
            "   require '#:fixture \"fixture\"))\n"
        ))
        self.add_file("fixture.el", "(provide 'fixture)\n")
        result = adapters._run_module_graph(self.graph_context(["a.el", "fixture.el"]))
        self.assertEqual(result.measurement["edges"], [])
        self.assertEqual(result.outcome, "pass")
        self.assertEqual(result.measurement.get("outside_extractor"), [
            {"file": "a.el", "line": line, "message": "uninterned require feature is outside the extractor"}
            for line in (1, 4)
        ])

    def test_module_graph_elisp_ignores_nested_requires_and_loads(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", (
            "(defun later () (require 'b))\n"
            "`(outer ,(require 'b))\n"
            "(eval-when-compile (progn (require 'b)))\n"
            '(load "b")\n'
            '(load-file "b.el")\n'
            "(require 'b)\n"
        ))
        self.add_file("b.el", "(provide 'b)\n")
        self.assertEqual(self.graph(0)["measurement"]["edges"], [edge("a.el", "b.el", 6, "require")])

    def test_module_graph_python_shebang_precedes_elisp_suffix(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("caller.el", "#!/usr/bin/env python3\nimport dep\n")
        self.add_file("dep.py", "")
        self.add_file("reader.el", "(require 'b)\n")
        self.add_file("b.el", "(provide 'b)\n")
        python_edge, *require_edges = self.graph(0)["measurement"]["edges"]
        self.assertEqual(
            (python_edge["source"], python_edge["target"], python_edge["line"]),
            ("caller.el", "dep.py", 2),
        )
        self.assertEqual(require_edges, [edge("reader.el", "b.el", 1, "require")])
        self.assertEqual(python_edge["kind"], "import")

    def graph_context(self, files: list[str], programs: tuple[str, ...] = ()) -> adapters.AdapterContext:
        config = policy.load_config(self.repo)
        check = config.checks["module-graph"]
        if programs:
            spec = SimpleNamespace(classes=check.spec.classes, suites=check.spec.suites, programs=programs)
            check = replace(check, spec=spec)
        classes = dict.fromkeys(files, "python")
        return adapters.AdapterContext(self.repo, config, check, files, classes, "check", {}, self.base)

    def test_module_graph_program_dependency(self) -> None:
        self.configure_graph()
        self.add_file("library.py", "import guarded\nimport program_cli\n")
        self.add_file("guarded.py", 'if __name__ == "__main__":\n    pass\n')
        self.add_file("program_cli.py", "")
        self.add_file("test_library.py", "import program_cli\n")
        files = ["library.py", "guarded.py", "program_cli.py", "test_library.py"]
        context = self.graph_context(files, ("program_*.py",))
        result = adapters._run_module_graph(context)
        self.assertEqual(result.outcome, "fail")
        finding, = result.findings
        self.assertIn("library.py -> program_cli.py", finding.subject)
        self.assertEqual(finding.location, "library.py:2")
        self.assertEqual(finding.measurement, {"edge": edge("library.py", "program_cli.py", 2)})

        self.add_file("library.py", "import guarded\n")
        result = adapters._run_module_graph(context)
        self.assertEqual(result.outcome, "pass")
        self.assertEqual(result.findings, [])
        self.assertEqual(result.measurement["edges"], [
            edge("library.py", "guarded.py", 1), edge("test_library.py", "program_cli.py", 1),
        ])

    def test_module_graph_programs_policy(self) -> None:
        self.configure_graph('programs = ["tools/*.py", "cli.py"]\n')
        spec = policy.load_config(self.repo).checks["module-graph"].spec
        self.assertEqual(spec.programs, ("tools/*.py", "cli.py"))
        self.configure_graph('programs = ["cli.py", 1]\n')
        with self.assertRaisesRegex(policy.ConfigError, r"checks\.module-graph\.programs.*expected"):
            policy.load_config(self.repo)

    def test_module_graph_duplicate_require_to_program(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", "(require 'b) (require 'b)\n")
        self.add_file("b.el", "(provide 'b)\n")
        context = self.graph_context(["a.el", "b.el"], ("b.el",))
        result = adapters._run_module_graph(context)
        self.assertEqual(result.outcome, "fail")
        finding, = result.findings
        expected_edge = edge("a.el", "b.el", 1, "require")
        self.assertEqual(result.measurement["edges"], [expected_edge])
        self.assertEqual(result.measurement["value"], 1)
        self.assertEqual(finding.measurement, {"edge": expected_edge})
        self.assertEqual(finding.location, "a.el:1")

    def test_module_graph_elisp_launch_failure(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", "(provide 'a)\n")
        context = self.graph_context(["a.el"])
        with mock.patch("quality_gate.runner.subprocess.Popen",
                        side_effect=FileNotFoundError("fixture cannot start Emacs")):
            result = adapters._run_module_graph(context)
        self.assertEqual(result.outcome, "error")
        self.assertEqual(result.diagnostics.error, (
            "cannot read Emacs Lisp module graph for a.el: cannot run command: fixture cannot start Emacs"
        ))

    def test_module_graph_empty_scope(self) -> None:
        self.configure_graph()
        config = policy.load_config(self.repo)
        check = config.checks["module-graph"]
        context = adapters.AdapterContext(self.repo, config, check, [], {}, "check", {}, self.base)
        result = adapters._run_module_graph(context)
        self.assertEqual(result.outcome, "pass")
        measurement, cycles, suite_edges, program_edges = module_graph.measure(self.repo, [], check.spec)
        self.assertEqual(result.measurement, measurement)
        self.assertEqual((measurement["modules"], cycles, suite_edges), ([], [], []))
        self.assertEqual(program_edges, [])

    def test_module_graph_classes_list_is_required(self) -> None:
        key = "checks.module-graph"
        with self.assertRaisesRegex(policy.ConfigError, r"classes.*expected.*got"):
            adapters._module_graph_spec({"classes": []}, self.repo, self.config_path, key)

    def test_module_graph_unknown_class(self) -> None:
        self.configure_graph()
        config = self.read_file("quality-gate.toml")
        self.write_config(config.replace('classes = ["python"]', 'classes = ["other"]'))
        check = self.graph(1)
        self.assertIn("checks.module-graph.classes", check["reason"])
        self.assertIn("other", check["reason"])

    def test_module_graph_measures_this_repository_directly(self) -> None:
        spec = module_graph.GraphSpec(("python", "test"), ("tests/test_*.py",))
        modules = [
            path.relative_to(GATE).as_posix()
            for directory in ("quality_gate", "tests")
            for path in (GATE / directory).glob("*.py")
        ]
        measurement, cycles, suite_edges, program_edges = module_graph.measure(GATE, modules, spec)
        (component, _), = cycles
        self.assertEqual(len(component), 23)
        self.assertTrue(all(path.startswith("quality_gate/") for path in component))
        self.assertEqual(len(suite_edges), 16)
        self.assertEqual(program_edges, [])
        self.assertIn(
            module_graph.Edge("tests/test_adapters.py", "tests/test_python_tests.py", 17),
            suite_edges,
        )
        self.assertEqual(measurement["modules"], sorted(modules))
        self.assertEqual(measurement["value"], 17)
