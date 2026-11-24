from __future__ import annotations

import subprocess
import sys
import tomllib
from collections import Counter
from contextlib import redirect_stderr
from dataclasses import replace
from io import StringIO
from types import SimpleNamespace
from typing import Any
from unittest import mock

from support import BASE_CONFIG, GATE, FixtureCase, output

from quality_gate import adapters, clones, module_graph, policy
from quality_gate import files as inventory


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

    def assert_elisp_outcomes(
        self,
        measurement: dict[str, Any],
        expected_edges: list[dict[str, Any]],
        expected_outside: list[dict[str, Any]] | None = None,
    ) -> None:
        def counts(edges: list[dict[str, Any]], outside: list[dict[str, Any]]) -> Counter[tuple[str, int]]:
            locations = Counter((row["source"], row["line"]) for row in edges if row["kind"] == "require")
            locations.update((row["file"], row["line"]) for row in outside)
            return locations

        edges = measurement["edges"]
        outside = measurement.get("outside_extractor", [])
        expected_outside = expected_outside or []
        self.assertEqual(counts(edges, outside), counts(expected_edges, expected_outside))
        self.assertEqual(edges, expected_edges)
        self.assertEqual(outside, expected_outside)

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

    def test_module_graph_resolves_literal_path_loads(self) -> None:
        self.configure_graph()
        fixtures = {
            "module": ("import runpy\nrunpy.run_path('../target.py')", 2),
            "global_read": ("import runpy\ndef f():\n global runpy\n runpy.run_path('../target.py')", 4),
            "method": (
                "import runpy\nclass C:\n other = 1\n def f(self):\n  runpy.run_path('../target.py')", 5,
            ),
            "runpy_keyword": ("import runpy\nrunpy.run_path(path_name='../target.py')", 2),
            "spec_positional": (
                "import importlib.util\n"
                "importlib.util.spec_from_file_location('target', '../target.py')", 2,
            ),
            "spec_keyword": (
                "import importlib.util\n"
                "importlib.util.spec_from_file_location(location='../target.py', name='target')", 2,
            ),
            "same_line": ("import runpy; runpy.run_path('../target.py')", 1),
            "lambda": ("import runpy\nf = lambda: runpy.run_path('../target.py')", 2),
            "argument_default": ("import runpy\ndef f(x: object = runpy.run_path('../target.py')): pass", 2),
            "variable_value": ("import runpy\nvalue: object = runpy.run_path('../target.py')", 2),
        }
        self.add_file("target.py", "")
        for name, (source, _) in fixtures.items():
            self.add_file(f"fixtures/{name}.py", source + "\n")
        measurement = self.graph(0)["measurement"]
        self.assertEqual(measurement["edges"], [
            edge(f"fixtures/{name}.py", "target.py", line, "path-load")
            for name, (_, line) in sorted(fixtures.items())
        ])
        self.assertNotIn("outside_extractor", measurement)

    def test_module_graph_refuses_other_bindings_anywhere_in_the_file(self) -> None:
        self.configure_graph()
        fixtures = {
            "parameter": "def f(runpy): pass",
            "local": "def f(): runpy = other",
            "delete": "del runpy",
            "closure": "def f(runpy):\n def g(): return runpy",
            "comprehension": "def f():\n return [runpy for runpy in items]",
            "module_comprehension": "[runpy for runpy in items]",
            "generator": "(runpy for runpy in items)",
            "method": "class C:\n def f(self, runpy): pass",
            "class": "class C:\n runpy = other",
            "module_assignment": "runpy = other",
            "global_assignment": "def f():\n global runpy\n runpy = other",
            "global_import": "def f():\n global runpy\n import runpy",
            "global_walrus": "[(runpy := x) for x in items]",
            "local_annotation": "def f():\n runpy: object",
            "type_parameter": "def f[runpy](): pass",
            "type_alias": "type runpy = object",
            "duplicate_import": "import runpy",
            "conditional_import": "try:\n import runpy\nexcept ImportError: pass",
            "local_import": "def f(): import runpy",
            "relative_import": "from . import runpy",
            "lambda_parameter": "lambda runpy: None",
            "pattern": "match other:\n case {'key': runpy}: pass",
            "except_alias": "try: pass\nexcept Error as runpy: pass",
            "inlined_class_comprehension": "class C:\n value = [runpy for runpy in items]",
        }
        self.add_file("target.py", "")
        context = self.graph_context(["caller.py", "target.py"])
        for name, binding in fixtures.items():
            with self.subTest(name=name):
                self.add_file("caller.py", f"import runpy\nrunpy.run_path('target.py')\n{binding}\n")
                measurement = adapters._run_module_graph(context).measurement
                self.assertEqual(measurement["edges"], [])
                self.assert_unresolved_path_loads(measurement, (2,), "binding")

    def test_module_graph_reports_unresolved_loader_references(self) -> None:
        self.configure_graph()
        fixtures = {
            "alias": ("import runpy as r\nr.run_path('target.py')", 2, "canonical"),
            "dotted_alias": (
                "import importlib.util as ilu\nilu.spec_from_file_location('n', 'target.py')", 2, "canonical",
            ),
            "parent_only": (
                "import importlib\nimportlib.util.spec_from_file_location('n', 'target.py')",
                2, "top-level import importlib.util",
            ),
            "parent_and_submodule": (
                "import importlib\nimport importlib.util\n"
                "importlib.util.spec_from_file_location('n', 'target.py')", 3, "binding",
            ),
            "missing": ("runpy.run_path('target.py')", 1, "top-level import runpy"),
            "try_import": (
                "try:\n import runpy\nexcept ImportError: pass\nrunpy.run_path('target.py')",
                4, "top-level import runpy",
            ),
            "early_call": ("runpy.run_path('target.py')\nimport runpy", 1, "before"),
            "early_definition": ("def f():\n runpy.run_path('target.py')\nimport runpy", 2, "before"),
            "star": ("import runpy\nfrom other import *\nrunpy.run_path('target.py')", 3, "star import"),
            "computed": ("import runpy\nrunpy.run_path(path)", 2, "string literal"),
            "outside": ("import runpy\nrunpy.run_path('not_measured.py')", 2, "'not_measured.py'"),
            "unpacked_path": ("import runpy\nrunpy.run_path(*args)", 2, "positional argument unpacking"),
            "unpacked_keyword": (
                "import runpy\nrunpy.run_path('target.py', **kwargs)", 2, "keyword argument unpacking",
            ),
            "duplicate_operand": (
                "import runpy\nrunpy.run_path('target.py', path_name='target.py')", 2, "argument",
            ),
            "duplicate_keyword": (
                "import runpy\nrunpy.run_path(path_name='target.py', run_name='a', run_name='b')",
                2, "repeated keyword argument",
            ),
            "extra_positional": ("import runpy\nrunpy.run_path('target.py', {}, 'n', 0)", 2, "argument"),
            "unknown_keyword": ("import runpy\nrunpy.run_path('qg.py', bogus=True)", 2, "argument"),
            "missing_name": (
                "import importlib.util\nimportlib.util.spec_from_file_location(location='qg.py')",
                2, "argument",
            ),
            "destructured": (
                "import runpy\nload, = (runpy.run_path,)\nload('target.py')", 2, "not called directly",
            ),
            "chained_assignment": (
                "import runpy\nload = other = runpy.run_path\nload('target.py')", 2, "not called directly",
            ),
            "multiline_alias": (
                "import runpy\nrp = (runpy\n .run_path)\nrp('target.py')", 3, "not called directly",
            ),
            "as_argument": ("import runpy\nregister(runpy.run_path)", 2, "not called directly"),
            "complex_receiver": ("factory().run_path('target.py')", 1, "canonical"),
            "local_annotation": (
                "import runpy\ndef f():\n value: runpy.run_path('target.py')", 3, "annotation",
            ),
        }
        self.add_file("qg.py", "")
        self.add_file("target.py", "")
        context = self.graph_context(["caller.py", "qg.py", "target.py"])
        for name, (source, line, reason) in fixtures.items():
            with self.subTest(name=name):
                self.add_file("caller.py", source + "\n")
                measurement = adapters._run_module_graph(context).measurement
                self.assertEqual(measurement["edges"], [])
                self.assert_unresolved_path_loads(measurement, (line,), reason)

    def test_module_graph_reports_loader_imports(self) -> None:
        self.configure_graph()
        self.add_file("qg.py", "")
        context = self.graph_context(["caller.py", "qg.py"])
        fixtures = {
            "class_body": (
                "from runpy import run_path as __module__\nclass C:\n __module__('qg.py')\n",
                ((1, "run_path: a from import"),),
            ),
            "destructured": (
                "from runpy import run_path as rp\na, = (rp,)\na('qg.py')\n",
                ((1, "run_path: a from import"),),
            ),
            "chained_alias": (
                "from runpy import run_path as rp\na = rp; b = a\nb('qg.py')\n",
                ((1, "run_path: a from import"),),
            ),
            "direct_call": (
                "from runpy import run_path\nrun_path('qg.py')\n",
                ((1, "run_path: a from import"), (2, "canonical")),
            ),
            "spec_without_name": (
                "from importlib.util import spec_from_file_location\n"
                "spec_from_file_location(location='qg.py')\n",
                ((1, "spec_from_file_location: a from import"), (2, "canonical")),
            ),
            "spelled_assignment": (
                "from runpy import run_path\nrp = run_path\na = rp; b = a\nb('qg.py')\n",
                ((1, "run_path: a from import"), (2, "not called directly")),
            ),
            "multiple_imports": (
                "from other import run_path as rp, spec_from_file_location, something as run_path\n",
                ((1, "run_path: a from import"), (1, "spec_from_file_location: a from import")),
            ),
        }
        for name, (source, expected) in fixtures.items():
            with self.subTest(name=name):
                self.add_file("caller.py", source)
                measurement = adapters._run_module_graph(context).measurement
                self.assertEqual(measurement["edges"], [])
                lines = tuple(line for line, _ in expected)
                self.assert_unresolved_path_loads(measurement, lines, "unresolved path load")
                for row, (_, reason) in zip(measurement["outside_extractor"], expected, strict=True):
                    self.assertIn(reason, row["message"])

    def test_module_graph_reports_postponed_parameter_annotation(self) -> None:
        self.configure_graph()
        self.add_file("qg.py", "")
        self.add_file("caller.py", (
            "from __future__ import annotations\n"
            "import runpy\n"
            "value: runpy.run_path('qg.py')\n"
            "def f(x: runpy.run_path('qg.py')): pass\n"
        ))
        measurement = adapters._run_module_graph(self.graph_context(["caller.py", "qg.py"])).measurement
        self.assertEqual(measurement["edges"], [])
        self.assert_unresolved_path_loads(measurement, (3, 4), "annotation")

    def test_module_graph_reports_loader_references_in_annotations(self) -> None:
        self.configure_graph()
        fixtures = {
            "postponed_return": (
                "from __future__ import annotations\n"
                "import runpy\n"
                "value: runpy.run_path('qg.py')\n"
                "def f() -> runpy.run_path('qg.py'): pass\n",
                (3, 4),
            ),
            "eager": (
                "import runpy\n"
                "value: runpy.run_path('qg.py')\n"
                "def f(arg: runpy.run_path('qg.py')) -> (\n"
                "    runpy.run_path('qg.py')\n"
                "): pass\n",
                (2, 3, 4),
            ),
            "type_alias": ("import runpy\ntype Alias = runpy.run_path('qg.py')\n", (2,)),
            "type_bound": ("import runpy\ndef f[T: runpy.run_path('qg.py')](): pass\n", (2,)),
            "references": (
                "import runpy\nvalue: tuple[\n    runpy.run_path,\n    run_path('qg.py'), run_path,\n]\n",
                (3, 4, 4),
            ),
        }
        if sys.version_info >= (3, 13):
            fixtures["type_defaults"] = (
                "import runpy\n"
                "type Alias[\n"
                "    T = runpy.run_path('qg.py'),\n"
                "    *Ts = *tuple[runpy.run_path('qg.py')],\n"
                "    **P = [runpy.run_path('qg.py')],\n"
                "] = tuple[T, *Ts]\n",
                (3, 4, 5),
            )
        self.add_file("qg.py", "")
        context = self.graph_context(["caller.py", "qg.py"])
        for name, (source, lines) in fixtures.items():
            with self.subTest(name=name):
                self.add_file("caller.py", source)
                measurement = adapters._run_module_graph(context).measurement
                self.assertEqual(measurement["edges"], [])
                self.assert_unresolved_path_loads(measurement, lines, "annotation")

    def assert_unresolved_path_loads(
        self, measurement: dict[str, Any], lines: tuple[int, ...], reason: str, *, source: str = "caller.py",
    ) -> None:
        diagnostics = measurement.get("outside_extractor", [])
        locations = [(row["file"], row["line"]) for row in diagnostics]
        self.assertEqual(locations, [(source, line) for line in lines])
        for diagnostic in diagnostics:
            self.assertIn("unresolved", diagnostic["message"])
            self.assertIn(reason, diagnostic["message"])

    def test_module_graph_refuses_repository_loader(self) -> None:
        self.configure_graph()
        self.add_file("target.py", "")
        fixtures = (
            ("runpy", "runpy.run_path('target.py')", "runpy/run_path.py"),
            ("runpy", "runpy.run_path('target.py')", "vendor/runpy.py"),
            ("importlib.util", "importlib.util.spec_from_file_location('target', 'target.py')",
             "vendor/importlib/util.py"),
        )
        for imported, call, shadow in fixtures:
            with self.subTest(shadow=shadow):
                self.add_file(shadow, "")
                self.add_file("caller.py", f"import {imported}\n{call}\n")
                measurement = adapters._run_module_graph(
                    self.graph_context(["caller.py", "target.py", shadow]),
                ).measurement
                self.assertEqual(measurement["edges"], [])
                self.assert_unresolved_path_loads(measurement, (2,), shadow)

    def test_module_graph_keeps_ordinary_import_edge_to_repository_loader(self) -> None:
        self.configure_graph()
        self.add_file("target.py", "")
        self.add_file("importlib/util.py", "")
        self.add_file("caller.py", (
            "import importlib.util\nimportlib.util.spec_from_file_location('n', 'target.py')\n"
        ))
        measurement = adapters._run_module_graph(
            self.graph_context(["caller.py", "target.py", "importlib/util.py"]),
        ).measurement
        self.assertEqual(measurement["edges"], [edge("caller.py", "importlib/util.py", 1)])
        self.assert_unresolved_path_loads(measurement, (2,), "importlib/util.py")

    def test_module_graph_refuses_unmeasured_repository_loader(self) -> None:
        self.configure_graph()
        self.add_file("target.py", "")
        for folder, filename, diagnostic_path in (
            ("namespace", "util.py", "namespace/runpy"),
            ("package", "__init__.py", "package/runpy/__init__.py"),
        ):
            with self.subTest(folder=folder):
                self.add_file(f"{folder}/runpy/{filename}", "")
                source = f"{folder}/caller.py"
                self.add_file(source, "import runpy\nrunpy.run_path('../target.py')\n")
                context = self.graph_context([source, "target.py"])
                measurement = adapters._run_module_graph(context).measurement
                self.assertEqual(measurement["edges"], [])
                self.assert_unresolved_path_loads(measurement, (2,), repr(diagnostic_path), source=source)

    def test_module_graph_path_loads_count_as_program_dependencies(self) -> None:
        self.configure_graph('programs = ["target.py"]\n')
        self.add_file("target.py", "")
        self.add_file("caller.py", "import runpy\nrunpy.run_path('target.py'); runpy.run_path('target.py')\n")
        check = self.graph(1)
        expected = edge("caller.py", "target.py", 2, "path-load")
        self.assertEqual(check["measurement"]["edges"], [expected, expected])
        finding, = check["findings"]
        self.assertEqual(finding["measurement"], {"edge": expected})

    def test_module_graph_python_path_load_reaches_elisp_module(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("caller.py", "import runpy\nrunpy.run_path('target.el')\n")
        self.add_file("target.el", "")
        measurement = self.graph(0)["measurement"]
        self.assertEqual(measurement["edges"], [edge("caller.py", "target.el", 2, "path-load")])
        self.assertNotIn("outside_extractor", measurement)

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
        self.assert_elisp_outcomes(self.graph(0)["measurement"], [edge("a.el", "b.el", 2, "require")])

    def test_module_graph_elisp_compile_time_require(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", "(eval-when-compile\n  (\n   require 'b))\n")
        self.add_file("b.el", "(provide 'b)\n")
        self.assert_elisp_outcomes(self.graph(0)["measurement"], [edge("a.el", "b.el", 3, "require")])

    def test_module_graph_elisp_compile_time_shared_reader_label(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", (
            "(eval-when-compile\n"
            "  '#1=(alpha beta)\n"
            "  '#1#\n"
            "  (require 'b))\n"
        ))
        self.add_file("b.el", "(provide 'b)\n")
        self.assert_reader_label_refused(self.graph(0)["measurement"], "a.el", 2, [])

    def test_module_graph_elisp_shared_require_head(self) -> None:
        self.assert_labelled_require_refused(
            "(eval-when-compile\n"
            "  '#1=require\n"
            "  (#1# 'fixture)\n"
            "  (#1# 'fixture))\n"
        )

    def test_module_graph_elisp_shared_require_operands(self) -> None:
        self.assert_labelled_require_refused(
            "(eval-when-compile\n"
            "  '#1=fixture\n"
            '  \'#2="fixture"\n'
            "  '#3='fixture\n"
            "  (require '#1#)\n"
            "  (require 'fixture #2#)\n"
            "  (require #3#)\n"
            "  '#4=[(require 'fixture) #4#]\n"
            "  '#5=(require 'fixture)\n"
            "  #5#\n"
            '  (require \'fixture "fixture"))\n'
        )

    def assert_labelled_require_refused(self, source: str) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", source)
        self.add_file("fixture.el", "(provide 'fixture)\n")
        context = self.graph_context(["a.el", "fixture.el"], ("fixture.el",))
        result = adapters._run_module_graph(context)
        self.assert_reader_label_refused(result.measurement, "a.el", 2, [])
        self.assertEqual(result.outcome, "pass")
        self.assertEqual(result.findings, [])

    def test_module_graph_elisp_compile_time_bare_list_reader_label(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", (
            "(eval-when-compile\n"
            "  #1=(alpha beta)\n"
            "  #1#\n"
            "  (require 'b))\n"
        ))
        self.add_file("b.el", "(provide 'b)\n")
        self.assert_reader_label_refused(self.graph(0)["measurement"], "a.el", 2, [])

    def test_module_graph_elisp_compile_time_symbol_reader_label(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", (
            "(eval-when-compile\n"
            "  #1=alpha\n"
            "  #1#\n"
            "  (require 'b))\n"
        ))
        self.add_file("b.el", "(provide 'b)\n")
        self.assert_reader_label_refused(self.graph(0)["measurement"], "a.el", 2, [])

    def test_module_graph_elisp_compile_time_character_literal(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", "(eval-when-compile\n  ?)\n  (require 'b))\n")
        self.add_file("b.el", "(provide 'b)\n")
        self.assert_elisp_outcomes(self.graph(0)["measurement"], [edge("a.el", "b.el", 3, "require")])

    def test_module_graph_elisp_literal_filename(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", '(require \'b "c")\n')
        self.add_file("b.el", "(provide 'b)\n")
        self.add_file("c.el", "(provide 'c)\n")
        self.assert_elisp_outcomes(self.graph(0)["measurement"], [edge("a.el", "c.el", 1, "require")])

    def test_module_graph_elisp_literal_filename_exact_fallback(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", '(require \'b "nested/target.el")\n(require \'b "missing")\n')
        self.add_file("nested/target.el", "")
        self.add_file("b.el", "(provide 'b)\n")
        measurement = self.graph(0)["measurement"]
        self.assert_elisp_outcomes(measurement, [edge("a.el", "nested/target.el", 1, "require")], [
            {"file": "a.el", "line": 2,
             "message": "require filename 'missing' has no measured target and is outside the extractor"},
        ])

    def assert_require_outside(self, measurement: dict[str, Any], line: int, message: str) -> None:
        self.assert_elisp_outcomes(measurement, [], [
            {"file": "a.el", "line": line, "message": message},
        ])

    def test_module_graph_elisp_require_load_file_name(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", "\n(require 'fixture #$)\n")
        self.add_file("fixture.el", "(provide 'fixture)\n")
        context = self.graph_context(["a.el", "fixture.el"])
        result = adapters._run_module_graph(context)
        self.assert_require_outside(
            result.measurement, 2, "noncanonical require filename is outside the extractor",
        )

    def test_module_graph_elisp_duplicate_providers(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", "\n(require 'fixture)\n")
        self.add_file("fixture.el", "(provide 'fixture)\n")
        self.add_file("other.el", "(provide 'fixture)\n")
        context = self.graph_context(["a.el", "fixture.el", "other.el"])
        result = adapters._run_module_graph(context)
        self.assert_require_outside(
            result.measurement, 2,
            "require feature 'fixture' has multiple measured providers and is outside the extractor",
        )

    def test_module_graph_elisp_ambiguous_literal_filename(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", "\n(require 'fixture \"fixture.el\")\n")
        self.add_file("fixture.el", "(provide 'fixture)\n")
        self.add_file("fixture.el.el", "")
        context = self.graph_context(["a.el", "fixture.el", "fixture.el.el"])
        stderr = StringIO()
        with redirect_stderr(stderr):
            result = adapters._run_module_graph(context)
        message = "require filename 'fixture.el' matches multiple measured files and is outside the extractor"
        self.assert_require_outside(result.measurement, 2, message)
        self.assertIn(f"check: a.el:2: {message}", stderr.getvalue().splitlines())

    def test_module_graph_elisp_file_local_shorthand(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", (
            "(require 'f-f)\n"
            "\n"
            ";; Local Variables:\n"
            ';; read-symbol-shorthands: (("f-" . "fixture-"))\n'
            ";; End:\n"
        ))
        self.add_file("fixture-f.el", "(provide 'fixture-f)\n")
        context = self.graph_context(["a.el", "fixture-f.el"], ("fixture-f.el",))
        result = adapters._run_module_graph(context)
        expected_edge = edge("a.el", "fixture-f.el", 1, "require")
        self.assert_elisp_outcomes(result.measurement, [expected_edge])
        self.assertEqual(result.outcome, "fail")
        finding, = result.findings
        self.assertIn("a.el -> fixture-f.el", finding.subject)
        self.assertEqual(finding.location, "a.el:1")
        self.assertEqual(finding.measurement, {"edge": expected_edge})

    def test_module_graph_elisp_feature_identity_survives_serialization(self) -> None:
        self.configure_graph(elisp=True)
        provider = r"caf\351.el"
        self.add_file("a.el", r"(require 'caf\\351)" + "\n")
        self.add_file(provider, r"(provide 'caf\\351)" + "\n")
        self.add_file("decoy.el", b"; -*- coding: raw-text -*-\n(provide 'caf\xe9)\n")
        context = self.graph_context(["a.el", provider, "decoy.el"], (provider,))
        result = adapters._run_module_graph(context)
        expected_edge = edge("a.el", provider, 1, "require")
        self.assert_elisp_outcomes(result.measurement, [expected_edge])
        self.assertEqual(result.outcome, "fail")
        finding, = result.findings
        self.assertIn(f"a.el -> {provider}", finding.subject)
        self.assertEqual(finding.location, "a.el:1")
        self.assertEqual(finding.measurement, {"edge": expected_edge})

    def assert_requires_on_consecutive_lines(self, separator: str) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", f"(require 'fixture){separator}\n(require 'fixture)\n")
        self.add_file("fixture.el", "(provide 'fixture)\n")
        context = self.graph_context(["a.el", "fixture.el"], ("fixture.el",))
        result = adapters._run_module_graph(context)
        expected_edges = [edge("a.el", "fixture.el", line, "require") for line in (1, 2)]
        self.assert_elisp_outcomes(result.measurement, expected_edges)
        self.assertEqual(result.outcome, "fail")
        self.assertEqual([finding.location for finding in result.findings], ["a.el:1", "a.el:2"])
        self.assertEqual(
            [finding.measurement for finding in result.findings],
            [{"edge": expected_edge} for expected_edge in expected_edges],
        )

    def test_module_graph_elisp_require_after_reader_comment(self) -> None:
        self.assert_requires_on_consecutive_lines(" #! ignored")

    def test_module_graph_elisp_require_after_vertical_tab(self) -> None:
        self.assert_requires_on_consecutive_lines("\v")

    def test_module_graph_elisp_trailing_mixed_line_endings(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", b"(require 'fixture-f)\n\r\n")
        self.add_file("fixture-f.el", "(provide 'fixture-f)\n")
        result = adapters._run_module_graph(self.graph_context(["a.el", "fixture-f.el"]))
        self.assertEqual(result.outcome, "pass", result.diagnostics.error)
        self.assert_elisp_outcomes(result.measurement, [edge("a.el", "fixture-f.el", 1, "require")])

    def test_module_graph_elisp_mixed_line_endings_before_require(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", b"; header\n\r\n(require 'fixture-f)\n")
        self.add_file("fixture-f.el", "(provide 'fixture-f)\n")
        result = adapters._run_module_graph(self.graph_context(["a.el", "fixture-f.el"]))
        self.assertEqual(result.outcome, "pass", result.diagnostics.error)
        self.assert_elisp_outcomes(result.measurement, [edge("a.el", "fixture-f.el", 3, "require")])

    def test_module_graph_elisp_require_outcome_invariant(self) -> None:
        self.configure_graph(elisp=True)
        source = "a.el"
        self.add_file(source, (
            "(require 'unique)\n"
            "(eval-when-compile\n"
            "  (\n"
            "   require 'unique nil))\n"
            "(require 'unused \"unique\")\n"
            "(require 'unused \"unique.el\")\n"
            "(require 'unique \"missing\")\n"
            "(require 'unique \"both.el\")\n"
            "(require 'shared)\n"
            "(require (intern \"unique\") (concat \"unique\" \".el\"))\n"
            "(require 'external)\n"
            "(defun later () (require 'unique))\n"
            "`(outer ,(require 'unique))\n"
            "(eval-when-compile (progn (require 'unique)))\n"
            "(load \"unique\")\n"
            "(load-file \"unique.el\")\n"
        ))
        targets = {
            "unique.el": "(provide 'unique)\n(progn (provide 'unique))\n",
            "both.el": "(provide 'shared)\n",
            "both.el.el": "(provide 'shared)\n",
        }
        for target, contents in targets.items():
            self.add_file(target, contents)
        result = adapters._run_module_graph(self.graph_context([source, *targets]))
        expected_edges = [edge(source, "unique.el", line, "require") for line in (1, 4, 5, 6)]
        expected = {
            7: "require filename 'missing' has no measured target and is outside the extractor",
            8: "require filename 'both.el' matches multiple measured files and is outside the extractor",
            9: "require feature 'shared' has multiple measured providers and is outside the extractor",
            10: "require with a computed feature and a computed filename is outside the extractor",
        }
        expected_outside = [
            {"file": source, "line": line, "message": message} for line, message in expected.items()
        ]
        self.assert_elisp_outcomes(result.measurement, expected_edges, expected_outside)
        extra_outside = {"file": source, "line": 1, "message": "require is outside the extractor"}
        with self.assertRaises(AssertionError):
            self.assert_elisp_outcomes(
                {**result.measurement, "outside_extractor": [extra_outside, *expected_outside]},
                expected_edges, expected_outside,
            )

    def assert_reader_label_refused(
        self, measurement: dict[str, Any], source: str, line: int,
        expected_edges: list[dict[str, Any]],
    ) -> None:
        outside = measurement.get("outside_extractor", [])
        self.assertEqual(len(outside), 1, outside)
        message = outside[0]["message"]
        self.assertIn('Invalid read syntax: "#1="', message)
        self.assertTrue(message.endswith("is outside the extractor"), message)
        self.assert_elisp_outcomes(measurement, expected_edges, [
            {"file": source, "line": line, "message": message},
        ])

    def test_module_graph_elisp_file_local_metadata_label_refuses_file(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", (
            "(require 'fixture)\n"
            "(provide 'a)\n"
            ";; Local Variables:\n"
            ';; read-symbol-shorthands: #1=(("f-" . "fixture-"))\n'
            ";; End:\n"
        ))
        self.add_file("fixture.el", "(provide 'fixture)\n")
        self.add_file("consumer.el", "(require 'a)\n(require 'fixture)\n")
        context = self.graph_context(["a.el", "consumer.el", "fixture.el"], ("fixture.el",))
        result = adapters._run_module_graph(context)
        self.assertEqual(result.outcome, "fail", result.diagnostics.error)
        expected_edge = edge("consumer.el", "fixture.el", 2, "require")
        self.assert_reader_label_refused(result.measurement, "a.el", 4, [expected_edge])
        finding, = result.findings
        self.assertIn("consumer.el -> fixture.el", finding.subject)
        self.assertEqual(finding.location, "consumer.el:2")
        self.assertEqual(finding.measurement, {"edge": expected_edge})

    def test_module_graph_elisp_truncated_form_refuses_file(self) -> None:
        self.add_file("a.el", "(require 'fixture)\n(provide 'a)\n(")
        self.assert_truncated_elisp_refused(3)

    def assert_truncated_elisp_refused(self, line: int) -> None:
        self.configure_graph(elisp=True)
        self.add_file("fixture.el", "(provide 'fixture)\n")
        self.add_file("consumer.el", "(require 'a)\n")
        context = self.graph_context(["a.el", "consumer.el", "fixture.el"], ("fixture.el",))
        result = adapters._run_module_graph(context)
        self.assertEqual(result.outcome, "pass", result.diagnostics.error)
        self.assertEqual(result.findings, [])
        self.assertEqual(result.measurement["edges"], [])
        outside, = result.measurement["outside_extractor"]
        self.assertIn("End of file during parsing", outside["message"])
        self.assertTrue(outside["message"].endswith("is outside the extractor"))
        self.assert_elisp_outcomes(result.measurement, [], [{
            "file": "a.el", "line": line, "message": outside["message"],
        }])

    def test_module_graph_elisp_refusal_uses_emacs_signal_line(self) -> None:
        read_signal_line = """
        (with-temp-buffer
          (insert-file-contents "a.el")
          (goto-char (point-min))
          (condition-case nil
              (handler-bind
                  ((end-of-file (lambda (_failure) (princ (line-number-at-pos (point))))))
                (while t (read (current-buffer))))
            (end-of-file nil)))
        """
        for preceding_line in ("", "#! ignored\n"):
            with self.subTest(preceding_line=preceding_line):
                self.add_file("a.el", f"(require 'fixture)\n(provide 'a)\n{preceding_line}(")
                emacs = subprocess.run(
                    ["emacs", "-Q", "--batch", "--eval", read_signal_line],
                    cwd=self.repo, capture_output=True, text=True, check=True,
                )
                self.assert_truncated_elisp_refused(int(emacs.stdout))

    def test_module_graph_elisp_reader_label(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", "(defconst fixture '#1=(alpha beta))\n(require 'b)\n")
        self.add_file("b.el", "(provide 'b)\n")
        self.assert_reader_label_refused(self.graph(0)["measurement"], "a.el", 1, [])

    def test_module_graph_elisp_top_level_labelled_require(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", "\n#1=\n(require 'b)\n")
        self.add_file("b.el", "(provide 'b)\n")
        self.assert_reader_label_refused(self.graph(0)["measurement"], "a.el", 2, [])

    def test_module_graph_elisp_reader_label_in_char_table(self) -> None:
        self.add_file("other.el", "(provide 'other)\n")
        table = "#^[#1=alpha nil nil" + " nil" * 65 + "]"
        self.assert_labelled_provider_refused(
            f"(require 'other)\n(provide 'fixture)\n'{table}\n", 3, ("other.el",),
        )

    def test_module_graph_elisp_round10_shared_operand_exact(self) -> None:
        self.assert_labelled_provider_refused("(progn\n  '#1='fixture\n  (provide #1#))\n", 2)

    def test_module_graph_elisp_round10_char_table_exact(self) -> None:
        table = "#^[nil nil #1#" + " nil" * 65 + "]"
        self.assert_labelled_provider_refused(f"(eval-when-compile\n  (#1=require 'fixture)\n  {table})\n", 2)

    def assert_labelled_provider_refused(
        self, decoy_source: str, label_line: int, other_files: tuple[str, ...] = (),
    ) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", "(require 'fixture)\n")
        self.add_file("fixture.el", "(provide 'fixture)\n")
        self.add_file("decoy.el", decoy_source)
        files = ["a.el", "fixture.el", "decoy.el", *other_files]
        context = self.graph_context(files, ("fixture.el",))
        result = adapters._run_module_graph(context)
        expected_edge = edge("a.el", "fixture.el", 1, "require")
        self.assert_reader_label_refused(result.measurement, "decoy.el", label_line, [expected_edge])
        self.assertEqual(result.outcome, "fail")
        finding, = result.findings
        self.assertIn("a.el -> fixture.el", finding.subject)
        self.assertEqual(finding.location, "a.el:1")
        self.assertEqual(finding.measurement, {"edge": expected_edge})

    def test_module_graph_elisp_dotted_literal_filename(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", '(require \'dotted-fixture "odd.name")\n')
        self.add_file("odd.name.el", "")
        self.add_file("other.el", "(provide 'dotted-fixture)\n")
        self.assert_elisp_outcomes(self.graph(0)["measurement"], [edge("a.el", "odd.name.el", 1, "require")])

    def test_module_graph_elisp_dotted_literal_filename_with_two_candidates(self) -> None:
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
        self.assert_require_outside(
            result.measurement, 1,
            "require filename 'odd.name' matches multiple measured files and is outside the extractor",
        )
        self.assertIn("odd.name", result.measurement["modules"])
        self.assertIn("odd.name.el", result.measurement["modules"])
        self.assertEqual(result.outcome, "pass")
        self.assertEqual(result.findings, [])

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
        self.assert_elisp_outcomes(measurement, [edge("a.el", f"{allowed}.el", 2, "require")])
        self.assertNotIn("outside_extractor", measurement)

    def assert_rejected_require_filenames(
        self, context: adapters.AdapterContext, feature: str, operands: tuple[str, ...],
    ) -> None:
        for operand in operands:
            with self.subTest(operand=operand):
                self.add_file("a.el", f'\n(require \'{feature} "{operand}")\n')
                result = adapters._run_module_graph(context)
                self.assert_require_outside(
                    result.measurement, 2, "noncanonical require filename is outside the extractor",
                )
                self.assertEqual(result.outcome, "pass")
                self.assertEqual(result.findings, [])

    def test_module_graph_elisp_top_level_progn_provider(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", "(require 'b)\n")
        self.add_file("b.el", "(progn (provide 'b) (require 'c))\n")
        self.add_file("c.el", "(provide 'c)\n(progn (progn (provide 'b)))\n")
        self.assert_elisp_outcomes(self.graph(0)["measurement"], [edge("a.el", "b.el", 1, "require")])

    def test_module_graph_elisp_shared_provide_head(self) -> None:
        self.assert_labelled_provider_refused("(progn\n  [#1=provide]\n  (#1# 'fixture))\n", 2)

    def test_module_graph_elisp_uninterned_provider_does_not_hide_edge(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", "\n(require 'fixture)\n")
        self.add_file("fixture.el", "(provide 'fixture)\n")
        context = self.graph_context(["a.el", "fixture.el", "decoy.el"], ("fixture.el",))
        expected_edge = edge("a.el", "fixture.el", 2, "require")
        for source, line in (("\n(\n provide '#:fixture)\n", 3),
                             ("(progn\n  (\n   provide '#:fixture))\n", 3)):
            with self.subTest(source=source):
                self.add_file("decoy.el", source)
                result = adapters._run_module_graph(context)
                self.assert_elisp_outcomes(result.measurement, [expected_edge], [
                    {"file": "decoy.el", "line": line,
                     "message": "uninterned provide feature is outside the extractor"},
                ])
                self.assertEqual(result.outcome, "fail")
                finding, = result.findings
                self.assertIn("a.el -> fixture.el", finding.subject)
                self.assertEqual(finding.location, "a.el:2")
                self.assertEqual(finding.measurement, {"edge": expected_edge})

    def test_module_graph_elisp_computed_operands(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("a.el", '(require (intern "b"))\n(require \'b (concat "b" ".el"))\n')
        self.add_file("b.el", "(provide 'b)\n")
        measurement = self.graph(0)["measurement"]
        self.assert_elisp_outcomes(measurement, [], [
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
        self.assertEqual(result.outcome, "pass")
        self.assert_elisp_outcomes(result.measurement, [], [
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
        self.assert_elisp_outcomes(self.graph(0)["measurement"], [edge("a.el", "b.el", 6, "require")])

    def test_module_graph_python_shebang_precedes_elisp_suffix(self) -> None:
        self.configure_graph(elisp=True)
        self.add_file("caller.el", "#!/usr/bin/env python3\nimport dep\n")
        self.add_file("dep.py", "")
        self.add_file("reader.el", "(require 'b)\n")
        self.add_file("b.el", "(provide 'b)\n")
        measurement = self.graph(0)["measurement"]
        python_edge, *require_edges = measurement["edges"]
        self.assertEqual(
            (python_edge["source"], python_edge["target"], python_edge["line"]),
            ("caller.el", "dep.py", 2),
        )
        self.assertEqual(require_edges, [edge("reader.el", "b.el", 1, "require")])
        self.assertEqual(python_edge["kind"], "import")
        self.assert_elisp_outcomes(measurement, [
            edge("caller.el", "dep.py", 2), edge("reader.el", "b.el", 1, "require"),
        ])

    def test_shell_shebang_controls_graph_and_clone_dispatch(self) -> None:
        self.configure_graph()
        config = self.read_file("quality-gate.toml") + """
[checks.comments]
adapter = "comments"
tier = 1
enforcement = "enforced"

[checks.clones]
adapter = "clones"
tier = 1
enforcement = "enforced"
"""
        (self.repo / "a.py").unlink()
        self.add_file("polyglot.py", '#!/bin/sh\n""":"\n# shell-only comment\ntrue\n":"""\n')
        args_file = self.base / "jscpd-args.txt"
        env = self.install_fake_jscpd(args_file=args_file)

        for checks in ('["smoke", "clones", "comments"]', '["smoke", "clones"]'):
            with self.subTest(checks=checks):
                self.write_config(config.replace('checks = ["smoke"]', f"checks = {checks}"))
                self.assertEqual(self.graph(0)["measurement"]["modules"], [])
                loaded = policy.load_config(self.repo)
                _, classes, violations = inventory.validate_inventory(self.repo, loaded)
                self.assertEqual(violations, [])
                self.assertEqual(classes.languages["polyglot.py"], "bash")
                result, report = self.run_json("--only", "clones", env=env)
                self.assertEqual(result.returncode, 0, output(result))
                self.assertEqual(self.check_by_id(report, "clones")["outcome"], "pass")
                arguments = args_file.read_text(encoding="utf-8").splitlines()
                self.assertEqual(arguments[arguments.index("--format") + 1], "bash")
                self.assertEqual(arguments[arguments.index("--") + 1:], ["polyglot.py"])

    def test_clones_keep_language_and_report_path_for_conflicting_basenames(self) -> None:
        shell = "#!/bin/sh\n" + "".join(
            f'printf "value {index} %s\\n" "item {index}"\n' for index in range(20)
        )
        self.add_file("shell/shared.py", shell)
        self.add_file("shared.py", "print(1)\nprint(2)\n" * 20)
        self.add_file("script.sh", shell)
        self.add_file("source-0", "#!/usr/bin/python3\n" + "print('a')\nprint('b')\n" * 20)
        result = clones.measure_clones(
            self.repo,
            {"shell/shared.py": "bash", "shared.py": "python", "script.sh": "bash", "source-0": "python"},
            min_tokens=20,
        )
        self.assertIsNone(result.error)
        self.assertIn(
            {"shell/shared.py", "script.sh"},
            [{location.path for location in finding.locations} for finding in result.findings],
        )

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
        self.assert_elisp_outcomes(result.measurement, [expected_edge])
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
