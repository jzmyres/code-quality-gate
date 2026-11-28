from __future__ import annotations

import json
import os
import subprocess
import sys
import tomllib
from collections import Counter, defaultdict
from contextlib import contextmanager, redirect_stderr
from copy import deepcopy
from dataclasses import replace
from io import StringIO
from inspect import getsource
from pathlib import PurePosixPath
from types import SimpleNamespace
from typing import Any
from unittest import mock

from support import BASE_CONFIG, GATE, FixtureCase, output

from quality_gate import adapters, clones, module_graph, policy, runner
from quality_gate import files as inventory
from quality_gate.checks import CheckSelection


def edge(source: str, target: str, line: int, kind: str = "import") -> dict[str, str | int]:
    return {"source": source, "target": target, "line": line, "kind": kind}


def shell_literal(value: str) -> dict:
    return {"Type": "Lit", "Value": value}


def shell_quote(*parts: str | dict) -> dict:
    return {
        "Type": "DblQuoted",
        "Parts": [shell_literal(part) if isinstance(part, str) else part for part in parts],
    }


def shell_call(line: int, *words: str | tuple[str, list[dict]], script: str) -> dict:
    lines = script.encode().splitlines(keepends=True)
    offset = sum(map(len, lines[:line - 1]))
    cursor = 0
    args = []
    for word in words:
        spelling, parts = (word, [shell_literal(word)]) if isinstance(word, str) else word
        raw = spelling.encode()
        start = lines[line - 1].index(raw, cursor)
        cursor = start + len(raw)
        args.append({"Parts": parts, "Pos": {"Offset": offset + start}, "End": {"Offset": offset + cursor}})
    return {"Cmd": {"Type": "CallExpr", "Pos": {"Line": line}, "Args": args}}


def shell_tree(*statements: dict) -> runner.RunResult:
    return shell_json({"Type": "File", "Stmts": statements})


def shell_json(tree: dict) -> runner.RunResult:
    return runner.RunResult((), "completed", 0, stdout=json.dumps(tree).encode())


def edge_order(row: dict) -> tuple:
    return tuple(row[key] for key in ("source", "target", "line", "kind"))


def locations(rows: list[dict]) -> list[dict]:
    return [{"path": row["source"], "start_line": row["line"], "end_line": row["line"]} for row in rows]


def reachable(pairs: set[tuple[str, str]], start: str, end: str) -> bool:
    pending = [start]
    visited: set[str] = set()
    while pending:
        node = pending.pop()
        if node == end:
            return True
        if node not in visited:
            visited.add(node)
            pending.extend(target for source, target in pairs if source == node)
    return False


def subject(rule, boundary, source, target, kind) -> str:
    return json.dumps([rule, boundary, source, target, kind], separators=(",", ":"))


class ModuleGraphTests(FixtureCase):
    def test_src_layout_absolute_and_relative_imports(self) -> None:
        self.configure_graph()
        self.write_config('python_import_roots = ["src"]\n' + self.config_path.read_text())
        self.add_file("scripts/build.py", "from pkg.runtime import util as helper\n")
        self.add_file("src/pkg/runtime/util.py", "from . import sibling\nfrom ... import unrelated\n")
        self.add_file("src/pkg/runtime/sibling.py", "value = 1\n")
        self.add_file("src/unrelated.py", "value = 2\n")
        self.assertEqual(self.graph(0)["measurement"]["edges"], [
            edge("scripts/build.py", "src/pkg/runtime/util.py", 1),
            edge("src/pkg/runtime/util.py", "src/pkg/runtime/sibling.py", 1),
        ])

    def test_graph_rejects_duplicate_module_providers_across_import_roots(self) -> None:
        self.configure_graph()
        self.write_config('python_import_roots = ["src", "vendor"]\n' + self.config_path.read_text())
        self.add_file("src/pkg/api.py", "")
        self.add_file("vendor/pkg/api/__init__.py", "")
        check = self.graph(1)
        self.assertIn("ambiguous Python module 'pkg.api': src/pkg/api.py, vendor/pkg/api/__init__.py",
                      check["reason"])

    def test_graph_rejects_unusable_import_root(self) -> None:
        self.configure_graph()
        self.write_config('python_import_roots = ["src"]\n' + self.config_path.read_text())
        diagnostic = "python_import_roots: 'src': expected an existing repository directory"
        self.assertIn(diagnostic, self.graph(1)["reason"])
        self.add_file(".gitignore", "__pycache__/\nsrc\n")
        (self.repo / "src").symlink_to(self.base, target_is_directory=True)
        self.assertIn(diagnostic, self.graph(1)["reason"])

    def configure_graph(self, options: str = "", *, elisp: bool = False, shell: bool = False) -> None:
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
        if shell:
            config += """
[[rule]]
pattern = "*.sh"
class = "python"
reason = "Shell measured by the graph"
"""
        self.write_config(config)

    def graph(self, exit_code: int) -> dict[str, Any]:
        result, document = self.run_json("--only", "module-graph")
        self.assertEqual(result.returncode, exit_code, result.stderr)
        return self.check_by_id(document, "module-graph")

    @contextmanager
    def mock_shell_parser(
        self, trees: dict[str, runner.RunResult], replay: dict[str, runner.RunResult] | None = None,
        *, formatted: dict[str, bytes] | None = None,
    ):
        def run_shfmt(argv, *, stdin=None, **options):
            if argv[0] == "emacs":
                return runner.run(argv, stdin=stdin, **options)
            filename = argv[-1]
            if "--to-json" in argv:
                return trees[filename]
            if "--from-json" in argv:
                if replay and filename in replay:
                    return replay[filename]
                stdin = (self.repo / filename).read_bytes()
            if formatted and filename in formatted:
                stdin = formatted[filename]
            return runner.RunResult((), "completed", 0, stdout=stdin)

        with (
            mock.patch.object(adapters, "tool_binary", return_value=self.repo / "shfmt"),
            mock.patch.object(adapters, "run", side_effect=run_shfmt) as run,
        ):
            yield run

    def shell_graph(
        self, exit_code: int, trees: dict[str, runner.RunResult], *,
        replay: dict[str, runner.RunResult] | None = None,
    ) -> dict[str, Any]:
        with self.mock_shell_parser(trees, replay):
            return self.graph(exit_code)

    def assert_elisp_outcomes(
        self,
        measurement: dict[str, Any],
        expected_edges: list[dict[str, Any]],
        expected_outside: list[dict[str, Any]] | None = None,
    ) -> None:
        def counts(edges: list[dict[str, Any]], outside: list[dict[str, Any]]) -> Counter[tuple[str, int]]:
            locations = Counter((row["source"], row["line"]) for row in edges)
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

    def configure_out_of_scope_submodule(self) -> None:
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

    def assert_out_of_scope_submodule_graph(self) -> dict:
        graph = self.graph(0)["measurement"]
        self.assertNotIn("lib/outside.py", graph["modules"])
        self.assertEqual(graph["edges"], [
            edge("caller.py", "lib/__init__.py", 1),
            edge("caller.py", "lib/__init__.py", 3),
        ])
        return graph

    def test_module_graph_out_of_scope_submodule_falls_back_to_package(self) -> None:
        self.configure_out_of_scope_submodule()
        self.assert_out_of_scope_submodule_graph()

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

    def test_module_graph_shell_literal_paths(self) -> None:
        self.configure_graph(shell=True)
        script = """value=café
source sibling.sh
. ./sibling.sh
source "$(dirname "$0")"/sibling.sh
. "${BASH_SOURCE%/*}"/sibling.sh
bash ./sibling.sh
if true; then sh ./sibling.sh; fi
./sibling.sh
"$(dirname "$0")"/sibling.sh
sh
"""
        self.add_file("scripts/main.sh", script)
        self.add_file("scripts/sibling.sh", "")
        dirname = {"Type": "CmdSubst"}
        bash_source = {"Type": "ParamExp", "Exp": {"Op": "%"}}
        dirname_word = ('"$(dirname "$0")"/sibling.sh', [shell_quote(dirname), shell_literal("/sibling.sh")])
        source_word = (
            '"${BASH_SOURCE%/*}"/sibling.sh', [shell_quote(bash_source), shell_literal("/sibling.sh")],
        )
        assignment_end = {"Offset": len("value=café".encode())}
        measurement = self.shell_graph(0, {
            "scripts/main.sh": shell_tree(
                {"Cmd": {"Type": "CallExpr", "Pos": {"Line": 1}, "End": assignment_end,
                         "Assigns": [{"End": assignment_end}]}},
                shell_call(2, "source", "sibling.sh", script=script),
                shell_call(3, ".", "./sibling.sh", script=script),
                shell_call(4, "source", dirname_word, script=script),
                shell_call(5, ".", source_word, script=script),
                shell_call(6, "bash", "./sibling.sh", script=script),
                {"Cmd": {"Type": "IfClause", "Cond": [shell_call(7, "true", script=script)],
                         "Then": [shell_call(7, "sh", "./sibling.sh", script=script)]}},
                shell_call(8, "./sibling.sh", script=script),
                shell_call(9, dirname_word, script=script),
                shell_call(10, "sh", script=script),
            ),
            "scripts/sibling.sh": shell_tree(),
        })["measurement"]
        self.assertEqual(measurement["edges"], [
            edge("scripts/main.sh", "scripts/sibling.sh", line, kind)
            for line, kind in (
                (2, "source"), (3, "source"), (4, "source"), (5, "source"),
                (6, "execute"), (7, "execute"), (8, "execute"), (9, "execute"),
            )
        ])
        self.assertNotIn("outside_extractor", measurement)

    def test_module_graph_shell_uses_shared_parser_for_inventory_shell_files(self) -> None:
        self.configure_graph(shell=True)
        content = "#!/bin/sh\n  true\n"
        self.add_file("script.py", content)
        self.add_file("sibling.sh", "")
        trees = {"script.py": shell_tree(shell_call(2, "true", script=content)), "sibling.sh": shell_tree()}
        with self.mock_shell_parser(trees, formatted={"script.py": b"#!/bin/sh\ntrue\n"}) as run:
            check = self.graph(0)
        self.assertEqual(check["measurement"]["modules"], ["a.py", "script.py", "sibling.sh"])
        self.assertEqual(check["measurement"]["edges"], [])
        self.assertEqual(run.call_args_list, [
            mock.call(
                [str(self.repo / "shfmt"), *flags, "-ln=bash", "--filename", path],
                stdin=stdin, budget_seconds=30, capture_limit=None,
            )
            for path, data in (("script.py", content.encode()), ("sibling.sh", b""))
            for flags, stdin in (
                (["--to-json"], data), (["--from-json"], trees[path].stdout), ([], data),
            )
        ])

    def test_module_graph_shell_reports_computed_and_missing_paths(self) -> None:
        self.configure_graph(shell=True)
        script = """source "$dir/sibling.sh"
. "$(printf .)/sibling.sh"
bash ./sib*.sh
./$name
source ../README.md
source ./absent.sh
source ./foo{a,{b}}.sh
bash -e "$dir/sibling.sh"
sh -- ./sibling.sh
source './sibling.sh'
source "$(dirname "$0")/sibling.sh"
. "${BASH_SOURCE[0]%/*}"/sibling.sh
"""
        self.add_file("scripts/main.sh", script)
        self.add_file("scripts/sibling.sh", "")
        self.add_file("scripts/foo{a,{b}}.sh", "")
        directory = {"Type": "ParamExp", "Short": True, "Param": {"Value": "dir"}}
        variable_word = ('"$dir/sibling.sh"', [shell_quote(directory, "/sibling.sh")])
        substitution = {"Type": "CmdSubst"}
        name = {"Type": "ParamExp", "Short": True, "Param": {"Value": "name"}}
        bash_source = {"Type": "ParamExp", "Exp": {"Op": "%"}}
        quoted_suffix = ('"$(dirname "$0")/sibling.sh"', [shell_quote(substitution, "/sibling.sh")])
        measurement = self.shell_graph(0, {
            "scripts/main.sh": shell_tree(
                shell_call(1, "source", variable_word, script=script),
                shell_call(2, ".", ('"$(printf .)/sibling.sh"', [shell_quote(substitution, "/sibling.sh")]),
                           script=script),
                shell_call(3, "bash", "./sib*.sh", script=script),
                shell_call(4, ("./$name", [shell_literal("./"), name]), script=script),
                shell_call(5, "source", "../README.md", script=script),
                shell_call(6, "source", "./absent.sh", script=script),
                shell_call(7, "source", "./foo{a,{b}}.sh", script=script),
                shell_call(8, "bash", "-e", variable_word, script=script),
                shell_call(9, "sh", "--", "./sibling.sh", script=script),
                shell_call(10, "source", ("'./sibling.sh'", [{"Type": "SglQuoted", "Value": "./sibling.sh"}]),
                           script=script),
                shell_call(11, "source", quoted_suffix, script=script),
                shell_call(12, ".", ('"${BASH_SOURCE[0]%/*}"/sibling.sh',
                           [shell_quote(bash_source), shell_literal("/sibling.sh")]), script=script),
            ),
            "scripts/sibling.sh": shell_tree(),
            "scripts/foo{a,{b}}.sh": shell_tree(),
        })["measurement"]
        self.assertEqual(measurement["edges"], [edge("scripts/main.sh", "scripts/sibling.sh", 10, "source")])
        diagnostics = measurement["outside_extractor"]
        self.assertEqual([(row["file"], row["line"]) for row in diagnostics], [
            ("scripts/main.sh", line) for line in range(1, 13) if line != 10
        ])
        for row in (*diagnostics[:4], *diagnostics[6:]):
            self.assertIn("outside the parser", row["message"])
        for row, target in zip(diagnostics[4:6], ("../README.md", "./absent.sh"), strict=True):
            self.assertIn("unresolved", row["message"])
            self.assertIn(target, row["message"])

    def test_module_graph_shell_rejects_tildes_options_and_words_changed_by_parser(self) -> None:
        self.configure_graph("""
[[rule]]
pattern = "scripts/--"
class = "python"
reason = "Shell option lookalike measured by the graph"
""", shell=True)
        self.add_file("scripts/name=~/sibling.sh", "")
        self.add_file("scripts/--", "#!/bin/sh\n")
        self.add_file("scripts/sibling.sh", "")
        directory = {"Type": "ParamExp", "Short": True, "Param": {"Value": "dir"}}
        variable_word = ('"$dir/sibling.sh"', [shell_quote(directory, "/sibling.sh")])
        for words in (
            ("source", "name=~/sibling.sh"),
            ("source", "--", variable_word),
            (".", "--", variable_word),
            ("source", ("./'other-'sibling.sh", [
                shell_literal("./"), {"Type": "SglQuoted"}, shell_literal("sibling.sh"),
            ])),
            ("source", ("./'other-'sibling.sh", [shell_literal("./sibling.sh")])),
        ):
            with self.subTest(words=words):
                script = " ".join(word if isinstance(word, str) else word[0] for word in words) + "\n"
                self.add_file("scripts/main.sh", script)
                measurement = self.shell_graph(0, {
                    "scripts/main.sh": shell_tree(shell_call(1, *words, script=script)),
                    "scripts/name=~/sibling.sh": shell_tree(),
                    "scripts/--": shell_tree(),
                    "scripts/sibling.sh": shell_tree(),
                })["measurement"]
                self.assertEqual(measurement["edges"], [])
                self.assertEqual(measurement["outside_extractor"], [{
                    "file": "scripts/main.sh",
                    "line": 1,
                    "message": "shell source: target is outside the parser",
                }])

    def test_module_graph_shell_syntax_error(self) -> None:
        self.configure_graph(shell=True)
        self.add_file("broken.sh", "if then\n")
        failure = runner.RunResult((), "completed", 1, stderr=b"1:1: if must be followed by a statement")
        check = self.shell_graph(1, {"broken.sh": failure})
        self.assertEqual(check["outcome"], "error")
        self.assertIn("broken.sh: shfmt parse failed", check["reason"])
        self.assertNotIn("measurement", check)

    def test_module_graph_shell_rejects_plus_options(self) -> None:
        self.configure_graph("""
[[rule]]
pattern = "+e"
class = "python"
reason = "Shell option lookalike measured by the graph"
""", shell=True)
        self.add_file("sibling.sh", "")
        self.add_file("+e", "#!/bin/sh\n")
        for command, kind in (("bash", "execute"), ("sh", "execute"), ("source", "source"), (".", "source")):
            with self.subTest(command=command):
                words = (command, "+e", "./sibling.sh")
                script = " ".join(words) + "\n"
                self.add_file("main.sh", script)
                measurement = self.shell_graph(0, {
                    "main.sh": shell_tree(shell_call(1, *words, script=script)),
                    "+e": shell_tree(),
                    "sibling.sh": shell_tree(),
                })["measurement"]
                self.assertEqual(measurement["edges"], [])
                self.assertEqual(measurement["outside_extractor"], [{
                    "file": "main.sh", "line": 1, "message": f"shell {kind}: target is outside the parser",
                }])

    def test_module_graph_shell_schema_errors_name_file_and_field(self) -> None:
        self.configure_graph(shell=True)
        script = 'source "${BASH_SOURCE%/*}"/sibling.sh\n'
        self.add_file("broken.sh", script)
        statement = shell_call(1, "source", ('"${BASH_SOURCE%/*}"/sibling.sh', [
            shell_quote({"Type": "ParamExp", "Exp": {"Op": "%"}}), shell_literal("/sibling.sh"),
        ]), script=script)
        call = statement["Cmd"]
        word, operand = call["Args"]
        for args, detail in (
            ([None], "field Args must contain objects"),
            ([{}], "missing field Parts"),
            ([{**word, "Parts": ""}], "field Parts must be list"),
            ([{**word, "Parts": [{}]}], "missing field Type"),
            ([{**word, "Parts": [{"Type": 0}]}], "field Type must be str"),
            ([{**word, "Parts": [{"Type": "Lit"}]}], "missing field Value"),
            ([{**word, "Pos": {}}], "missing field Pos.Offset"),
            ([{**word, "Pos": {"Offset": True}}], "field Pos.Offset must be int"),
            ([{**word, "End": {}}], "missing field End.Offset"),
            ([word, {**operand, "Parts": [shell_quote({})]}], "missing field Type"),
            ([word, {**operand, "Parts": [
                shell_quote({"Type": "ParamExp", "Exp": {}}), shell_literal("/sibling.sh"),
            ]}], "missing field Exp.Op"),
        ):
            with self.subTest(detail=detail):
                tree = {key: value for key, value in call.items() if key != "Args"}
                if args is not None:
                    tree["Args"] = args
                result = self.shell_graph(1, {"broken.sh": shell_tree({"Cmd": tree})})
                self.assertEqual(result["outcome"], "error")
                self.assertIn(f"broken.sh: shfmt JSON {detail}", result["reason"])

    def test_module_graph_shell_requires_statement_fields(self) -> None:
        self.configure_graph(shell=True)
        script = "source ./sibling.sh\n"
        self.add_file("main.sh", script)
        self.add_file("sibling.sh", "")
        for tree, detail in (
            ({"Type": "File", "Stmts": [{"Cmd": {}}]}, "missing field Type"),
            ({"Type": "File", "Stmts": [{"Cmd": [], "Redirs": []}]}, "field Cmd must be dict"),
            ({"Type": "File", "Stmts": [{"Cmd": {"Type": "Unknown"}}]},
             "unsupported field Type value 'Unknown'"),
        ):
            with self.subTest(detail=detail):
                check = self.shell_graph(1, {"main.sh": shell_json(tree), "sibling.sh": shell_tree()})
                self.assertEqual(check["outcome"], "error")
                self.assertIn(f"main.sh: shfmt JSON {detail}", check["reason"])

    def test_module_graph_shell_rejects_trees_that_drop_source_fields(self) -> None:
        self.configure_graph(shell=True)
        self.add_file("sibling.sh", "")
        source = "source ./sibling.sh"
        script = source + "\n"
        statement = shell_call(1, "source", "./sibling.sh", script=script)
        assigned_script = "value=1 " + script
        assigned = shell_call(1, "source", "./sibling.sh", script=assigned_script)
        assigned["Cmd"]["Assigns"] = [{"Value": {"Parts": [shell_literal("1")]}}]
        redirected = {**statement, "Redirs": [{"Word": {"Parts": [shell_literal("out")]}}]}
        fixtures = [
            (script, statement, ("Stmts",), b""),
            (script, statement, ("Stmts", 0, "Cmd"), b""),
            (source + " >out\n", redirected, ("Stmts", 0, "Cmd"), b">out\n"),
            (assigned_script, assigned, ("Stmts", 0, "Cmd", "Args"), b"value=1\n"),
        ]
        for kind, prefix, expansion, field in (
            ("CmdSubst", '"$(dirname "$0")"', {"Stmts": []}, ("Parts",)),
            ("ParamExp", '"${BASH_SOURCE%/*}"', {"Exp": {"Op": "%"}}, ("Parts", 0, "Exp")),
            ("ParamExp", '"${BASH_SOURCE%/*}"', {"Exp": {"Op": "%"}}, ("Parts", 0, "Exp", "Op")),
        ):
            operand = prefix + "/sibling.sh"
            script = f"source {operand}\n"
            word = operand, [shell_quote({"Type": kind, **expansion}), shell_literal("/sibling.sh")]
            fixtures.append((
                script, shell_call(1, "source", word, script=script),
                ("Stmts", 0, "Cmd", "Args", 1, "Parts", 0, *field), b'source ""/sibling.sh\n',
            ))
        for kind, operand in (("CmdSubst", f'"$({source})"'), ("ProcSubst", f"<({source})")):
            script = f"echo {operand}\n"
            substitution = {"Type": kind, "Stmts": [shell_call(1, "source", "./sibling.sh", script=script)]}
            parts = [shell_quote(substitution)] if kind == "CmdSubst" else [substitution]
            path = ("Stmts", 0, "Cmd", "Args", 1, "Parts", 0)
            if kind == "CmdSubst":
                path += ("Parts", 0)
            fixtures.append((
                script, shell_call(1, "echo", (operand, parts), script=script),
                (*path, "Stmts"), script.replace(source, "").encode(),
            ))
        script = "if true; then " + source + "; fi\n"
        fixtures.append((
            script, {"Cmd": {
                "Type": "IfClause", "Cond": [shell_call(1, "true", script=script)],
                "Then": [shell_call(1, "source", "./sibling.sh", script=script)],
            }}, ("Stmts", 0, "Cmd", "Then"), b"if true; then fi\n",
        ))
        for script, statement, path, printed in fixtures:
            with self.subTest(script=script.strip(), field=path[-1]):
                self.add_file("main.sh", script)
                tree = {"Type": "File", "Stmts": [statement]}
                trees = {"main.sh": shell_json(tree), "sibling.sh": shell_tree()}
                check = self.shell_graph(0, trees)
                self.assertEqual(check["measurement"]["edges"], [edge("main.sh", "sibling.sh", 1, "source")])
                damaged = deepcopy(tree)
                node = damaged
                for key in path[:-1]:
                    node = node[key]
                del node[path[-1]]
                trees["main.sh"] = shell_json(damaged)
                check = self.shell_graph(1, trees, replay={
                    "main.sh": runner.RunResult((), "completed", 0, stdout=printed),
                })
                self.assertEqual(check["outcome"], "error")
                self.assertIn("main.sh: shfmt parser tree does not reproduce the file", check["reason"])
                self.assertNotIn("measurement", check)

    def test_module_graph_shell_fails_when_shfmt_cannot_print_json(self) -> None:
        self.configure_graph(shell=True)
        self.add_file("main.sh", "true\n")
        failure = runner.RunResult((), "completed", 2, stderr=b"flag provided but not defined: -from-json")
        check = self.shell_graph(1, {"main.sh": shell_tree()}, replay={"main.sh": failure})
        self.assertEqual(check["outcome"], "error")
        self.assertIn("main.sh: shfmt parser tree does not reproduce the file", check["reason"])
        self.assertIn("flag provided but not defined: -from-json", check["reason"])

    def test_module_graph_shell_accepts_omitted_empty_fields(self) -> None:
        self.configure_graph(shell=True)
        self.add_file("blank.sh", " \n")
        self.add_file("empty.sh", "")
        self.add_file("header.sh", "#!/bin/bash\n")
        script = ">out\nvalue=1\n"
        self.add_file("main.sh", script)
        out, = shell_call(1, "out", script=script)["Cmd"]["Args"]
        end = {"Offset": len(script.rstrip())}
        measurement = self.shell_graph(0, {
            "blank.sh": shell_json({"Type": "File"}),
            "empty.sh": shell_json({"Type": "File"}),
            "header.sh": shell_json({"Type": "File"}),
            "main.sh": shell_tree(
                {"Redirs": [{"Word": out}]},
                {"Cmd": {"Type": "CallExpr", "Pos": {"Line": 2}, "End": end, "Assigns": [{"End": end}]}},
            ),
        })["measurement"]
        self.assertEqual(measurement["edges"], [])
        self.assertNotIn("outside_extractor", measurement)

    def test_module_graph_shell_uses_required_field_accessor(self) -> None:
        source = getsource(module_graph).split("_SHELL_SCHEMA =", 1)[1].split("def _elisp_records(", 1)[0]
        self.assertNotIn(".get(", source)

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
            "unresolved": [],
            "reader_refusals": [],
            "providers": [],
            "python_import_roots": [],
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
        expected_edges.extend(edge(source, "unique.el", line, "path-load") for line in (15, 16))
        expected = {
            7: "require filename 'missing' has no measured target and is outside the extractor",
            8: "require filename 'both.el' matches multiple measured files and is outside the extractor",
            9: "require feature 'shared' has multiple measured providers and is outside the extractor",
            10: "require with a computed feature and a computed filename is outside the extractor",
            11: "require feature 'external' has no measured provider and is outside the extractor",
            **dict.fromkeys(
                (12, 13, 14), "require in an unsupported evaluation context is outside the extractor",
            ),
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
        outside = result.measurement["outside_extractor"]
        refusal, = result.measurement["reader_refusals"]
        self.assertEqual(outside[1:], [{
            "file": "consumer.el", "line": 1,
            "message": "require feature 'a' has no measured provider and is outside the extractor",
        }])
        self.assert_reader_label_refused(
            {**result.measurement, "outside_extractor": outside[:1]}, "a.el", 4, [expected_edge],
        )
        self.assertEqual(refusal["line"], 4)
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
        outside, missing = result.measurement["outside_extractor"]
        refusal, = result.measurement["reader_refusals"]
        self.assertEqual(refusal["line"], line)
        self.assertIn("End of file during parsing", outside["message"])
        self.assertTrue(outside["message"].endswith("is outside the extractor"))
        self.assert_elisp_outcomes(result.measurement, [], [{
            "file": "a.el", "line": line, "message": outside["message"],
        }, {"file": "consumer.el", "line": 1,
            "message": "require feature 'a' has no measured provider and is outside the extractor"}])
        self.assertEqual(missing["file"], "consumer.el")

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
        self.assert_elisp_outcomes(self.graph(0)["measurement"], [edge("a.el", "b.el", 1, "require")], [
            {"file": "b.el", "line": 1,
             "message": "require in an unsupported evaluation context is outside the extractor"},
            {"file": "c.el", "line": 2,
             "message": "provide in an unsupported evaluation context is outside the extractor"},
        ])

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

    def configure_nested_requires_and_loads(self) -> None:
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

    def assert_nested_requires_and_loads(self, report: dict) -> None:
        self.assert_elisp_outcomes(report, [
            edge("a.el", "b.el", 4, "path-load"), edge("a.el", "b.el", 5, "path-load"),
            edge("a.el", "b.el", 6, "require"),
        ], [
            {"file": "a.el", "line": line,
             "message": "require in an unsupported evaluation context is outside the extractor"}
            for line in (1, 2, 3)
        ])

    def test_module_graph_elisp_ignores_nested_requires_and_loads(self) -> None:
        self.configure_nested_requires_and_loads()
        self.assert_nested_requires_and_loads(self.graph(0)["measurement"])

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
        script = '#!/bin/sh\n""":"\n# shell-only comment\ntrue\n":"""\n'
        self.add_file("polyglot.py", script)
        args_file = self.base / "jscpd-args.txt"
        env = self.install_fake_jscpd(args_file=args_file)

        for checks in ('["smoke", "clones", "comments"]', '["smoke", "clones"]'):
            with self.subTest(checks=checks):
                self.write_config(config.replace('checks = ["smoke"]', f"checks = {checks}"))
                graph = self.shell_graph(0, {"polyglot.py": shell_tree(shell_call(2, ":", script=script))})
                self.assertEqual(graph["measurement"]["modules"], ["polyglot.py"])
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
        return adapters.AdapterContext(
            self.repo, config, check, files, classes, "check", {}, self.base, inventory_files=files,
        )

    def test_module_graph_selects_configured_classes_from_the_inventory(self) -> None:
        self.configure_graph()
        self.add_file("library.py", "")
        self.add_file("other.py", "")
        context = self.graph_context(["a.py", "library.py", "other.py"])
        context.classes["other.py"] = "doc"
        context = replace(context, files=["a.py"])
        for inventory_files, expected in (
            (context.inventory_files, ["a.py", "library.py"]),
            ([], []),
        ):
            with self.subTest(inventory_files=inventory_files):
                result = adapters._run_module_graph(replace(context, inventory_files=inventory_files))
                self.assertEqual(result.measurement["modules"], expected)

    def test_affected_graph_receives_the_full_inventory(self) -> None:
        self.configure_graph()
        self.add_file("caller.py", "import a\n")
        config = policy.load_config(self.repo)
        paths, classes, violations = inventory.validate_inventory(self.repo, config)
        self.assertEqual(violations, [])
        with mock.patch.object(adapters, "_extract_graph", wraps=adapters._extract_graph) as extract:
            nodes, expanded, affected = adapters.affected_graph(
                self.repo, config, paths, classes, self.base, {"a.py"},
            )
        context = extract.call_args.args[0]
        self.assertIs(context.inventory_files, paths)
        self.assertEqual(nodes, {"a.py", "caller.py"})
        self.assertEqual(expanded, {"a.py": "changed"})
        self.assertEqual(affected, {"a.py": "changed", "caller.py": "depends on a.py"})

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
        self.assert_elisp_outcomes(result.measurement, [expected_edge, expected_edge])
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
        context = adapters.AdapterContext(
            self.repo, config, check, [], {}, "check", {}, self.base, inventory_files=[],
        )
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
        self.assertEqual(len(suite_edges), 21)
        self.assertEqual(program_edges, [])
        self.assertIn(
            module_graph.Edge("tests/test_adapters.py", "tests/test_python_tests.py", 17),
            suite_edges,
        )
        self.assertIn(
            module_graph.Edge("tests/test_pytest_mutation.py", "tests/test_python_mutation.py", 15),
            suite_edges,
        )
        self.assertIn(
            module_graph.Edge("tests/test_public_vocabulary.py", "tests/test_secrets.py", 10),
            suite_edges,
        )
        self.assertIn(
            module_graph.Edge("tests/test_public_hardware_model.py", "tests/test_secrets.py", 16),
            suite_edges,
        )
        self.assertIn(
            module_graph.Edge("tests/test_public_git_revision.py", "tests/test_public_hardware_model.py", 15),
            suite_edges,
        )
        self.assertIn(
            module_graph.Edge("tests/test_public_git_revision.py", "tests/test_secrets.py", 16),
            suite_edges,
        )
        self.assertEqual(measurement["modules"], sorted(modules))
        self.assertEqual(measurement["value"], 22)

    def declare_check(
        self, name: str, adapter: str, *, tier: int, enforcement: str,
        classes: list[str] | None = None,
    ) -> None:
        fixture_policy = self.config_path.read_text(encoding="utf-8")
        fields = [
            ("adapter", json.dumps(adapter, ensure_ascii=False)),
            ("tier", str(tier)),
            ("enforcement", json.dumps(enforcement, ensure_ascii=False)),
        ]
        if classes is not None:
            fields.append(("classes", json.dumps(classes, ensure_ascii=False)))
        table = f"\n[checks.{name}]\n" + "".join(f"{key} = {value}\n" for key, value in fields)
        self.write_config(fixture_policy + table)

    def assert_continued_python_import(self, statement: str) -> None:
        self.configure_graph('suites = ["caller.py", "pkg/program.py"]\nprograms = ["pkg/program.py"]\n')
        self.declare_check("module-tree", "module_tree", tier=1, enforcement="enforced")
        self.add_file("caller.py", statement)
        self.add_file("pkg/__init__.py", "")
        self.add_file("pkg/program.py", "import caller\n")
        result, document = self.run_json("--only", "module-graph", "module-tree")
        self.assertEqual(result.returncode, 1, output(result))
        check = self.check_by_id(document, "module-graph")
        self.assertEqual(check["outcome"], "fail")
        self.assertEqual(check["measurement"]["value"], 4)
        forward = edge("caller.py", "pkg/program.py", 1)
        reverse = edge("pkg/program.py", "caller.py", 1)
        witness = [forward, reverse]
        occurrences = [forward, forward, reverse]
        self.assertEqual(check["measurement"]["edges"], occurrences)
        direct, *_ = module_graph.measure(
            self.repo, ["a.py", "caller.py", "pkg/__init__.py", "pkg/program.py"],
            module_graph.GraphSpec(("python",), ("caller.py", "pkg/program.py"), ("pkg/program.py",)),
        )
        self.assertEqual(direct["edges"], occurrences)
        tree = self.check_by_id(document, "module-tree")
        self.assertEqual(tree["outcome"], "fail")
        self.assertEqual(tree["measurement"]["value"], len(witness))
        self.assertEqual(tree["measurement"]["edges"], occurrences)
        self.assert_cycle_subjects(tree, occurrences)
        expected = [
            (
                "Cyclic import (caller.py -> pkg/program.py -> caller.py), "
                "component [caller.py, pkg/program.py]",
                witness, {"component": ["caller.py", "pkg/program.py"], "cycle": witness},
            ),
            ("Suite import (caller.py -> pkg/program.py) at line 1", [forward], {"edge": forward}),
            ("Suite import (pkg/program.py -> caller.py) at line 1", [reverse], {"edge": reverse}),
            ("Dependency on program (caller.py -> pkg/program.py) at line 1", [forward], {"edge": forward}),
        ]
        self.assert_legacy_graph_findings(check, result, expected)

    def assert_cycle_subjects(self, check: dict, occurrences: list[dict]) -> set[str]:
        pairs = {(row["source"], row["target"]) for row in occurrences}
        expected = defaultdict(list)
        for row in occurrences:
            source, target, kind = (row[key] for key in ("source", "target", "kind"))
            if reachable(pairs, target, source):
                expected[subject("file-cycle", None, source, target, kind)].append(row)
        self.assertEqual(
            [finding["subject"] for finding in check["findings"]], sorted(expected, key=json.loads),
        )
        for finding in check["findings"]:
            rows = expected[finding["subject"]]
            self.assertEqual(finding["value"], 1)
            self.assertEqual(finding["measurement"]["rule"], "file-cycle")
            self.assertIsNone(finding["measurement"]["boundary"])
            self.assertEqual(finding["locations"], locations(sorted(rows, key=edge_order)))
            self.assert_edge_rows(finding["measurement"]["occurrences"], rows)
        return set(expected)

    def assert_edge_rows(self, rows: list[dict], expected: list[dict], label: str = "file edges") -> None:
        self.assertCountEqual(
            [json.dumps(row, sort_keys=True) for row in rows],
            [json.dumps(row, sort_keys=True) for row in expected], label,
        )
        if expected:
            key = edge_order if "source" in expected[0] else lambda row: (row["file"], row["line"])
            self.assertEqual(rows, sorted(expected, key=key), label)

    def assert_legacy_graph_findings(
        self, check: dict, result: subprocess.CompletedProcess, expected: list,
    ) -> None:
        findings, diagnostics = [], []
        for name, rows, measurement in expected:
            location = ", ".join(f"{row['source']}:{row['line']}" for row in rows)
            findings.append({
                "subject": name, "value": 1, "bound": None, "threshold": 0,
                "baseline_reason": None, "covered_by_baseline": False, "blocking": True, "expired": False,
                "location": location, "locations": locations(rows), "measurement": measurement,
            })
            diagnostics.append(f"check: module-graph: {name}: value 1 exceeds threshold 0 at {location}")
        self.assertEqual(check["findings"], findings)
        finding_lines = [
            line for line in result.stderr.splitlines() if line.startswith("check: module-graph:")
        ]
        self.assertEqual(finding_lines, diagnostics)

    def assert_rollups(self, report: list[dict], leaves: list[str], occurrences: list[dict]) -> None:
        parts = {name: name.split("/")[:-1] for name in leaves}
        depths = list(range(max(map(len, parts.values())) + 1)) if parts else []
        self.assertEqual([row["depth"] for row in report], depths, "missing or extra rollup levels")
        for depth, row in zip(depths, report, strict=True):
            by_file = {name: "/".join(folders[:depth]) or "." for name, folders in parts.items()}
            directories = set(by_file.values())
            self.assertEqual(row["directories"], sorted(directories), f"directories at depth {depth}")
            groups = defaultdict(list)
            for item in occurrences:
                groups[by_file[item["source"]], by_file[item["target"]]].append(item)
            observed = {(group["source"], group["target"]): group["edges"] for group in row["edges"]}
            self.assertEqual(
                [(group["source"], group["target"]) for group in row["edges"]], sorted(groups),
            )
            for pair, expected in groups.items():
                self.assert_edge_rows(observed[pair], expected, f"rollup group {pair} at depth {depth}")
            pairs = {(source, target) for source, target in groups if source != target}
            components = {
                frozenset(other for other in directories
                          if reachable(pairs, node, other) and reachable(pairs, other, node))
                for node in directories
            }
            cyclic = {component for component in components if len(component) > 1}
            self.assertEqual([cycle["component"] for cycle in row["cycles"]], sorted(map(sorted, cyclic)))
            for cycle in row["cycles"]:
                component = set(cycle["component"])
                supporting = [
                    item for source, target in pairs if {source, target} <= component
                    for item in groups[source, target]
                ]
                self.assert_edge_rows(
                    cycle["edges"], supporting, f"cycle {sorted(component)} at depth {depth}",
                )

    def assert_tree_leaves(self, tree: dict) -> list[str]:
        config = policy.load_config(self.repo)
        files, classes, violations = inventory.validate_inventory(self.repo, config)
        self.assertEqual(violations, [])
        languages = inventory.source_languages(self.repo, files, config, classes)
        expected = {(path, kind) for path, kind in languages.items() if kind in {"python", "lisp", "bash"}}
        pending = [tree]
        leaves = []
        directories = []
        while pending:
            directory = pending.pop()
            directories.append(directory["path"])
            for key in ("directories", "files"):
                paths = [row["path"] for row in directory[key]]
                self.assertEqual(paths, sorted(paths), f"{key} in {directory['path']}")
            for child in directory["directories"]:
                self.assertEqual(str(PurePosixPath(child["path"]).parent), directory["path"])
            for leaf in directory["files"]:
                self.assertEqual(str(PurePosixPath(leaf["path"]).parent), directory["path"])
                leaves.append((leaf["path"], leaf["language"]))
            pending.extend(directory["directories"])
        self.assertCountEqual(leaves, expected, "missing or extra inventory leaves")
        self.assertCountEqual(directories, {".", *(
            str(parent) for path, _ in expected for parent in PurePosixPath(path).parents
        )}, "missing or extra inventory directories")
        return sorted(path for path, _ in expected)

    def assert_unbaselined_tree_cycles(
        self, occurrences: list[dict], unresolved: list[dict], evidence_label: str,
        *, env: dict[str, str] | None = None,
    ) -> None:
        check = self.tree(1, env=env)
        self.assertEqual(check["outcome"], "fail", check.get("reason"))
        report = check["measurement"]
        self.assert_edge_rows(report["edges"], occurrences)
        self.assert_edge_rows(report["unresolved"], unresolved, evidence_label)
        subjects = self.assert_cycle_subjects(check, occurrences)
        self.assertEqual({row["subject"] for row in check["findings"] if row["blocking"]}, subjects)

    def configure_tree(self, options: str = "", *, elisp: bool = False, shell: bool = False) -> None:
        self.configure_graph(elisp=elisp, shell=shell)
        config = self.read_file("quality-gate.toml").replace("module-graph", "module-tree")
        config = config.replace('"module_graph"', '"module_tree"')
        self.write_config(config.replace('classes = ["python"]\n', options + "\n"))

    def cycle_fixture(self, shift: int, extra: bool = False) -> tuple[dict, list[dict]]:
        python, shell, lisp = "apps/start.py", "scripts/link.sh", "lisp/core.el"
        prefix = "\n" * shift
        self.add_file(python, prefix + "import runpy\nrunpy.run_path('../scripts/link.sh')\n")
        script = prefix + ". ../lisp/core.el\n"
        self.add_file(shell, script)
        self.add_file(lisp, prefix + '(load-file "../apps/start.py")\n'
                      "(require 'loop) (require 'loop) (load-file \"core.el\")\n(provide 'loop)\n"
                      + ('(require \'file "apps/start.py")\n' if extra else ""))
        occurrences = [
            edge(python, shell, shift + 2, "path-load"),
            edge(shell, lisp, shift + 1, "source"),
            edge(lisp, python, shift + 1, "path-load"),
            edge(lisp, lisp, shift + 2, "require"),
            edge(lisp, lisp, shift + 2, "require"),
            edge(lisp, lisp, shift + 2, "path-load"),
        ]
        if extra:
            occurrences.append(edge(lisp, python, shift + 4, "require"))
        statement = shell_call(shift + 1, ".", "../lisp/core.el", script=script)
        return {shell: shell_tree(statement)}, occurrences

    def run_graph_and_tree_with_distinct_inputs(self) -> tuple[subprocess.CompletedProcess, dict]:
        with mock.patch.object(module_graph, "dependencies", wraps=module_graph.dependencies) as extract:
            result, document = self.run_json("--only", "module-tree", "module-graph")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertCountEqual([call.args[1] for call in extract.call_args_list], [["a.py"], ["a.py", "b.py"]])
        return result, document

    def tree(self, code: int, *args: str, env: dict[str, str] | None = None) -> dict:
        result, document = self.run_json("--only", "module-tree", *args, env=env)
        self.assertEqual(result.returncode, code, output(result))
        return self.check_by_id(document, "module-tree")

    def tree_baseline(self, subjects: set[str]) -> None:
        baseline = 'check = "module-tree"\nmetric_version = "module-tree/1"\n'
        for name in sorted(subjects):
            baseline += (
                f"\n[[entry]]\nsubject = {json.dumps(name)}\nbound = 1\nreason = 'Fixture dependency'\n"
            )
        self.add_file("tree-baseline.toml", baseline)

    def test_module_graph_multiline_from_import_preserves_legacy_findings(self) -> None:
        statement = "from pkg.program import (\n    first as one,\n    first as two,\n)\n"
        self.assert_continued_python_import(statement)

    def test_module_graph_backslash_continued_import_preserves_legacy_findings(self) -> None:
        continuation = "\\\n"
        self.assert_continued_python_import(f"import {continuation}    pkg.program, pkg.program\n")

    def test_module_graph_out_of_scope_submodule_falls_back_to_measured_parent(self) -> None:
        self.configure_out_of_scope_submodule()
        graph = self.assert_out_of_scope_submodule_graph()
        self.assertEqual(graph["unresolved"], [])
        self.declare_check("module-tree", "module_tree", tier=1, enforcement="enforced")
        self.add_file("lib/outside.py", "")
        tree = self.tree(0)["measurement"]
        targets = {1: "lib/outside.py", 2: "lib/outside.py", 3: "lib/__init__.py"}
        self.assert_edge_rows(tree["edges"], [
            edge("caller.py", target, line) for line, target in targets.items()
        ])

    def test_module_graph_elisp_reports_nested_requires_and_resolves_loads(self) -> None:
        self.configure_nested_requires_and_loads()
        self.assert_nested_requires_and_loads(self.graph(0)["measurement"])
        self.declare_check("module-tree", "module_tree", tier=1, enforcement="enforced")
        self.assert_nested_requires_and_loads(self.tree(0)["measurement"])

    def test_module_graph_elisp_walks_expression_positions(self) -> None:
        self.maxDiff = None
        self.configure_graph(elisp=True)
        declarations = (
            ('(let ((load "data")) load)', []),
            ('(defun example (require name) require)', []),
            ('(let* ((load-file (load "init"))) (load-file "body.el"))',
             [("load", "init"), ("load-file", "body.el")]),
            ('(defun later (load name) (load "body") (load "body"))',
             [("load", "body"), ("load", "body")]),
            ('(defmacro later (load-file name) (load-file "macro.el"))', [("load-file", "macro.el")]),
            ('#\'(lambda (require name) (load "lambda"))', [("load", "lambda")]),
            ('(let ((load \'(load "inert"))) \'(load-file "inert.el"))', []),
            ('(condition-case load (load "protected") '
             '((load require) "data") (error (load-file "handler.el") (load "handler")))',
             [("load", "protected"), ("load-file", "handler.el"), ("load", "handler")]),
            ('(cond (load "inert") (require \'(load "quoted")))', []),
            ('(cond ((load "predicate") (load "body")) (t (load-file "fallback.el")))',
             [("load", "predicate"), ("load", "body"), ("load-file", "fallback.el")]),
            ("(progn (progn (provide 'deep)))", [("provide", "deep")]),
            ("(unknown (load \"inert\"))", []),
            ('`(outer `(inner ,(load "inert") ,,(load "active")) ,@(load "splice"))',
             [("load", "active"), ("load", "splice")]),
        )
        self.add_file("caller.el", "\n".join(form for form, _ in declarations) + "\n")
        report = self.graph(0)["measurement"]
        self.assertEqual(report["edges"], [])
        expected = []
        for line, (_, calls) in enumerate(declarations, 1):
            for kind, operand in calls:
                reason = f"{kind} in an unsupported evaluation context"
                expected.append({"file": "caller.el", "line": line, "kind": kind, "operand": operand,
                                 "reason": reason, "message": f"{reason} is outside the extractor"})
        self.assert_edge_rows(report["unresolved"], expected, "Emacs unresolved occurrences")

    def test_module_graph_same_line_kind_collisions_preserve_legacy_findings(self) -> None:
        self.configure_graph('suites = ["*.el"]\nprograms = ["program.el"]\n', elisp=True)
        caller, program = "caller.el", "program.el"
        self.add_file(caller, "(load-file \"program.el\") (require 'program \"program.el\")\n")
        self.add_file(program, "(require 'caller \"caller.el\")\n")
        result, document = self.run_json("--only", "module-graph")
        self.assertEqual(result.returncode, 1, output(result))
        check = self.check_by_id(document, "module-graph")
        forward = edge(caller, program, 1, "require")
        reverse = edge(program, caller, 1, "require")
        self.assertEqual(check["measurement"]["edges"], [
            edge(caller, program, 1, "path-load"), forward, reverse,
        ])
        witness = [forward, reverse]
        self.assertEqual(check["measurement"]["value"], 4)
        self.assert_legacy_graph_findings(check, result, [
            (
                "Cyclic require (caller.el -> program.el -> caller.el), component [caller.el, program.el]",
                witness, {"component": [caller, program], "cycle": witness},
            ),
            ("Suite require (caller.el -> program.el) at line 1", [forward], {"edge": forward}),
            ("Suite require (program.el -> caller.el) at line 1", [reverse], {"edge": reverse}),
            ("Dependency on program (caller.el -> program.el) at line 1", [forward], {"edge": forward}),
        ])

    def test_module_graph_dependency_occurrence_coverage(self) -> None:
        self.maxDiff = None
        self.configure_graph(elisp=True, shell=True)
        caller = "client/main.py"
        shell = "scripts/main.sh"
        lisp = "editor/client.el"
        imports = [
            ("import deep.api", ["deep/api.py"]),
            ("from deep import api, exported", ["deep/api.py", "deep/__init__.py"]),
            ("import shadow", ["shadow.py"]),
            ("import nearby", ["client/nearby.py"]),
            ("import unique_origin", []),
            ("from ... import x", []),
            ("runpy.run_path('missing'); runpy.run_path('missing')", []),
        ]
        self.add_file(caller, "\n".join(statement for statement, _ in imports) + "\n")
        for target in ("deep/api.py", "deep/__init__.py", "shadow.py", "client/shadow.py",
                       "client/nearby.py", "deps/lib/unique_origin.py"):
            self.add_file(target, "")
        expected_edges = [
            edge(caller, line_target, line)
            for line, (_, targets) in enumerate(imports, 1)
            for line_target in targets
        ]
        expected_unresolved = [
            (caller, 7, "path-load", "runpy.run_path", "requires a direct, unaliased top-level import runpy"),
        ] * 2

        destination = "scripts/tool space.sh"
        escaped_path = r"./tool\ space.sh"
        variable = {"Type": "ParamExp", "Short": True, "Param": {"Value": "target"}}
        computed = "path word is computed or cannot be verified"
        shell_declarations = [
            (
                (('sou"rc"e', [shell_literal("sou"), shell_quote("rc"), shell_literal("e")]),
                 ("'./tool space.sh'", [{"Type": "SglQuoted", "Value": "./tool space.sh"}])),
                ("source", destination), None,
            ),
            (("sh", "-e", "--", (escaped_path, [shell_literal(escaped_path)])), None,
             ("execute", "-e", computed)),
            (("source", ('"$target"', [shell_quote(variable)])), None,
             ("source", '"$target"', computed)),
            (("sh", "-s", "./tool"), None, ("execute", "-s", computed)),
            (("sh",), None, None),
            (("sh", "--"), None, ("execute", "--", computed)),
            (("sh", "-c", "inline"), None, ("execute", "-c", computed)),
            (("sh", "-c"), None, ("execute", "-c", computed)),
            (("source",), None, ("source", None, "path operand is missing")),
            (("sh", "--", ('"$target"', [shell_quote(variable)])), None, ("execute", "--", computed)),
            (("sh", "--unknown", "script.sh"), None, ("execute", "--unknown", computed)),
            ((('"$target"', [shell_quote(variable)]),), None, ("execute", '"$target"', computed)),
            (("sh", "./utility.sh"), ("execute", "scripts/utility.sh"), None),
        ]
        script = "".join(
            " ".join(word if isinstance(word, str) else word[0] for word in words) + "\n"
            for words, _, _ in shell_declarations
        )
        self.add_file(shell, script)
        self.add_file(destination, "")
        self.add_file("scripts/utility.sh", "")
        statements = []
        for lineno, (words, resolved, unresolved) in enumerate(shell_declarations, 1):
            statements.append(shell_call(lineno, *words, script=script))
            if resolved:
                kind, target = resolved
                expected_edges.append(edge(shell, target, lineno, kind))
            if unresolved:
                expected_unresolved.append((shell, lineno, *unresolved))

        lisp_declarations = [
            ('(load "editor/lib")', "editor/lib.el", None),
            ('(load-file "lib.el")', "editor/lib.el", None),
            ('(eval-when-compile (load-file "../scripts/tool space.sh"))', destination, None),
            ('(load "editor/lib" nil nil t)', None,
             ("load", "editor/lib", "load filename 'editor/lib' has no measured target")),
            ('(load "editor/lib.el" nil nil t t)', "editor/lib.el", None),
            ('(load "editor/lib" nil nil flag)', None,
             ("load", "editor/lib", "load with unsupported arguments")),
            ('(defun later () (load-file "lib.el"))', None,
             ("load-file", "lib.el", "load-file in an unsupported evaluation context")),
            ('\'(load "editor/lib")', None, None),
            ('(load "editor/both.el")', None,
             ("load", "editor/both.el", "load filename 'editor/both.el' matches multiple measured files")),
            ('(load-file . "lib.el")', None, ("load-file", "nil", "load-file with unsupported arguments")),
            ('(load "editor/spaced name")', "editor/spaced name.el", None),
            ('(load-file "$HOME/lib.el")', None,
             ("load-file", "$HOME/lib.el", "load-file with an unusable filename")),
        ]
        self.add_file(lisp, "\n".join(line for line, _, _ in lisp_declarations) + "\n")
        for name in ("editor/lib.el", "editor/both.el", "editor/both.el.el", "editor/spaced name.el"):
            self.add_file(name, "")
        for lineno, (_, target, problem) in enumerate(lisp_declarations, 1):
            if target:
                expected_edges.append(edge(lisp, target, lineno, "path-load"))
            if problem:
                expected_unresolved.append((lisp, lineno, *problem))
        with self.mock_shell_parser({
            shell: shell_tree(*statements), destination: shell_tree(), "scripts/utility.sh": shell_tree(),
        }):
            measurement = self.graph(0)["measurement"]
        self.assert_edge_rows(measurement["edges"], expected_edges)
        rows = []
        for file, line, kind, operand, reason in expected_unresolved:
            if kind == "path-load":
                message = f"unresolved path load {operand}: {reason}"
            elif kind in {"source", "execute"}:
                message = f"shell {kind}: target is outside the parser"
            else:
                conjunction = " and" if " filename '" in reason else ""
                message = f"{reason}{conjunction} is outside the extractor"
            rows.append({"file": file, "line": line, "kind": kind, "operand": operand,
                         "reason": reason, "message": message})
        self.assert_edge_rows(measurement["unresolved"], rows, "unresolved occurrences")
        self.assertEqual(measurement["python_import_roots"], [])
        self.assert_edge_rows(measurement["outside_extractor"], [
            {key: row[key] for key in ("file", "line", "message")} for row in rows
        ], "outside extractor diagnostics")

    def test_module_tree_inventory_and_rollups(self) -> None:
        self.configure_tree()
        fixtures = {
            "left/start.py": [("import right.end", "right/end.py")],
            "left/nested/end.py": [],
            "right/end.py": [],
            "right/start.py": [("import left.nested.end", "left/nested/end.py")],
            "deep/unused/directory/lonely.py": [],
            "root_import.py": [("import left.start", "left/start.py"), ("import right.end", "right/end.py")],
        }
        expected = []
        for source, declarations in fixtures.items():
            self.add_file(source, "\n".join(line for line, _ in declarations) + "\n")
            expected.extend(edge(source, target, line) for line, (_, target) in enumerate(declarations, 1))
        self.commit_all()
        self.add_file("a.py", "print('changed')\n")
        check = self.tree(0, "--base", "HEAD")
        report = check["measurement"]
        leaves = self.assert_tree_leaves(report["tree"])
        self.assertEqual(report["modules"], leaves)
        self.assertEqual(set(check["selection"]["selected"]), set(leaves))
        self.assertEqual(check["selection"]["left_out"], {})
        self.assertEqual(check["metric_version"], "module-tree/1")
        self.assertEqual(check["location_coverage"], "complete")
        self.assert_edge_rows(report["edges"], expected)
        self.assertEqual(report["unresolved"], [])
        self.assertEqual(report["fan_in"], {
            name: len({row["source"] for row in expected if row["target"] == name}) for name in leaves
        })
        self.assertEqual(report["fan_out"], {
            name: len({row["target"] for row in expected if row["source"] == name}) for name in leaves
        })
        self.assert_rollups(report["directory_rollups"], leaves, expected)
        self.assertTrue(report["directory_rollups"][1]["cycles"])
        self.assertEqual(check["findings"], [])

    def test_module_tree_dependency_occurrence_coverage(self) -> None:
        self.configure_tree(elisp=True, shell=True)
        self.add_file("client.py", "import a; runpy.run_path('missing'); runpy.run_path('missing')\n")
        self.add_file("client.el", '(load-file "absent.el") (load-file "a.py") (load-file "absent.el")\n')
        script = 'source "$target"\n'
        self.add_file("client.sh", script)
        variable = {"Type": "ParamExp", "Short": True, "Param": {"Value": "target"}}
        statement = shell_call(1, "source", ('"$target"', [shell_quote(variable)]), script=script)
        with self.mock_shell_parser({"client.sh": shell_tree(statement)}):
            check = self.tree(0)
        loader_reason = "requires a direct, unaliased top-level import runpy"
        expected = [
            {"file": "client.el", "line": 1, "kind": "load-file", "operand": "absent.el",
             "reason": "load-file filename 'absent.el' has no measured target",
             "message": "load-file filename 'absent.el' has no measured target and is outside the extractor"},
            {"file": "client.py", "line": 1, "kind": "path-load", "operand": "runpy.run_path",
             "reason": loader_reason, "message": f"unresolved path load runpy.run_path: {loader_reason}"},
        ] * 2 + [
            {"file": "client.sh", "line": 1, "kind": "source", "operand": '"$target"',
             "reason": "path word is computed or cannot be verified",
             "message": "shell source: target is outside the parser",
            }
        ]
        self.assertEqual(check["outcome"], "pass")
        self.assertEqual(check["findings"], [])
        report = check["measurement"]
        self.assert_edge_rows(report["edges"], [
            edge("client.el", "a.py", 1, "path-load"),
            edge("client.py", "a.py", 1),
        ])
        self.assert_edge_rows(report["unresolved"], expected, "tree unresolved occurrences")
        projected = [{key: row[key] for key in ("file", "line", "message")} for row in expected]
        self.assert_edge_rows(report["outside_extractor"], projected, "tree outside-extractor occurrences")

    def test_module_graph_and_tree_share_completed_extraction(self) -> None:
        self.configure_graph(elisp=True)
        self.declare_check("module-tree", "module_tree", tier=1, enforcement="enforced")
        self.add_file("a.py", "runpy.run_path('missing'); runpy.run_path('missing')\n")
        self.add_file("provider.el", "(provide 'fixture)\n")
        with mock.patch.object(module_graph, "dependencies", wraps=module_graph.dependencies) as extract:
            result, document = self.run_json("--only", "module-tree", "module-graph")
        self.assertEqual(result.returncode, 0, output(result))
        extract.assert_called_once()
        self.assertEqual(extract.call_args.args[1], ["a.py"])
        self.assertEqual(list(extract.call_args.kwargs["elisp"]), ["provider.el"])
        self.assertEqual(extract.call_args.kwargs["shell_modules"], [])
        graph, tree = [
            self.check_by_id(document, check)["measurement"] for check in ("module-graph", "module-tree")
        ]
        for field in ("modules", "edges", "unresolved", "outside_extractor", "python_import_roots",
                      "reader_refusals", "providers"):
            self.assertEqual(graph.get(field), tree.get(field), field)
        repeated = ["runpy.run_path", "runpy.run_path"]
        self.assertEqual([row["operand"] for row in tree["unresolved"]], repeated)
        original_diagnostic = "a.py:1: unresolved path load runpy.run_path"
        self.assertEqual(result.stderr.count(original_diagnostic), 2)

        config = self.read_file("quality-gate.toml").replace('pattern = "*.py"', 'pattern = "a.py"')
        self.write_config(config + """
[classes.other]
description = "Additional tree inputs"
code = true
checks = ["smoke"]

[[rule]]
pattern = "b.py"
class = "other"
reason = "Tree-only source"
""")
        self.add_file("b.py", "importlib.util.spec_from_file_location('fixture', 'absent.py')\n")
        _, document = self.run_graph_and_tree_with_distinct_inputs()
        graph = self.check_by_id(document, "module-graph")["measurement"]
        tree = self.check_by_id(document, "module-tree")["measurement"]
        self.assertEqual(graph["modules"], ["a.py", "provider.el"])
        self.assertEqual(tree["modules"], ["a.py", "b.py", "provider.el"])
        tree_only = "importlib.util.spec_from_file_location"
        self.assertEqual([row["operand"] for row in tree["unresolved"]], [*repeated, tree_only])

        self.add_file("a.py", "run_path('replacement')\n")
        result, document = self.run_graph_and_tree_with_distinct_inputs()
        expected_by_check = {
            "module-graph": ["run_path"], "module-tree": ["run_path", tree_only],
        }
        for identifier, expected in expected_by_check.items():
            rows = self.check_by_id(document, identifier)["measurement"]["unresolved"]
            self.assertEqual([row["operand"] for row in rows], expected)
        self.assertNotIn(original_diagnostic, result.stderr)
        self.assertEqual(result.stderr.count("a.py:1: unresolved path load run_path"), 2)

    def declare_rewrite_command(self, path: str, replacement: str, status: int = 0) -> None:
        program = (
            "from pathlib import Path\n"
            f"Path({path!r}).write_text({replacement!r}, encoding='utf-8')\n"
            f"raise SystemExit({status})\n"
        )
        command = json.dumps(["python3", "-c", program])
        self.write_config(self.read_file("quality-gate.toml") + f"""
[checks.rewrite]
adapter = "command"
tier = 1
enforcement = "advisory"
run = {command}
""")

    def test_graph_consumers_reread_sources_after_command_dispatch(self) -> None:
        for status in (0, 7):
            with self.subTest(status=status):
                self.configure_graph()
                self.declare_rewrite_command("driver.py", "import after\n", status)
                self.declare_check("module-tree", "module_tree", tier=1, enforcement="enforced")
                self.add_file("driver.py", "import before\n")
                for name in ("before.py", "after.py"):
                    self.add_file(name, "")
                self.add_file("diagnostic.py", "run_path('missing')\n")
                with mock.patch.object(
                    module_graph, "dependencies", wraps=module_graph.dependencies,
                ) as extract:
                    result, document = self.run_json("--only", "module-graph", "rewrite", "module-tree")
                self.assertEqual(result.returncode, 0, output(result))
                self.assertEqual(extract.call_count, 2, result.stderr)
                self.assertEqual(extract.call_args_list[0].args[1], extract.call_args_list[1].args[1])
                rewrite = self.check_by_id(document, "rewrite")
                self.assertEqual(rewrite["diagnostics"]["exit_code"], status)
                for identifier, target in (("module-graph", "before.py"), ("module-tree", "after.py")):
                    graph = self.check_by_id(document, identifier)
                    self.assertEqual(graph["measurement"]["edges"], [edge("driver.py", target, 1)])
                self.assertEqual(result.stderr.count("diagnostic.py:1: unresolved path load"), 2)

    def configure_extensionless_python_link(self) -> None:
        self.configure_graph("""
[[rule]]
pattern = "launcher"
class = "doc"
reason = "Extensionless executable link"
""")
        self.add_file("target.py", "#!/usr/bin/env python3\n")
        (self.repo / "launcher").symlink_to("target.py")

    def test_tree_keeps_deferred_inventory_language_after_command(self) -> None:
        self.configure_extensionless_python_link()
        self.declare_rewrite_command("target.py", "import a\n")
        self.declare_check("module-tree", "module_tree", tier=1, enforcement="enforced")
        result, document = self.run_json("--only", "module-graph", "rewrite", "module-tree")
        self.assertEqual(result.returncode, 0, output(result))
        graph = self.check_by_id(document, "module-graph")["measurement"]
        self.assertEqual(graph["modules"], ["a.py", "target.py"])
        self.assertEqual(graph["edges"], [])
        tree = self.check_by_id(document, "module-tree")["measurement"]
        self.assertEqual(tree["modules"], ["a.py", "launcher", "target.py"])
        self.assertEqual(tree["edges"], [edge("launcher", "a.py", 1), edge("target.py", "a.py", 1)])

    def test_deferred_language_error_blocks_only_consumer_that_measures_the_path(self) -> None:
        self.configure_extensionless_python_link()
        self.declare_check("module-tree", "module_tree", tier=1, enforcement="enforced")
        error = policy.GateError("launcher: cannot read shebang")
        with mock.patch.object(inventory, "_selected_language", side_effect=error) as classify:
            result, document = self.run_json("--only", "module-graph", "module-tree")
        self.assertEqual(result.returncode, 1, output(result))
        classify.assert_called_once()
        self.assertEqual(self.check_by_id(document, "module-graph")["outcome"], "pass")
        tree = self.check_by_id(document, "module-tree")
        self.assertEqual(tree["outcome"], "error")
        self.assertEqual(tree["reason"], str(error))
        self.assertNotIn("measurement", tree)

    def test_module_tree_spec_resolves_baseline_and_fixes_threshold(self) -> None:
        key = "checks.module-tree"
        spec = adapters._module_tree_spec(
            {"direction": "max", "baseline": "tree.toml"}, self.repo, self.config_path, key,
        )
        self.assertEqual(spec.metric_version, "module-tree/1")
        self.assertEqual(spec.threshold, 0)
        self.assertEqual(spec.evidence, ("static",))
        self.assertEqual(spec.baseline, self.repo / "tree.toml")
        with self.assertRaisesRegex(policy.ConfigError, r"checks\.module-tree\.direction"):
            adapters._module_tree_spec({"direction": "min"}, self.repo, self.config_path, key)

    def test_run_module_tree_measures_inventory_with_empty_class_selection(self) -> None:
        self.configure_tree()
        self.add_file("isolated.py", "")
        config = policy.load_config(self.repo)
        selection = CheckSelection({}, {}, "full run")
        context = adapters.AdapterContext(
            self.repo, config, config.checks["module-tree"], [], {"isolated.py": "python"},
            "check: module-tree", {}, self.base, selection=selection, inventory_files=["isolated.py"],
        )
        result = adapters._run_module_tree(context)
        self.assertEqual(result.outcome, "pass")
        self.assertEqual(result.measurement["tree"], {
            "path": ".", "directories": [], "files": [{"path": "isolated.py", "language": "python"}],
        })
        self.assertEqual(result.report_fields["selection"], {
            "selected": {"isolated.py": "full run"}, "left_out": {}, "reason": "full run",
        })

    def test_measure_tree_preserves_occurrences_in_advisory_cycles(self) -> None:
        forward = module_graph.Edge("left/a.sh", "right/b.py", 1, "source")
        reverse = module_graph.Edge("right/c.py", "left/a.sh", 1, "path-load")
        self_loop = module_graph.Edge("left/a.sh", "left/a.sh", 2, "source")
        edges = [forward, forward, reverse, self_loop]
        languages = {"left/a.sh": "bash", "right/b.py": "python", "right/c.py": "python"}
        extraction = module_graph.Extraction(sorted(languages), edges, module_graph.DependencyEvidence())
        report, cycles = module_graph.measure_tree(extraction, languages)
        self.assertEqual(cycles, [(self_loop,)])
        self.assertEqual(report["value"], 1)
        occurrences = [item.to_json() for item in edges]
        self.assert_edge_rows(report["edges"], occurrences)
        self.assert_rollups(report["directory_rollups"], sorted(languages), occurrences)

    def test_module_tree_empty_inventory(self) -> None:
        self.configure_tree()
        config = self.read_file("quality-gate.toml").replace(
            '[[rule]]\npattern = "*.py"\nclass = "python"\nreason = "Python source"\n\n', "",
        )
        self.write_config(config)
        (self.repo / "a.py").unlink()
        self.git("add", "-A")
        report = self.tree(0)["measurement"]
        self.assertEqual(report["tree"], {"path": ".", "files": [], "directories": []})
        self.assertEqual(report["edges"], [])
        self.assertEqual(report["fan_in"], {})
        self.assert_rollups(report["directory_rollups"], self.assert_tree_leaves(report["tree"]), [])

    def test_module_tree_runner_preserves_refusal_on_later_failure(self) -> None:
        self.configure_tree(elisp=True)
        self.commit_all()
        self.add_file("broken.el", "(provide 'broken)\n(")
        self.add_file("broken.py", "import (\n")
        result, document = self.run_json("--only", "module-tree", "--base", "HEAD")
        self.assertEqual(result.returncode, 1, output(result))
        check = self.check_by_id(document, "module-tree")
        self.assertEqual(check["outcome"], "error")
        self.assertIn("broken.py: expected readable, valid Python source", check["reason"])
        self.assertCountEqual(check["selection"]["selected"], ["a.py", "broken.py", "broken.el"])
        refusal, = check["measurement"]["reader_refusals"]
        self.assertEqual((refusal["file"], refusal["line"], refusal["stage"]), ("broken.el", 2, "reader"))
        self.assertEqual(check["measurement"]["providers"], [])
        self.assertIn(f"check: module-tree: broken.el:2: {refusal['message']}", result.stderr)

    def test_module_tree_allows_acyclic_private_package_dependency(self) -> None:
        self.configure_tree(elisp=True)
        self.add_file("pkg/__init__.py", "")
        self.add_file("pkg/_nested/__init__.py", "")
        self.add_file("pkg/_nested/_hidden.py", "")
        self.add_file("a.py", "import pkg._nested._hidden\n")
        self.add_file("outside.el", '(load-file "pkg/_nested/__init__.py")\n')
        self.add_file("pkg/_nested/caller.el", '(load-file "_hidden.py")\n')
        check = self.tree(0)
        report = check["measurement"]
        self.assert_edge_rows(report["edges"], [
            edge("a.py", "pkg/_nested/_hidden.py", 1),
            edge("outside.el", "pkg/_nested/__init__.py", 1, "path-load"),
            edge("pkg/_nested/caller.el", "pkg/_nested/_hidden.py", 1, "path-load"),
        ])
        self.assertEqual(check["findings"], [])
        self.assertEqual(report["value"], 0)
        self.assertNotIn("boundary_incomplete", report)

    def test_module_tree_shell_continued_heads(self) -> None:
        self.configure_tree(shell=True)
        caller, target = "caller.sh", "target.sh"
        continuation = "\\\n"
        continued_operand = f"./tar{continuation}get.sh"
        escaped_head = f'"sou\\{continuation}rce"'
        computed = "path word is computed or cannot be verified"
        directory_word = f'"${{BASH_SOURCE%/*}}{continuation}{os.sep}{target}"'
        declarations = (
            (f"sou{continuation}rce ./target.sh", "source", None),
            (f'"sou{continuation}rce" ./target.sh', "source", None),
            (f'"sou"{continuation}rce ./target.sh', "source", None),
            (f".{continuation} ./target.sh", "source", None),
            (f'"ba{continuation}sh" ./target.sh', "execute", f'"ba{continuation}sh"'),
            (continued_operand, "execute", continued_operand),
            (directory_word, "execute", directory_word),
            (f"'sou{continuation}rce' ./target.sh", "execute", f"'sou{continuation}rce'"),
            (f"{escaped_head} ./target.sh", "execute", escaped_head),
            (f"sou{continuation}rce {continued_operand}", "source", continued_operand),
            (f"ba{continuation}sh -s", "execute", f"ba{continuation}sh"),
        )
        self.add_file(caller, "\n".join(command for command, _, _ in declarations) + "\n")
        self.add_file(target, "source ./caller.sh\n")
        occurrences = [edge(target, caller, 1, "source")]
        unresolved = []
        line = 1
        for command, kind, operand in declarations:
            if operand is not None:
                unresolved.append({
                    "file": caller, "line": line, "kind": kind, "operand": operand,
                    "reason": computed, "message": f"shell {kind}: target is outside the parser",
                })
            else:
                occurrences.append(edge(caller, target, line, kind))
            line += command.count("\n") + 1

        self.assert_unbaselined_tree_cycles(
            occurrences, unresolved, "shell unresolved occurrences", env=self.default_tool_env(),
        )

    def test_module_tree_shell_non_load_commands_emit_no_dependencies(self) -> None:
        self.configure_tree(shell=True)
        caller = "caller.sh"
        variable_call = f'"$other"{os.sep}{caller}'
        self.add_file(caller, f"""root="${{BASH_SOURCE%/*}}"
other="$(dirname "$0")"
dirname $0
cd "$root"
"${{BASH_SOURCE%/*}}" ./caller.sh
"$(dirname "$0")" ./caller.sh
{variable_call}
./caller.sh
bash ./caller.sh
sh ./caller.sh
""")
        occurrences = [edge(caller, caller, line, "execute") for line in (8, 9, 10)]
        unresolved = [
            {"file": caller, "line": line, "kind": "execute", "operand": operand,
             "reason": "path word is computed or cannot be verified",
             "message": "shell execute: target is outside the parser"}
            for line, operand in enumerate(('"${BASH_SOURCE%/*}"', '"$(dirname "$0")"', variable_call), 5)
        ]
        self.assert_unbaselined_tree_cycles(
            occurrences, unresolved, "shell execution evidence", env=self.default_tool_env(),
        )

    def test_module_tree_shell_unsupported_words_are_evidence(self) -> None:
        self.configure_tree(shell=True)
        declarations = (
            (r"$'scripts/has\8.sh'", r"scripts/has\8.sh"),
            (r"$'scripts/has\9.sh'", r"scripts/has\9.sh"),
            (r"$'scripts/has\c\\x.sh'", "scripts/has\x1cx.sh"),
            (r"$'scripts/hex-\x619.sh'", "scripts/hex-a9.sh"),
            (r"scripts/has\ space.sh", "scripts/has space.sh"),
            ('"$script"', "scripts/variable.sh"),
            ("scripts/{x{y}z,foo}.sh", "scripts/{x{y}z,foo}.sh"),
            ("scripts/[]a].sh", "scripts/[]a].sh"),
            ("scripts/[!]]-option.sh", "scripts/[!]]-option.sh"),
        )
        for line, (word, target) in enumerate(declarations, 1):
            with self.subTest(word=word):
                self.add_file(target, "")
                head = '"source"' if line % 2 else "'.'"
                self.add_file("caller.sh", f"{head} {word}\n{head} '{target}'\n")
                check = self.tree(0, env=self.default_tool_env())
                self.assertEqual(check["outcome"], "pass")
                self.assertEqual(check["findings"], [])
                report = check["measurement"]
                self.assert_edge_rows(report["edges"], [edge("caller.sh", target, 2, "source")])
                self.assertEqual(report["unresolved"], [{
                    "file": "caller.sh", "line": 1, "kind": "source", "operand": word,
                    "reason": "path word is computed or cannot be verified",
                    "message": "shell source: target is outside the parser",
                }])
                self.assertNotIn("boundary_incomplete", report)

    def test_module_tree_shell_assignment_tilde_requires_proof(self) -> None:
        self.configure_tree(shell=True)
        leaf = "leaf.sh"
        declarations = (
            (f"NAME=prefix:~+{os.sep}{leaf}", f"NAME=prefix:'~+'{os.sep}{leaf}"),
            (f"NAME+=prefix:~{os.sep}{leaf}", f"NAME+=prefix:'~'{os.sep}{leaf}"),
        )
        for computed, literal in declarations:
            with self.subTest(computed=computed):
                self.add_file(computed, "")
                self.add_file("caller.sh", f'"source" {literal}\n')
                result, document = self.run_json("--only", "module-tree", env=self.default_tool_env())
                self.assertEqual(result.returncode, 0, output(result))
                report = self.check_by_id(document, "module-tree")["measurement"]
                self.assertEqual(report["edges"], [edge("caller.sh", computed, 1, "source")])
                self.assertEqual(report["unresolved"], [])

                self.add_file("caller.sh", f'"source" {computed}\n')
                result, document = self.run_json("--only", "module-tree", env=self.default_tool_env())
                self.assertEqual(result.returncode, 0, output(result))
                check = self.check_by_id(document, "module-tree")
                self.assertEqual(check["findings"], [])
                report = check["measurement"]
                self.assertEqual(report["edges"], [])
                unresolved, = report["unresolved"]
                self.assertEqual(unresolved, {
                    "file": "caller.sh", "line": 1, "kind": "source", "operand": computed,
                    "reason": "path word is computed or cannot be verified",
                    "message": "shell source: target is outside the parser",
                })

    def test_module_tree_cycle_edge_ratchet(self) -> None:
        self.configure_tree(elisp=True, shell=True)
        trees, occurrences = self.cycle_fixture(0)
        with self.mock_shell_parser(trees):
            check = self.tree(1)
        report = check["measurement"]
        self.assert_edge_rows(report["edges"], occurrences)
        self.assert_rollups(report["directory_rollups"], self.assert_tree_leaves(report["tree"]), occurrences)
        original = self.assert_cycle_subjects(check, occurrences)
        self.assertEqual(len(original), 5)
        self.tree_baseline(original)
        self.configure_tree('baseline = "tree-baseline.toml"', elisp=True, shell=True)
        self.declare_check("module-graph", "module_graph", tier=1, enforcement="advisory", classes=["python"])
        self.commit_all()
        trusted = str(self.trusted_directory("HEAD"))
        trees, occurrences = self.cycle_fixture(4)
        with self.mock_shell_parser(trees):
            result, document = self.run_json("--policy-from", trusted, "--base", "HEAD")
            self.assertEqual(result.returncode, 0, output(result))
            self.assertEqual(document["schema"], 4)
            moved = self.check_by_id(document, "module-tree")
            original_witness, = self.check_by_id(document, "module-graph")["findings"]
        self.assertEqual(self.assert_cycle_subjects(moved, occurrences), original)
        self.assertTrue(all(finding["covered_by_baseline"] for finding in moved["findings"]))
        self.assert_edge_rows(moved["measurement"]["edges"], occurrences)
        trees, occurrences = self.cycle_fixture(4, extra=True)
        with self.mock_shell_parser(trees):
            check = self.tree(1)
            current_witness, = self.graph(0)["findings"]
        self.assertEqual(original_witness["measurement"], current_witness["measurement"])
        self.assert_edge_rows(check["measurement"]["edges"], occurrences)
        added = self.assert_cycle_subjects(check, occurrences) - original
        self.assertEqual(added, {subject("file-cycle", None, "lisp/core.el", "apps/start.py", "require")})
        self.assertEqual({row["subject"] for row in check["findings"] if row["blocking"]}, added)

    def test_module_tree_singleton_self_loop_requires_own_baseline(self) -> None:
        self.configure_tree('baseline = "tree-baseline.toml"')
        declarations = {"left.py": "right", "right.py": "left", "solo.py": "solo"}
        occurrences = []
        for source, name in declarations.items():
            self.add_file(source, f"import {name}\n")
            occurrences.append(edge(source, f"{name}.py", 1))
        singleton = subject("file-cycle", None, "solo.py", "solo.py", "import")
        subjects = {
            subject("file-cycle", None, row["source"], row["target"], row["kind"]) for row in occurrences
        }
        self.tree_baseline(subjects - {singleton})
        check = self.tree(1)
        self.assertEqual(self.assert_cycle_subjects(check, occurrences), subjects)
        self.assertEqual({row["subject"] for row in check["findings"] if row["blocking"]}, {singleton})
        self.tree_baseline(subjects)
        check = self.tree(0)
        self.assertEqual(self.assert_cycle_subjects(check, occurrences), subjects)
        self.assertTrue(all(row["covered_by_baseline"] for row in check["findings"]))

    def test_module_tree_provide_evidence_and_require_resolution(self) -> None:
        self.configure_tree(elisp=True)
        declarations = {
            "lib/arity.el": "(provide 'arity nil nil)",
            "lib/number.el": "(provide 'number 1)",
            "lib/plain.el": "(provide 'plain) (provide 'plain)",
            "lib/optional.el": "(progn (provide 'optional '(subfeature)))",
            "lib/nil.el": "(provide 'optional-nil nil)",
            "lib/quoted-nil.el": "(provide 'quoted-nil 'nil)",
            "lib/dotted.el": "(provide 'dotted '(one . two))",
            "lib/quoted-atom.el": "(provide 'quoted-atom 'atom)",
            "lib/computed.el": "(provide 'computed (load-file \"../open.el\"))",
            "lib/feature.el": '(provide (load-file "../open.el"))',
            "lib/disputed.el": "(provide 'disputed)",
            "lib/extra.el": "(provide 'extra (load-file \"../open.el\")\n  (load \"open.el\"))",
        }
        for path, form in declarations.items():
            self.add_file(path, form + "\n")
        self.add_file("open.el", "(provide 'disputed nil)\n")
        loads = [f'(load-file "{path}")\n' for path in declarations]
        required = {
            "plain": "lib/plain.el",
            "optional": "lib/optional.el",
            "optional-nil": "lib/nil.el",
            "quoted-nil": "lib/quoted-nil.el",
            "dotted": "lib/dotted.el",
            "quoted-atom": None,
            "arity": None,
            "number": None,
            "computed": None,
            "extra": None,
            "disputed": None,
        }
        self.add_file("caller.el", "".join([*loads, *(f"(require '{name})\n" for name in required)]))
        check = self.tree(0)
        self.assertEqual(check["findings"], [])
        occurrences = [
            edge("caller.el", path, line, "path-load") for line, path in enumerate(declarations, 1)
        ]
        unresolved = []
        for line, (name, target) in enumerate(required.items(), len(loads) + 1):
            if target:
                occurrences.append(edge("caller.el", target, line, "require"))
            else:
                failure = (
                    "has multiple measured providers" if name == "disputed" else "has no measured provider"
                )
                reason = f"require feature '{name}' {failure}"
                unresolved.append(("caller.el", line, "require", name, reason, f"{reason} and"))
        unsupported = "provide with unsupported arguments"
        nested = "load-file in an unsupported evaluation context"
        provider_evidence = [
            ("lib/arity.el", 1, "provide", "arity", unsupported),
            ("lib/number.el", 1, "provide", "number", unsupported),
            ("lib/quoted-atom.el", 1, "provide", "quoted-atom", unsupported),
            ("lib/computed.el", 1, "provide", "computed", unsupported),
            ("lib/computed.el", 1, "load-file", "../open.el", nested),
            ("lib/feature.el", 1, "provide", '(load-file "../open.el")',
             "computed provide feature"),
            ("lib/feature.el", 1, "load-file", "../open.el", nested),
            ("lib/extra.el", 1, "provide", "extra", unsupported),
            ("lib/extra.el", 1, "load-file", "../open.el", nested),
            ("lib/extra.el", 2, "load", "open.el", "load in an unsupported evaluation context"),
        ]
        unresolved.extend((*row, row[-1]) for row in provider_evidence)
        report = check["measurement"]
        self.assert_edge_rows(report["edges"], occurrences)
        self.assertEqual(report["providers"], [
            {"file": "lib/disputed.el", "line": 1, "feature": "disputed"},
            {"file": "lib/plain.el", "line": 1, "feature": "plain"},
            {"file": "lib/plain.el", "line": 1, "feature": "plain"},
        ])
        self.assert_edge_rows(report["unresolved"], [
            {"file": file, "line": line, "kind": kind, "operand": operand,
             "reason": reason, "message": f"{message} is outside the extractor"}
            for file, line, kind, operand, reason, message in unresolved
        ], "provider and require evidence")

    def test_module_tree_require_noerror_preserves_cycles(self) -> None:
        self.configure_tree(elisp=True)
        caller, target = "caller.el", "target.el"
        self.add_file(caller, (
            "(provide 'caller)\n"
            "(require 'target nil 1)\n"
            "(eval-when-compile (require 'target nil 'anything))\n"
            '(require \'unused "target" "non-nil")\n'
            '(require \'target nil (load-file "target.el"))\n'
            '(require "target" nil (load "target.el") nil)\n'
        ))
        self.add_file(target, "(provide 'target)\n(require 'caller)\n")
        occurrences = [
            *(edge(caller, target, line, "require") for line in (2, 3, 4, 5)),
            edge(target, caller, 2, "require"),
        ]
        unresolved = [
            (5, "load-file", target, "load-file in an unsupported evaluation context"),
            (6, "require", "target", "require with unsupported arguments"),
            (6, "load", target, "load in an unsupported evaluation context"),
        ]
        self.assert_unbaselined_tree_cycles(occurrences, [
            {"file": caller, "line": line, "kind": kind, "operand": operand,
             "reason": reason, "message": f"{reason} is outside the extractor"}
            for line, kind, operand, reason in unresolved
        ], "NOERROR argument evidence")

    def test_module_tree_rejects_boundary_key(self) -> None:
        self.add_file("pkg/entry.sh", "")
        for declaration, field, diagnostic in (
            ('boundary = {directory = "pkg", source = ["pkg/entry.sh"]}', "boundary", "unknown key"),
            ('[checks.module-tree.boundary]\ndirectory = "pkg"', "boundary", "unknown key"),
            ('direction = "min"', "direction", "'min'"),
            ('threshold = 1', "threshold", "unknown key"),
            ('classes = ["python"]', "classes", "unknown key"),
            ('suites = ["*.sh"]', "suites", "unknown key"),
            ('programs = ["*.sh"]', "programs", "unknown key"),
        ):
            with self.subTest(declaration=declaration):
                self.configure_tree(declaration, shell=True)
                with mock.patch.object(adapters, "_extract_graph", wraps=adapters._extract_graph) as extract:
                    result, document = self.run_json("--only", "module-tree", env=self.default_tool_env())
                self.assertEqual(result.returncode, 2, output(result))
                self.assertIn(f"checks.module-tree.{field}", document["error"])
                self.assertIn(diagnostic, document["error"])
                extract.assert_not_called()

    def test_module_tree_invalid_baseline_blocks_extraction(self) -> None:
        self.configure_tree('baseline = "tree-baseline.toml"')
        self.add_file(
            "tree-baseline.toml", 'check = "module-tree"\nmetric_version = "module-tree/1"\n[[entry\n',
        )
        with mock.patch.object(module_graph, "dependencies") as extract:
            check = self.tree(1)
        self.assertEqual(check["outcome"], "error")
        self.assertIn("tree-baseline.toml", check["reason"])
        self.assertEqual(check["selection"]["selected"], {"a.py": "full run"})
        self.assertNotIn("measurement", check)
        extract.assert_not_called()

    def test_module_tree_inventory_failure_blocks_extraction(self) -> None:
        self.configure_tree()
        self.commit_all()
        self.add_file("unclassified.data", "")
        with mock.patch.object(module_graph, "dependencies") as extract:
            result, document = self.run_json("--only", "module-tree", "--base", "HEAD")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unclassified.data", result.stderr)
        check = self.check_by_id(document, "module-tree")
        self.assertEqual(check["outcome"], "unsupported")
        self.assertEqual(check["reason"], "skipped because inventory failed")
        self.assertEqual(check["selection"]["selected"], {})
        self.assertNotIn("measurement", check)
        extract.assert_not_called()

    def test_module_tree_reader_refusal_keeps_baseline_unmeasured(self) -> None:
        self.configure_tree(elisp=True)
        self.add_file("caller.el", '(provide \'caller)\n(load-file "closed/target.el")\n(require \'target)\n')
        self.add_file("consumer.el", "(require 'caller)\n")
        self.add_file("closed/target.el", "(provide 'target)\n(require 'caller)\n")
        self.add_file("solo.py", "import solo\n")
        unaffected = edge("solo.py", "solo.py", 1)
        observed = subject("file-cycle", None, "solo.py", "solo.py", "import")
        stale = subject("file-cycle", None, "deleted.py", "deleted.py", "import")
        original = self.tree(1)
        dependent = {
            subject("file-cycle", None, "caller.el", "closed/target.el", "path-load"),
            subject("file-cycle", None, "caller.el", "closed/target.el", "require"),
            subject("file-cycle", None, "closed/target.el", "caller.el", "require"),
        }
        self.assertEqual({row["subject"] for row in original["findings"]}, {observed, *dependent})
        absent = {stale, *dependent}
        retained = {observed, *absent}
        self.tree_baseline(retained)
        self.configure_tree('baseline = "tree-baseline.toml"', elisp=True)
        self.commit_all()
        worklist = self.run_qg("worklist", "module-tree", "--json")
        self.assertEqual(worklist.returncode, 0, output(worklist))
        self.assertCountEqual(
            [row["subject"] for row in self.parse_json(worklist)["rows"]], {observed, *dependent},
        )
        self.add_file("closed/target.el", "(provide 'target)\n(")
        check = self.tree(0)
        self.assertEqual(self.assert_cycle_subjects(check, [unaffected]), {observed})
        self.assertTrue(check["findings"][0]["covered_by_baseline"])
        self.assertCountEqual(check["unmeasured_baseline_entries"], absent)
        self.assertEqual(check["resolved_baseline_entries"], [])
        report = check["measurement"]
        self.assertIn("closed/target.el", self.assert_tree_leaves(report["tree"]))
        self.assert_edge_rows(report["edges"], [
            edge("caller.el", "closed/target.el", 2, "path-load"),
            edge("consumer.el", "caller.el", 1, "require"),
            unaffected,
        ])
        refusal, = report["reader_refusals"]
        self.assertEqual(
            (refusal["file"], refusal["line"], refusal["stage"]), ("closed/target.el", 2, "reader"),
        )
        self.assertEqual(report["providers"], [{"file": "caller.el", "line": 1, "feature": "caller"}])
        unresolved, = report["unresolved"]
        self.assertEqual(unresolved, {
            "file": "caller.el", "line": 3, "kind": "require", "operand": "target",
            "reason": "require feature 'target' has no measured provider",
            "message": "require feature 'target' has no measured provider and is outside the extractor",
        })
        self.assertEqual(report["outside_extractor"], [
            {key: unresolved[key] for key in ("file", "line", "message")},
            {key: refusal[key] for key in ("file", "line", "message")},
        ])
        worklist = self.run_qg("worklist", "module-tree", "--json")
        self.assertEqual(worklist.returncode, 0, output(worklist))
        work = self.parse_json(worklist)
        self.assertEqual([row["subject"] for row in work["rows"]], [observed])
        self.assertCountEqual(work["notes"], [
            {"check": "module-tree", "subject": name, "reason": "unmeasured"} for name in absent
        ])
        self.assert_tree_pruned_subjects(retained)
        self.tree_baseline(absent)
        observed_check = self.tree(1)
        self.assertEqual(self.assert_cycle_subjects(observed_check, [unaffected]), {observed})
        self.assertTrue(observed_check["findings"][0]["blocking"])
        self.tree_baseline(retained)
        self.add_file("closed/target.el", "(provide 'target)\n")
        check = self.tree(0)
        self.assertEqual(self.assert_cycle_subjects(check, [unaffected]), {observed})
        self.assertCountEqual(check["resolved_baseline_entries"], absent)
        self.assertEqual(check["unmeasured_baseline_entries"], [])
        worklist = self.run_qg("worklist", "module-tree", "--json")
        self.assertEqual(worklist.returncode, 0, output(worklist))
        self.assertCountEqual(self.parse_json(worklist)["notes"], [
            {"check": "module-tree", "subject": name, "reason": "no longer exists"} for name in absent
        ])
        self.assert_tree_pruned_subjects({observed})
        worklist = self.run_qg("worklist", "module-tree", "--json")
        self.assertEqual(worklist.returncode, 0, output(worklist))
        self.assertEqual(self.parse_json(worklist)["notes"], [])

    def assert_tree_pruned_subjects(self, subjects: set[str]) -> None:
        result, document = self.run_json("--prune", "module-tree")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertTrue(document["prune"]["performed"], document["prune"])
        baseline = tomllib.loads(self.read_file("tree-baseline.toml"))
        self.assertEqual(
            {key: baseline[key] for key in ("check", "metric_version")},
            {"check": "module-tree", "metric_version": "module-tree/1"},
        )
        self.assertCountEqual(baseline["entry"], [
            {"subject": name, "bound": 1, "reason": "Fixture dependency"} for name in subjects
        ])

    def test_tree_cycle_grouping_includes_edges_outside_legacy_witness(self) -> None:
        self.configure_graph()
        self.declare_check("module-tree", "module_tree", tier=1, enforcement="enforced")
        declarations = {
            "left/a.py": [
                ("import runpy", []),
                ("import left.deep.b, left.deep.b; runpy.run_path('deep/b.py')", [
                    ("left/deep/b.py", "import"), ("left/deep/b.py", "import"),
                    ("left/deep/b.py", "path-load"),
                ]),
            ],
            "left/deep/b.py": [
                ("import left.a, right.c", [("left/a.py", "import"), ("right/c.py", "import")]),
            ],
            "right/c.py": [("import left.a, right.c", [("left/a.py", "import"), ("right/c.py", "import")])],
            "left/sender.py": [("import right.shallow", [("right/shallow.py", "import")])],
            "right/shallow.py": [],
            "right/send.py": [("import left.receiver", [("left/receiver.py", "import")])],
            "left/receiver.py": [],
        }
        expected = []
        for path, lines in declarations.items():
            self.add_file(path, "".join(f"{code}\n" for code, _ in lines))
            expected.extend(
                edge(path, target, number, kind)
                for number, (_, targets) in enumerate(lines, 1)
                for target, kind in targets
            )
        result, document = self.run_json("--only", "module-graph", "module-tree")
        self.assertEqual(result.returncode, 1, output(result))
        tree = self.check_by_id(document, "module-tree")
        legacy = self.check_by_id(document, "module-graph")
        leaves = self.assert_tree_leaves(tree["measurement"]["tree"])
        self.assert_edge_rows(tree["measurement"]["edges"], expected)
        self.assert_edge_rows(legacy["measurement"]["edges"], expected)
        self.assert_rollups(tree["measurement"]["directory_rollups"], leaves, expected)
        self.assert_cycle_subjects(tree, expected)
        self.assertEqual(tree["measurement"]["value"], 6)
        witness, = legacy["findings"]
        self.assertEqual(witness["measurement"], {
            "component": ["left/a.py", "left/deep/b.py", "right/c.py"],
            "cycle": [edge("left/a.py", "left/deep/b.py", 2), edge("left/deep/b.py", "left/a.py", 1)],
        })

    def test_module_tree_reader_protocol_validates_the_entire_report(self) -> None:
        self.configure_tree(elisp=True)
        self.add_file("a.el", "")
        self.add_file("b.el", "")
        refusal = {"kind": "reader-error", "stage": "reader", "line": 1, "message": "fixture refusal"}
        valid = {"kind": "require", "line": 1, "target": "b.el"}
        malformed = [
            {"a.el": [refusal]},
            {"a.el": [refusal], "b.el": [], "extra.el": []},
            {"a.el": "not a row array", "b.el": []},
            {"a.el": [37], "b.el": []},
            {"a.el": [{**refusal, "stage": "walker"}], "b.el": []},
            {"a.el": [{"kind": "provider", "line": 1, "feature": True}], "b.el": []},
            {"a.el": [valid], "b.el": [{"kind": "outside", "line": 1, "message": "no fields"}]},
            {"a.el": [refusal], "b.el": [{**valid, "line": True}]},
            {"a.el": [refusal], "b.el": [{**valid, "line": 0}]},
            {"a.el": [refusal], "b.el": [{**valid, "target": "not-inventory.el"}]},
            {"a.el": [refusal, refusal], "b.el": []},
            {"a.el": [valid, refusal], "b.el": []},
        ]

        def helper(argv, **_options):
            report = self.repo / argv[-1]
            report.write_text(json.dumps(payload), encoding="utf-8")
            return runner.RunResult((), "completed", 0)

        for payload in malformed:
            with self.subTest(payload=payload), mock.patch.object(adapters, "run", side_effect=helper):
                with mock.patch.object(module_graph, "dependencies") as extract:
                    check = self.tree(1)
                self.assertEqual(check["outcome"], "error")
                self.assertIn("Emacs reader", check["reason"])
                self.assertNotIn("measurement", check)
                extract.assert_not_called()

    def test_module_tree_elisp_walker_exception_is_hard(self) -> None:
        self.configure_tree(elisp=True)
        self.add_file("a.el", "(load-file \"a.py\")\n")
        reader = adapters.elisp_batch.MODULE_GRAPH_READER.replace(
            "(defun qg-graph-walk (forms path modules providers)",
            '(defun qg-graph-walk (forms path modules providers) (error "forced walker failure")',
        )
        with mock.patch.object(adapters.elisp_batch, "MODULE_GRAPH_READER", reader):
            check = self.tree(1)
        self.assertEqual(check["outcome"], "error")
        self.assertIn("forced walker failure", check["reason"])
        self.assertNotIn("measurement", check)

    def test_module_tree_elisp_load_normalizes_names_and_refuses_escape(self) -> None:
        self.configure_tree(elisp=True)
        caller = "lisp/nested/caller.el"
        target = "lib/space name.py"
        self.add_file(target, "")
        for path in ("lib/choice.el", "lib/choice.el.el", "lib/$DEC0Y.el", "lib/c:drive.el",
                     "lib/control\x1c.el", "lib/back\\slash.el"):
            self.add_file(path, "")
        declarations = [
            ('(load "lib//./gone/../space name.py")', target, None),
            ('(load-file "../../lib//./space name.py")', target, None),
            ('(load-file "../../../lib/space name.py")', None, "with an unusable filename"),
            ('(load "lib/../../lib/space name.py")', None, "with an unusable filename"),
            ('(load "lib/space name.py" nil nil t)', target, None),
            ('(load "lib/space name.py" nil nil nil t)', None, "has no measured target"),
            ('(load "lib/choice.el")', None, "matches multiple measured files"),
            ('(load "lib/choice.el" nil nil t t)', "lib/choice.el", None),
            ('(load "lib/choice" nil nil nil t)', "lib/choice.el", None),
            ('(load "~/lib/choice.el")', None, "with an unusable filename"),
            (f'(load "{os.sep}lib/choice.el")', None, "with an unusable filename"),
            ('(load "lib/$DEC0Y.el")', None, "with an unusable filename"),
            ('(load "lib/c:drive.el")', None, "with an unusable filename"),
            (r'(load "lib/control\034.el")', None, "with an unusable filename"),
            (r'(load "lib/back\\slash.el")', None, "with an unusable filename"),
        ]
        self.add_file(caller, "".join(f"{form}\n" for form, _, _ in declarations))
        report = self.tree(0)["measurement"]
        self.assert_edge_rows(report["edges"], [
            edge(caller, destination, line, "path-load")
            for line, (_, destination, _) in enumerate(declarations, 1) if destination is not None
        ])
        unresolved = [(row["line"], row["kind"], row["reason"]) for row in report["unresolved"]]
        rejected = [
            (line, "load-file" if form.startswith("(load-file") else "load", reason)
            for line, (form, _, reason) in enumerate(declarations, 1) if reason
        ]
        self.assertEqual(len(unresolved), len(rejected), unresolved)
        for (line, kind, reason), expected in zip(unresolved, rejected, strict=True):
            wanted_line, wanted_kind, suffix = expected
            self.assertEqual((line, kind), (wanted_line, wanted_kind))
            self.assertTrue(reason.endswith(suffix), reason)

    def test_module_tree_shell_options_expansions_and_mismatched_parts(self) -> None:
        self.configure_tree(shell=True)
        caller = "caller.sh"
        computed = "path word is computed or cannot be verified"
        cases = [
            ("-flag.sh", "'-flag.sh'", "path operand is an option"),
            ("+flag.sh", '"+"flag.sh', "path operand is an option"),
            ("vars/$item.sh", "vars/$item.sh", computed),
            ("cmd/$(echo x).sh", "cmd/$(echo x).sh", computed),
            ("wild/*.sh", "wild/*.sh", computed),
            ("brace/{a,b}.sh", "brace/{a,b}.sh", computed),
            ("~/home.sh", "~/home.sh", computed),
            ("name=prefix:~/assignment.sh", "name=prefix:~/assignment.sh", computed),
        ]
        for filename, _, _ in cases:
            self.add_file(filename, "")
        commands = [f"source {operand}" for _, operand, _ in cases]
        commands.extend(f"source '{filename}'" for filename, _, why in cases if why == computed)
        self.add_file(caller, "\n".join(commands) + "\n")
        report = self.tree(0, env=self.default_tool_env())["measurement"]
        self.assert_edge_rows(report["edges"], [
            edge(caller, filename, line, "source")
            for line, (filename, _, _) in enumerate(cases[2:], len(cases) + 1)
        ])
        self.assert_edge_rows(report["unresolved"], [
            {"file": caller, "line": line, "kind": "source", "operand": operand, "reason": why,
             "message": "shell source: target is outside the parser"}
            for line, (_, operand, why) in enumerate(cases, 1)
        ])

        decoy = "madeup.sh"
        self.add_file(decoy, "")
        script = 'source "./real".sh\nsource "./madeup".sh\n'
        self.add_file(caller, script)
        parts = [shell_quote("./madeup"), shell_literal(".sh")]
        bad = shell_call(1, "source", ('"./real".sh', parts), script=script)
        good = shell_call(2, "source", ('"./madeup".sh', parts), script=script)
        parsers = {filename: shell_tree() for filename, _, _ in cases}
        parsers.update({decoy: shell_tree(), caller: shell_tree(bad, good)})
        with self.mock_shell_parser(parsers):
            actual = self.tree(0)["measurement"]
        self.assertEqual(actual["edges"], [edge(caller, decoy, 2, "source")])
        self.assertEqual(actual["unresolved"], [
            {"file": caller, "line": 1, "kind": "source", "operand": '"./real".sh', "reason": computed,
             "message": "shell source: target is outside the parser"},
        ])

    def test_same_line_shell_kinds_preserve_legacy_occurrence_order(self) -> None:
        self.configure_graph('programs = ["program.sh"]\n', shell=True)
        self.add_file("caller.sh", "source ./program.sh; ./program.sh; . ./program.sh\n")
        self.add_file("program.sh", "")
        result, document = self.run_json("--only", "module-graph", env=self.default_tool_env())
        self.assertEqual(result.returncode, 1, output(result))
        check = self.check_by_id(document, "module-graph")
        source = edge("caller.sh", "program.sh", 1, "source")
        self.assertEqual(check["measurement"]["edges"], [
            edge("caller.sh", "program.sh", 1, "execute"), source, source,
        ])
        self.assert_legacy_graph_findings(check, result, [
            ("Dependency on program (caller.sh -> program.sh) at line 1", [source], {"edge": source}),
        ])
