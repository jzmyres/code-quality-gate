from __future__ import annotations

import tomllib
from typing import Any

from support import BASE_CONFIG, GATE, FixtureCase

from quality_gate import adapters, module_graph, policy


def edge(source: str, target: str, line: int) -> dict[str, str | int]:
    return {"source": source, "target": target, "line": line}


class ModuleGraphTests(FixtureCase):
    def configure_graph(self, suites: str = "") -> None:
        self.write_config(BASE_CONFIG + """
[checks.module-graph]
adapter = "module_graph"
tier = 1
enforcement = "enforced"
classes = ["python"]
""" + suites)

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

    def test_module_graph_empty_scope(self) -> None:
        self.configure_graph()
        config = policy.load_config(self.repo)
        check = config.checks["module-graph"]
        context = adapters.AdapterContext(self.repo, config, check, [], {}, "check", {}, self.base)
        result = adapters._run_module_graph(context)
        self.assertEqual(result.outcome, "pass")
        measurement, cycles, suite_edges = module_graph.measure(self.repo, [], check.spec)
        self.assertEqual(result.measurement, measurement)
        self.assertEqual((measurement["modules"], cycles, suite_edges), ([], [], []))

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
        measurement, cycles, suite_edges = module_graph.measure(GATE, modules, spec)
        (component, _), = cycles
        self.assertEqual(len(component), 24)
        self.assertIn("quality_gate/env_surface.py", component)
        self.assertTrue(all(path.startswith("quality_gate/") for path in component))
        self.assertEqual(len(suite_edges), 16)
        self.assertIn(
            module_graph.Edge("tests/test_adapters.py", "tests/test_python_tests.py", 17),
            suite_edges,
        )
        self.assertEqual(measurement["modules"], sorted(modules))
        self.assertEqual(measurement["value"], 17)
