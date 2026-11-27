"""Exercise the environment inventory through both readers and the gate."""
from __future__ import annotations

import ast
import os
import shutil
import subprocess
import unittest
from textwrap import indent
from unittest import mock

from support import BASE_CONFIG, GATE, FixtureCase, output

from quality_gate import adapters, env_surface, policy


FIXTURES = GATE / "tests" / "fixtures" / "env_surface"


def fixture_source(language: str) -> str:
    lines = (FIXTURES / f"{language}.md").read_text(encoding="utf-8").splitlines(keepends=True)
    return "".join(lines[1:-1])


class EnvSurfaceTests(FixtureCase):
    def configure(self, allow: str = "[]", *, shell: bool = False) -> None:
        self.write_config(BASE_CONFIG.replace(
            'checks = ["smoke"]', 'checks = ["smoke", "env_surface"]',
        ) + f'''
[checks.env_surface]
adapter = "env_surface"
tier = 1
enforcement = "enforced"
allow = {allow}
''' + ('''
[[rule]]
pattern = "*.sh"
class = "python"
reason = "selected shell fixture"
''' if shell else ""))

    def inventory(self, expected: int):
        self.git("add", "-A")
        result, report = self.run_json("--only", "env_surface")
        self.assertEqual(result.returncode, expected, output(result))
        return self.check_by_id(report, "env_surface")

    def assert_rows(self, path, source, expected):
        self.add_file(path, source)
        rows, errors = env_surface.measure(self.repo, [path])
        self.assertEqual(errors, [])
        self.assertEqual(rows, [
            env_surface.Finding(name, path, line, access)
            for line, name, access in expected
        ])

    def test_env_surface_python_constructs(self):
        self.assert_rows("a.py", fixture_source("python"), [
            (5, "SUBSCRIPT", "read"),
            (6, "GET", "read"),
            (7, "GETENV", "read"),
            (8, "MEMBER", "read"),
            (9, "ABSENT", "read"),
            (10, "STORE", "write"),
            (11, "DELETE", "write"),
            (12, "POP", "write"),
            (13, "DEFAULT", "write"),
            (14, "UPDATE", "write"),
            (14, "KEYWORD", "write"),
            (15, "PUT", "write"),
            (16, "UNSET", "write"),
            (17, "CHILD", "write"),
            (18, "EXTRA", "write"),
            (21, None, "computed"),
            (22, "EXEC", "write"),
            (23, "SPAWN", "write"),
            (24, "EXEC_LIST", "write"),
            (25, None, "computed"),
            (27, None, "computed"),
            (28, None, "computed"),
            (29, None, "computed"),
            (30, None, "computed"),
            (31, None, "computed"),
            (32, "PAIR", "write"),
            (32, None, "computed"),
            (33, "KEYWORD_GET", "read"),
            (34, None, "computed"),
        ])

    def test_env_surface_scoped_imports(self):
        source = """\
import os
def uses_alias():
    from os import environ as env
    return env.get("ALIASED")
async def uses_os():
    return os.getenv("MODULE")
def shadows_os(os):
    return os.getenv("LOCAL")
class Example:
    import os as platform
    value = platform.getenv("CLASS")
"""
        self.assert_rows("a.py", source, [
            (4, "ALIASED", "read"),
            (6, "MODULE", "read"),
            (11, "CLASS", "read"),
        ])

    def test_env_surface_imports_stop_at_scope_boundaries(self):
        imports = env_surface.PythonImports([])
        imports.visit_Import(ast.parse("import os, subprocess as sp").body[0])
        imports.visit_ImportFrom(ast.parse("from os import environ as env").body[0])
        imports.visit_FunctionDef(ast.parse("def local(): import os as hidden").body[0])
        self.assertEqual(imports.names, {"os": "os", "sp": "subprocess", "env": "os.environ"})

    def test_env_surface_function_and_class_headers_use_outer_imports(self):
        tree = ast.parse(
            'import os\n'
            'def example(os=os.getenv("DEFAULT")): os.getenv("SHADOWED")\n'
            'class Example(os.getenv("BASE")): import os; os.getenv("BODY")\n'
        )
        reader = env_surface.PythonReader(tree, "a.py")
        reader.visit_FunctionDef(tree.body[1])
        reader.visit_ClassDef(tree.body[2])
        self.assertEqual([row.name for row in reader.findings], ["DEFAULT", "BASE", "BODY"])

    def test_env_surface_subscript_and_membership_consume_the_mapping(self):
        tree = ast.parse('import os\n"FIRST" in os.environ in values\nos.environ["SECOND"]')
        reader = env_surface.PythonReader(tree, "a.py")
        reader.visit_Compare(tree.body[1].value)
        reader.visit_Subscript(tree.body[2].value)
        self.assertEqual([row.name for row in reader.findings], ["FIRST", "SECOND"])

    def test_env_surface_inherited_copy_is_consumed_only_for_child_environment(self):
        tree = ast.parse(
            'import os, subprocess\n'
            'subprocess.run([], env=os.environ.copy())\n'
            'os.environ.copy()\n'
        )
        reader = env_surface.PythonReader(tree, "a.py")
        child, standalone = (statement.value for statement in tree.body[1:])
        self.assertTrue(reader.is_copy(standalone))
        self.assertFalse(reader.is_copy(ast.parse('os.environ.copy(1)', mode="eval").body))
        self.assertTrue(reader.inherited(child.keywords[0].value))
        self.assertFalse(reader.inherited(ast.Name(id="other")))
        reader.visit_Call(child)
        reader.environment_method(standalone, standalone.func)
        self.assertEqual(reader.findings, [env_surface.Finding(None, "a.py", 3, "computed")])

    def test_env_surface_mapping_reports_literal_and_computed_keys(self):
        tree = ast.parse(
            'import os\n{**os.environ, "CHILD": "value", key: "value"}\n'
            '[("PAIR", "value"), dynamic_pair]'
        )
        reader = env_surface.PythonReader(tree, "a.py")
        reader.dict_writes(tree.body[1].value, inherited=True)
        reader.pair_writes(tree.body[2].value)
        self.assertEqual([(row.name, row.access) for row in reader.findings], [
            ("CHILD", "write"), (None, "computed"), ("PAIR", "write"), (None, "computed"),
        ])

    def test_env_surface_allowlists_adjacent_local_child_environment_overrides(self):
        names = ("EARLY", "LATE", "VALUE", "FIRST", "SECOND", "METHOD")
        self.configure("[" + ", ".join(f'{{name = "{name}", owner = "fixture"}}' for name in names) + "]")
        self.add_file("a.py", '''\
import os as system
import subprocess as process
from subprocess import check_output as output
def inline(argv):
    return process.run(argv, env={"EARLY": "before", **system.environ, "LATE": system.getenv("VALUE")})
def local(argv):
    child = {"EARLY": "before", **system.environ, "LATE": system.getenv("VALUE")}
    return process.run(argv, env=child)
def copied(argv):
    child = system.environ.copy()
    output(argv, env=child)
async def constructed(argv):
    from os import environ as inherited
    import subprocess as local_process
    child = dict(inherited, FIRST="initial",
                 SECOND="next")
    result = local_process.Popen(argv, env=child)
    return result
class Worker:
    def launch(self, argv):
        child = {**system.environ, "METHOD": "enabled"}
        return process.run(argv, env=child)
''')
        report = self.inventory(0)
        expected = [(5, "EARLY", "write"), (5, "LATE", "write"), (5, "VALUE", "read"),
                    (7, "EARLY", "write"), (7, "LATE", "write"), (7, "VALUE", "read"),
                    (15, "FIRST", "write"), (16, "SECOND", "write"), (21, "METHOD", "write")]
        self.assertEqual(report["measurement"]["findings"], [
            {"name": name, "path": "a.py", "line": line, "access": access} for line, name, access in expected
        ])

    def assert_computed_child_environment(self, body, lines, *, module="", parameters="argv"):
        header = f"import os\nimport subprocess\n{module}def launch({parameters}):\n"
        source = header + indent(body + "\n", "    ")
        self.assert_rows("a.py", source, [(line + header.count("\n"), None, "computed") for line in lines])

    def test_env_surface_keeps_nonlocal_or_escaping_child_mappings_computed(self):
        assignment = 'child = {**os.environ, "MODE": "demo"}'
        invocation = 'subprocess.run(argv, env=child)'
        cases = (
            (f'{assignment}\n{invocation}\n{invocation}', (1, 2, 3)),
            (f'{assignment}\ninspect_mapping(child)\n{invocation}', (1, 3)),
            (f'{assignment}\n{invocation}\nreturn child', (1, 2)),
            (f'child = {{}}\n{assignment}\n{invocation}', (2, 3)),
            (f'global child\n{assignment}\n{invocation}', (2, 3)),
            (f'{assignment}\nsubprocess.run(child, env=child)', (1, 2)),
            (f'import another_module as child\n{assignment}\n{invocation}', (2, 3)),
            (f'match argv:\n    case child:\n        pass\n{assignment}\n{invocation}', (4, 5)),
            (f'try:\n    pass\nexcept Exception as child:\n    pass\n{assignment}\n{invocation}', (5, 6)),
            (f'def nested(child): pass\n{assignment}\n{invocation}', (2, 3)),
        )
        for body, lines in cases:
            with self.subTest(body=body):
                self.assert_computed_child_environment(body, lines)
        self.assert_rows("a.py", '''\
import os, subprocess
def outer():
    child = None
    def launch(argv):
        nonlocal child
        child = {**os.environ, "MODE": "demo"}
        return subprocess.run(argv, env=child)
''', [(6, None, "computed"), (7, None, "computed")])

    def test_env_surface_keeps_unresolved_child_mappings_computed(self):
        assignment = 'child = {**os.environ, "MODE": "demo"}'
        invocation = 'subprocess.run(argv, env=child)'
        cases = (
            (f'{assignment}\nother.run(argv, env=child)', (1,), {}),
            (f'{assignment}\nsubprocess.unknown(argv, env=child)', (1, 2), {}),
            (f'{assignment}\nsubprocess.run(argv, env=child, **opts)', (1, 2), {}),
            (f'child = {{**os.environ, key: "demo"}}\n{invocation}', (1, 2), {}),
            (f'child = {{**os.environ, **extra}}\n{invocation}', (1, 2), {}),
            (f'child = dict(os.environ, **extra)\n{invocation}', (1, 2), {}),
            (f'child = os.environ.copy(extra)\n{invocation}', (1, 2), {}),
            (f'child = other\n{invocation}', (2,), {}),
            (f'{assignment}\n{invocation}', (1,), {"parameters": "argv, subprocess"}),
            (f'{assignment}\n{invocation}', (2,), {"parameters": "argv, os"}),
            (f'child = dict(os.environ, MODE="demo")\n{invocation}', (1, 2), {"module": "dict = other\n"}),
            (f'{assignment}\n{invocation}', (1, 2), {"module": "subprocess = other\n"}),
            (f'{assignment}\n{invocation}', (1, 2), {"module": "subprocess.run = other\n"}),
            (f'{assignment}\n{invocation}', (1, 2), {"module": "from extra import *\n"}),
            (f'vars()\n{assignment}\n{invocation}', (2, 3), {}),
            (f'getattr(subprocess, "__dict__")\n{assignment}\n{invocation}', (2, 3), {}),
            (f'{assignment}\n{invocation}', (1, 2), {"module": "from builtins import setattr as reflect\n"}),
        )
        for body, lines, options in cases:
            with self.subTest(body=body, options=options):
                self.assert_computed_child_environment(body, lines, **options)

    def test_env_surface_elisp_constructs(self):
        self.assert_rows("example.el", fixture_source("elisp"), [
            (2, "GET", "read"),
            (3, "SET", "write"),
            (4, None, "computed"),
            (5, "PUSH", "write"),
            (6, None, "computed"),
            (7, "ONE", "write"),
            (7, "TWO", "write"),
            (8, "ONE", "read"),
            (9, None, "computed"),
            (11, "ADDED", "write"),
            (12, None, "computed"),
            (13, None, "computed"),
            (14, "C", "write"),
            (15, "LOCAL", "write"),
            (15, "LOCAL", "read"),
            (16, None, "computed"),
            (16, "A", "read"),
            (17, "A", "read"),
            (18, None, "computed"),
            (19, "KNOWN", "write"),
            (19, None, "computed"),
        ])

    def test_env_surface_star_os_import_fails_at_import(self):
        self.configure('[{name = "X", owner = "fixture"}]')
        self.add_file("a.py", '\nfrom os import *\ngetenv("X")\n')
        check = self.inventory(1)
        self.assertEqual(check["measurement"]["findings"], [
            {"name": None, "path": "a.py", "line": 2, "access": "computed"},
        ])

    def test_env_surface_local_mapping_alias_preserves_literal_names(self):
        tree = ast.parse(
            'import os as platform\n'
            'def local():\n'
            '    env = platform.environ\n'
            '    alias: dict = env\n'
            '    alias["READ"]\n'
            '    env["WRITE"] = "value"\n'
        )
        reader = env_surface.PythonReader(tree, "a.py")
        local, alias = tree.body[1].body[:2]
        reader.visit_Assign(local)
        reader.visit_AnnAssign(alias)
        self.assertEqual(reader.findings, [])
        for statement in tree.body[1].body[2:]:
            reader.visit(statement)
        self.assertEqual(reader.findings, [
            env_surface.Finding("READ", "a.py", 5, "read"),
            env_surface.Finding("WRITE", "a.py", 6, "write"),
        ])

    def test_env_surface_star_import_visitor_ignores_non_os_imports(self):
        tree = ast.parse("from pathlib import *\nfrom .os import *\nfrom os import *")
        reader = env_surface.PythonReader(tree, "a.py")
        for node in tree.body:
            reader.visit_ImportFrom(node)
        self.assertEqual(reader.findings, [env_surface.Finding(None, "a.py", 3, "computed")])

    def test_env_surface_python_shebang(self):
        self.assert_rows("script", '#!/usr/bin/env -S python3 -I\nimport os\nos.getenv("HOME")\n', [
            (3, "HOME", "read"),
        ])

    def test_env_surface_adapter_applies_parsed_policy_to_selected_classes(self):
        self.configure('[{name = "HOME", owner = "POSIX"}]')
        self.add_file("a.py", 'import os\nos.getenv("HOME")\n')
        config = policy.load_config(self.repo)
        check = config.checks["env_surface"]
        parsed = adapters._env_surface_spec(
            {"allow": [{"name": "HOME", "owner": "POSIX"}]},
            self.repo, self.config_path, "checks.env_surface",
        )
        self.assertEqual(parsed.spec, check.spec)
        context = adapters.AdapterContext(
            self.repo, config, check, ["a.py", "README.md"],
            {"a.py": "python", "README.md": "doc"}, "check: env_surface", {}, self.base,
            inventory_files=["a.py", "README.md"],
        )
        result = adapters._run_env_surface(context)
        self.assertEqual(result.outcome, "pass")
        self.assertEqual(result.measurement["findings"], [
            {"name": "HOME", "path": "a.py", "line": 2, "access": "read"},
        ])

    def test_env_surface_allowed_names_remain_in_report(self):
        self.configure('[{name = "HOME", owner = "POSIX"}, {prefix = "XDG_", owner = "XDG"}]')
        self.add_file("a.py", 'import os\nos.getenv("HOME")\nos.putenv("XDG_CACHE_HOME", "/cache")\n')
        check = self.inventory(0)
        self.assertEqual(check["outcome"], "pass")
        self.assertEqual(check["measurement"]["findings"], [
            {"name": "HOME", "path": "a.py", "line": 2, "access": "read"},
            {"name": "XDG_CACHE_HOME", "path": "a.py", "line": 3, "access": "write"},
        ])

    def test_env_surface_unapproved_name_fails(self):
        self.configure('[{name = "HOME", owner = "POSIX"}]')
        self.add_file("a.py", 'import os\nos.getenv("OTHER")\n')
        check = self.inventory(1)
        self.assertEqual(check["outcome"], "fail")
        self.assertEqual(check["measurement"]["findings"][0]["name"], "OTHER")

    def test_env_surface_computed_fails(self):
        self.configure('[{name = "HOME", owner = "POSIX"}]')
        self.add_file("a.py", "import os\nos.getenv(key)\n")
        check = self.inventory(1)
        self.assertEqual(check["outcome"], "fail")
        self.assertEqual(check["measurement"]["findings"], [
            {"name": None, "path": "a.py", "line": 2, "access": "computed"},
        ])

    def test_env_surface_missing_driver_fails(self):
        self.configure('[{name = "HOME", owner = "POSIX"}]', shell=True)
        self.add_file("a.py", 'import os\nos.getenv("HOME")\n')
        self.add_file("script.sh", "#!/bin/sh\ntrue\n")
        check = self.inventory(1)
        self.assertEqual(check["outcome"], "fail")
        self.assertIn("script.sh", check["reason"])
        self.assertEqual(check["measurement"]["findings"][0]["name"], "HOME")

    def test_env_surface_missing_emacs_fails_with_path(self):
        self.add_file("example.el", '(getenv "HOME")')
        with mock.patch.dict(os.environ, {"PATH": ""}):
            rows, errors = env_surface.measure(self.repo, ["example.el"])
        self.assertEqual(rows, [])
        self.assertEqual(len(errors), 1)
        self.assertIn("example.el", errors[0])
        self.assertIn("emacs", errors[0])

    def test_env_surface_reader_errors_name_files(self):
        self.add_file("broken.py", "def incomplete(")
        self.add_file("broken.el", "(getenv")
        self.add_file("valid.el", '(getenv "OK")')
        rows, errors = env_surface.measure(self.repo, ["broken.py", "broken.el", "valid.el"])
        self.assertEqual(rows, [env_surface.Finding("OK", "valid.el", 1, "read")])
        self.assertEqual(len(errors), 2)
        self.assertIn("broken.py", errors[0])
        self.assertIn("broken.el", errors[1])

    def test_env_surface_rejects_invalid_allow_entries_at_policy_load(self):
        for entry, error in (
            ('{name = "HOME"}', r"allow\[0\]\.owner"),
            ('{name = "HOME", owner = " "}', r"allow\[0\]\.owner"),
            ('{name = "HOME", prefix = "XDG_", owner = "POSIX"}', r"allow\[0\].*exactly one"),
            ('{owner = "POSIX"}', r"allow\[0\].*exactly one"),
        ):
            with self.subTest(entry=entry):
                self.configure(f"[{entry}]")
                with self.assertRaisesRegex(policy.GateError, error):
                    policy.load_config(self.repo)

    def test_env_surface_measures_gate_package_without_policy(self):
        files = [path.relative_to(GATE).as_posix() for path in (GATE / "quality_gate").rglob("*")
                 if path.suffix in (".py", ".el")]
        rows, errors = env_surface.measure(GATE, files)
        self.assertEqual(errors, [])
        self.assertIn("QG_PYTHON", {row.name for row in rows})

    def test_self_policy_enforces_elisp_environment_surface(self):
        tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=GATE)
        paths = os.fsdecode(tracked).split("\0")[:-1]
        elisp_paths = sorted(path for path in paths if path.endswith(".el"))
        self.assertTrue(elisp_paths)

        (self.repo / "a.py").unlink()
        for relative in paths:
            destination = self.repo / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(GATE / relative, destination, follow_symlinks=False)
        self.git("add", "-A", "-f")

        args = ("check", "--only", "env_surface", "--json")
        result = self.run_qg_process(*args)
        self.assertEqual(result.returncode, 0, output(result))
        check = self.check_by_id(self.parse_json(result), "env_surface")
        self.assertEqual((check["tier"], check["enforcement"], check["outcome"]),
                         (1, "enforced", "pass"))

        allowed_name = "XDG_QG_ENV_SURFACE_TEST"
        allowed = set()
        forbidden = set()
        for relative in elisp_paths:
            path = self.repo / relative
            source = path.read_bytes()
            line = source.count(b"\n") + 2
            path.write_bytes(source + f'\n(getenv "{allowed_name}")\n(getenv "OTHER")\n'.encode())
            allowed.add((relative, line))
            forbidden.add((relative, line + 1))

        result = self.run_qg_process(*args)
        self.assertEqual(result.returncode, 1, output(result))
        check = self.check_by_id(self.parse_json(result), "env_surface")
        self.assertEqual(check["outcome"], "fail")
        for name, expected in ((allowed_name, allowed), ("OTHER", forbidden)):
            actual = {
                (row["path"], row["line"]) for row in check["measurement"]["findings"]
                if row["name"] == name and row["access"] == "read"
            }
            self.assertSetEqual(expected, actual, f"findings for {name}")
        for relative, line in sorted(forbidden):
            with self.subTest(path=relative):
                self.assertIn(f"{relative}:{line}: read 'OTHER'", result.stderr)


if __name__ == "__main__":
    unittest.main()
