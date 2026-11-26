"""Exercise the comments gate across its language drivers."""
from __future__ import annotations

import json
import time
from importlib import import_module
from unittest import mock

from support import BASE_CONFIG, GATE, FixtureCase, output

from quality_gate import adapters, comments, policy, runner
from quality_gate import files as inventory


FIXTURES = GATE / "tests" / "fixtures" / "comments"


def fixture_source(language: str) -> str:
    return "".join((FIXTURES / f"{language}.md").read_text(encoding="utf-8").splitlines(keepends=True)[1:-1])


class CommentsTests(FixtureCase):
    def setUp(self):
        super().setUp()
        config = BASE_CONFIG.replace('checks = ["smoke"]', 'checks = ["comments"]')
        config = config.replace('pattern = "*.py"', 'pattern = "[apsz]*"')
        self.write_config(config + '''
[checks.comments]
adapter = "comments"
tier = 1
enforcement = "enforced"
''')

    def check_comments_none(self, expected):
        self.git("add", "-A")
        result, report = self.run_json("--only", "comments")
        self.assertEqual(result.returncode, expected, output(result))
        check = self.check_by_id(report, "comments")
        self.assertEqual(check["outcome"], "fail" if expected else "pass", output(result))
        return check

    def test_comments_none_adapter_spec_and_selected_files(self):
        config = policy.load_config(self.repo)
        check = config.checks["comments"]
        parsed = adapters._comments_spec({}, self.repo, self.repo / "quality-gate.toml", "checks.comments")
        self.assertEqual(check.metric_version, parsed.metric_version)
        self.assertEqual(parsed.evidence, ("static",))
        self.add_file("sample.py", "# selected\n")
        context = adapters.AdapterContext(
            self.repo, config, check, ["a.py", "sample.py", "ignored.py"],
            {"a.py": "python", "sample.py": "python", "ignored.py": "doc"}, "check", {}, self.repo,
            inventory_files=["a.py", "sample.py", "ignored.py"],
        )
        result = adapters._run_comments(context)
        self.assertEqual(result.outcome, "fail")
        self.assertEqual(result.measurement, {
            "findings": [{"path": "sample.py", "line": 1, "text": "# selected"}],
        })

    def test_comments_none_unavailable_emacs_names_selected_file(self):
        self.add_file("sample.el", "(message \"ok\")\n")
        rows, errors = comments.measure(
            self.repo, ["sample.el"], {"sample.el": "lisp"}, adapters._parse_shell,
            runner.remaining_budget, emacs=str(self.repo / "missing-emacs"),
        )
        self.assertEqual(rows, [])
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].path, "sample.el")
        self.assertIn("cannot read sample.el", errors[0].text)

    def test_comments_none_python_findings(self):
        long_comment = "# " + "x" * 70
        self.add_file("sample.py", f'{long_comment}\nx = 1  # inline\npass  # noqa\n')
        check = self.check_comments_none(1)
        self.assertEqual(check["measurement"]["findings"], [
            {"path": "sample.py", "line": 1, "text": long_comment[:60]},
            {"path": "sample.py", "line": 2, "text": "# inline"},
            {"path": "sample.py", "line": 3, "text": "# noqa"},
        ])
        self.assertIn("sample.py:2: # inline", check["reason"])

    def test_comments_none_python_shebang_and_literals(self):
        self.add_file("sample", fixture_source("python"))
        self.assertEqual(self.check_comments_none(0)["measurement"]["findings"], [])

    def test_comments_none_python_fstring_expression_comment(self):
        self.add_file("sample.py", 'value = f"""{1  # expression comment\n}"""\n')
        check = self.check_comments_none(1)
        self.assertEqual(check["measurement"]["findings"], [
            {"path": "sample.py", "line": 1, "text": "# expression comment"},
        ])

    def test_comments_none_python_late_shebang(self):
        self.add_file("sample.py", "\n" + fixture_source("python"))
        check = self.check_comments_none(1)
        self.assertIn("sample.py:2: #!/usr/bin/env python3", check["reason"])

    def test_comments_none_python_unterminated_source(self):
        for source in ('value = (\n', 'value = "unfinished\n'):
            with self.subTest(source=source):
                self.add_file("sample.py", source)
                self.assertIn("sample.py", self.check_comments_none(1)["reason"])

    def test_comments_none_elisp_findings(self):
        self.add_file("sample.el", "(list ?; ; single\n  2 ;; double\n  3)\n;;; History:\n")
        check = self.check_comments_none(1)
        self.assertEqual(check["measurement"]["findings"], [
            {"path": "sample.el", "line": 1, "text": "; single"},
            {"path": "sample.el", "line": 2, "text": ";; double"},
            {"path": "sample.el", "line": 4, "text": ";;; History:"},
        ])

    def test_comments_none_elisp_invalid_reader_syntax(self):
        self.add_file("a.el", "(list 1 #|a|#) ; c\n")
        check = self.check_comments_none(1)
        self.assertIn("cannot read a.el: Invalid read syntax:", check["reason"])
        self.assertEqual(check["measurement"]["findings"], [])

    def test_comments_none_elisp_tool_lines_and_literals(self):
        for prefix in ("", "#!/usr/bin/emacs --script\n", "#!/usr/bin/env emacs --script\n"):
            with self.subTest(prefix=prefix):
                self.add_file("sample.el", prefix + fixture_source("elisp"))
                self.assertEqual(self.check_comments_none(0)["measurement"]["findings"], [])

    def test_comments_none_elisp_shebang_requires_emacs(self):
        config = self.read_file("quality-gate.toml").replace(
            'shebangs = ["sh", "bash", "python*"]', 'shebangs = ["bash"]',
        )
        self.write_config(config)
        for shebang in ("#! TODO replace this", "#!/bin/sh", "#!/usr/bin/env python3"):
            with self.subTest(shebang=shebang):
                self.add_file("a.el", f"{shebang}\n(list 1)\n")
                check = self.check_comments_none(1)
                self.assertEqual(check["measurement"]["findings"], [
                    {"path": "a.el", "line": 1, "text": shebang},
                ])

    def test_comments_none_elisp_bom_prevents_shebang_exemption(self):
        self.add_file("a.el", "\ufeff#!/usr/bin/emacs --script\n(list 1)\n")
        check = self.check_comments_none(1)
        self.assertEqual(check["measurement"]["findings"], [
            {"path": "a.el", "line": 1, "text": "#!/usr/bin/emacs --script"},
        ])

    def test_comments_none_elisp_near_matches(self):
        self.add_file("sample.el", fixture_source("elisp").replace(
            ";;; Code:", ";;; Code: extra\n;; prose",
        ).replace("sample.el ends here", "another.el ends here"))
        check = self.check_comments_none(1)
        self.assertEqual([row["text"] for row in check["measurement"]["findings"]], [
            ";;; Code: extra", ";; prose", ";;; another.el ends here",
        ])

    def test_comments_none_elisp_code_requires_exact_commentary(self):
        self.add_file("sample.el", ";;; Documentation:\n;;; Code:\n(message \"ok\")\n")
        check = self.check_comments_none(1)
        self.assertEqual([row["text"] for row in check["measurement"]["findings"]], [
            ";;; Documentation:", ";;; Code:",
        ])

    def test_comments_none_elisp_unterminated_source(self):
        self.add_file("sample.el", "(list 1\n")
        self.assertIn("cannot read sample.el", self.check_comments_none(1)["reason"])

    def test_comments_none_reason_orders_errors_and_findings(self):
        self.add_file("a.unknown", "unknown source\n")
        self.add_file("a.py", "# first\n# second\n")
        self.add_file("z.py", "x = 1  # c\n")
        check = self.check_comments_none(1)
        reason = check["reason"].splitlines()
        self.assertEqual(reason, [
            "a.py:1: # first", "a.py:2: # second", "a.unknown: no comments driver", "z.py:1: # c",
        ])
        self.assertEqual([*reason[:2], reason[-1]], [
            "{path}:{line}: {text}".format(**row) for row in check["measurement"]["findings"]
        ])

    def shell_check(self, path, source, tree, *, elapsed=0, decode_budget=30, scan_expires=False):
        self.add_file(path, source)
        config = policy.load_config(self.repo)
        check = config.checks["comments"]
        paths, classes, violations = inventory.validate_inventory(self.repo, config)
        self.assertEqual(violations, [])
        self.assertIn(path, paths)
        context = adapters.AdapterContext(
            self.repo, config, check, [path], classes, "check", {}, self.repo,
            inventory_files=paths,
        )
        try:
            shell_syntax = import_module("quality_gate.shell_syntax")
        except ModuleNotFoundError as error:
            if error.name != "quality_gate.shell_syntax":
                raise
            return adapters._run_comments(context)
        result = runner.RunResult((), "completed", 0, stdout=json.dumps(tree).encode())
        decode_tree = shell_syntax._decode_tree
        comment_nodes = comments._shell_comment_nodes

        def decode(*args):
            parsed = decode_tree(*args)
            deadline.seconds = decode_budget
            return parsed

        def scan(parsed):
            yield from comment_nodes(parsed)
            if scan_expires:
                deadline.seconds = 0

        with (
            mock.patch.object(adapters, "tool_binary", return_value=self.base / "shfmt"),
            mock.patch.object(adapters, "run", return_value=result) as run,
            mock.patch.object(shell_syntax, "_decode_tree", side_effect=decode),
            mock.patch.object(comments, "_shell_comment_nodes", side_effect=scan),
            runner.check_deadline("comments", time.monotonic() - elapsed, 30) as deadline,
        ):
            checked = adapters._run_comments(context)
        if elapsed < 30:
            run.assert_called_once()
            self.assertEqual(run.call_args.args[0][-1], path)
            self.assertEqual(run.call_args.kwargs["stdin"], source.encode())
        else:
            run.assert_not_called()
        return checked

    def test_comments_none_shell_findings(self):
        source = "# full line\ntrue  # inline\n# shellcheck disable=SC2086\ntrue\n#\n#!/bin/sh\n"
        tree = {
            "Stmts": [
                {"Comments": [{"Hash": {"Line": 1}, "Text": " full line"},
                              {"Hash": {"Line": 2}, "Text": " inline"}]},
                {"Comments": [{"Hash": {"Line": 3}, "Text": " shellcheck disable=SC2086"}]},
            ],
            "Last": [{"Hash": {"Line": 5}}, {"Hash": {"Line": 6}, "Text": "!/bin/sh"}],
        }
        result = self.shell_check("sample.sh", source, tree)
        self.assertEqual(result.outcome, "fail")
        self.assertEqual(result.measurement["findings"], [
            {"path": "sample.sh", "line": 1, "text": "# full line"},
            {"path": "sample.sh", "line": 2, "text": "# inline"},
            {"path": "sample.sh", "line": 3, "text": "# shellcheck disable=SC2086"},
            {"path": "sample.sh", "line": 5, "text": "#"},
            {"path": "sample.sh", "line": 6, "text": "#!/bin/sh"},
        ])

    def test_comments_none_shell_shebang_and_literals(self):
        tree = {"Stmts": [
            {"Comments": [{"Hash": {"Line": 1}, "Text": "!/usr/bin/env bash"}],
             "Cmd": {"Args": [{"Parts": [{"Value": "# inside a string"}]}]}},
            {"Redirs": [{"Hdoc": {"Parts": [{"Value": "# inside a heredoc\n"}]}}]},
        ]}
        result = self.shell_check("sample", fixture_source("shell"), tree)
        self.assertEqual(result.outcome, "pass", result.reason)
        self.assertEqual(result.measurement["findings"], [])

    def test_comments_none_shell_indented_shebang(self):
        tree = {"Last": [{"Hash": {"Line": 1}, "Text": "!/bin/sh"}]}
        result = self.shell_check("sample.bash", "  #!/bin/sh\n", tree)
        self.assertEqual(result.outcome, "fail")
        self.assertEqual(result.measurement["findings"], [
            {"path": "sample.bash", "line": 1, "text": "#!/bin/sh"},
        ])

    def test_comments_none_shell_dispatch_uses_inventory_detection(self):
        for path, shebang, line in (("sample.sh", "", 1), ("script", "#!./bash\n", 2)):
            with self.subTest(path=path):
                rows = [{"Hash": {"Line": line}, "Text": " shell comment"}]
                if shebang:
                    rows.insert(0, {"Hash": {"Line": 1}, "Text": "!./bash"})
                result = self.shell_check(path, shebang + "# shell comment\ntrue\n", {"Last": rows})
                expected = [{"path": path, "line": line, "text": "# shell comment"}]
                if shebang:
                    expected.insert(0, {"path": path, "line": 1, "text": "#!./bash"})
                self.assertEqual(result.measurement["findings"], expected)

    def test_comments_none_unknown_interpreter_leaves_shell_suffix_in_charge(self):
        config = self.read_file("quality-gate.toml").replace(
            'shebangs = ["sh", "bash", "python*"]', 'shebangs = ["sh", "bash", "python*", "zsh"]',
        )
        self.write_config(config)
        source = "#!/bin/zsh\n# shell comment\ntrue\n"
        tree = {"Stmts": [{"Comments": [
            {"Hash": {"Line": 1}, "Text": "!/bin/zsh"},
            {"Hash": {"Line": 2}, "Text": " shell comment"},
        ]}]}
        result = self.shell_check("script.sh", source, tree)
        self.assertEqual(result.outcome, "fail")
        self.assertEqual(result.measurement["findings"], [
            {"path": "script.sh", "line": 2, "text": "# shell comment"},
        ])

    def test_comments_none_polyglot_uses_inventory_shell_language(self):
        config = self.read_file("quality-gate.toml")
        for shebang, pattern in (
            ("#!/bin/sh", "bash*"),
            ("#!/usr/bin/env bash5", "bash*"),
            ("#!/usr/bin/env -S bash5.1 -e", "bash"),
            ("#!/bin/rbash", "*bash"),
        ):
            with self.subTest(shebang=shebang):
                self.write_config(config.replace(
                    'shebangs = ["sh", "bash", "python*"]', f'shebangs = ["sh", "{pattern}", "python*"]',
                ))
                source = f'{shebang}\n""":"\n# shell-only comment\ntrue\n":"""\n'
                tree = {"Stmts": [{"Comments": [
                    {"Hash": {"Line": 1}, "Text": shebang[1:]},
                    {"Hash": {"Line": 3}, "Text": " shell-only comment"},
                ]}]}
                result = self.shell_check("polyglot.py", source, tree)
                self.assertEqual(result.outcome, "fail")
                self.assertEqual(result.measurement["findings"], [
                    {"path": "polyglot.py", "line": 3, "text": "# shell-only comment"},
                ])

    def test_comments_none_selected_extensionless_python_symlink(self):
        self.add_file("source.py", fixture_source("python"))
        (self.repo / "sample").symlink_to("source.py")
        self.assertEqual(self.check_comments_none(0)["measurement"]["findings"], [])

    def test_inventory_reuses_selected_symlink_language(self):
        self.add_file("source.py", fixture_source("python"))
        link = self.repo / "sample"
        link.symlink_to("source.py")
        config = policy.load_config(self.repo)
        with mock.patch.object(inventory, "_shebang_line", wraps=inventory._shebang_line) as reads:
            _, classes, violations = inventory.validate_inventory(self.repo, config)
            self.assertEqual(violations, [])
            self.assertNotIn(mock.call(link), reads.call_args_list)
            for _ in range(2):
                self.assertEqual(
                    inventory.source_languages(self.repo, ["sample"], config, classes),
                    {"sample": "python"},
                )
        self.assertEqual(reads.call_args_list.count(mock.call(link)), 1)

    def test_inventory_does_not_open_unselected_extensionless_symlink(self):
        config = self.read_file("quality-gate.toml") + """
[[rule]]
pattern = "linked"
class = "doc"
reason = "Reference outside the repository"
"""
        self.write_config(config)
        target = self.base / "unreadable"
        target.write_text(fixture_source("python"), encoding="utf-8")
        target.chmod(0)
        link = self.repo / "linked"
        link.symlink_to(target)

        with mock.patch.object(inventory, "_shebang_line", wraps=inventory._shebang_line) as reads:
            paths, classes, violations = inventory.validate_inventory(
                self.repo, policy.load_config(self.repo),
            )
        self.assertEqual(violations, [])
        self.assertIn("linked", paths)
        self.assertEqual(classes["linked"], "doc")
        self.assertNotIn(mock.call(link), reads.call_args_list)

    def test_comments_none_shell_deadline_already_spent(self):
        result = self.shell_check("sample.sh", "true\n", {}, elapsed=31)
        self.assertEqual(result.outcome, "fail")
        self.assertIn("cannot read sample.sh: shfmt deadline exceeded", result.reason)

    def test_comments_none_shell_deadline_spent_during_decoding(self):
        tree = {"Last": [{"Hash": {"Line": 1}, "Text": " late"}]}
        result = self.shell_check("sample.sh", "# late\n", tree, decode_budget=0)
        self.assertEqual(result.outcome, "fail")
        self.assertIn("cannot read sample.sh: shfmt deadline exceeded", result.reason)
        self.assertEqual(result.measurement["findings"], [])

    def test_comments_none_shell_deadline_spent_during_scan(self):
        tree = {"Last": [{"Hash": {"Line": 1}, "Text": " late"}]}
        result = self.shell_check("sample.sh", "# late\n", tree, scan_expires=True)
        self.assertEqual(result.outcome, "fail")
        self.assertIn("cannot read sample.sh: shfmt deadline exceeded", result.reason)
        self.assertEqual(result.measurement["findings"], [])

    def test_comments_none_shell_schema_error(self):
        tree = {"Last": [{"Hash": {}, "Text": " missing position"}]}
        result = self.shell_check("sample.sh", "# missing position\n", tree)
        self.assertEqual(result.outcome, "fail")
        self.assertIn("cannot read sample.sh", result.reason)
        self.assertIn("missing field Hash.Line", result.reason)
        self.assertEqual(result.measurement["findings"], [])

    def test_comments_none_measures_gate_package_directly(self):
        files = [
            path.relative_to(GATE).as_posix()
            for path in (GATE / "quality_gate").rglob("*") if path.suffix in {".py", ".el"}
        ]
        config = policy.load_config(GATE)
        languages = {
            path: inventory.source_language(GATE / path, path, config).language
            for path in files
        }
        findings, errors = comments.measure(
            GATE, files, languages, adapters._parse_shell, runner.remaining_budget,
        )
        self.assertEqual(errors, [])
        self.assertEqual(findings, [])
