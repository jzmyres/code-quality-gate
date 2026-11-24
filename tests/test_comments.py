"""Exercise the comments gate across its language drivers."""
from __future__ import annotations

import json
from subprocess import CompletedProcess
from unittest import mock

from support import BASE_CONFIG, GATE, FixtureCase, output

from quality_gate import adapters, comments, policy, shell_syntax


FIXTURES = GATE / "tests" / "fixtures" / "comments"


def fixture_source(language: str) -> str:
    return "".join((FIXTURES / f"{language}.md").read_text(encoding="utf-8").splitlines(keepends=True)[1:-1])


class CommentsTests(FixtureCase):
    def setUp(self):
        super().setUp()
        config = BASE_CONFIG.replace('checks = ["smoke"]', 'checks = ["comments"]')
        config = config.replace('pattern = "*.py"', 'pattern = "[asz]*"')
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
        )
        result = adapters._run_comments(context)
        self.assertEqual(result.outcome, "fail")
        self.assertEqual(result.measurement, {
            "findings": [{"path": "sample.py", "line": 1, "text": "# selected"}],
        })

    def test_comments_none_unavailable_emacs_names_selected_file(self):
        self.add_file("sample.el", "(message \"ok\")\n")
        rows, errors = comments.measure(self.repo, ["sample.el"], emacs=str(self.repo / "missing-emacs"))
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

    def shell_check(self, path, source, tree):
        self.add_file(path, source)
        config = policy.load_config(self.repo)
        check = config.checks["comments"]
        context = adapters.AdapterContext(
            self.repo, config, check, [path], {path: "python"}, "check", {}, self.repo,
        )
        result = CompletedProcess([], 0, json.dumps(tree).encode(), b"")
        with (
            mock.patch.object(shell_syntax, "tool_binary", return_value=self.base / "shfmt"),
            mock.patch.object(shell_syntax, "run", return_value=result) as run,
        ):
            checked = adapters._run_comments(context)
        self.assertEqual(run.call_args.kwargs["input"], source.encode())
        self.assertEqual(run.call_args.args[0][-2:], ["--filename", path])
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
        self.assertEqual(result.outcome, "pass")
        self.assertEqual(result.measurement["findings"], [])

    def test_comments_none_shell_indented_shebang(self):
        tree = {"Last": [{"Hash": {"Line": 1}, "Text": "!/bin/sh"}]}
        result = self.shell_check("sample.bash", "  #!/bin/sh\n", tree)
        self.assertEqual(result.outcome, "fail")
        self.assertEqual(result.measurement["findings"], [
            {"path": "sample.bash", "line": 1, "text": "#!/bin/sh"},
        ])

    def test_comments_none_shell_schema_error(self):
        tree = {"Last": [{"Hash": {}, "Text": " missing position"}]}
        result = self.shell_check("sample.sh", "# missing position\n", tree)
        self.assertEqual(result.outcome, "fail")
        self.assertIn("cannot read sample.sh", result.reason)
        self.assertIn("missing field Hash.Line", result.reason)
        self.assertEqual(result.measurement["findings"], [])

    def test_shell_comment_fields_require_position_and_allow_omitted_text(self):
        self.assertEqual(comments._shell_comment_fields({"Hash": {}}), {"Hash.Line": int})
        self.assertEqual(comments._shell_comment_fields({"Hash": {}, "Text": " hi"}), {
            "Hash.Line": int, "Text": str,
        })
        self.assertEqual(comments._shell_comment_fields({"Text": " hi"}), {})

    def test_comments_none_measures_gate_package_directly(self):
        files = [
            path.relative_to(GATE).as_posix()
            for path in (GATE / "quality_gate").rglob("*") if path.suffix in {".py", ".el"}
        ]
        findings, errors = comments.measure(GATE, files)
        self.assertEqual(errors, [])
        self.assertEqual(findings, [])
