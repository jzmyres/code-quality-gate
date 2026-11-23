"""Exercise the comments gate with both language parsers."""
from __future__ import annotations

from support import BASE_CONFIG, GATE, FixtureCase, output

from quality_gate import adapters, comments, policy


FIXTURES = GATE / "tests" / "fixtures" / "comments"


def fixture_source(language: str) -> str:
    return "".join((FIXTURES / f"{language}.md").read_text(encoding="utf-8").splitlines(keepends=True)[1:-1])


class CommentsTests(FixtureCase):
    def setUp(self):
        super().setUp()
        config = BASE_CONFIG.replace('checks = ["smoke"]', 'checks = ["comments"]')
        config = config.replace('pattern = "*.py"', 'pattern = "[as]*"')
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
        self.assertIn("cannot read Emacs Lisp files sample.el", errors[0])

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
        self.add_file("sample.el", "(list 1 ; single\n  2 ;; double\n  #| block |# 3)\n;;; History:\n")
        check = self.check_comments_none(1)
        self.assertEqual(check["measurement"]["findings"], [
            {"path": "sample.el", "line": 1, "text": "; single"},
            {"path": "sample.el", "line": 2, "text": ";; double"},
            {"path": "sample.el", "line": 3, "text": "#| block |#"},
            {"path": "sample.el", "line": 4, "text": ";;; History:"},
        ])

    def test_comments_none_elisp_adjacent_blocks_and_character(self):
        self.add_file("sample.el", "(list ?; ; after literal\n  #|a #|nested|# b|##|second|# 1)\n")
        check = self.check_comments_none(1)
        self.assertEqual(check["measurement"]["findings"], [
            {"path": "sample.el", "line": 1, "text": "; after literal"},
            {"path": "sample.el", "line": 2, "text": "#|a #|nested|# b|#"},
            {"path": "sample.el", "line": 2, "text": "#|second|#"},
        ])

    def test_comments_none_elisp_tool_lines_and_literals(self):
        for prefix in ("", "#!/usr/bin/emacs --script\n"):
            with self.subTest(prefix=prefix):
                self.add_file("sample.el", prefix + fixture_source("elisp"))
                self.assertEqual(self.check_comments_none(0)["measurement"]["findings"], [])

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
        for source in ("(list 1\n", "#| unfinished\n"):
            with self.subTest(source=source):
                self.add_file("sample.el", source)
                self.assertIn("sample.el", self.check_comments_none(1)["reason"])

    def test_comments_none_missing_driver(self):
        self.add_file("sample.sh", "#!/bin/sh\ntrue\n")
        self.assertIn("sample.sh: no comments driver", self.check_comments_none(1)["reason"])

    def test_comments_none_measures_gate_package_directly(self):
        files = [
            path.relative_to(GATE).as_posix()
            for path in (GATE / "quality_gate").rglob("*") if path.suffix in {".py", ".el"}
        ]
        findings, errors = comments.measure(GATE, files)
        self.assertEqual(errors, [])
        self.assertTrue(findings)
