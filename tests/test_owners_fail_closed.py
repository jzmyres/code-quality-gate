"""The owners scanner reports invocations it cannot analyse."""

from __future__ import annotations

import unittest

from quality_gate.owners_match import script_index
from quality_gate.owners_python import python_events
from quality_gate.owners_shell import shell_events
from test_owners import OwnerCase, baseline, pattern, rule, subject


class InterpreterOptionsTests(unittest.TestCase):
    def test_documented_options_have_the_same_script_in_both_languages(self) -> None:
        cases = [
            (["python3", "--check-hash-based-pycs", "never", "private.py"], "private.py"),
            (["python3", "-IbW", "ignore", "-Xdev", "private.py"], "private.py"),
            (["python2.7", "-Q", "new", "private.py"], "private.py"),
            (["python3", "--", "-private.py"], "-private.py"),
            (["bash", "+e", "private.sh"], "private.sh"),
            (["bash", "-O", "nullglob", "private.sh"], "private.sh"),
            (["bash", "-oe", "errexit", "private.sh"], "private.sh"),
            (["bash", "-oO", "errexit", "extglob", "private.sh"], "private.sh"),
            (["bash", "--init-file", "init", "private.sh"], "private.sh"),
            (["dash", "+o", "errexit", "private.sh"], "private.sh"),
            (["dash", "-oe", "errexit", "private.sh"], "private.sh"),
            (["sh", "-o", "errexit", "private.sh"], "private.sh"),
            (["ksh", "-R", "profile", "private.sh"], "private.sh"),
            (["zsh", "-O", "private.sh"], "private.sh"),
            (["zsh", "--emulate", "sh", "private.sh"], "private.sh"),
            (["zsh", "+-sh-word-split", "private.sh"], "private.sh"),
            (["zsh", "--emulate", "sh", "-b", "-e", "private.sh"], "private.sh"),
            (["zsh", "-o", "shoptionletters", "-b", "-e", "private.sh"], "private.sh"),
            (["zsh", "-x-", "-private.sh"], "-private.sh"),
            (["zsh", "+-", "+private.sh"], "+private.sh"),
            (["python3", "-m", "private.py"], None),
            (["bash", "-ec", "private.sh"], None),
            (["bash", "-s", "private.sh"], None),
            (["bash", "-se", "private.sh"], None),
            (["bash", "-sc", "private.sh"], None),
            (["bash", "-s", "+s", "private.sh"], "private.sh"),
            (["zsh", "-s", "private.sh"], None),
            (["zsh", "-s", "+s", "private.sh"], "private.sh"),
        ]
        for argv, expected in cases:
            with self.subTest(argv=argv):
                shell, _ = shell_events("test.sh", " ".join(argv) + "\n")
                python = python_events("test.py", f"run({argv!r})\n")
                self.assertEqual([e.value for e in shell if e.kind == "shell-script"],
                                 [expected] if expected is not None else [])
                self.assertEqual([e.value for e in python if e.kind == "python-script"],
                                 [expected] if expected is not None else [])
                self.assertFalse([e for e in shell + python if e.kind == "unanalysable"])

    def test_unknown_short_long_and_cross_interpreter_options_are_rejected(self) -> None:
        for argv, word in (
            (["python3", "--no-such-option", "private.py"], "--no-such-option"),
            (["python3", "-IZ", "private.py"], "-IZ"),
            (["dash", "--rcfile", "init", "private.sh"], "--rcfile"),
            (["bash", "+Z", "private.sh"], "+Z"),
            (["bash", "-sZ", "private.sh"], "-sZ"),
            (["zsh", "--no-such-option", "private.sh"], "--no-such-option"),
        ):
            with self.subTest(argv=argv):
                result = script_index(argv)
                self.assertEqual(argv[result.error_index], word)
                self.assertIn("unknown", result.reason)

    def test_unversioned_python_does_not_guess_the_meaning_of_x(self) -> None:
        result = script_index(["python", "-X", "private.py"])
        self.assertEqual(result.error_index, 1)
        self.assertIn("version", result.reason)

    def test_shell_operand_clusters_with_implementation_dependent_syntax_are_reported(self) -> None:
        for argv in (["sh", "-oe", "errexit", "private.sh"], ["ksh", "-Rfile", "private.sh"]):
            with self.subTest(argv=argv):
                shell, _ = shell_events("test.sh", " ".join(argv) + "\n")
                python = python_events("test.py", f"run({argv!r})\n")
                for events in (shell, python):
                    findings = [event for event in events if event.kind == "unanalysable"]
                    self.assertEqual(len(findings), 1)
                    self.assertIn("implementation", findings[0].reason)

    def test_arithmetic_assignment_keeps_outer_and_nested_commands(self) -> None:
        source = "VALUE=$((1 + $(python3 -I private.py))) python3 -I private.py\n"
        events, _ = shell_events("test.sh", source)
        self.assertEqual([e.value for e in events if e.kind == "shell-command"],
                         ["python3", "python3"])
        self.assertEqual([e.value for e in events if e.kind == "shell-script"],
                         ["private.py", "private.py"])
        self.assertFalse([e for e in events if e.kind == "unanalysable"])

    def test_arithmetic_assignment_prefix_records_the_command_and_script(self) -> None:
        for assignment in ("VALUE=$((1))", "VALUE+=$((1))", "VALUE[0]=$((1))"):
            with self.subTest(assignment=assignment):
                shell, _ = shell_events("test.sh", f"{assignment} python3 -I private.py\n")
                self.assertEqual([(e.kind, e.value) for e in shell],
                                 [("shell-command", "python3"), ("shell-script", "private.py")])
        python = python_events("test.py", "run(['python3', '-I', 'private.py'], env={'VALUE': '1'})\n")
        self.assertEqual([(e.kind, e.value) for e in python if e.kind.startswith('python-')],
                         [("python-call", "run"), ("python-argv", "python3"),
                          ("python-script", "private.py")])


class ShellStructureTests(unittest.TestCase):
    def test_non_extended_glob_forms_parse_as_before(self) -> None:
        cases = [
            ("<(printf python3) -I private.py\n",
             [("unanalysable", "<(printf python3)"), ("shell-command", "printf")]),
            (">(printf python3) -I private.py\n",
             [("unanalysable", ">(printf python3)"), ("shell-command", "printf")]),
            ("( python3 -I private.py )\n",
             [("shell-command", "python3"), ("shell-script", "private.py")]),
            ("f() { python3 -I private.py; }\n",
             [("shell-command", "f"), ("shell-command", "python3"),
              ("shell-script", "private.py")]),
            ('"@(x)" -I private.py\n', [("shell-command", "@(x)")]),
        ]
        for source, expected in cases:
            with self.subTest(source=source):
                events, _ = shell_events("test.sh", source)
                self.assertEqual(
                    [(event.kind, event.value) for event in events
                     if event.kind in ("shell-command", "shell-script", "unanalysable")],
                    expected,
                )


class FailClosedCliTests(OwnerCase):
    def setUp(self) -> None:
        super().setUp()
        self.add_file("owner.sh", "python3 -I private.py\nbash private.sh\n")
        self.add_file("a.py", "run(['python3', '-I', 'private.py'])\nrun(['bash', 'private.sh'])\n")
        item = rule([pattern("shell-script", "private.py"), pattern("shell-script", "private.sh"),
                     pattern("python-script", "private.py"), pattern("python-script", "private.sh")])
        item["owners"] = ["a.py", "owner.sh"]
        self.set_rule(item, shell=True)

    def test_review_cases_fail_through_shell_and_literal_python_argv(self) -> None:
        cases = [
            ("python3 --check-hash-based-pycs never private.py",
             "run(['python3', '--check-hash-based-pycs', 'never', 'private.py'])", "private.py"),
            ("bash +e private.sh", "run(['bash', '+e', 'private.sh'])", "private.sh"),
            # An argv list has no shell assignment prefix: Python passes the value in env instead.
            ("VALUE=$((1)) python3 -I private.py",
             "run(['python3', '-I', 'private.py'], env={'VALUE': '1'})", "private.py"),
        ]
        for shell, python, script in cases:
            for path, source, kind in (("other.sh", shell, "shell-script"),
                                       ("other.py", python, "python-script")):
                with self.subTest(source=source):
                    self.add_file(path, source + "\n")
                    check = self.assert_rejected(f"{path}:1: {kind}:{script}")
                    self.assertEqual(len(check["findings"]), 1)
                    (self.repo / path).unlink()

    def test_unknown_option_fails_once_with_location_and_word_in_both_languages(self) -> None:
        for path, source in (
            ("other.sh", "python3 --no-such-option private.py"),
            ("other.py", "run(['python3', '--no-such-option', 'private.py'])"),
        ):
            with self.subTest(path=path):
                self.add_file(path, "\n" + source + "\n")
                check = self.assert_rejected(f"{path}:2: unanalysable '--no-such-option'")
                self.assertEqual(len(check["findings"]), 1)
                finding = check["findings"][0]
                self.assertEqual(finding["measurement"]["word"], "--no-such-option")
                self.assertEqual(finding["measurement"]["reason"], "unknown python option")
                self.assertEqual(finding["locations"],
                                 [{"path": path, "start_line": 2, "end_line": 2}])
                (self.repo / path).unlink()

    def test_dynamic_command_head_fails_once_with_location_and_word(self) -> None:
        self.add_file("other.sh", "echo ok\n${RUNNER} -I private.py\n")
        check = self.assert_rejected("other.sh:2: unanalysable '${RUNNER}'")
        self.assertEqual(len(check["findings"]), 1)
        self.assertEqual(check["findings"][0]["measurement"]["reason"],
                         "cannot determine command head")

    def test_dynamic_script_or_option_fails_and_literal_quotes_are_analysed(self) -> None:
        for word in ('"$SCRIPT"', '${SCRIPT:-private.py}', '$((1 + 2))', '*.py'):
            with self.subTest(word=word):
                self.add_file("other.sh", f"python3 -I {word}\n")
                check = self.assert_rejected(f"other.sh:1: unanalysable {word!r}")
                self.assertEqual(len(check["findings"]), 1)
        self.add_file("other.sh", "'python3' -I 'private.py'\n")
        self.assert_rejected("other.sh:1: shell-script:private.py")

    def test_unanalysable_owner_is_not_waived_by_allowance_or_baseline(self) -> None:
        self.add_file("owner.sh", "python3 --no-such-option private.py\nbash private.sh\n")
        key = subject("unanalysable", "owner.sh", "--no-such-option", "unknown python option")
        self.add_file("owners-baseline.toml", baseline([(key, 1, "attempted waiver")]))
        check = self.assert_rejected("owner.sh:1: unanalysable '--no-such-option'")
        finding = check["findings"][0]
        self.assertTrue(finding["blocking"])
        self.assertFalse(finding["covered_by_baseline"])

    def test_nonliteral_python_script_reports_its_expression(self) -> None:
        self.add_file("other.py", "run(['python3', '-I', script])\n")
        check = self.assert_rejected("other.py:1: unanalysable 'script'")
        self.assertEqual(len(check["findings"]), 1)

    def test_process_substitution_in_command_head_is_reported(self) -> None:
        self.add_file("other.sh", "<(printf python3) -I private.py\n")
        check = self.assert_rejected("other.sh:1: unanalysable '<(printf python3)'")
        self.assertEqual(len(check["findings"]), 1)

    def test_review_case_extended_glob_script_fails_closed(self) -> None:
        self.add_file("other.sh", "python3 ./@(private).py\n")
        word = "./@(private).py"
        check = self.assert_rejected(f"other.sh:1: unanalysable {word!r}")
        self.assertEqual(len(check["findings"]), 1)
        finding = check["findings"][0]
        self.assertEqual(finding["measurement"]["word"], word)
        self.assertEqual(finding["locations"],
                         [{"path": "other.sh", "start_line": 1, "end_line": 1}])

    def test_each_extended_glob_operator_in_command_position_fails_closed(self) -> None:
        for operator in "?*+@!":
            word = f"{operator}(private).py"
            with self.subTest(operator=operator):
                self.add_file("other.sh", word + "\n")
                check = self.assert_rejected(f"other.sh:1: unanalysable {word!r}")
                self.assertEqual(len(check["findings"]), 1)
                self.assertEqual(check["findings"][0]["measurement"]["word"], word)
                (self.repo / "other.sh").unlink()

    def test_backtick_substitution_commands_are_still_scanned(self) -> None:
        self.add_file("other.sh", 'VALUE="`python3 -I private.py`" echo done\n')
        check = self.assert_rejected("other.sh:1: shell-script:private.py")
        self.assertEqual(len(check["findings"]), 1)


if __name__ == "__main__":
    unittest.main()
