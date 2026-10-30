"""End-to-end single-owner checks on disposable Git repositories."""

from __future__ import annotations

import json
import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest import mock

from support import BASE_CONFIG, FixtureCase, output
from test_trust import TrustCase
from quality_gate.owners import _read_regular, _regex_events
from quality_gate.owners_regex import _matches, _run
from quality_gate.policy import GateError


def pattern(kind: str, value: str, paths: list[str] | None = None) -> dict[str, object]:
    result: dict[str, object] = {"kind": kind, "value": value}
    if paths is not None:
        result["paths"] = paths
    return result


def toml_pattern(value: dict[str, object]) -> str:
    return "{ " + ", ".join(f"{key} = {json.dumps(item)}" for key, item in value.items()) + " }"


def owner_config(rules: list[dict[str, object]], *, shell: bool = False) -> str:
    text = BASE_CONFIG + '\n[checks.arch]\nadapter = "owners"\ntier = 1\n'
    text += 'enforcement = "enforced"\nbaseline = "owners-baseline.toml"\n'
    for rule in rules:
        text += "\n[[checks.arch.rule]]\n"
        for key in ("name", "reason", "owners"):
            text += f"{key} = {json.dumps(rule[key])}\n"
        for key in ("forbid", "allow"):
            if key in rule:
                text += f"{key} = [" + ", ".join(toml_pattern(item) for item in rule[key]) + "]\n"
    if shell:
        text += '\n[[rule]]\npattern = "*.sh"\nclass = "python"\nreason = "shell"\n'
    return text


def rule(
    forbid: list[dict[str, object]],
    *,
    allow: list[dict[str, object]] | None = None,
    owner: str = "a.py",
    name: str = "single-owner",
) -> dict[str, object]:
    result: dict[str, object] = {
        "name": name,
        "reason": "one implementation",
        "owners": [owner],
        "forbid": forbid,
    }
    if allow is not None:
        result["allow"] = allow
    return result


def subject(name: str, relative: str, kind: str, value: str) -> str:
    return json.dumps([name, relative, kind, value], ensure_ascii=True, separators=(",", ":"))


def baseline(entries: list[tuple[str, int, str]]) -> str:
    text = 'check = "arch"\nmetric_version = "owners/1"\n'
    for name, bound, reason in entries:
        text += f"\n[[entry]]\nsubject = {json.dumps(name)}\nbound = {bound}\nreason = {json.dumps(reason)}\n"
    return text


class OwnerCase(FixtureCase):
    def set_rule(self, item: dict[str, object], *, shell: bool = False) -> None:
        self.write_config(owner_config([item], shell=shell))

    def result(self):
        result, document = self.run_json()
        return result, document, self.check_by_id(document, "arch")

    def assert_pass(self) -> dict[str, object]:
        result, document, check = self.result()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(document["decision"], "accepted")
        return check

    def assert_rejected(self, expected: str) -> dict[str, object]:
        result, document, check = self.result()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "rejected")
        self.assertIn(expected, result.stderr)
        return check


class PatternTests(OwnerCase):
    def test_python_call_and_dotted_call_ignore_strings_and_comments(self) -> None:
        for name in ("peak_window", "clock.in_peak"):
            with self.subTest(name=name):
                self.add_file("a.py", f"{name}()\n")
                self.add_file("clean.py", f'# {name}()\ntext = "{name}()"\n')
                self.set_rule(rule([pattern("python-call", name)]))
                self.assert_pass()
                self.add_file("other.py", f"{name}()\n")
                check = self.assert_rejected(f"python-call:{name} outside its owners")
                self.assertEqual(check["findings"][0]["location"], "other.py:1")
                (self.repo / "other.py").unlink()

    def test_python_import_ignores_strings_and_comments(self) -> None:
        for statement, module in (
            ("import peak.window", "peak.window"),
            ("from peak import clock", "peak"),
        ):
            with self.subTest(statement=statement):
                self.add_file("a.py", statement + "\n")
                self.add_file("clean.py", f'# {statement}\ntext = "{statement}"\n')
                self.set_rule(rule([pattern("python-import", module)]))
                self.assert_pass()
                self.add_file("other.py", statement + "\n")
                self.assert_rejected(f"python-import:{module}")
                (self.repo / "other.py").unlink()

    def test_python_literal_argv_and_owner_builder(self) -> None:
        self.add_file("a.py", 'def git_argv():\n    return ["git", "status"]\n')
        self.add_file(
            "clean.py", '# subprocess.run(["git"])\ntext = \'["git"]\'\nlabels = ["git", "docs"]\n'
        )
        self.set_rule(rule([pattern("python-argv", "git")]))
        self.assert_pass()
        self.add_file("other.py", 'import subprocess\nsubprocess.run(["git", "status"])\n')
        check = self.assert_rejected("owners: single-owner: other.py:2: python-argv:git")
        self.assertEqual(check["findings"][0]["measurement"]["owners"], ["a.py"])

    def test_shell_command_words_after_operators_and_substitution(self) -> None:
        self.add_file("a.py", "print('owner')\n")
        self.add_file("owner.sh", "peak_calc\n")
        self.add_file("other.sh", "echo start | peak_calc && peak_calc; echo $(peak_calc)\n")
        self.add_file("clean.sh", 'echo "peak_calc"\n# peak_calc\ncat <<EOF\npeak_calc\nEOF\n')
        self.set_rule(rule([pattern("shell-command", "peak_calc")], owner="owner.sh"), shell=True)
        check = self.assert_rejected("other.sh:1: shell-command:peak_calc")
        finding = check["findings"][0]
        self.assertEqual(finding["value"], 3)
        self.assertEqual(finding["measurement"]["lines"], [1, 1, 1])
        self.assertEqual(len(check["findings"]), 1)

    def test_shell_assignments_redirection_and_arithmetic_are_not_commands(self) -> None:
        self.add_file("owner.sh", "python3 -I peak-window.py\n")
        self.add_file(
            "other.sh",
            'VAR="value" 2>/dev/null python3 -I other.py\n'
            "/usr/bin/python3 -I other.py\n"
            "value=$((python3 + 1))\n",
        )
        self.set_rule(rule([pattern("shell-command", "python3")], owner="owner.sh"), shell=True)
        check = self.assert_rejected("other.sh:1: shell-command:python3")
        self.assertEqual(check["findings"][0]["value"], 2)
        self.assertEqual(check["findings"][0]["measurement"]["lines"], [1, 2])

    def test_shell_line_continuation_keeps_the_interpreter_script(self) -> None:
        self.add_file("owner.sh", "python3 -I peak-window.py\n")
        self.add_file("other.sh", "python3 \\\n  -I peak-window.py\n")
        self.set_rule(
            rule([pattern("shell-script", "peak-window.py")], owner="owner.sh"), shell=True
        )
        self.assert_rejected("other.sh:2: shell-script:peak-window.py")

    def test_shell_script_after_interpreter_options(self) -> None:
        self.add_file("a.py", "print('owner')\n")
        self.add_file("owner.sh", "python3 -I peak-window.py\n")
        self.add_file("clean.sh", '# python3 -I peak-window.py\necho "python3 -I peak-window.py"\n')
        self.set_rule(
            rule([pattern("shell-script", "peak-window.py")], owner="owner.sh"), shell=True
        )
        self.assert_pass()
        self.add_file("other.sh", "true && python3 -I peak-window.py\n")
        self.assert_rejected("other.sh:1: shell-script:peak-window.py")

    def test_command_substitution_in_double_quotes_is_executed_code(self) -> None:
        self.add_file("owner.sh", "peak_calc\n")
        self.add_file("other.sh", 'answer="$(peak_calc)"\n')
        self.add_file("clean.sh", "echo '$(peak_calc)'\n# $(peak_calc)\n")
        self.set_rule(rule([pattern("shell-command", "peak_calc")], owner="owner.sh"), shell=True)
        check = self.assert_rejected("other.sh:1: shell-command:peak_calc")
        self.assertEqual(len(check["findings"]), 1)

    def test_quoted_substitution_skips_inner_quoted_parentheses_and_comments(self) -> None:
        self.add_file("owner.sh", "peak_calc\n")
        self.add_file(
            "other.sh",
            "one=\"$(printf ')' ; peak_calc)\"\n"
            'two="$(printf "escaped\\" )" ; peak_calc)"\n'
            'three="$(printf ok # ) is in a comment\npeak_calc)"\n',
        )
        self.set_rule(rule([pattern("shell-command", "peak_calc")], owner="owner.sh"), shell=True)
        check = self.assert_rejected("other.sh:1: shell-command:peak_calc")
        self.assertEqual(check["findings"][0]["measurement"]["lines"], [1, 2, 4])

    def test_script_pattern_is_the_interpreter_script_not_an_option_or_later_argument(self) -> None:
        self.add_file("owner.sh", "python3 -I peak-window.py\n")
        self.add_file("other.sh", "python3 -m module peak-window.py\nbash -c peak-window.py\n")
        self.set_rule(
            rule([pattern("shell-script", "peak-window.py")], owner="owner.sh"), shell=True
        )
        self.assert_pass()
        self.add_file("other.sh", "bash -- peak-window.py\n")
        self.assert_rejected("other.sh:1: shell-script:peak-window.py")

    def test_substitution_commands_keep_the_outer_command_apart(self) -> None:
        self.add_file("owner.sh", "python3 -I copied-window.py\n")
        self.add_file(
            "other.sh",
            'echo "$(date)" python3 -I copied-window.py\n'
            "echo $(date) python3 -I copied-window.py\n",
        )
        self.set_rule(rule([pattern("shell-command", "python3")], owner="owner.sh"), shell=True)
        self.assert_pass()
        self.add_file("other.sh", "echo $(python3 -I copied-window.py)\n")
        check = self.assert_rejected("other.sh:1: shell-command:python3")
        self.assertEqual(check["findings"][0]["value"], 1)
        self.add_file("other.sh", "value=$(date) python3 -I copied-window.py\n")
        check = self.assert_rejected("other.sh:1: shell-command:python3")
        self.assertEqual(check["findings"][0]["value"], 1)

    def test_shell_options_distinguish_command_strings_from_rc_files(self) -> None:
        self.add_file("owner.sh", "bash --norc private.sh\n")
        self.add_file("clean.sh", "bash -c private.sh\nbash -ec private.sh\n")
        self.set_rule(rule([pattern("shell-script", "private.sh")], owner="owner.sh"), shell=True)
        self.assert_pass()
        self.add_file(
            "other.sh", "bash --norc private.sh\nbash --rcfile x private.sh\n"
        )
        check = self.assert_rejected("other.sh:1: shell-script:private.sh")
        self.assertEqual(check["findings"][0]["value"], 2)
        self.assertEqual(check["findings"][0]["measurement"]["lines"], [1, 2])

    def test_python_argv_shell_options_distinguish_command_strings_from_rc_files(self) -> None:
        self.add_file("a.py", "subprocess.run(['bash', '--norc', 'private.sh'])\n")
        self.add_file(
            "clean.py",
            "subprocess.run(['bash', '-c', 'private.sh'])\n"
            "subprocess.run(['bash', '-ec', 'private.sh'])\n"
            "subprocess.run(['bash', '--rcfile', 'x', '-c', 'private.sh'])\n",
        )
        self.set_rule(rule([pattern("python-script", "private.sh")]))
        self.assert_pass()
        self.add_file(
            "other.py",
            "subprocess.run(['bash', '--norc', 'private.sh'])\n"
            "subprocess.run(['bash', '--rcfile', 'x', 'private.sh'])\n",
        )
        check = self.assert_rejected("other.py:1: python-script:private.sh")
        self.assertEqual(check["findings"][0]["value"], 2)

    def test_python_script_pattern_distinguishes_script_from_later_argument(self) -> None:
        self.add_file("a.py", "subprocess.run(['python3', '-I', 'peak-window.py'])\n")
        self.add_file(
            "other.py",
            "# subprocess.run(['python3', '-I', 'peak-window.py'])\n"
            "text = \"subprocess.run(['python3', '-I', 'peak-window.py'])\"\n"
            "subprocess.run(['python3', '-m', 'peak-window.py'])\n",
        )
        self.set_rule(rule([pattern("python-script", "peak-window.py")]))
        self.assert_pass()
        self.add_file("other.py", "subprocess.run(['python3', '-I', 'peak-window.py'])\n")
        self.assert_rejected("other.py:1: python-script:peak-window.py")

    def test_text_regex_masks_python_and_shell_comments_and_strings(self) -> None:
        self.add_file("a.py", "window_peak = 1\n")
        self.add_file("clean.py", '# window_peak\ntext = "window_peak"\n')
        self.add_file("clean.sh", '# window_peak\necho "window_peak"\n')
        self.set_rule(rule([pattern("text-regex", "window_peak", ["*.py", "*.sh"])]), shell=True)
        self.assert_pass()
        self.add_file("other.sh", "window_peak=1\n")
        check = self.assert_rejected("text-regex:window_peak outside its owners")
        self.assertTrue(check["findings"][0]["measurement"]["text_fallback"])

    def test_text_fallback_masks_common_comments_and_scans_other_classes(self) -> None:
        self.add_file("README.md", "owner_marker()\n")
        self.add_file(
            "other.md",
            '# owner_marker()\n"owner_marker()"\n// owner_marker()\n'
            "/* owner_marker() */\n'owner_marker()'\n",
        )
        self.set_rule(rule([pattern("text-regex", "owner_marker", ["*.md"])], owner="README.md"))
        self.assert_pass()
        self.add_file("other.md", "# owner_marker()\nowner_marker()\n")
        self.assert_rejected("other.md:2: text-regex:owner_marker")

    def test_text_fallback_masks_elisp_comments_and_strings(self) -> None:
        self.add_file("owner.el", "(owner_marker)\n")
        self.add_file("other.el", '; (owner_marker)\n(message "owner_marker")\n')
        configured = owner_config(
            [rule([pattern("text-regex", "owner_marker", ["*.el"])], owner="owner.el")]
        )
        configured += '\n[[rule]]\npattern = "*.el"\nclass = "python"\nreason = "elisp"\n'
        self.write_config(configured)
        self.assert_pass()
        self.add_file("other.el", "(owner_marker)\n")
        self.assert_rejected("other.el:1: text-regex:owner_marker")

    def test_text_allow_must_contain_the_forbidden_match(self) -> None:
        self.add_file("a.py", "prefix = 1\n")
        self.add_file("other.py", "prefix_helper = 1\n")
        self.set_rule(
            rule(
                [pattern("text-regex", "prefix", ["*.py"])],
                allow=[pattern("text-regex", "prefix_helper", ["*.py"])],
            )
        )
        self.assert_pass()
        self.add_file("other.py", "prefix_helper = prefix\n")
        check = self.assert_rejected("other.py:1: text-regex:prefix")
        self.assertEqual(check["findings"][0]["value"], 1)

    def test_allow_covers_only_same_shell_command(self) -> None:
        self.add_file("a.py", "print('owner')\n")
        self.add_file("owner.sh", "python3 -I peak-window.py\n")
        self.add_file("runner.sh", "python3 -I peak-window.py\n")
        forbid = [pattern("shell-command", "python3")]
        allow = [pattern("shell-script", "peak-window.py")]
        self.set_rule(rule(forbid, allow=allow, owner="owner.sh"), shell=True)
        self.assert_pass()
        self.set_rule(rule(forbid, owner="owner.sh"), shell=True)
        self.assert_rejected("runner.sh:1: shell-command:python3")
        self.set_rule(rule(forbid, allow=allow, owner="owner.sh"), shell=True)
        self.add_file("runner.sh", "python3 other.py; python3 -I peak-window.py\n")
        check = self.assert_rejected("runner.sh:1: shell-command:python3")
        self.assertEqual(check["findings"][0]["value"], 1)

    def test_allow_nested_owner_call_covers_only_its_outer_first_argument(self) -> None:
        self.add_file("a.py", "subprocess.run(['git'])\n")
        self.add_file("caller.py", "subprocess.run(git_argv('status'))\n")
        forbid = [pattern("python-call", "subprocess.run")]
        allow = [pattern("python-call", "git_argv")]
        self.set_rule(rule(forbid, allow=allow))
        self.assert_pass()
        self.add_file("caller.py", "subprocess.run(['git'], env=git_argv('status'))\n")
        self.assert_rejected("caller.py:1: python-call:subprocess.run")


class RuleAndBaselineTests(OwnerCase):
    def setUp(self) -> None:
        super().setUp()
        self.add_file("a.py", "peak()\n")
        self.set_rule(rule([pattern("python-call", "peak")]))

    def test_each_stale_condition_is_a_configuration_error(self) -> None:
        cases = [
            (
                rule([pattern("python-call", "missing")]),
                "forbid pattern 'python-call:missing' matches nothing",
            ),
            (rule([pattern("python-call", "peak")], owner="absent.py"), "owner file absent.py"),
            (
                rule([pattern("python-call", "peak")], allow=[pattern("python-call", "missing")]),
                "allow pattern 'python-call:missing' matches nothing",
            ),
        ]
        for item, message in cases:
            with self.subTest(message=message):
                self.set_rule(item)
                result, document, check = self.result()
                self.assertEqual(result.returncode, 2, output(result))
                self.assertEqual(document["decision"], "error")
                self.assertIn(message, result.stderr)
                self.assertEqual(check["outcome"], "error")

    def test_baseline_ratchets_counts_without_line_identity_and_prunes_resolved(self) -> None:
        self.add_file("other.py", "peak()\n")
        key = subject("single-owner", "other.py", "python-call", "peak")
        self.add_file("owners-baseline.toml", baseline([(key, 1, "reviewed legacy copy")]))
        result, document, check = self.result()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(document["decision"], "accepted_with_exceptions")
        self.assertTrue(check["findings"][0]["covered_by_baseline"])
        self.add_file("other.py", "\npeak()\n")
        result, _document, check = self.result()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(check["findings"][0]["location"], "other.py:2")
        self.add_file("other.py", "peak()\npeak()\n")
        self.assert_rejected("other.py:2")
        self.add_file("other.py", "print(1)\n")
        result, _document, check = self.result()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(check["resolved_baseline_entries"], [key])
        result, document = self.run_json("--prune", "arch")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertTrue(document["prune"]["performed"])
        self.assertFalse((self.repo / "owners-baseline.toml").exists())
        self.add_file("new.py", "peak()\n")
        self.assert_rejected("new.py:1")

    def test_malformed_rule_and_min_direction_are_rejected(self) -> None:
        valid = owner_config([rule([pattern("python-call", "peak")])])
        for old, new in (
            ('peak" }', 'peak", bogus = 1 }'),
            (
                'tier = 1\nenforcement = "enforced"',
                'tier = 1\nenforcement = "enforced"\ndirection = "min"',
            ),
            ('tier = 1\nenforcement = "enforced"', 'tier = 2\nenforcement = "enforced"'),
            ('tier = 1\nenforcement = "enforced"', 'tier = 1\nenforcement = "advisory"'),
        ):
            with self.subTest(new=new):
                self.write_config(valid.replace(old, new))
                result, document = self.run_json()
                self.assertEqual(result.returncode, 2, output(result))
                self.assertEqual(document["decision"], "error")

    def test_existing_tracked_violation_is_checked_when_only_another_file_changes(self) -> None:
        self.add_file("other.py", "peak()\n")
        self.commit_all()
        self.add_file("a.py", "peak()\nprint('changed')\n")
        self.assert_rejected("other.py:1: python-call:peak")

    def test_empty_baseline_reason_does_not_waive_violation(self) -> None:
        self.add_file("other.py", "peak()\n")
        key = subject("single-owner", "other.py", "python-call", "peak")
        self.add_file("owners-baseline.toml", baseline([(key, 1, "")]))
        self.assert_rejected("empty reason")

    def test_invalid_policy_items_are_rejected_before_checks(self) -> None:
        cases = [
            (rule([pattern("python-call", "peak")], owner="../owner.py"), "repository-relative"),
            (rule([pattern("unknown", "peak")]), "one of python-call"),
            (rule([pattern("text-regex", "[")]), "valid regular expression"),
            (
                rule([pattern("python-call", "peak"), pattern("python-call", "peak")]),
                "distinct pattern kinds",
            ),
        ]
        for item, message in cases:
            with self.subTest(message=message):
                self.set_rule(item)
                result, document = self.run_json()
                self.assertEqual(result.returncode, 2, output(result))
                self.assertEqual(document["decision"], "error")
                self.assertIn(message, result.stderr)

    def test_nonregular_owner_and_symlinked_parent_cannot_be_read(self) -> None:
        (self.repo / "linked.py").symlink_to("a.py")
        self.set_rule(rule([pattern("python-call", "peak")], owner="linked.py"))
        result, document, _check = self.result()
        self.assertEqual(result.returncode, 2, output(result))
        self.assertEqual(document["decision"], "error")
        self.assertIn("owner file linked.py", result.stderr)
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "foreign.py").write_text("peak()\n", encoding="utf-8")
        (self.repo / "linkdir").symlink_to(outside)
        with self.assertRaisesRegex(GateError, "cannot scan linkdir/foreign.py"):
            _read_regular(self.repo, "linkdir/foreign.py")

    def test_bad_python_and_shell_are_not_silent_passes(self) -> None:
        self.add_file("other.py", "if :\n")
        result, _document, check = self.result()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(check["outcome"], "error")
        self.assertIn("cannot parse Python other.py", result.stderr)
        (self.repo / "other.py").unlink()
        self.add_file("owner.sh", "peak_calc\n")
        self.add_file("other.sh", 'echo "unterminated\n')
        self.set_rule(rule([pattern("shell-command", "peak_calc")], owner="owner.sh"), shell=True)
        result, _document, check = self.result()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(check["outcome"], "error")
        self.assertIn("unterminated", result.stderr)

    def test_regex_worker_reports_lines_and_ignores_empty_matches(self) -> None:
        source = "first needle\nneedle\n"
        expected = [["needle", 1, 6, 12], ["needle", 2, 13, 19]]
        self.assertEqual(_matches(source, ["needle", "^"]), expected)
        job = self.base / "regex-job.json"
        job.write_text(
            json.dumps([{"path": "p", "source": source, "patterns": ["needle"]}]), encoding="utf-8"
        )
        buffer = StringIO()
        with redirect_stdout(buffer):
            _run(str(job))
        self.assertEqual(json.loads(buffer.getvalue()), {"p": expected})

    def test_ambiguous_or_non_json_regex_results_are_errors(self) -> None:
        for text in ('{"p": [["needle", 1, 0, 6]], "p": []}', '{"p": NaN}',
                     '{"p": Infinity}', '{"p": -Infinity}'):
            with self.subTest(text=text):
                with mock.patch("quality_gate.owners._run_regex", return_value=text):
                    with self.assertRaisesRegex(GateError, "invalid owners text regular expression results"):
                        _regex_events([{"path": "p"}], 0.0)


class RealCallSiteTests(OwnerCase):
    def test_peak_helper_callers_and_reimplementation(self) -> None:
        self.add_file("peak-window.py", "def in_peak(now):\n    return now.hour >= 17\n")
        self.add_file("dsh-implement.sh", "python3 -I peak-window.py\n")
        self.add_file(
            "agent-usage.py",
            "import subprocess\nsubprocess.run(['python3', '-I', 'peak-window.py'])\n",
        )
        peak = rule(
            [
                pattern("shell-command", "python3"),
                pattern("python-argv", "python3"),
                pattern("text-regex", r"hour\s*>=\s*17", ["*.py", "*.sh"]),
            ],
            allow=[
                pattern("shell-script", "peak-window.py"),
                pattern("python-script", "peak-window.py"),
            ],
            owner="peak-window.py",
            name="peak-window",
        )
        self.set_rule(peak, shell=True)
        self.assert_pass()
        self.add_file("opencode.sh", "python3 -I copied-window.py\n")
        self.assert_rejected("opencode.sh:1: shell-command:python3")
        self.add_file("opencode.sh", "(( hour >= 17 ))\n")
        self.assert_rejected("opencode.sh:1: text-regex:")
        (self.repo / "opencode.sh").unlink()
        self.add_file("opencode.py", "def in_peak(now):\n    return now.hour >= 17\n")
        self.assert_rejected("opencode.py:2: text-regex:")
        self.add_file("opencode.py", "subprocess.run(['python3', '-I', 'copied-window.py'])\n")
        self.assert_rejected("opencode.py:1: python-argv:python3")

    def test_gate_git_builder_and_bypass(self) -> None:
        self.add_file(
            "files.py", 'def git_argv(root, *args):\n    return ["git", "-C", root, *args]\n'
        )
        self.add_file("trust.py", 'import subprocess\nsubprocess.run(git_argv(root, "status"))\n')
        git_rule = rule([pattern("python-argv", "git")], owner="files.py", name="git")
        self.set_rule(git_rule)
        self.assert_pass()
        self.add_file("bypass.py", 'import subprocess\nsubprocess.run(["git", "status"])\n')
        self.assert_rejected(
            "owners: git: bypass.py:2: python-argv:git outside its owners (files.py)"
        )


class OwnersTrustTests(TrustCase):
    def test_unreviewed_rule_and_baseline_edits_cannot_waive_a_violation(self) -> None:
        self.add_file("a.py", "peak()\n")
        self.add_file("other.py", "peak()\n")
        configured = owner_config([rule([pattern("python-call", "peak")])])
        self.write_config(configured)
        self.add_file("owners-baseline.toml", baseline([]))
        revision = self.commit_revision()
        self.write_config(configured.replace('owners = ["a.py"]', 'owners = ["a.py", "other.py"]'))
        key = subject("single-owner", "other.py", "python-call", "peak")
        self.add_file("owners-baseline.toml", baseline([(key, 1, "candidate waiver")]))
        result, document = self.trust_json(revision)
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "rejected")
        self.assertEqual(self.protected(document, "quality-gate.toml")["status"], "ignored")
        self.assertEqual(self.protected(document, "owners-baseline.toml")["status"], "ignored")
        self.assertEqual(self.protected(document, "owners-baseline.toml")["ignored_entries"], [key])


if __name__ == "__main__":
    unittest.main()
