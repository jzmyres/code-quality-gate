"""Exercise shfmt invocation and validation of caller-declared JSON fields."""
import sys
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, mock

import support

from quality_gate import adapters, runner
from quality_gate.policy import UnsupportedError


class ShellSyntaxTests(TestCase):
    def setUp(self):
        self.parse = adapters._parse_shell
        self.binary = support.GATE / "tools" / "bin" / "shfmt"
        self.lookup = self.enterContext(
            mock.patch.object(adapters, "tool_binary", return_value=self.binary),
        )
        self.run = self.enterContext(mock.patch.object(adapters, "run"))

    def test_passes_filename_and_unmodified_bytes_to_pinned_shfmt(self):
        content = b"printf '\xc3\xa9'\r\n"

        def read_stdin(argv, *, stdin, budget_seconds, capture_limit):
            self.assertEqual(stdin, content)
            self.assertEqual(argv, [
                str(self.binary), "--to-json", "-ln=bash", "--filename", "my script.sh",
            ])
            self.assertEqual(budget_seconds, 30)
            self.assertIsNone(capture_limit)
            return runner.RunResult((), "completed", 0, stdout=b'{"Stmts": []}')

        self.run.side_effect = read_stdin
        self.assertEqual(self.parse(content, "my script.sh", lambda node: {"Stmts": list}), {"Stmts": []})
        self.lookup.assert_called_once_with("shfmt")
        self.run.assert_called_once()

    def test_missing_field_names_file_and_field(self):
        self.run.return_value = runner.RunResult((), "completed", 0, stdout=b'{"Last": [{"Hash": {}}]}')
        with self.assertRaisesRegex(ValueError, r"broken\.sh: shfmt JSON missing field Hash\.Line"):
            self.parse(b"#\n", "broken.sh", lambda node: {"Hash.Line": int} if "Hash" in node else {})

    def test_wrong_field_type_names_file_and_field(self):
        self.run.return_value = runner.RunResult((), "completed", 0, stdout=b'{"Hash": {"Line": "1"}}')
        with self.assertRaisesRegex(ValueError, r"broken\.sh: shfmt JSON field Hash\.Line must be int"):
            self.parse(b"#\n", "broken.sh", lambda node: {"Hash.Line": int} if "Hash" in node else {})

    def test_unparsable_file_names_file(self):
        self.run.return_value = runner.RunResult(
            (), "completed", 1, stderr=b"1:1: if must be followed by a statement\n",
        )
        with self.assertRaisesRegex(ValueError, r"broken\.sh: shfmt parse failed: .*if must be followed"):
            self.parse(b"if\n", "broken.sh", lambda node: {})

    def test_runner_timeout_names_file(self):
        self.run.return_value = runner.RunResult((), "budget", None)
        with self.assertRaisesRegex(ValueError, r"slow\.sh: shfmt deadline exceeded"):
            self.parse(b"true\n", "slow.sh", lambda node: {})

    def test_runner_error_names_file(self):
        self.run.return_value = runner.RunResult((), "error", None, error="cannot start fixture")
        with self.assertRaisesRegex(ValueError, r"broken\.sh: cannot run shfmt: cannot start fixture"):
            self.parse(b"true\n", "broken.sh", lambda node: {})

    def test_runner_feeds_bytes_to_child_stdin(self):
        with TemporaryDirectory() as directory:
            binary = Path(directory) / "shfmt"
            binary.write_text(
                f"#!{sys.executable}\nimport sys\nsys.stdout.buffer.write(sys.stdin.buffer.read())\n",
                encoding="utf-8",
            )
            binary.chmod(0o700)
            self.lookup.return_value = binary
            self.run.side_effect = runner.run
            self.assertEqual(self.parse(b'{"Stmts": []}', "stdin.sh", lambda node: {}), {"Stmts": []})

    def test_expired_check_never_launches_shfmt(self):
        with runner.check_deadline("comments", time.monotonic() - 2, 1):
            with self.assertRaisesRegex(ValueError, r"late\.sh: shfmt deadline exceeded"):
                self.parse(b"true\n", "late.sh", lambda node: {})
        self.lookup.assert_not_called()
        self.run.assert_not_called()

    def test_lookup_spends_deadline_before_launch(self):
        with mock.patch.object(adapters, "remaining_budget", side_effect=[1, 0]):
            with self.assertRaisesRegex(ValueError, r"late\.sh: shfmt deadline exceeded"):
                self.parse(b"true\n", "late.sh", lambda node: {})
        self.run.assert_not_called()

    def test_missing_pinned_tool_fails_before_invocation(self):
        self.lookup.side_effect = UnsupportedError("pinned shfmt is missing")
        with self.assertRaisesRegex(ValueError, r"script\.sh: cannot run shfmt: pinned shfmt is missing"):
            self.parse(b"true\n", "script.sh", lambda node: {})
        self.run.assert_not_called()

    def test_invalid_json_names_file(self):
        for payload, detail in ((b"{", "invalid shfmt JSON"), (b"[]", "tree must be an object")):
            with self.subTest(payload=payload):
                self.run.return_value = runner.RunResult((), "completed", 0, stdout=payload)
                with self.assertRaisesRegex(ValueError, rf"script\.sh: .*{detail}"):
                    self.parse(b"true\n", "script.sh", lambda node: {})


class ShellCommentSchemaTests(TestCase):
    def test_declares_position_for_comments_and_text_only_when_present(self):
        from quality_gate.comments import _shell_comment_fields

        self.assertEqual(_shell_comment_fields({"Text": "# in a string"}), {})
        self.assertEqual(_shell_comment_fields({"Hash": {}}), {"Hash.Line": int})
        self.assertEqual(
            _shell_comment_fields({"Hash": {"Line": 1}, "Text": " comment"}),
            {"Hash.Line": int, "Text": str},
        )
