"""Exercise shfmt invocation and validation of caller-declared JSON fields."""
from subprocess import CompletedProcess
from unittest import TestCase, mock

import support

from quality_gate import shell_syntax
from quality_gate.policy import UnsupportedError


class ShellSyntaxTests(TestCase):
    def setUp(self):
        self.binary = support.GATE / "tools" / "bin" / "shfmt"
        self.lookup = self.enterContext(
            mock.patch.object(shell_syntax, "tool_binary", return_value=self.binary),
        )
        self.run = self.enterContext(mock.patch.object(shell_syntax, "run"))

    def test_passes_filename_and_unmodified_bytes_to_pinned_shfmt(self):
        self.run.return_value = CompletedProcess([], 0, b'{"Stmts": []}', b"")
        content = b"printf '\xc3\xa9'\r\n"
        tree = shell_syntax.parse(content, "my script.sh", lambda node: {"Stmts": list})
        self.assertEqual(tree, {"Stmts": []})
        self.lookup.assert_called_once_with("shfmt")
        self.run.assert_called_once_with(
            [str(self.binary), "--to-json", "-ln=bash", "--filename", "my script.sh"],
            input=content, capture_output=True, timeout=30, check=False,
        )

    def test_missing_field_names_file_and_field(self):
        self.run.return_value = CompletedProcess([], 0, b'{"Last": [{"Hash": {}}]}', b"")
        with self.assertRaisesRegex(ValueError, r"broken\.sh: shfmt JSON missing field Hash\.Line"):
            shell_syntax.parse(b"#\n", "broken.sh", lambda node: {"Hash.Line": int} if "Hash" in node else {})

    def test_unparsable_file_names_file(self):
        self.run.return_value = CompletedProcess([], 1, b"", b"1:1: if must be followed by a statement\n")
        with self.assertRaisesRegex(ValueError, r"broken\.sh: shfmt parse failed: .*if must be followed"):
            shell_syntax.parse(b"if\n", "broken.sh", lambda node: {})

    def test_missing_pinned_tool_fails_before_invocation(self):
        self.lookup.side_effect = UnsupportedError("pinned shfmt is missing")
        with self.assertRaisesRegex(ValueError, r"script\.sh: cannot run shfmt: pinned shfmt is missing"):
            shell_syntax.parse(b"true\n", "script.sh", lambda node: {})
        self.run.assert_not_called()

    def test_invalid_json_names_file(self):
        for payload, detail in ((b"{", "invalid shfmt JSON"), (b"[]", "tree must be an object")):
            with self.subTest(payload=payload):
                self.run.return_value = CompletedProcess([], 0, payload, b"")
                with self.assertRaisesRegex(ValueError, rf"script\.sh: .*{detail}"):
                    shell_syntax.parse(b"true\n", "script.sh", lambda node: {})
