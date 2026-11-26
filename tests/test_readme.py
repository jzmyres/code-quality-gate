import re
import unittest
from unittest import mock

from support import GATE


class ReadmeTests(unittest.TestCase):
    def test_readme_inline_code(self) -> None:
        readme = (GATE / "README.md").read_text(encoding="utf-8")
        sections = re.findall(r"(?ms)^### Python mutation\n(.*?)(?=^#{1,3} |\Z)", readme)
        self.assertEqual(len(sections), 1, "Expected one Python mutation section in README.md")

        clauses = re.split(r"\bLines are split only on\b", sections[0])
        self.assertEqual(len(clauses) - 1, 1, "Expected one LF-split clause in Python mutation")
        self.assertIsNotNone(
            re.match(r"\s+`\\n`,", clauses[1]),
            r"README.md Python mutation must show the delimiter as `\n` followed immediately by a comma",
        )

    def test_readme_inline_code_rejects_displaced_comma(self) -> None:
        readme = "### Python mutation\n" r"Lines are split only on `\n`junk, and the target"
        with (
            mock.patch.object(type(GATE), "read_text", return_value=readme),
            self.assertRaisesRegex(AssertionError, r"README\.md Python mutation must show the delimiter"),
        ):
            self.test_readme_inline_code()
