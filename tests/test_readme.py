import unittest

from support import GATE


class ReadmeTests(unittest.TestCase):
    def test_readme_inline_code(self) -> None:
        readme = (GATE / "README.md").read_text(encoding="utf-8")
        mutation = readme.partition("\n### Python mutation\n")[2].partition("\n### ")[0]
        delimiter_line = mutation.partition("Lines are split only on ")[2].partition("\n")[0]
        self.assertTrue(
            delimiter_line.startswith(r"`\n`,"),
            f"README.md Python mutation must show the delimiter as `\\n` on one line. "
            f"Found {delimiter_line!r} after 'Lines are split only on '.",
        )
