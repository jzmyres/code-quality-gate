from __future__ import annotations

from support import BASE_CONFIG, FixtureCase, output


class ModuleDirectoryCheckTests(FixtureCase):
    def test_check_reports_module_placement_as_inventory_failure(self) -> None:
        self.write_config('module_dirs = ["src"]\n' + BASE_CONFIG)
        self.add_file("src/README.md", "# Source\n")
        self.git("add", "src")
        result, document = self.run_json()
        self.assertEqual(result.returncode, 1, output(result))
        inventory = self.check_by_id(document, "inventory")
        self.assertEqual(inventory["outcome"], "fail")
        self.assertIn(
            "a.py: code file outside declared module directories ('src')",
            inventory["reason"],
        )
