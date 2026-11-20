"""Tests for the mutation messages and the inherited PATH, kept small."""
from __future__ import annotations

import ast
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from quality_gate import python_mutation


class MessageTests(unittest.TestCase):
    def generated(self, source: str) -> list[python_mutation.Mutation]:
        function = ast.parse(source).body[0]
        return python_mutation._mutations(function, source, 100)

    def test_a_non_ascii_prefix_is_shown_with_its_bytes(self) -> None:
        source = 'def choose(x):\n    return "éé" if x == 1 else "b"\n'
        changed = next(
            record for record in self.generated(source)
            if record.operator == "!=" and record.line == 2
        )
        self.assertEqual(
            changed.mutated_line, 'return "éé" if x != 1 else "b"'
        )

    def test_a_form_feed_before_the_target_keeps_ast_line_numbers(self) -> None:
        source = "def choose(x):\n    marker = 1\n\f\n    return x == 1\n"
        changed = next(
            record for record in self.generated(source)
            if record.operator == "!=" and record.line == 4
        )
        self.assertEqual(changed.mutated_line, "return x != 1")

    def test_string_breaks_before_the_target_are_not_line_breaks(self) -> None:
        source = 'def choose(x):\n    text = "a\x85b\u2028c"\n    return x == 1\n'
        changed = next(
            record for record in self.generated(source)
            if record.operator == "!=" and record.line == 3
        )
        self.assertEqual(changed.mutated_line, "return x != 1")

    def test_two_statements_on_one_line_show_only_the_deleted_one(self) -> None:
        source = "def pair():\n    a = 1; b = 2\n    return a + b\n"
        deleted = next(
            record for record in self.generated(source)
            if record.operator == "delete" and record.line == 2
            and record.column == 11
        )
        self.assertEqual(deleted.mutated_line, "deleted: b = 2")

    def test_deletions_exclude_the_next_statement_and_trailing_comment(self) -> None:
        source = "def pair():\n    a = 10; b = 20  # comment\n    return a + b\n"
        deleted = [
            record.mutated_line for record in self.generated(source)
            if record.operator == "delete" and record.line == 2
        ]
        self.assertEqual(deleted, ["deleted: a = 10", "deleted: b = 20"])

    def test_deletion_after_non_ascii_text_uses_byte_offsets(self) -> None:
        source = 'def pair():\n    text = "éé"; b = 20  # comment\n    return text, b\n'
        deleted = next(
            record for record in self.generated(source)
            if record.operator == "delete" and record.line == 2
            and record.column == 19
        )
        self.assertEqual(deleted.mutated_line, "deleted: b = 20")

    def test_multiline_deletion_keeps_the_whole_first_line(self) -> None:
        source = "def work():\n    value = (  \n        10\n    )\n    return value\n"
        deleted = next(
            record for record in self.generated(source)
            if record.operator == "delete" and record.line == 2
        )
        self.assertEqual(deleted.mutated_line, "deleted: value = (  ")

    def test_multiline_replacement_keeps_the_first_prefix_and_last_suffix(self) -> None:
        source = "def choose(x):\n    return (x\n        == 1)  # comment\n"
        changed = next(
            record for record in self.generated(source)
            if record.operator == "!=" and record.line == 2
        )
        self.assertEqual(changed.mutated_line, "return (x != 1)  # comment")

    def test_every_message_contains_its_replacement_once_on_its_line(self) -> None:
        source = (
            'def choose(x):\n'
            '    text = "é\x85\u2028"\n'
            "\f\n"
            "    a = 10; b = 20  # comment\n"
            "    value = (  \n"
            "        a + b\n"
            "    )\n"
            '    return "éé" if x == 1 else text\n'
        )
        function = ast.parse(source).body[0]
        changes = python_mutation._raw_changes(function)
        records = python_mutation._mutations(function, source, 100)
        self.assertEqual(len(records), len(changes))
        for change, record in zip(changes, records, strict=True):
            with self.subTest(operator=record.operator, line=record.line):
                self.assertEqual(record.line, change.target.lineno)
                if change.delete:
                    segment = ast.get_source_segment(source, change.target)
                    self.assertEqual(
                        record.mutated_line, "deleted: " + segment.split("\n", 1)[0]
                    )
                    continue
                replacement = ast.unparse(change.replacement_node)
                self.assertEqual(
                    record.mutated_line.count(replacement), 1,
                    record.mutated_line,
                )

    def test_mutated_line_uses_the_change_span(self) -> None:
        source = "def work():\n    return 1\n"
        function = ast.parse(source).body[0]
        change = next(
            item for item in python_mutation._raw_changes(function)
            if item.operator == "n+1"
        )
        self.assertEqual(
            python_mutation._mutated_line(change, source), "return 2"
        )


class InheritedPathTests(unittest.TestCase):
    def test_inherited_path_moves_source_entries_into_the_copy(self) -> None:
        with tempfile.TemporaryDirectory() as source_directory, (
            tempfile.TemporaryDirectory()
        ) as copy_directory:
            source_root = Path(source_directory)
            copy_root = Path(copy_directory)
            (source_root / "bin").mkdir()
            with mock.patch.dict(os.environ, {
                "PATH": f"{source_root / 'bin'}{os.pathsep}/usr/bin",
            }, clear=True):
                path = python_mutation._inherited_path(source_root, copy_root)
        self.assertEqual(
            path, f"{copy_root / 'bin'}{os.pathsep}/usr/bin"
        )

    def test_inherited_path_resolves_entries_from_the_gate_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source_root = base / "src"
            (source_root / "bin").mkdir(parents=True)
            copy_root = base / "work/qg-mutation-x/copy-0000"
            copy_root.mkdir(parents=True)
            working = base / "a/b"
            working.mkdir(parents=True)
            previous = os.getcwd()
            os.chdir(working)
            try:
                with mock.patch.dict(os.environ, {
                    "PATH": os.pathsep.join(
                        ["../../../src/bin", "", "/usr/bin"]
                    ),
                }, clear=True):
                    path = python_mutation._inherited_path(
                        source_root, copy_root
                    )
            finally:
                os.chdir(previous)
        entries = path.split(os.pathsep)
        self.assertEqual(
            entries[0],
            os.path.realpath(working / "../../../src/bin"),
        )
        self.assertEqual(entries[1], os.path.realpath(working))
        self.assertEqual(entries[2], "/usr/bin")
        for entry in entries:
            self.assertTrue(os.path.isabs(entry), entry)
            self.assertFalse(
                Path(entry).is_relative_to(source_root), entry
            )


if __name__ == "__main__":
    unittest.main()
