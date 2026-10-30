"""Strict JSON decoding shared by parent-side evidence readers."""
from __future__ import annotations

import json
import sys
import unittest

from support import GATE

sys.path.insert(0, str(GATE))
from quality_gate.json_input import load_json


class JsonInputTests(unittest.TestCase):
    def test_duplicate_names_are_refused_at_every_depth(self) -> None:
        for text in ('{"failed": 1, "failed": 0}',
                     '{"failed": null, "failed": null}',
                     '[{"failed": 1, "failed": 0}]',
                     '{"report": {"failed": 1, "failed": 0}}',
                     '{"failed": 1, "\\u0066ailed": 0}'):
            with self.subTest(text=text):
                with self.assertRaisesRegex(ValueError, "duplicate name 'failed'"):
                    load_json(text)

    def test_non_json_constants_are_refused(self) -> None:
        for constant in ("NaN", "Infinity", "-Infinity"):
            for text in (constant, f'{{"value": [{constant}]}}'):
                with self.subTest(text=text):
                    with self.assertRaisesRegex(ValueError, f"non-JSON constant '{constant}'"):
                        load_json(text)

    def test_ordinary_documents_decode_as_before(self) -> None:
        for text in ('null', 'true', '42', '-1.25e2', '"NaN"', '[]', '{}',
                     '[{"name": "first"}, {"name": "second"}]',
                     '{"left": {"name": 1}, "right": {"name": 2}}'):
            with self.subTest(text=text):
                self.assertEqual(load_json(text), json.loads(text))

    def test_malformed_json_is_still_a_value_error(self) -> None:
        with self.assertRaises(ValueError):
            load_json('{"failed":')

    def test_quoted_duplicate_name_is_bounded(self) -> None:
        name = "\0" * 45000
        text = "{" + json.dumps(name) + ": 1, " + json.dumps(name) + ": 0}"
        with self.assertRaises(ValueError) as raised:
            load_json(text)
        message = str(raised.exception)
        self.assertIn("duplicate name", message)
        self.assertLess(len(message), 1024)
