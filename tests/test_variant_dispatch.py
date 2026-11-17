"""Tests for variant_dispatch: the VSD vocabularies and the TRIAL fallback rule."""
from __future__ import annotations

import ast
import unittest
from types import SimpleNamespace
from typing import Any
from unittest import mock

from support import (
    BASE_CONFIG,
    FixtureCase,
    _add_check_to_class,
    output,
)

from quality_gate import policy, variant_dispatch


VARIANT_CHECK = "variant-dispatch"

SHELL_RULE = (
    "\n[[rule]]\n"
    'pattern = "*.sh"\n'
    'class = "python"\n'
    'reason = "shell scripts measured with Python source"\n'
)


def variant_config(
    *, scope: str = "tree", base: str | None = None, extra: str = ""
) -> str:
    text = _add_check_to_class(BASE_CONFIG, "python", VARIANT_CHECK)
    table = (
        "\n[checks.variant-dispatch]\n"
        'adapter = "variant_dispatch"\n'
        "tier = 1\n"
        'enforcement = "enforced"\n'
        f'scope = "{scope}"\n'
    )
    if base is not None:
        table += f'base = "{base}"\n'
    return text + table + extra


PY_COMPARE = """\
def first(kind):
    if kind == "alpha":
        return 1
    if kind == "beta":
        return 2
    return 0


def second(kind):
    if kind == "alpha":
        return 3
    if kind == "beta":
        return 4
    return 0
"""

PY_COMPARE_ONE = """\
def first(kind):
    if kind == "alpha":
        return 1
    if kind == "beta":
        return 2
    return 0
"""

PY_COMPARE_ONE_LITERAL = """\
def first(kind):
    if kind == "alpha":
        return 1
    return 0


def second(kind):
    if kind == "alpha":
        return 2
    return 0
"""

PY_IN = """\
def first(kind):
    if kind in ("alpha", "beta"):
        return 1
    return 0


def second(kind):
    if kind not in ("alpha", "beta"):
        return 2
    return 0
"""

PY_IN_ONE = """\
def first(kind):
    if kind in ("alpha", "beta"):
        return 1
    return 0
"""

PY_MATCH = """\
def first(kind):
    match kind:
        case "alpha":
            return 1
        case "beta":
            return 2
    return 0


def second(kind):
    match kind:
        case "alpha" | "beta":
            return 3
    return 0
"""

PY_MATCH_ONE = """\
def first(kind):
    match kind:
        case "alpha" | "beta":
            return 1
    return 0
"""

PY_DICT = """\
def first(kind):
    return {"alpha": 1, "beta": 2}[kind]


def second(kind):
    return {"alpha": 3, "beta": 4}.get(kind)
"""

PY_DICT_ONE = """\
def first(kind):
    return {"alpha": 1, "beta": 2}[kind]
"""

PY_MIXED_DICT = """\
def first(kind):
    return {"alpha": 1, "beta": 2, 0: 3}[kind]


def second(kind):
    return {"alpha": 3, "beta": 4, 0: 5}.get(kind)
"""

PY_MIXED_DICT_ONE = """\
def first(kind):
    return {"alpha": 1, 0: 2}[kind]


def second(kind):
    return {"alpha": 3, 0: 4}[kind]
"""

PY_CONSTANT_IN_DISPLAY = """\
def first():
    return "alpha" in ("alpha", "beta")


def second():
    return "alpha" in ("alpha", "beta")
"""

PY_CONSTANT_COMPARE = """\
def first():
    return "alpha" == "alpha"


def second():
    return "beta" == "beta"
"""

TABLE_DICT = 'TABLE = {"alpha": 1, "beta": 2}\nOTHER = {"alpha": 3, "beta": 4}\n'
TABLE_TUPLE = 'TABLE = ("alpha", "beta")\nOTHER = ("alpha", "beta")\n'
TABLE_LIST = "TABLE = ['alpha', 'beta']\nOTHER = ['alpha', 'beta']\n"
TABLE_SET = "TABLE = {'alpha', 'beta'}\nOTHER = {'alpha', 'beta'}\n"
TABLE_FROZENSET = (
    'TABLE = frozenset({"alpha", "beta"})\n'
    'OTHER = frozenset({"alpha", "beta"})\n'
)

TABLE_DICT_ONE = 'TABLE = {"alpha": 1, "beta": 2}\n'
TABLE_TUPLE_ONE = 'TABLE = ("alpha", "beta")\n'

TABLE_AND_FUNCTION = """\
TABLE = ("alpha", "beta")


def dispatch(kind):
    if kind == "alpha":
        return 1
    if kind == "beta":
        return 2
    return 0
"""

PY_NUMBERS = """\
def first(kind):
    if kind == 1:
        return 1
    if kind == 2:
        return 2
    return 0


def second(kind):
    if kind == "":
        return 3
    if kind == " ":
        return 4
    return 0
"""

THREE_OWNERS = """\
def first(kind):
    if kind == "alpha":
        return 1
    if kind == "beta":
        return 2
    return 0


def middle(kind):
    if kind == "alpha":
        return 3
    if kind == "beta":
        return 4
    if kind == "gamma":
        return 5
    if kind == "delta":
        return 6
    return 0


def last(kind):
    if kind == "gamma":
        return 7
    if kind == "delta":
        return 8
    return 0
"""


TRIAL_HEADER = """\
FORMATS = ("json", "csv")


def read_json(value) -> str:
    return value


def read_csv(value) -> str:
    return value


"""

TRIAL_OR = TRIAL_HEADER + """\
def load(value):
    return read_json(value) or read_csv(value)
"""
TRIAL_GUARD = TRIAL_HEADER + """\
def load(value):
    result = read_json(value)
    if result is None:
        result = read_csv(value)
    return result
"""
TRIAL_NOT = TRIAL_HEADER + """\
def load(value):
    result = read_json(value)
    if not result:
        result = read_csv(value)
    return result
"""
TRIAL_TRY = TRIAL_HEADER + """\
def load(value):
    try:
        return read_json(value)
    except ValueError:
        return read_csv(value)
"""
TRIAL_GUARD_ELSE = TRIAL_HEADER + """\
def load(value):
    result = read_json(value)
    if result is None:
        result = read_csv(value)
    else:
        result = None
    return result
"""
TRIAL_GUARD_TWO = TRIAL_HEADER + """\
def load(value):
    result = read_json(value)
    if result is None:
        result = read_csv(value)
        result = None
    return result
"""
TRIAL_OVERWRITTEN_TRY = TRIAL_HEADER + """\
def load(value):
    try:
        return read_json(value)
    except ValueError:
        result = read_csv(value)
        result = None
    return result
"""
TRIAL_NOT_CONSECUTIVE = TRIAL_HEADER + """\
def load(value):
    result = read_json(value)
    value = value
    if result is None:
        result = read_csv(value)
    return result
"""
TRIAL_OR_DISCARDED = TRIAL_HEADER + """\
def load(value):
    read_json(value) or read_csv(value)
    return "fixed"
"""
TRIAL_GUARD_DISCARDED = TRIAL_HEADER + """\
def load(value):
    result = read_json(value)
    if result is None:
        result = read_csv(value)
    return "fixed"
"""
TRIAL_TRY_DISCARDED = TRIAL_HEADER + """\
def load(value):
    try:
        read_json(value)
    except ValueError:
        read_csv(value)
    return "fixed"
"""
TRIAL_HARNESS = """\
FORMATS = ("dsh", "codex")


def dsh_run_values(records) -> str:
    return records


def codex_run_values(records) -> str:
    return records


def load(records):
    values = dsh_run_values(records)
    if values is None:
        values = codex_run_values(records)
    return values
"""


class VariantCase(FixtureCase):
    def setUp(self) -> None:
        super().setUp()
        self.write_config(variant_config())

    def run_variant(
        self, env: dict[str, str] | None = None
    ) -> tuple[Any, dict[str, Any], dict[str, Any]]:
        result, document = self.run_json(
            "--only", VARIANT_CHECK, env=env
        )
        return result, document, self.check_by_id(document, VARIANT_CHECK)

    def rejected(self) -> list[dict[str, Any]]:
        result, _document, check = self.run_variant()
        self.assertEqual(result.returncode, 1, output(result))
        return check["findings"]

    def accepted(self) -> dict[str, Any]:
        result, _document, check = self.run_variant()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(check["findings"], [])
        return check

    def assert_check_error(self, needle: str) -> dict[str, Any]:
        result, document, check = self.run_variant()
        self.assertEqual(result.returncode, 2, output(result))
        self.assertEqual(document["decision"], "error")
        self.assertEqual(check["outcome"], "error")
        self.assertIn(needle, document["error"])
        return document

    def base_commit(self, files: dict[str, str]) -> None:
        for relative, content in files.items():
            self.add_file(relative, content)
        self.commit_all("base")

    def change(self, files: dict[str, str]) -> None:
        for relative, content in files.items():
            self.add_file(relative, content)
        self.commit_all("change")


class ComparisonTests(VariantCase):
    def test_two_functions_that_compare_the_same_literals_are_a_finding(self):
        self.add_file("pkg/app.py", PY_COMPARE)
        findings = self.rejected()
        self.assertEqual(len(findings), 1, findings)
        self.assertEqual(findings[0]["measurement"]["literals"], ["alpha", "beta"])

    def test_one_function_is_not_a_finding(self):
        self.add_file("pkg/app.py", PY_COMPARE_ONE)
        self.accepted()

    def test_the_exact_message(self):
        self.add_file("pkg/app.py", PY_COMPARE)
        finding = self.rejected()[0]
        self.assertEqual(
            finding["subject"],
            'VSD variant-dispatch: "alpha", "beta" are listed in 2 places: '
            "pkg/app.py:1 first (function), pkg/app.py:9 second (function)\n"
            "Declare this vocabulary once, in one table, and read every "
            "per-variant difference through it.",
        )
        self.assertEqual(
            finding["measurement"]["owners"],
            [
                {
                    "path": "pkg/app.py",
                    "line": 1,
                    "name": "first",
                    "kind": "function",
                    "literals": ["alpha", "beta"],
                },
                {
                    "path": "pkg/app.py",
                    "line": 9,
                    "name": "second",
                    "kind": "function",
                    "literals": ["alpha", "beta"],
                },
            ],
        )

    def test_exactly_one_shared_literal_is_not_a_finding(self):
        self.add_file("pkg/app.py", PY_COMPARE_ONE_LITERAL)
        self.accepted()


class InDisplayTests(VariantCase):
    def test_two_functions_that_test_the_same_display_are_a_finding(self):
        self.add_file("pkg/app.py", PY_IN)
        findings = self.rejected()
        self.assertEqual(findings[0]["measurement"]["literals"], ["alpha", "beta"])

    def test_one_function_is_not_a_finding(self):
        self.add_file("pkg/app.py", PY_IN_ONE)
        self.accepted()


class MatchTests(VariantCase):
    def test_two_functions_with_case_literals_are_a_finding(self):
        self.add_file("pkg/app.py", PY_MATCH)
        self.assertEqual(len(self.rejected()), 1)

    def test_one_function_is_not_a_finding(self):
        self.add_file("pkg/app.py", PY_MATCH_ONE)
        self.accepted()


class InlineDictTests(VariantCase):
    def test_two_functions_with_inline_dicts_are_a_finding(self):
        self.add_file("pkg/app.py", PY_DICT)
        self.assertEqual(len(self.rejected()), 1)

    def test_one_function_is_not_a_finding(self):
        self.add_file("pkg/app.py", PY_DICT_ONE)
        self.accepted()

    def test_a_mixed_key_dict_contributes_its_two_string_keys(self):
        self.add_file("pkg/app.py", PY_MIXED_DICT)
        finding = self.rejected()[0]
        self.assertEqual(
            finding["measurement"]["literals"], ["alpha", "beta"]
        )

    def test_a_mixed_key_dict_with_one_string_key_contributes_nothing(self):
        self.add_file("pkg/app.py", PY_MIXED_DICT_ONE)
        self.accepted()


class ConstantSubjectTests(VariantCase):
    def test_a_constant_is_not_a_subject_of_a_membership_display(self):
        self.add_file("pkg/app.py", PY_CONSTANT_IN_DISPLAY)
        self.accepted()

    def test_a_constant_against_a_constant_is_not_a_subject(self):
        self.add_file("pkg/app.py", PY_CONSTANT_COMPARE)
        self.accepted()


class DeclaredTableTests(VariantCase):
    def test_two_dict_tables_are_a_finding(self):
        self.add_file("pkg/app.py", TABLE_DICT)
        self.assertEqual(len(self.rejected()), 1)

    def test_two_tuple_tables_are_a_finding(self):
        self.add_file("pkg/app.py", TABLE_TUPLE)
        self.assertEqual(len(self.rejected()), 1)

    def test_two_list_tables_are_a_finding(self):
        self.add_file("pkg/app.py", TABLE_LIST)
        self.assertEqual(len(self.rejected()), 1)

    def test_two_set_tables_are_a_finding(self):
        self.add_file("pkg/app.py", TABLE_SET)
        self.assertEqual(len(self.rejected()), 1)

    def test_two_frozenset_tables_are_a_finding(self):
        self.add_file("pkg/app.py", TABLE_FROZENSET)
        self.assertEqual(len(self.rejected()), 1)

    def test_one_dict_table_is_not_a_finding(self):
        self.add_file("pkg/app.py", TABLE_DICT_ONE)
        self.accepted()

    def test_one_tuple_table_is_not_a_finding(self):
        self.add_file("pkg/app.py", TABLE_TUPLE_ONE)
        self.accepted()

    def test_a_table_and_a_function_are_a_finding(self):
        self.add_file("pkg/app.py", TABLE_AND_FUNCTION)
        finding = self.rejected()[0]
        kinds = [owner["kind"] for owner in finding["measurement"]["owners"]]
        self.assertEqual(kinds, ["table", "function"])


class ShellNotReadTests(VariantCase):
    def test_a_shell_file_is_not_read(self):
        self.write_config(variant_config(extra=SHELL_RULE))
        self.add_file(
            "run.sh",
            "first() {\n"
            "    case \"$1\" in\n"
            "        alpha|beta) echo one ;;\n"
            "    esac\n"
            "}\n"
            "\n"
            "second() {\n"
            "    case \"$1\" in\n"
            "        alpha|beta) echo two ;;\n"
            "    esac\n"
            "}\n",
        )
        self.accepted()



class GroupTests(VariantCase):
    def test_three_owners_linked_through_two_pairs_are_one_finding(self):
        self.add_file("pkg/app.py", THREE_OWNERS)
        findings = self.rejected()
        self.assertEqual(len(findings), 1, findings)
        self.assertEqual(
            findings[0]["measurement"]["literals"],
            ["alpha", "beta", "delta", "gamma"],
        )
        self.assertEqual(len(findings[0]["measurement"]["owners"]), 3)

    def test_numeric_and_empty_string_literals_are_not_a_vocabulary(self):
        self.add_file("pkg/app.py", PY_NUMBERS)
        self.accepted()


class ChangedScopeTests(VariantCase):
    def setUp(self) -> None:
        super().setUp()
        self.write_config(variant_config(scope="changed", base="HEAD^"))

    def test_a_changed_function_owner_reports_the_finding(self):
        self.base_commit({"pkg/app.py": PY_COMPARE_ONE})
        self.change({"pkg/app.py": PY_COMPARE})
        findings = self.rejected()
        self.assertEqual(len(findings), 1, findings)
        self.assertEqual(len(findings[0]["measurement"]["owners"]), 2)

    def test_a_changed_table_owner_reports_the_finding(self):
        self.base_commit({"pkg/app.py": TABLE_AND_FUNCTION})
        self.change({
            "pkg/app.py": TABLE_AND_FUNCTION + '\nOTHER = ("alpha", "beta")\n'
        })
        findings = self.rejected()
        names = [
            owner["name"] for owner in findings[0]["measurement"]["owners"]
        ]
        self.assertIn("OTHER", names)

    def test_unchanged_owners_are_not_reported(self):
        self.base_commit({"pkg/app.py": PY_COMPARE})
        self.change({"notes.md": "# nothing changed\n"})
        self.accepted()

    def test_an_invalid_base_is_a_check_error(self):
        self.write_config(variant_config(
            scope="changed", base="no-such-revision"
        ))
        self.assert_check_error("no-such-revision")

    def test_the_measurement_names_the_base(self):
        self.base_commit({"pkg/app.py": PY_COMPARE_ONE})
        self.change({"pkg/app.py": PY_COMPARE})
        _result, _document, check = self.run_variant()
        self.assertEqual(
            check["measurement"]["base"],
            {
                "commit": self.git("rev-parse", "HEAD^").stdout.strip(),
                "source": "base",
            },
        )


class InputTests(VariantCase):
    def test_an_unparsable_python_file_is_a_check_error(self):
        self.add_file("pkg/broken.py", "def broken(:\n")
        self.assert_check_error("cannot parse pkg/broken.py")


class SpecTests(VariantCase):
    def test_the_adapter_declares_its_parse_and_run_functions(self):
        self.assertTrue(callable(variant_dispatch._variant_dispatch_spec))
        self.assertTrue(callable(variant_dispatch._run_variant_dispatch))

    def test_the_policy_keys_are_parsed_with_their_defaults(self):
        parsed = variant_dispatch._variant_dispatch_spec(
            {}, self.repo, self.repo / "quality-gate.toml",
            "checks.variant-dispatch",
        )
        self.assertEqual(
            parsed.spec, variant_dispatch.VariantSpec("tree", "HEAD")
        )
        self.assertEqual(parsed.metric_version, "variant-dispatch/1")
        self.assertEqual(parsed.evidence, ("static",))
        self.assertEqual(parsed.threshold, 0)
        changed = variant_dispatch._variant_dispatch_spec(
            {"scope": "changed", "base": "main"},
            self.repo,
            self.repo / "quality-gate.toml",
            "checks.variant-dispatch",
        )
        self.assertEqual(
            changed.spec, variant_dispatch.VariantSpec("changed", "main")
        )
        spec = policy.load_config(self.repo).checks[VARIANT_CHECK].spec
        self.assertEqual((spec.scope, spec.base), ("tree", "HEAD"))

    def test_the_run_hook_reports_a_one_finding_fixture(self):
        self.add_file("pkg/app.py", PY_COMPARE)
        config = policy.load_config(self.repo)
        context = SimpleNamespace(
            root=self.repo,
            config=config,
            check=config.checks[VARIANT_CHECK],
            files=None,
            classes=None,
            base_override=None,
            prefix="pkg",
        )
        with mock.patch(
            "quality_gate.checks._select_files",
            return_value=(["pkg/app.py"], []),
        ):
            result = variant_dispatch._run_variant_dispatch(context)
        document = result.to_json()
        self.assertEqual(document["id"], VARIANT_CHECK)
        self.assertEqual(document["adapter"], "variant_dispatch")
        self.assertEqual(document["evidence"], ["static"])
        self.assertEqual(document["metric_version"], "variant-dispatch/1")
        self.assertEqual(document["outcome"], "fail")
        self.assertEqual(document["measurement"], {"owners": 2})
        self.assertEqual(len(document["findings"]), 1)
        self.assertIn("VSD variant-dispatch:", document["findings"][0]["subject"])

    def test_invalid_scope_is_a_configuration_error(self):
        self.write_config(variant_config(scope="repository"))
        result = self.run_qg("check", "--only", VARIANT_CHECK)
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn("checks.variant-dispatch.scope", output(result))
        self.assertIn("changed, tree", output(result))

    def test_an_unknown_key_is_a_configuration_error(self):
        self.write_config(variant_config(extra="min_places = 2\n"))
        result = self.run_qg("check", "--only", VARIANT_CHECK)
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn("min_places", output(result))


class FinishTests(unittest.TestCase):
    def measured(self) -> tuple[list[Any], int, Any]:
        candidates = [
            variant_dispatch.Candidate(
                SimpleNamespace(subject=subject), ()
            )
            for subject in ("second", "first")
        ]
        base = SimpleNamespace(
            measurement=lambda: {"commit": "abc", "source": "base"}
        )
        return candidates, 3, base

    def run_finish(self, evaluated: tuple[Any, Any]) -> tuple[Any, Any, Any, Any]:
        candidates, count, base = self.measured()
        result = SimpleNamespace(outcome="sentinel")
        with mock.patch(
            "quality_gate.checks._evaluate_ratchet",
            return_value=evaluated,
        ) as evaluate, mock.patch(
            "quality_gate.checks._ratchet_result", return_value=result
        ) as finish:
            returned = variant_dispatch._finish(
                SimpleNamespace(prefix="pkg"), SimpleNamespace(), 1.0,
                (candidates, count, base),
            )
        return returned, result, evaluate, finish

    def test_finish_sorts_findings_and_reports_the_owner_count(self):
        ratchet = SimpleNamespace(satisfied=True, outcome="pass")
        returned, result, evaluate, finish = self.run_finish(
            (ratchet, None)
        )
        self.assertIs(returned, result)
        self.assertEqual(
            [finding.subject for finding in evaluate.call_args.args[0]],
            ["first", "second"],
        )
        self.assertEqual(
            finish.call_args.kwargs["measurement"],
            {
                "owners": 3,
                "base": {"commit": "abc", "source": "base"},
            },
        )
        self.assertEqual(finish.call_args.args[2], "pass")

    def test_finish_returns_the_ratchet_failure_as_the_reason(self):
        returned, result, _evaluate, finish = self.run_finish(
            (None, "measured reason")
        )
        self.assertIs(returned, result)
        self.assertEqual(finish.call_args.kwargs["reason"], "measured reason")
        self.assertNotIn("ratchet", finish.call_args.kwargs)


class HelperTests(VariantCase):
    def test_an_annotated_and_a_plain_assignment_are_declared_tables(self):
        tree = ast.parse(
            'TABLE = ("alpha", "beta")\n'
            'OTHER: tuple = ("alpha", "gamma")\n'
            "VALUE = 1\n"
        )
        self.assertEqual(
            variant_dispatch._table_names(tree.body[0]), ["TABLE"]
        )
        self.assertEqual(
            variant_dispatch._table_names(tree.body[1]), ["OTHER"]
        )
        self.assertEqual(variant_dispatch._table_names(tree.body[2]), ["VALUE"])
        self.assertEqual(
            variant_dispatch._declared_literals(tree.body[1].value),
            frozenset({"alpha", "gamma"}),
        )

    def test_a_dict_with_a_non_string_key_is_not_a_table(self):
        for source in ('{1: "a", "b": 2}', '{"a": 1}', '{"a": 1, **other}'):
            with self.subTest(source=source):
                self.assertIsNone(
                    variant_dispatch._declared_literals(
                        ast.parse(source).body[0].value
                    )
                )

    def test_a_nested_display_contributes_its_string_elements(self):
        display = ast.parse(
            '(("alpha", lambda member: member), ("beta", 1))'
        ).body[0].value
        self.assertEqual(
            variant_dispatch._word_display(display, 2),
            frozenset({"alpha", "beta"}),
        )

    def test_display_words_read_nested_displays_and_strings_only(self):
        display = ast.parse(
            "('alpha', ('beta', [1, {'gamma'}]), b'delta')"
        ).body[0].value
        self.assertEqual(
            variant_dispatch._display_words(display),
            ["alpha", "beta", "gamma"],
        )

    def test_a_display_compared_with_an_expression_is_its_own_set(self):
        subjects: dict[str, set[str]] = {}
        displays: list[frozenset[str]] = []
        compare = ast.parse('load() in ("alpha", "beta")').body[0].value
        variant_dispatch._compare_literals(compare, subjects, displays)
        self.assertEqual(subjects, {})
        self.assertEqual(displays, [frozenset({"alpha", "beta"})])
        self.assertEqual(
            variant_dispatch._vocabulary_literals(subjects, displays),
            frozenset({"alpha", "beta"}),
        )

    def test_a_case_pattern_with_an_as_name_keeps_its_literal(self):
        tree = ast.parse("match kind:\n    case \"alpha\" as name:\n        pass\n")
        pattern = tree.body[0].cases[0].pattern
        self.assertEqual(
            variant_dispatch._pattern_literals(pattern), {"alpha"}
        )

    def test_the_literal_handlers_read_their_node_kinds(self):
        subjects: dict[str, set[str]] = {}
        displays: list[frozenset[str]] = []
        compare = ast.parse('kind == "alpha"').body[0].value
        match = ast.parse(
            'match kind:\n    case "beta":\n        pass\n'
        ).body[0]
        selection = ast.parse('{"gamma": 1, "delta": 2}[kind]').body[0].value
        variant_dispatch._compare_literals(compare, subjects, displays)
        variant_dispatch._match_into(match, subjects, displays)
        variant_dispatch._selection_into(selection, subjects, displays)
        self.assertEqual(displays[-2:], [frozenset({"beta"}), frozenset({"gamma", "delta"})])


class ReaderHelperTests(VariantCase):
    def test_python_reader_pieces(self):
        source = (
            'TABLE = ("alpha", "beta")\n'
            "\n"
            "\n"
            "def first(kind):\n"
            '    if kind == "alpha":\n'
            "        return 1\n"
            '    if kind == "beta":\n'
            "        return 2\n"
            "    return 0\n"
        )
        tree = ast.parse(source)
        first = tree.body[1]
        self.assertEqual(
            variant_dispatch._function_literals(first),
            frozenset({"alpha", "beta"}),
        )
        selection = ast.parse('{"alpha": 1, "beta": 2}[kind]').body[0].value
        display, key = variant_dispatch._selection_parts(selection)
        self.assertEqual(ast.unparse(display), '{\'alpha\': 1, \'beta\': 2}')
        self.assertEqual(ast.unparse(key), "kind")
        call = ast.parse('{"alpha": 1}.get(kind)').body[0].value
        display, key = variant_dispatch._selection_parts(call)
        self.assertEqual(ast.unparse(display), "{'alpha': 1}")
        self.assertEqual(ast.unparse(key), "kind")
        self.assertEqual(variant_dispatch._selection_parts(ast.Name(id="x")),
                         (None, None))
        compare = ast.parse('kind in ("alpha", "beta")').body[0].value
        subjects: dict[str, set[str]] = {}
        displays: list[frozenset[str]] = []
        self.assertTrue(variant_dispatch._display_sets(
            compare.left, compare.comparators[0], subjects, displays
        ))
        self.assertEqual(subjects[ast.dump(compare.left)], {"alpha", "beta"})
        pattern = ast.parse(
            'match kind:\n    case "alpha" | "beta":\n        pass\n'
        ).body[0].cases[0].pattern
        self.assertEqual(
            variant_dispatch._or_pattern_literals(pattern),
            {"alpha", "beta"},
        )
        owners = variant_dispatch._python_owners("pkg/app.py", source)
        self.assertEqual(
            [(owner.name, owner.kind) for owner in owners],
            [("TABLE", "table"), ("first", "function")],
        )

    def test_owner_collection_qualifies_functions_through_classes(self):
        source = (
            "def top(kind):\n"
            '    if kind == "alpha":\n'
            "        return 1\n"
            '    if kind == "beta":\n'
            "        return 2\n"
            "    return 0\n"
            "class Thing:\n"
            "    def method(self):\n"
            "        return 1\n"
            "    class Inner:\n"
            "        def deep(self):\n"
            "            return 2\n"
        )
        owners: list[variant_dispatch.Owner] = []
        variant_dispatch._collect_owners(
            ast.parse(source).body, "", "pkg/app.py", owners
        )
        self.assertEqual(
            [
                (
                    owner.path,
                    owner.name,
                    owner.kind,
                    owner.start_line,
                    owner.end_line,
                )
                for owner in owners
            ],
            [
                ("pkg/app.py", "top", "function", 1, 6),
                ("pkg/app.py", "Thing.method", "function", 8, 9),
                (
                    "pkg/app.py",
                    "Thing.Inner.deep",
                    "function",
                    11,
                    12,
                ),
            ],
        )
        self.assertEqual(owners[0].literals, frozenset({"alpha", "beta"}))


    def test_vocabulary_grouping_and_findings(self):
        def owner(name: str, literals: set[str]) -> Any:
            return variant_dispatch.Owner(
                "pkg/app.py", name, "function", 1, 2, frozenset(literals)
            )

        owners = [
            owner("first", {"alpha", "beta"}),
            owner("second", {"alpha", "beta"}),
            owner("third", {"gamma", "delta"}),
        ]
        pairs = variant_dispatch._linked_pairs(owners)
        self.assertEqual(pairs, [(0, 1)])
        groups = variant_dispatch._groups(owners)
        self.assertEqual(
            [[item.name for item in group] for group in groups],
            [["first", "second"]],
        )
        self.assertEqual(
            variant_dispatch._shared_literals(groups[0]),
            ["alpha", "beta"],
        )
        finding = variant_dispatch._vsd_finding(groups[0])
        self.assertIn('VSD variant-dispatch: "alpha", "beta"', finding.subject)
        candidates = variant_dispatch._candidate_findings(owners, [])
        self.assertEqual(len(candidates), 1)
        spec = variant_dispatch.VariantSpec("changed", "HEAD")
        with mock.patch.object(variant_dispatch, "_touched", return_value=True):
            self.assertEqual(
                len(variant_dispatch._changed_candidates(
                    spec, object(), candidates
                )),
                1,
            )

    def test_trial_reader_pieces(self):
        tree = ast.parse(TRIAL_OR)
        functions = variant_dispatch._module_functions(tree)
        self.assertEqual(
            set(functions), {"read_json", "read_csv", "load"}
        )
        self.assertEqual(
            {node.name for node in variant_dispatch._all_functions(tree)},
            {"read_json", "read_csv", "load"},
        )
        self.assertEqual(
            variant_dispatch._format_literals(tree), {"json", "csv"}
        )
        load = functions["load"]
        self.assertEqual(
            len(variant_dispatch._or_chain(
                load.body[0].value, functions
            )),
            1,
        )
        self.assertEqual(
            len(variant_dispatch._chains(load.body, functions)), 1
        )
        self.assertEqual(
            [block[0].lineno for block in variant_dispatch._blocks(load)],
            [13],
        )
        guard_tree = ast.parse(TRIAL_GUARD)
        guard_functions = variant_dispatch._module_functions(guard_tree)
        guard_load = guard_functions["load"]
        guard = guard_load.body[1]
        self.assertEqual(
            variant_dispatch._guard_name(guard.test), "result"
        )
        self.assertEqual(
            variant_dispatch._assigned_call(
                guard_load.body[0], guard_functions
            )[0],
            "result",
        )
        self.assertEqual(
            len(variant_dispatch._chains(
                guard_load.body, guard_functions
            )),
            1,
        )
        try_tree = ast.parse(TRIAL_TRY)
        try_functions = variant_dispatch._module_functions(try_tree)
        try_load = try_functions["load"]
        self.assertEqual(
            len(variant_dispatch._chains(
                try_load.body, try_functions
            )),
            1,
        )
        span = variant_dispatch._caller_span("pkg/app.py", load)
        self.assertEqual((span.name, span.start_line), ("load", 12))
        first = functions["read_json"]
        second = functions["read_csv"]
        argument = ast.parse("read_json(value)").body[0].value.args[0]
        self.assertIsNotNone(variant_dispatch._trial_finding(
            span, first, second, argument, frozenset({"json", "csv"})
        ))
        self.assertIsNone(variant_dispatch._trial_finding(
            span, first, second, argument, frozenset({"alpha", "beta"})
        ))
        self.assertEqual(
            len(variant_dispatch._python_trials("pkg/app.py", TRIAL_OR)), 1
        )
        self.assertEqual(
            variant_dispatch._python_trials("pkg/app.py", PY_COMPARE_ONE),
            [],
        )

    def test_trial_flow_helpers(self):
        tree = ast.parse(
            "def f(flag):\n    if flag:\n        return 1\n    return 0\n"
        )
        function = tree.body[0]
        self.assertEqual(
            [block[0].lineno for block in variant_dispatch._blocks(function)],
            [2, 3],
        )
        body = function.body[0].body
        self.assertIs(variant_dispatch._statement_list(body), body)
        self.assertIsNone(variant_dispatch._statement_list([]))
        self.assertIsNone(
            variant_dispatch._statement_list([ast.Name(id="x")])
        )
        self.assertEqual(
            [
                block[0].lineno
                for block in variant_dispatch._child_blocks(
                    function.body[0]
                )
            ],
            [3],
        )
        self.assertEqual(
            list(variant_dispatch._child_blocks([1, ast.Name(id="x")])),
            [],
        )
        guard_tree = ast.parse(TRIAL_GUARD)
        guard_functions = variant_dispatch._module_functions(guard_tree)
        guard_load = guard_functions["load"]
        self.assertEqual(
            len(variant_dispatch._guard_chain(
                guard_load.body, 0, guard_functions
            )),
            1,
        )
        try_tree = ast.parse(TRIAL_TRY)
        try_functions = variant_dispatch._module_functions(try_tree)
        try_load = try_functions["load"]
        self.assertEqual(
            len(variant_dispatch._try_chain(
                try_load.body[0], try_functions
            )),
            1,
        )
        or_tree = ast.parse(TRIAL_OR)
        or_functions = variant_dispatch._module_functions(or_tree)
        or_load = or_functions["load"]
        chain = variant_dispatch._chains(
            or_load.body, or_functions
        )[0]
        span = variant_dispatch._caller_span("pkg/app.py", or_load)
        seen: set[tuple[tuple[str, str], str]] = set()
        self.assertIsNotNone(variant_dispatch._new_trial(
            seen, span, chain, frozenset({"json", "csv"})
        ))
        self.assertIsNone(variant_dispatch._new_trial(
            seen, span, chain, frozenset({"json", "csv"})
        ))
        first, second, argument = chain
        self.assertTrue(variant_dispatch._same_call(
            first, argument, second, argument
        ))
        self.assertFalse(variant_dispatch._same_call(
            first, argument, first, argument
        ))
        guard_body = variant_dispatch._guard_body(guard_load.body[1])
        self.assertIs(guard_body, guard_load.body[1].body[0])
        self.assertIsNone(variant_dispatch._guard_body(
            ast.parse("if flag:\n    pass\nelse:\n    pass\n").body[0]
        ))
        self.assertEqual(
            variant_dispatch._guard_assignment(
                guard_load.body, 0, guard_functions
            ),
            variant_dispatch._assigned_call(
                guard_load.body[0], guard_functions
            ),
        )
        self.assertIsNone(variant_dispatch._guard_assignment(
            guard_load.body, 1, guard_functions
        ))
        fallback = variant_dispatch._guard_fallback(
            guard_load.body[1].body[0], "result", guard_functions
        )
        self.assertEqual(
            fallback,
            variant_dispatch._assigned_call(
                guard_load.body[1].body[0], guard_functions
            )[1],
        )
        self.assertIsNone(variant_dispatch._guard_fallback(
            guard_load.body[1].body[0], "other", guard_functions
        ))
        self.assertTrue(variant_dispatch._returns_name(
            guard_load.body[2], "result"
        ))
        self.assertFalse(variant_dispatch._returns_name(
            guard_load.body[2], "other"
        ))
        self.assertIsNone(variant_dispatch._single_return([], try_functions))
        self.assertEqual(
            variant_dispatch._single_return(
                try_load.body[0].body, try_functions
            ),
            variant_dispatch._module_call(
                try_load.body[0].body[0].value, try_functions
            ),
        )
        self.assertEqual(
            variant_dispatch._matching_calls(
                (first, argument), (second, argument)
            ),
            chain,
        )
        handler = variant_dispatch._single_handler(try_load.body[0])
        self.assertIs(handler, try_load.body[0].handlers[0])
        self.assertIsNone(variant_dispatch._single_handler(
            ast.parse("if flag:\n    pass\n").body[0]
        ))


    def test_the_adapter_measure_step(self):
        self.add_file("pkg/app.py", PY_COMPARE_ONE)
        context = SimpleNamespace(
            root=self.repo,
            check=SimpleNamespace(
                spec=variant_dispatch.VariantSpec("tree", "HEAD")
            ),
            config=None,
            files=None,
            classes=None,
            base_override=None,
        )
        with mock.patch(
            "quality_gate.checks._select_files",
            return_value=(["pkg/app.py"], []),
        ):
            candidates, count, base = variant_dispatch._measure(context)
        self.assertEqual((candidates, count, base), ([], 1, None))


class TrialTests(VariantCase):
    def assert_trial(
        self,
        source: str,
        argument: str = "value",
        first: str = "read_json",
        second: str = "read_csv",
    ) -> None:
        self.add_file("pkg/app.py", source)
        findings = self.rejected()
        self.assertEqual(len(findings), 1, findings)
        self.assertEqual(
            findings[0]["subject"],
            f"TRIAL variant-dispatch: pkg/app.py:12 load tries {first} then "
            f"{second} on {argument}; select the reader from the table that "
            "names the formats, by the record's declared format, instead of "
            "trying each.",
        )

    def test_f_or_g_is_a_finding(self):
        self.assert_trial(TRIAL_OR)

    def test_assignment_then_none_guard_is_a_finding(self):
        self.assert_trial(TRIAL_GUARD)

    def test_assignment_then_not_guard_is_a_finding(self):
        self.assert_trial(TRIAL_NOT)

    def test_try_then_handler_is_a_finding(self):
        self.assert_trial(TRIAL_TRY)

    def test_the_harness_guard_shape_is_a_finding(self):
        self.assert_trial(
            TRIAL_HARNESS,
            argument="records",
            first="dsh_run_values",
            second="codex_run_values",
        )

    def test_a_discarded_or_chain_is_not_a_finding(self):
        self.add_file("pkg/app.py", TRIAL_OR_DISCARDED)
        self.accepted()

    def test_a_discarded_guard_chain_is_not_a_finding(self):
        self.add_file("pkg/app.py", TRIAL_GUARD_DISCARDED)
        self.accepted()

    def test_a_discarded_try_chain_is_not_a_finding(self):
        self.add_file("pkg/app.py", TRIAL_TRY_DISCARDED)
        self.accepted()

    def test_an_overwritten_guard_is_not_a_finding(self):
        self.add_file("pkg/app.py", TRIAL_GUARD_TWO)
        self.accepted()

    def test_a_guard_body_of_two_statements_is_not_a_finding(self):
        self.add_file(
            "pkg/app.py",
            TRIAL_HEADER
            + "def load(value):\n"
            "    result = read_json(value)\n"
            "    if result is None:\n"
            "        fallback = read_csv(value)\n"
            "        result = fallback\n"
            "    return result\n",
        )
        self.accepted()

    def test_a_guard_with_an_else_is_not_a_finding(self):
        self.add_file("pkg/app.py", TRIAL_GUARD_ELSE)
        self.accepted()

    def test_statements_that_are_not_consecutive_are_not_a_finding(self):
        self.add_file("pkg/app.py", TRIAL_NOT_CONSECUTIVE)
        self.accepted()

    def test_an_overwritten_try_handler_is_not_a_finding(self):
        self.add_file("pkg/app.py", TRIAL_OVERWRITTEN_TRY)
        self.accepted()

    def test_an_or_chain_of_three_calls_is_not_a_finding(self):
        self.add_file(
            "pkg/app.py",
            TRIAL_HEADER
            + "def load(value):\n"
            "    return read_json(value) or read_csv(value) or read_json(value)\n",
        )
        self.accepted()

    def test_a_table_without_the_name_token_is_not_a_finding(self):
        self.add_file(
            "pkg/app.py", TRIAL_OR.replace(
                'FORMATS = ("json", "csv")', 'FORMATS = ("alpha", "beta")'
            ),
        )
        self.accepted()

    def test_different_return_annotations_are_not_a_finding(self):
        self.add_file(
            "pkg/app.py", TRIAL_OR.replace(
                "def read_csv(value) -> str:", "def read_csv(value) -> int:"
            ),
        )
        self.accepted()

    def test_different_first_arguments_are_not_a_finding(self):
        self.add_file(
            "pkg/app.py", TRIAL_OR.replace(
                "read_json(value) or read_csv(value)",
                "read_json(value) or read_csv(other)",
            ),
        )
        self.accepted()


if __name__ == "__main__":
    unittest.main()
