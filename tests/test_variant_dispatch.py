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

SHELL_CASE = """\
#!/bin/sh
first() {
    case "$1" in
        alpha|beta) echo one ;;
        *) echo other ;;
    esac
}

second() {
    case "$1" in
        alpha|beta) echo two ;;
    esac
}
"""

SHELL_CASE_ONE = """\
#!/bin/sh
first() {
    case "$1" in
        alpha|beta) echo one ;;
    esac
}
"""

SHELL_TEST = """\
#!/bin/sh
first() {
    if [[ $FORMAT == alpha ]]; then
        echo one
    fi
    if [[ $FORMAT == beta ]]; then
        echo two
    fi
}

second() {
    if [ "$FORMAT" = alpha ]; then
        echo three
    fi
    if [[ ${FORMAT:-} != beta ]]; then
        echo four
    fi
}
"""

SHELL_TEST_ONE = """\
#!/bin/sh
first() {
    if [[ $FORMAT == alpha ]]; then
        echo one
    fi
    if [[ $FORMAT == beta ]]; then
        echo two
    fi
}
"""

SHELL_CASE_SEPARATE_ARMS = """\
#!/bin/sh
first() {
    case "$1" in
        alpha) echo one ;;
        beta) echo two ;;
    esac
}
"""

SHELL_CASE_SEVERAL = """\
#!/bin/sh
first() {
    case "$1" in
        alpha|beta|gamma) echo one ;;
        *) echo other ;;
    esac
}
"""

SHELL_CASE_QUOTED = """\
#!/bin/sh
first() {
    case "$1" in
        "alpha type"|'beta type') echo one ;;
        *) echo other ;;
    esac
}
"""

SHELL_COMMENTS = """\
#!/bin/sh
reader() {
    case "$1" in
        # alpha|beta) echo commented ;;
        *) echo other ;;
    esac
    # if [[ $FORMAT == alpha ]]; then echo one; fi
    # if [[ $FORMAT == beta ]]; then echo two; fi
}
"""

SHELL_HEREDOC = """\
#!/bin/sh
reader() {
    cat <<EOF
case "$1" in
alpha) echo one ;;
beta) echo two ;;
esac
if [[ $FORMAT == alpha ]]; then echo one; fi
if [[ $FORMAT == beta ]]; then echo two; fi
EOF
    cat <<-END
alpha) echo one ;;
beta) echo two ;;
END
    cat <<'SQ'
alpha) echo one ;;
beta) echo two ;;
SQ
    cat <<"DQ"
alpha) echo one ;;
beta) echo two ;;
DQ
}
"""

PY_QUOTED = """\
def first(kind):
    if kind == "alpha type":
        return 1
    if kind == "beta type":
        return 2
    return 0
"""

SHELL_ARRAY = "#!/bin/sh\nFORMATS=(alpha beta)\nOTHER=(alpha beta)\n"
SHELL_ARRAY_ONE = "#!/bin/sh\nFORMATS=(alpha beta)\n"

SHELL_TOP_LEVEL = """\
#!/bin/sh
case "$1" in
    alpha|beta) echo top ;;
esac
"""

SHELL_FUNCTION = """\
#!/bin/sh
reader() {
    case "$1" in
        alpha|beta) echo reader ;;
    esac
}
"""

PY_AND_SHELL = """\
def dispatch(kind):
    if kind == "alpha":
        return 1
    if kind == "beta":
        return 2
    return 0
"""

PY_AND_SHELL_SH = """\
#!/bin/sh
reader() {
    case "$1" in
        alpha|beta) echo ok ;;
    esac
    return 0
}
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
TRIAL_GUARD_RETURN = TRIAL_HEADER + """\
def load(value):
    result = read_json(value)
    if result is None:
        return read_csv(value)
    return result
"""
TRIAL_TRY_ASSIGN = TRIAL_HEADER + """\
def load(value):
    try:
        result = read_json(value)
    except ValueError:
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
TRIAL_STALE_GUARD = TRIAL_HEADER + """\
def load(value):
    result = read_json(value)
    if result is None:
        result = read_csv(value)
    result = None
    return result
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


class ShellTests(VariantCase):
    def setUp(self) -> None:
        super().setUp()
        self.write_config(variant_config(extra=SHELL_RULE))

    def test_two_shell_functions_with_case_patterns_are_a_finding(self):
        self.add_file("run.sh", SHELL_CASE)
        finding = self.rejected()[0]
        self.assertEqual(len(finding["measurement"]["owners"]), 2)

    def test_one_shell_function_is_not_a_finding(self):
        self.add_file("run.sh", SHELL_CASE_ONE)
        self.accepted()

    def test_separate_case_arms_contribute_each_pattern(self):
        self.add_file("pkg/app.py", PY_AND_SHELL)
        self.add_file("run.sh", SHELL_CASE_SEPARATE_ARMS)
        finding = self.rejected()[0]
        self.assertEqual(
            finding["measurement"]["literals"], ["alpha", "beta"]
        )

    def test_an_arm_with_several_patterns_contributes_all_of_them(self):
        self.add_file("pkg/app.py", PY_AND_SHELL)
        self.add_file("run.sh", SHELL_CASE_SEVERAL)
        finding = self.rejected()[0]
        self.assertEqual(
            finding["measurement"]["literals"], ["alpha", "beta"]
        )

    def test_quoted_case_words_with_spaces_are_literals(self):
        self.add_file("pkg/app.py", PY_QUOTED)
        self.add_file("run.sh", SHELL_CASE_QUOTED)
        finding = self.rejected()[0]
        self.assertEqual(
            finding["measurement"]["literals"],
            ["alpha type", "beta type"],
        )

    def test_comments_are_never_read(self):
        self.add_file("pkg/app.py", PY_AND_SHELL)
        self.add_file("run.sh", SHELL_COMMENTS)
        self.accepted()

    def test_here_document_bodies_are_never_read(self):
        self.add_file("pkg/app.py", PY_AND_SHELL)
        self.add_file("run.sh", SHELL_HEREDOC)
        self.accepted()

    def test_shell_tests_group_by_the_normalised_subject(self):
        self.add_file("run.sh", SHELL_TEST)
        finding = self.rejected()[0]
        self.assertEqual(finding["measurement"]["literals"], ["alpha", "beta"])

    def test_one_shell_test_owner_is_not_a_finding(self):
        self.add_file("run.sh", SHELL_TEST_ONE)
        self.accepted()

    def test_two_top_level_arrays_are_a_finding(self):
        self.add_file("run.sh", SHELL_ARRAY)
        finding = self.rejected()[0]
        self.assertEqual(
            [owner["kind"] for owner in finding["measurement"]["owners"]],
            ["table", "table"],
        )

    def test_one_top_level_array_is_not_a_finding(self):
        self.add_file("run.sh", SHELL_ARRAY_ONE)
        self.accepted()

    def test_top_level_statements_are_one_owner_read_by_another_file(self):
        self.add_file("top.sh", SHELL_TOP_LEVEL)
        self.add_file("reader.sh", SHELL_FUNCTION)
        finding = self.rejected()[0]
        kinds = sorted(
            owner["kind"] for owner in finding["measurement"]["owners"]
        )
        self.assertEqual(kinds, ["function", "top level"])

    def test_a_python_owner_and_a_shell_owner_are_one_finding(self):
        self.add_file("pkg/app.py", PY_AND_SHELL)
        self.add_file("run.sh", PY_AND_SHELL_SH)
        finding = self.rejected()[0]
        self.assertEqual(len(finding["measurement"]["owners"]), 2)
        paths = {
            owner["path"] for owner in finding["measurement"]["owners"]
        }
        self.assertEqual(paths, {"pkg/app.py", "run.sh"})


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
        spec = policy.load_config(self.repo).checks[VARIANT_CHECK].spec
        self.assertEqual((spec.scope, spec.base), ("tree", "HEAD"))

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

    def test_a_shell_file_is_a_suffix_or_a_shell_shebang(self):
        self.add_file("plain.sh", "#!/bin/sh\ntrue\n")
        self.add_file("script", "#!/usr/bin/env bash\ntrue\n")
        self.add_file("python-script", "#!/usr/bin/env python3\nprint(1)\n")
        self.assertTrue(variant_dispatch._is_shell_program(self.repo, "plain.sh"))
        self.assertTrue(variant_dispatch._is_shell_program(self.repo, "script"))
        self.assertFalse(
            variant_dispatch._is_shell_program(self.repo, "python-script")
        )


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

    def test_shell_reader_pieces(self):
        self.assertEqual(
            variant_dispatch._shell_code('echo "a # b" # alpha').strip(),
            'echo "a # b"',
        )
        self.assertEqual(
            variant_dispatch._readable_lines([
                "cat <<EOF",
                "alpha",
                "EOF",
                "echo x # beta",
            ]),
            ["cat <<EOF", "", "", "echo x "],
        )
        self.assertEqual(
            variant_dispatch._case_pattern_literals([
                'case "$1" in',
                "    alpha) echo one ;;",
                "    beta) echo two ;;",
                "esac",
            ]),
            {"alpha", "beta"},
        )
        lines = ["reader() {", "    case \"$1\" in", "}", "x=1"]
        blocks = variant_dispatch._shell_blocks(lines)
        self.assertEqual(
            [(block.name, block.first, block.last) for block in blocks],
            [("reader", 0, 2)],
        )
        self.assertEqual(
            variant_dispatch._top_level_indexes(blocks, len(lines)), [3]
        )
        arrays = variant_dispatch._array_owners(
            "run.sh", ["FORMATS=(alpha beta)"], [0]
        )
        self.assertEqual(
            [(owner.name, owner.literals) for owner in arrays],
            [("FORMATS", frozenset({"alpha", "beta"}))],
        )
        owners = variant_dispatch._shell_owners(
            "run.sh", SHELL_CASE_ONE
        )
        self.assertEqual(
            [(owner.name, owner.kind) for owner in owners],
            [("first", "function"), ("<module>", "top level")],
        )

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
        self.assertEqual(len(variant_dispatch._or_chains(load, functions)), 1)
        self.assertEqual(
            len(variant_dispatch._or_chain(
                load.body[0].value, functions
            )),
            1,
        )
        guard_tree = ast.parse(TRIAL_GUARD)
        guard_functions = variant_dispatch._module_functions(guard_tree)
        guard_load = guard_functions["load"]
        self.assertEqual(
            [name for _guard, name in variant_dispatch._guards(guard_load)],
            ["result"],
        )
        guard = variant_dispatch._guards(guard_load)[0][0]
        _line, _name, (callee, argument) = variant_dispatch._assign_calls(
            guard_load, guard_functions
        )[0]
        self.assertEqual(
            len(variant_dispatch._matching_actions(
                variant_dispatch._call_actions(guard, guard_functions),
                callee,
                argument,
            )),
            1,
        )
        self.assertEqual(
            len(variant_dispatch._guard_chains(guard_load, guard_functions)),
            1,
        )
        try_tree = ast.parse(TRIAL_TRY)
        try_functions = variant_dispatch._module_functions(try_tree)
        try_load = try_functions["load"]
        self.assertEqual(
            len(variant_dispatch._try_chains(try_load, try_functions)), 1
        )
        rebound = ast.parse(
            "def f():\n    value = 1\n    value = 2\n    return value\n"
        ).body[0]
        self.assertTrue(
            variant_dispatch._rebound_between(rebound, "value", 2, 4)
        )
        self.assertFalse(
            variant_dispatch._rebound_between(rebound, "value", 3, 4)
        )
        returned = ast.parse(
            "def f():\n    value = 1\n    return value\n"
        ).body[0]
        self.assertTrue(variant_dispatch._later_return(returned, "value", 2))
        self.assertFalse(variant_dispatch._later_return(returned, "value", 3))
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
    def assert_trial(self, source: str, argument: str = "value") -> None:
        self.add_file("pkg/app.py", source)
        findings = self.rejected()
        self.assertEqual(len(findings), 1, findings)
        self.assertEqual(
            findings[0]["subject"],
            "TRIAL variant-dispatch: pkg/app.py:12 load tries read_json then "
            f"read_csv on {argument}; select the reader from the table that "
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

    def test_a_guard_that_returns_the_fallback_is_a_finding(self):
        self.assert_trial(TRIAL_GUARD_RETURN)

    def test_a_try_that_assigns_the_chain_returned_later_is_a_finding(self):
        self.assert_trial(TRIAL_TRY_ASSIGN)

    def test_a_discarded_or_chain_is_not_a_finding(self):
        self.add_file("pkg/app.py", TRIAL_OR_DISCARDED)
        self.accepted()

    def test_a_discarded_guard_chain_is_not_a_finding(self):
        self.add_file("pkg/app.py", TRIAL_GUARD_DISCARDED)
        self.accepted()

    def test_a_discarded_try_chain_is_not_a_finding(self):
        self.add_file("pkg/app.py", TRIAL_TRY_DISCARDED)
        self.accepted()

    def test_a_guard_value_rebound_before_the_return_is_not_a_finding(self):
        self.add_file("pkg/app.py", TRIAL_STALE_GUARD)
        self.accepted()

    def test_the_same_chain_twice_reports_one_finding(self):
        self.add_file(
            "pkg/app.py",
            TRIAL_HEADER
            + "def load(value):\n"
            "    return read_json(value) or read_csv(value) or read_json(value)\n",
        )
        self.assertEqual(len(self.rejected()), 1)

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
