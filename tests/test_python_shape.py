"""Tests for the python_shape adapter: its four rules, keys, scope and messages."""
from __future__ import annotations

import subprocess
import unittest
from pathlib import Path
from typing import Any

from support import BASE_CONFIG, FixtureCase, _add_check_to_class, output

from quality_gate import policy


SHAPE_TABLE = (
    "\n[checks.shape]\n"
    'adapter = "python_shape"\n'
    "tier = 1\n"
    'enforcement = "enforced"\n'
    'scope = "changed"\n'
    'base = "HEAD^"\n'
    'crap_check = "crap"\n'
)

TEST_CHECK = (
    "\n[checks.tests]\n"
    'adapter = "python_tests"\n'
    "tier = 1\n"
    'enforcement = "enforced"\n'
    'run = ["{python}", "-m", "unittest", "discover", "-s", "tests"]\n'
    'tests_pattern = "^Ran ([0-9]+) tests? in"\n'
)

CRAP_CHECK = (
    "\n[checks.crap]\n"
    'adapter = "python_crap"\n'
    "tier = 1\n"
    'enforcement = "enforced"\n'
    'requires = "tests"\n'
    "threshold = 6\n"
)


def shape_config(*, extra: str = "", table: str = SHAPE_TABLE) -> str:
    text = _add_check_to_class(BASE_CONFIG, "python", "shape")
    return text + TEST_CHECK + CRAP_CHECK + table + extra


# A base function with CC 7: a for, three ifs, an elif and a while.
COMPLEX_BASE = """\
def process(items, flag):
    total = 0
    for item in items:
        if flag:
            if item > 0:
                total += item
            elif item < 0:
                total -= item
            else:
                total += 1
        else:
            if item:
                total += 2
            while total > 100:
                total -= 10
    return total
"""

# CPF: the CRAP-impossible function pays off with an untested single-use helper.
CPF_FRAGMENT = """\
def process(items, flag):
    total = 0
    for item in items:
        total += _step(item, flag)
    return total


def _step(item, flag):
    if flag:
        return _signed(item)
    return 2 if item else 0


def _signed(item):
    if item > 0:
        return item
    if item < 0:
        return -item
    return 1
"""

# The QF12 shape: the same split, and every helper has a direct test.
QF12_TEST = """\
import sys
import unittest

sys.path.insert(0, ".")

from pkg.app import _signed, _step


class SplitTests(unittest.TestCase):
    def test_step(self):
        self.assertEqual(_step(1, False), 2)

    def test_signed(self):
        self.assertEqual(_signed(-2), -2)
"""

# PTW-SU: the added render_json is one call, one call site and untested.
PTW_BASE = """\
import json


def main(data):
    text = json.dumps(data)
    return text
"""

PTW_WRAPPED = """\
import json


def main(data):
    return render_json(data)


def render_json(data):
    return json.dumps(data, indent=2, sort_keys=True)
"""

PTW_TEST = """\
import sys
import unittest

sys.path.insert(0, ".")

from pkg.app import render_json


class WrapperTests(unittest.TestCase):
    def test_json(self):
        self.assertEqual(render_json({"a": 1}), '{\\\\n  "a": 1\\\\n}')
"""

# LTC: two added functions that are alpha-renamed duplicates below 50 tokens.
LTC_DUPLICATE = """\
def chip_class(lane: dict) -> str:
    window = "chip--peak" if lane.get("window") == "peak" else "chip--off"
    fill = "chip--working" if lane.get("working") else "chip--idle"
    return f"chip {window} {fill}"


def lane_class(lane: dict) -> str:
    window = "lane--peak" if lane.get("window") == "peak" else "lane--off"
    fill = " lane--working" if lane.get("working") else " lane--idle"
    return f"lane {window}{fill}"
"""

# The report's judged false positive: 29 shared tokens at similarity 0.967.
LTC_NEAR_MISS = """\
def _codex_payload(record):
    if not isinstance(record, dict):
        return None
    payload = record.get("payload")
    return payload if isinstance(payload, dict) else record


def _top_usage(record):
    if not isinstance(record, dict):
        return None
    usage = record.get("usage")
    return usage if isinstance(usage, dict) else None
"""

# A table-driven refactor: the decisions leave the function for one data table.
TABLE_BASE = """\
def label(kind):
    if kind == "a":
        return "alpha"
    if kind == "b":
        return "beta"
    if kind == "c":
        return "gamma"
    if kind == "d":
        return "delta"
    if kind == "e":
        return "epsilon"
    if kind == "f":
        return "zeta"
    return "unknown"
"""

TABLE_REFACTOR = """\
LABELS = {
    "a": "alpha",
    "b": "beta",
    "c": "gamma",
    "d": "delta",
    "e": "epsilon",
    "f": "zeta",
}


def label(kind):
    return LABELS.get(kind, "unknown")
"""

# A decision function with tests, plus a thin adapter that also has a test.
DECISION_AND_ADAPTER = """\
def decide(kind):
    if kind == "a":
        return 1
    if kind == "b":
        return 2
    if kind == "c":
        return 3
    if kind == "d":
        return 4
    if kind == "e":
        return 5
    if kind == "f":
        return 6
    return 0


def parse(text):
    return decide(text)
"""

DECISION_TEST = """\
import sys
import unittest

sys.path.insert(0, ".")

from pkg.app import decide, parse


class DecisionTests(unittest.TestCase):
    def test_decide(self):
        self.assertEqual(decide("a"), 1)

    def test_parse(self):
        self.assertEqual(parse("a"), 1)
"""


def chain_module(links: int) -> str:
    """A dispatcher plus LINKS single-caller functions, each with real work."""
    lines = ["def run(value):", "    first = value + 1", "    return _chain_1(first)", ""]
    for index in range(1, links + 1):
        lines.extend([
            "",
            f"def _chain_{index}(value):",
            "    total = value * 2",
            (
                f"    return _chain_{index + 1}(total)"
                if index < links else "    return total"
            ),
        ])
    return "\n".join(lines) + "\n"


class ShapeCase(FixtureCase):
    """A fixture repository whose last commit is the change under test."""

    def setUp(self) -> None:
        super().setUp()
        self.write_config(shape_config())

    def base_commit(self, files: dict[str, str] | None = None) -> None:
        for relative, content in (files or {}).items():
            self.add_file(relative, content)
        self.commit_all("base")

    def commit(self, files: dict[str, str]) -> None:
        for relative, content in files.items():
            self.add_file(relative, content)
        self.commit_all("change")

    def run_shape(self) -> tuple[Any, dict[str, Any], dict[str, Any]]:
        result, document = self.run_json("--only", "shape")
        return result, document, self.check_by_id(document, "shape")

    def rejected(self) -> dict[str, Any]:
        """Run the check and return the single finding it must report."""
        result, document, check = self.run_shape()
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(document["decision"], "rejected")
        self.assertEqual(len(check["findings"]), 1, check["findings"])
        return check["findings"][0]

    def accepted(self) -> dict[str, Any]:
        result, _document, check = self.run_shape()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(check["outcome"], "pass")
        self.assertEqual(check["findings"], [])
        return check

    def errored(self) -> tuple[dict[str, Any], dict[str, Any]]:
        result, document, check = self.run_shape()
        self.assertEqual(result.returncode, 2, output(result))
        self.assertEqual(document["decision"], "error")
        self.assertEqual(check["outcome"], "error")
        return document, check


class RuleTests(ShapeCase):
    def test_a_crap_payoff_fragmentation_fails(self) -> None:
        self.base_commit({"pkg/app.py": COMPLEX_BASE})
        self.commit({"pkg/app.py": CPF_FRAGMENT})
        finding = self.rejected()
        self.assertIn("CPF pkg/app.py:process CC 7 -> 2", finding["subject"])
        self.assertIn("helper pkg/app.py:_step (1 call site, no direct test", finding["subject"])
        self.assertIn("limit 6 CC", finding["subject"])
        self.assertEqual(finding["measurement"]["rule"], "CPF")
        self.assertEqual(finding["measurement"]["cc_before"], 7)
        self.assertEqual(finding["measurement"]["cc_after"], 2)
        self.assertEqual(finding["measurement"]["limit"], 6)
        self.assertEqual(finding["location"], "pkg/app.py:1-5")

    def test_the_qf12_split_with_tested_helpers_passes(self) -> None:
        self.base_commit({"pkg/app.py": COMPLEX_BASE})
        self.commit({"pkg/app.py": CPF_FRAGMENT, "tests/test_app.py": QF12_TEST})
        check = self.accepted()
        self.assertEqual(check["measurement"]["added"], 2)

    def test_a_pass_through_wrapper_with_one_untested_call_site_fails(self) -> None:
        self.base_commit({"pkg/app.py": PTW_BASE})
        self.commit({"pkg/app.py": PTW_WRAPPED})
        finding = self.rejected()
        subject = finding["subject"]
        self.assertTrue(
            subject.startswith("PTW-SU pkg/app.py:render_json -> json.dumps"), subject
        )
        self.assertIn("forwards data, 2 constants, 1 call site, no direct test", subject)
        self.assertIn("limit 1 call site with no direct test", subject)
        self.assertEqual(finding["measurement"]["forwarded"], ["data"])
        self.assertEqual(finding["measurement"]["constants"], 2)
        self.assertEqual(finding["location"], "pkg/app.py:8-9")

    def test_a_wrapper_with_a_direct_test_passes(self) -> None:
        self.base_commit({"pkg/app.py": PTW_BASE})
        self.commit({"pkg/app.py": PTW_WRAPPED, "tests/test_app.py": PTW_TEST})
        self.accepted()

    def test_a_wrapper_with_a_second_caller_passes(self) -> None:
        self.base_commit({"pkg/app.py": PTW_BASE})
        self.commit({
            "pkg/app.py": PTW_WRAPPED + (
                "\n\ndef other(data):\n    return render_json(data)\n"
            ),
        })
        self.accepted()

    def test_a_chain_deeper_than_the_limit_fails(self) -> None:
        self.base_commit({"pkg/chain.py": "VALUE = 0\n"})
        self.commit({"pkg/chain.py": chain_module(6)})
        finding = self.rejected()
        subject = finding["subject"]
        self.assertTrue(subject.startswith("SCC chain depth 7: "), subject)
        self.assertIn("pkg/chain.py:run -> pkg/chain.py:_chain_1", subject)
        self.assertIn("pkg/chain.py:_chain_6", subject)
        self.assertIn("limit 6; expected at most 6 consecutive single-caller", subject)
        self.assertEqual(finding["measurement"]["chain_depth"], 7)
        self.assertEqual(finding["measurement"]["limit"], 6)
        self.assertEqual(len(finding["locations"]), 7)

    def test_a_chain_at_the_limit_passes(self) -> None:
        self.base_commit({"pkg/chain.py": "VALUE = 0\n"})
        self.commit({"pkg/chain.py": chain_module(5)})
        check = self.accepted()
        self.assertEqual(check["measurement"]["added"], 6)

    def test_a_shattered_duplicate_fails(self) -> None:
        self.base_commit({"pkg/app.py": "VALUE = 0\n"})
        self.commit({"pkg/app.py": LTC_DUPLICATE})
        finding = self.rejected()
        self.assertIn(
            "LTC pkg/app.py:chip_class <-> pkg/app.py:lane_class", finding["subject"]
        )
        self.assertIn("34 normalised tokens, similarity 1.00", finding["subject"])
        self.assertIn("limit 30-49 tokens at similarity 0.95", finding["subject"])
        self.assertEqual(finding["measurement"]["longest"], 34)
        self.assertEqual(finding["measurement"]["ratio"], 1.0)
        self.assertEqual(len(finding["locations"]), 2)

    def test_a_near_duplicate_at_lower_similarity_passes(self) -> None:
        self.base_commit({"pkg/app.py": "VALUE = 0\n"})
        self.commit({"pkg/app.py": LTC_NEAR_MISS})
        check = self.accepted()
        self.assertEqual(check["measurement"]["added"], 2)

    def test_a_table_driven_refactor_passes(self) -> None:
        self.base_commit({"pkg/app.py": TABLE_BASE})
        self.commit({"pkg/app.py": TABLE_REFACTOR})
        self.accepted()

    def test_a_tested_decision_function_and_tested_adapter_pass(self) -> None:
        self.base_commit()
        self.commit({
            "pkg/app.py": DECISION_AND_ADAPTER,
            "tests/test_app.py": DECISION_TEST,
        })
        check = self.accepted()
        self.assertEqual(check["measurement"]["added"], 2)

    def test_the_same_split_with_a_second_caller_passes(self) -> None:
        self.base_commit({"pkg/app.py": COMPLEX_BASE})
        self.commit({
            "pkg/app.py": CPF_FRAGMENT + (
                "\n\ndef summary(items, flag):\n    return _step(items, flag)\n"
            ),
        })
        self.accepted()


class ScopeTests(ShapeCase):
    def test_changed_scope_ignores_an_untouched_long_chain(self) -> None:
        self.base_commit({"pkg/chain.py": chain_module(6)})
        self.commit({"notes.md": "# the chain is untouched\n"})
        check = self.accepted()
        self.assertEqual(check["measurement"], {"functions": 0, "added": 0})

    def test_tree_scope_reports_the_untouched_long_chain(self) -> None:
        self.write_config(shape_config(table=SHAPE_TABLE.replace(
            'scope = "changed"', 'scope = "tree"'
        )))
        self.base_commit({"pkg/chain.py": chain_module(6)})
        self.commit({"notes.md": "# the chain is untouched\n"})
        finding = self.rejected()
        self.assertTrue(
            finding["subject"].startswith("SCC chain depth 7: "),
            finding["subject"],
        )
        self.assertEqual(finding["measurement"]["chain_depth"], 7)

    def test_a_changed_scope_run_without_a_python_change_passes(self) -> None:
        self.base_commit()
        self.commit({"notes.md": "# change\n"})
        self.accepted()

    def test_changed_scope_measures_the_functions_the_diff_touches(self) -> None:
        self.base_commit({"pkg/app.py": PTW_BASE})
        self.commit({"pkg/app.py": PTW_BASE + "\n\ndef extra():\n    return 2\n"})
        check = self.accepted()
        self.assertEqual(check["measurement"], {"functions": 1, "added": 1})


class InputTests(ShapeCase):
    def test_a_quoted_diff_path_is_an_error_not_a_skip(self) -> None:
        self.add_file('pkg/odd"name.py', "VALUE = 1\n")
        self.commit_all("base")
        self.add_file('pkg/odd"name.py', "VALUE = 2\n")
        self.commit_all("change")
        document, _check = self.errored()
        self.assertIn("quoted path", document["error"])

    def test_an_unparsable_changed_file_is_an_error_not_a_skip(self) -> None:
        self.base_commit()
        self.commit({"pkg/broken.py": "def broken(:\n"})
        document, _check = self.errored()
        self.assertIn("cannot parse pkg/broken.py", document["error"])


class KeyTests(ShapeCase):
    def run_config(self, extra: str = "", table: str = SHAPE_TABLE) -> Any:
        self.write_config(shape_config(extra=extra, table=table))
        return self.run_qg("check", "--only", "shape")

    def assert_config_error(self, result: Any, needle: str) -> None:
        self.assertEqual(result.returncode, 2, output(result))
        self.assertIn(needle, output(result))

    def test_invalid_scope_is_a_configuration_error(self) -> None:
        result = self.run_config(table=SHAPE_TABLE.replace(
            'scope = "changed"', 'scope = "repository"'
        ))
        self.assert_config_error(result, "checks.shape.scope")
        self.assertIn("changed, tree", output(result))

    def test_missing_base_is_a_configuration_error(self) -> None:
        result = self.run_config(table=SHAPE_TABLE.replace('base = "HEAD^"\n', ""))
        self.assert_config_error(result, "checks.shape.base")
        self.assertIn("missing", output(result))

    def test_a_base_that_is_not_a_revision_is_an_error_not_a_skip(self) -> None:
        result = self.run_config(table=SHAPE_TABLE.replace(
            'base = "HEAD^"', 'base = "no-such-revision"'
        ))
        self.assert_config_error(result, "no-such-revision")
        self.assertIn("no such revision", output(result))
        self.assertNotIn("skipped", output(result))

    def test_max_chain_must_be_a_positive_integer(self) -> None:
        for value in ("0", '"seven"', "true", "2.5"):
            with self.subTest(value=value):
                result = self.run_config(extra=f"max_chain = {value}\n")
                self.assert_config_error(result, "checks.shape.max_chain")

    def test_clone_min_tokens_must_be_between_20_and_49(self) -> None:
        for value in ("19", "50", "0", '"thirty"'):
            with self.subTest(value=value):
                result = self.run_config(extra=f"clone_min_tokens = {value}\n")
                self.assert_config_error(result, "checks.shape.clone_min_tokens")

    def test_clone_similarity_must_be_a_finite_number_from_0_5_to_1(self) -> None:
        for value in ("0.49", "1.01", "nan", "inf", '"high"'):
            with self.subTest(value=value):
                result = self.run_config(extra=f"clone_similarity = {value}\n")
                self.assert_config_error(result, "checks.shape.clone_similarity")

    def test_crap_check_must_name_a_declared_check(self) -> None:
        result = self.run_config(table=SHAPE_TABLE.replace(
            'crap_check = "crap"', 'crap_check = "mystery"'
        ))
        self.assert_config_error(result, "crap_check 'mystery'")
        self.assertIn("unknown check", output(result))

    def test_crap_check_must_name_a_crap_check(self) -> None:
        result = self.run_config(table=SHAPE_TABLE.replace(
            'crap_check = "crap"', 'crap_check = "smoke"'
        ))
        self.assert_config_error(result, "crap_check 'smoke'")
        self.assertIn("got a command check", output(result))

    def test_an_unknown_key_is_a_configuration_error(self) -> None:
        result = self.run_config(extra="max_chain_length = 3\n")
        self.assert_config_error(result, "checks.shape.max_chain_length")
        self.assertIn("allowed keys", output(result))

    def test_the_policy_keys_are_parsed_with_their_defaults(self) -> None:
        spec = policy.load_config(self.repo).checks["shape"].spec
        self.assertEqual(
            (spec.scope, spec.base, spec.max_chain, spec.clone_min_tokens,
             spec.clone_similarity, spec.crap_check),
            ("changed", "HEAD^", 6, 30, 0.95, "crap"),
        )


MUTATIONS = {
    "CPF": ("before > limit >= after", "False"),
    "PTW-SU": (
        "_single_call_site(data, function) is not None\n"
        "        and not _has_direct_test(data, function)",
        "False",
    ),
    "SCC": ("depth > limit", "False"),
    "LTC": (
        "spec.clone_min_tokens <= run <= CLONE_MAX_TOKENS\n"
        "        and ratio >= spec.clone_similarity",
        "False",
    ),
}


class MutationTests(ShapeCase):
    """Removing one rule's condition lets that rule's failing fixture pass."""

    def mutated_gate(self, rule: str) -> Path:
        gate = self.fixture_gate()
        module = gate / "quality_gate" / "python_shape.py"
        source = module.read_text(encoding="utf-8")
        old, new = MUTATIONS[rule]
        self.assertEqual(source.count(old), 1, f"{rule}: target is not unique")
        module.write_text(source.replace(old, new), encoding="utf-8")
        return gate

    def run_copy(self, gate: Path) -> subprocess.CompletedProcess[str]:
        argv = [
            *self.python_prefix(), str(gate / "qg.py"),
            "--repo", str(self.repo), "check", "--only", "shape",
        ]
        return subprocess.run(
            argv, cwd=str(self.repo), env=self.env(), capture_output=True,
            text=True, encoding="utf-8", timeout=120,
        )

    def assert_rule_dies_without_its_condition(self, rule: str) -> None:
        result = self.run_copy(self.gate)
        self.assertEqual(result.returncode, 1, output(result))
        mutated = self.run_copy(self.mutated_gate(rule))
        self.assertEqual(mutated.returncode, 0, output(mutated))
        self.assertIn("check: partial run passed", mutated.stdout)

    def test_cpf_needs_its_condition(self) -> None:
        self.base_commit({"pkg/app.py": COMPLEX_BASE})
        self.commit({"pkg/app.py": CPF_FRAGMENT})
        self.assert_rule_dies_without_its_condition("CPF")

    def test_ptw_su_needs_its_condition(self) -> None:
        self.base_commit({"pkg/app.py": PTW_BASE})
        self.commit({"pkg/app.py": PTW_WRAPPED})
        self.assert_rule_dies_without_its_condition("PTW-SU")

    def test_scc_needs_its_condition(self) -> None:
        self.base_commit({"pkg/chain.py": "VALUE = 0\n"})
        self.commit({"pkg/chain.py": chain_module(6)})
        self.assert_rule_dies_without_its_condition("SCC")

    def test_ltc_needs_its_condition(self) -> None:
        self.base_commit({"pkg/app.py": "VALUE = 0\n"})
        self.commit({"pkg/app.py": LTC_DUPLICATE})
        self.assert_rule_dies_without_its_condition("LTC")


if __name__ == "__main__":
    unittest.main()
