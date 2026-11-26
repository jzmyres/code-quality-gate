"""Tests for the python_shape adapter: its five rules, keys, scope and messages.

COMPLEX_BASE has complexity seven from a for, three ifs, an elif and
a while. CPF_FRAGMENT splits it into a complexity-three function and
a helper. QF12_TEST describes the same split with direct tests for
every helper. SINGLE_USE_METHOD_CALLER gives a new method and static
method one caller each in another module and no direct tests.

The PTW fixtures distinguish an untested render_json with one call and
one call site from bodies where no parameter can be forwarded, a call
is only one of two statements, the callee is the wrapper's own
parameter, or only one of two parameters is forwarded. SHIPPED_WRAPPER
adds an untested single-use pass-through wrapper. SHIPPED_FILES covers
every shipped inventory rule.

The LTC fixtures cover alpha-renamed duplicates below 50 tokens,
reverse alphabetical source order, a reported false positive with
30 shared tokens at similarity 0.938, 18 shared tokens at full
similarity below the minimum, 62 shared tokens above the cap covered
by the clone check, and a nested function that duplicates its
enclosing function. TABLE_BASE moves the decisions into one data table.
DECISION_AND_ADAPTER directly tests the decision function and its
thin adapter.

For UNCALLED, DISPATCH_BASE routes three decisions through subscripts
with no named call sites. KEY_BASE passes a function as a keyword
value, TABLE_REGISTERED registers one in a descriptor table, and
DEAD_FUNCTION gives a function with no references. SINGLEDISPATCH_BASE
registers a handler by decorator, GETATTR_BASE names a method only in
an attribute string, and CALLED_BASE includes one direct call and an
edited existing function. Editing an existing function does not make
it an addition.

Each mutant deletes one guard and names both the original fragment
and its replacement. A missing target string proves nothing, so each
mutation test runs the gate against a real fixture twice.
"""
from __future__ import annotations

import ast
import io
import subprocess
import tokenize
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock

from support import (
    BASE_CONFIG,
    GATE,
    FixtureCase,
    _add_check_to_class,
    assert_base_measurement,
    baseline_text,
    output,
)

from quality_gate import policy, python_shape
from quality_gate.files import SHEBANG_LIMIT, DiffBase, is_python_blob
from quality_gate.python_shape import (
    CallSite,
    Diff,
    FileIndex,
    ShapeFunction,
    ShapeInput,
    ShapeSpec,
    _added_functions,
    _added_lines,
    _after_path,
    _arguments,
    _base_complexities,
    _before_complexities,
    _body_value,
    _chain_edges,
    _clone_finding,
    _clone_pairs,
    _collect_definitions,
    _cpf_findings,
    _cpf_targets,
    _crap_limit,
    _diff_lines,
    _file_index,
    _findings,
    _forwarded,
    _hunks,
    _inside_test,
    _longest_common_run,
    _measured_paths,
    _normalised_tokens,
    _own_names,
    _references,
    _scan_files,
    _shape_input,
    _test_functions,
    _token_text,
    _touched,
    _tree_selection,
    _uncalled_findings,
    _uses,
    _wrapper,
    _wrapper_call,
)


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

CPF_FRAGMENT = """\
def process(items, flag):
    total = 0
    if not items:
        return total
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

PTW_ZERO_PARAMETER = """\
import json


def main():
    return render_json()


def render_json():
    return json.dumps("value", indent=2, sort_keys=True)


main()
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

PTW_MORE_THAN_ONE_STATEMENT = """\
import json


def main(data):
    return render_json(data)


def render_json(data):
    log(data)
    return json.dumps(data, indent=2, sort_keys=True)
"""

PTW_PARAMETER_CALLEE = """\
def main(render):
    return render(render)


def render(render):
    return render(render)


main(render)
"""

PTW_UNFORWARDED = """\
import json


def main(data, flag):
    return render_json(data, flag)


def render_json(data, flag):
    return json.dumps(data, indent=2)
"""

LTC_DUPLICATE = """\
def chip_class(lane: dict) -> str:
    window = "chip--peak" if lane.get("window") == "peak" else "chip--off"
    fill = "chip--working" if lane.get("working") else "chip--idle"
    return f"chip {window} {fill}"


def lane_class(lane: dict) -> str:
    window = "lane--peak" if lane.get("window") == "peak" else "lane--off"
    fill = " lane--working" if lane.get("working") else " lane--idle"
    return f"lane {window}{fill}"


chip_class({})
lane_class({})
"""

LTC_REVERSED = """\
def lane_class(lane: dict) -> str:
    window = "lane--peak" if lane.get("window") == "peak" else "lane--off"
    fill = "lane--working" if lane.get("working") else "lane--idle"
    return f"lane {window}{fill}"


def chip_class(lane: dict) -> str:
    window = "chip--peak" if lane.get("window") == "peak" else "chip--off"
    fill = "chip--working" if lane.get("working") else "chip--idle"
    return f"chip {window} {fill}"


lane_class({})
chip_class({})
"""

LTC_NEAR_MISS = """\
def _codex_payload(record):
    if not isinstance(record, dict):
        return None
    payload = record.get("payload")
    if not isinstance(payload, dict):
        return None
    return payload


def _top_usage(record):
    if not isinstance(record, dict):
        return None
    payload = record.get("payload")
    if not isinstance(payload, dict):
        return None
    for key in record:
        if key.startswith("usage"):
            return record[key]
    return None


_codex_payload({})
_top_usage({})
"""

LTC_BELOW_MINIMUM = """\
def first_label(lane):
    window = "peak" if lane else "off"
    fill = "working" if lane else "idle"
    return window + fill


def second_label(lane):
    window = "peak" if lane else "off"
    fill = "working" if lane else "idle"
    return window + fill


first_label({})
second_label({})
"""

LTC_ABOVE_CAP = """\
def _first_class(record):
    window = record.get("window")
    fill = record.get("fill")
    if window == "peak":
        window = "chip--peak"
    elif window == "off":
        window = "chip--off"
    else:
        window = "chip--idle"
    if fill == "working":
        fill = "chip--working"
    elif fill == "idle":
        fill = "chip--idle"
    else:
        fill = "chip--off"
    return window + fill


def _second_class(record):
    window = record.get("window")
    fill = record.get("fill")
    if window == "peak":
        window = "lane--peak"
    elif window == "off":
        window = "lane--off"
    else:
        window = "lane--idle"
    if fill == "working":
        fill = "lane--working"
    elif fill == "idle":
        fill = "lane--idle"
    else:
        fill = "lane--off"
    return window + fill


_first_class({})
_second_class({})
"""

LTC_ANCESTOR = """\
def outer(lane):
    def inner(lane):
        window = "chip--peak" if lane.get("window") == "peak" else "chip--off"
        fill = "chip--working" if lane.get("working") else "chip--idle"
        return f"chip {window} {fill}"
    return inner(lane)


outer({})
"""

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


DISPATCH_BASE = """\
def run(kind):
    return kind
"""

DISPATCH_TABLE = """\
def run(kind):
    return TABLE[kind](kind)


def _run_files(kind):
    return ["files", kind]


def _run_tool(kind):
    return ["tool", kind]


def _run_check(kind):
    return ["check", kind]


TABLE = {"files": _run_files, "tool": _run_tool, "check": _run_check}
"""

DISPATCH_TEST = """\
import sys
import unittest

sys.path.insert(0, ".")

from pkg.app import _run_check, _run_files, _run_tool


class DispatchTests(unittest.TestCase):
    def test_each_entry_is_a_callable(self):
        self.assertEqual(
            [_run_files, _run_tool, _run_check],
            [_run_files, _run_tool, _run_check],
        )
"""

KEY_BASE = """\
def ordered(items):
    return sorted(items)
"""

KEY_PASSED = """\
def ordered(items):
    return sorted(items, key=by_length)


def by_length(text):
    return len(text)
"""

KEY_TEST = """\
import sys
import unittest

sys.path.insert(0, ".")

from pkg.app import by_length


class KeyTests(unittest.TestCase):
    def test_the_key_exists(self):
        self.assertIs(by_length, by_length)
"""

TABLE_REGISTERED = """\
def _files(kind):
    return kind


TABLE = {"files": _files}
"""

DEAD_FUNCTION = """\
def lonely(value):
    return 1 if value else 0
"""

DEAD_TEST = """\
import sys
import unittest

sys.path.insert(0, ".")

from pkg.app import lonely


class DeadTests(unittest.TestCase):
    def test_the_dead_function_exists(self):
        self.assertIs(lonely, lonely)
"""

SINGLEDISPATCH_BASE = """\
def entry(value):
    return render(value)
"""

SINGLEDISPATCH = """\
from functools import singledispatch


@singledispatch
def render(value):
    return [value]


@render.register
def _render_int(value):
    return "int"
"""

SINGLEDISPATCH_RENDER_TEST = """\
import sys
import unittest

sys.path.insert(0, ".")

from pkg.app import render


class RenderTests(unittest.TestCase):
    def test_the_renderer_exists(self):
        self.assertIs(render, render)
"""

SINGLEDISPATCH_TEST = """\
import sys
import unittest

sys.path.insert(0, ".")

from pkg.app import _render_int, render


class HandlerTests(unittest.TestCase):
    def test_the_handler_exists(self):
        self.assertIs(_render_int, _render_int)
        self.assertIs(render, render)
"""

GETATTR_BASE = """\
def dispatch(handler):
    return getattr(handler, "handle")
"""

GETATTR_ONLY = """\
class Handler:
    def handle(self):
        return 1
"""

GETATTR_TEST = """\
import sys
import unittest

sys.path.insert(0, ".")

from pkg.app import Handler


class HandlerTests(unittest.TestCase):
    def test_the_handler_exists(self):
        self.assertIs(Handler.handle, Handler.handle)
"""

SINGLE_USE_METHOD_CALLER = """\
from pkg.app import Registry


def use(value):
    registry = Registry()
    return registry.required(value) + Registry.dependency(value)
"""

SINGLE_USE_METHODS = """\
class Registry:
    def required(self, value):
        return value + 1

    @staticmethod
    def dependency(value):
        return value * 2
"""

SINGLE_USE_METHOD_TEST = """\
import sys
import unittest

sys.path.insert(0, ".")

from pkg.app import Registry


class RegistryTests(unittest.TestCase):
    def test_the_methods_exist(self):
        self.assertIs(Registry.required, Registry.required)
        self.assertIs(Registry.dependency, Registry.dependency)
"""

CALLED_BASE = """\
def entry(value):
    return value
"""

CALLED_BY_NAME = """\
def entry(value):
    return helper(value)


def helper(value):
    return value + 1
"""

EDITED_BASE = """\
def edited(value):
    return value
"""

EDITED = """\
def edited(value):
    if value:
        return value + 1
    return value
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
    lines.extend(["", "run(1)"])
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

    def names_test(self, *names: str) -> str:
        """A test module that directly names each given function."""
        checks = "\n".join(
            f"        self.assertIs({name}, {name})" for name in names
        )
        return (
            "import sys\nimport unittest\n\nsys.path.insert(0, \".\")\n\n"
            f"from pkg.app import {', '.join(names)}\n\n\n"
            "class NamingTests(unittest.TestCase):\n"
            "    def test_each_name(self):\n"
            f"{checks}\n"
        )

    def run_shape(
        self, env: dict[str, str] | None = None
    ) -> tuple[Any, dict[str, Any], dict[str, Any]]:
        result, document = self.run_json("--only", "shape", env=env)
        return result, document, self.check_by_id(document, "shape")

    def policy_base(self, revision: str = "HEAD^") -> dict[str, str]:
        """The measurement of the base the policy's revision resolves to."""
        return {
            "commit": self.git("rev-parse", revision).stdout.strip(),
            "source": "base",
        }

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

    def errored(
        self, env: dict[str, str] | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        result, document, check = self.run_shape(env)
        self.assertEqual(result.returncode, 2, output(result))
        self.assertEqual(document["decision"], "error")
        self.assertEqual(check["outcome"], "error")
        return document, check


class RuleTests(ShapeCase):
    def test_a_crap_payoff_fragmentation_fails(self) -> None:
        self.base_commit({"pkg/app.py": COMPLEX_BASE})
        self.commit({"pkg/app.py": CPF_FRAGMENT})
        finding = self.rejected()
        self.assertIn("CPF pkg/app.py:process CC 7 -> 3", finding["subject"])
        self.assertIn("helper pkg/app.py:_step (1 call site, no direct test", finding["subject"])
        self.assertIn("limit 6 CC", finding["subject"])
        self.assertEqual(finding["measurement"]["rule"], "CPF")
        self.assertEqual(finding["measurement"]["cc_before"], 7)
        self.assertEqual(finding["measurement"]["cc_after"], 3)
        self.assertEqual(finding["measurement"]["limit"], 6)
        self.assertEqual(finding["location"], "pkg/app.py:1-7")

    def test_the_qf12_split_with_tested_helpers_passes(self) -> None:
        self.base_commit({"pkg/app.py": COMPLEX_BASE})
        self.commit({"pkg/app.py": CPF_FRAGMENT, "tests/test_app.py": QF12_TEST})
        check = self.accepted()
        self.assertEqual(check["measurement"]["added"], 2)

    def test_a_pass_through_wrapper_with_one_untested_call_site_fails(self) -> None:
        self.base_commit({"pkg/app.py": PTW_BASE})
        self.commit({
            "pkg/app.py": PTW_WRAPPED,
            "tests/test_app.py": self.names_test("main"),
        })
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

    def test_a_wrapper_whose_body_is_more_than_one_statement_passes(self) -> None:
        self.base_commit({"pkg/app.py": PTW_BASE})
        self.commit({"pkg/app.py": PTW_MORE_THAN_ONE_STATEMENT})
        check = self.accepted()
        self.assertEqual(check["measurement"]["added"], 1)

    def test_a_wrapper_whose_callee_is_its_own_parameter_passes(self) -> None:
        self.base_commit({"pkg/app.py": PTW_BASE})
        self.commit({"pkg/app.py": PTW_PARAMETER_CALLEE})
        self.accepted()

    def test_a_wrapper_that_does_not_forward_every_parameter_passes(self) -> None:
        self.base_commit({"pkg/app.py": PTW_BASE})
        self.commit({
            "pkg/app.py": PTW_UNFORWARDED,
            "tests/test_app.py": self.names_test("main"),
        })
        self.accepted()

    def test_a_zero_parameter_function_is_not_a_pass_through_wrapper(self) -> None:
        self.base_commit({"pkg/app.py": PTW_BASE})
        self.commit({"pkg/app.py": PTW_ZERO_PARAMETER})
        self.accepted()

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
            "tests/test_app.py": self.names_test("other"),
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

    def test_a_clone_pair_is_reported_in_source_order(self) -> None:
        self.base_commit({"pkg/app.py": "VALUE = 0\n"})
        self.commit({"pkg/app.py": LTC_REVERSED})
        finding = self.rejected()
        self.assertIn(
            "LTC pkg/app.py:lane_class <-> pkg/app.py:chip_class",
            finding["subject"],
        )
        self.assertEqual(finding["measurement"]["first"], "pkg/app.py:lane_class")
        self.assertEqual(finding["measurement"]["second"], "pkg/app.py:chip_class")

    def test_a_near_duplicate_at_lower_similarity_passes(self) -> None:
        self.base_commit({"pkg/app.py": "VALUE = 0\n"})
        self.commit({"pkg/app.py": LTC_NEAR_MISS})
        check = self.accepted()
        self.assertEqual(check["measurement"]["added"], 2)

    def test_a_duplicate_below_the_token_minimum_passes(self) -> None:
        self.base_commit({"pkg/app.py": "VALUE = 0\n"})
        self.commit({"pkg/app.py": LTC_BELOW_MINIMUM})
        check = self.accepted()
        self.assertEqual(check["measurement"]["added"], 2)

    def test_a_duplicate_above_the_token_cap_passes(self) -> None:
        self.base_commit({"pkg/app.py": "VALUE = 0\n"})
        self.commit({"pkg/app.py": LTC_ABOVE_CAP})
        check = self.accepted()
        self.assertEqual(check["measurement"]["added"], 2)

    def test_a_duplicate_of_its_own_ancestor_passes(self) -> None:
        self.base_commit({"pkg/app.py": "VALUE = 0\n"})
        self.commit({"pkg/app.py": LTC_ANCESTOR})
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
            "tests/test_app.py": self.names_test("summary"),
        })
        self.accepted()


class SingleUseMethodTests(ShapeCase):
    """An added method with one caller and no direct test is refused."""

    def test_an_added_method_and_static_method_with_one_caller_fail(self) -> None:
        self.base_commit({"pkg/caller.py": SINGLE_USE_METHOD_CALLER})
        self.commit({"pkg/app.py": SINGLE_USE_METHODS})
        result, _document, check = self.run_shape()
        self.assertEqual(result.returncode, 1, output(result))
        subjects = [finding["subject"] for finding in check["findings"]]
        self.assertEqual(len(subjects), 2, subjects)
        for name in ("Registry.required", "Registry.dependency"):
            self.assertTrue(
                any(
                    subject.startswith(f"CPF pkg/app.py:{name} ")
                    for subject in subjects
                ),
                subjects,
            )

    def test_a_direct_test_naming_each_method_passes(self) -> None:
        self.base_commit({"pkg/caller.py": SINGLE_USE_METHOD_CALLER})
        self.commit({
            "pkg/app.py": SINGLE_USE_METHODS,
            "tests/test_app.py": SINGLE_USE_METHOD_TEST,
        })
        self.accepted()


class UncalledTests(ShapeCase):
    """An added or newly orphaned function needs an outside call or direct test."""

    def uncalled_subjects(self, check: dict[str, Any]) -> list[str]:
        return [finding["subject"] for finding in check["findings"]]

    def assert_uncalled(self, name: str) -> None:
        result, _document, check = self.run_shape()
        self.assertEqual(result.returncode, 1, output(result))
        subjects = self.uncalled_subjects(check)
        self.assertEqual(len(subjects), 1, subjects)
        self.assertTrue(
            subjects[0].startswith(f"UNCALLED pkg/app.py:{name} "), subjects
        )

    def test_orphan_from_deleted_caller_and_same_file_span(self) -> None:
        notes = "pkg/notes.py"
        archive = "pkg/archive"
        shifted = "pkg/shifted.py"
        removed = "pkg/removed.py"
        deleted_caller = "pkg/legacy"
        policy_caller = "pkg/commands-old"
        surviving_caller = "pkg/commands-still"
        moved_caller = "pkg/commands-moved"
        normalized_caller = "pkg/normalized.py"
        test_path = "tests/test_notes"
        definitions = {
            f"{archive}:Archive.archive_note": True,
            f"{notes}:from_policy": True,
            f"{notes}:retained": True,
            f"{notes}:relocated": True,
            f"{notes}:normalized": True,
            f"{notes}:covered": True,
            f"{notes}:already_unused": True,
            f"{shifted}:shifted": True,
            f"{shifted}:recursive_only": True,
            f"{removed}:removed": False,
        }
        self_calls = {f"{shifted}:shifted", f"{shifted}:recursive_only"}
        before = {
            deleted_caller: ("archive_note", "retained", "relocated", "normalized", "covered", "removed"),
            policy_caller: ("from_policy",),
            surviving_caller: ("retained", "relocated"),
            normalized_caller: ("normalized",),
            shifted: ("shifted",),
        }
        deletion_only = {
            path: calls for path, calls in before.items() if path not in (deleted_caller, policy_caller)
        }
        after_move = {
            surviving_caller: ("retained",), moved_caller: ("relocated",),
            normalized_caller: before[normalized_caller],
        }
        direct_tests = {"covered"}
        prior_names = set().union(*before.values())
        expected = []
        for after in (deletion_only, after_move):
            current_names = set().union(*after.values())
            expected.append({
                identity for identity, survives in definitions.items()
                if survives and (name := identity.rsplit(":", 1)[1].rsplit(".", 1)[-1])
                in prior_names and name not in current_names
                and name not in direct_tests
            })

        self.write_config(shape_config(extra="".join(
            f'\n[[rule]]\npattern = "{pattern}"\nclass = "python"\nreason = "suffixless Python"\n'
            for pattern in (f"{deleted_caller}*", "pkg/commands-*", archive, test_path)
        )))
        sources = {f"{deleted_caller}-stub": "#!/usr/bin/env python3\n"}
        for identity in definitions:
            path, qualified = identity.split(":")
            owner, _, name = qualified.rpartition(".")
            indent = "    " if owner else ""
            header = f"class {owner}:\n" if owner else ""
            value = f"{qualified}()" if identity in self_calls else "None"
            definition = f"{header}{indent}def {name}():\n{indent}    return {value}\n"
            sources[path] = sources.get(path, "") + definition
        for path, calls in before.items():
            prefix = "#!/usr/bin/env python3\n" if path == deleted_caller else ""
            spellings = (
                [name.replace("z", "\uff5a") for name in calls] if path == normalized_caller else calls
            )
            sources[path] = prefix + "".join(f"{name}()\n" for name in spellings) + sources.get(path, "")
        sources[test_path] = (
            "def test_covered():\n" + "".join(f"    {name}()\n" for name in sorted(direct_tests))
            + "\narchive_note()\n"
        )
        self.base_commit(sources)
        self.git("rm", "--", deleted_caller, policy_caller, removed)
        self.commit_all("remove the legacy caller and an obsolete definition")

        locations = {
            f"{archive}:Archive.archive_note": (archive, 2, 3),
            f"{notes}:from_policy": (notes, 1, 2),
            f"{shifted}:shifted": (shifted, 1, 3),
        }
        for moved, identities in enumerate(expected):
            if moved:
                for path, calls in after_move.items():
                    if calls != deletion_only.get(path):
                        self.add_file(path, "".join(f"{name}()\n" for name in calls))
                definition = sources[shifted].removeprefix("shifted()\n")
                definition = definition.replace("def recursive_only", "\n\n\ndef recursive_only")
                self.add_file(shifted, definition.replace("    return", "\n    return", 1))
            for override in ((), ("--base", "HEAD^")):
                with self.subTest(moved=bool(moved), base=override):
                    result, document = self.run_json("--only", "shape", *override)
                    self.assertEqual(result.returncode, 1, output(result))
                    self.assertEqual(document["decision"], "rejected")
                    check = self.check_by_id(document, "shape")
                    actual = [
                        (f'{item["measurement"]["file"]}:{item["measurement"]["name"]}', item)
                        for item in check["findings"] if item["measurement"]["rule"] == "UNCALLED"
                    ]
                    self.assertCountEqual([identity for identity, _ in actual], identities, output(result))
                    for identity, item in actual:
                        path, start, end = locations[identity]
                        self.assertEqual((item["value"], item["threshold"], item["blocking"]), (1, 0, True))
                        self.assertEqual(item["location"], f"{path}:{start}-{end}")
                        self.assertEqual(
                            item["locations"], [{"path": path, "start_line": start, "end_line": end}],
                        )
                    self.assertEqual(check["measurement"]["functions"], len(identities))
                    self.assertEqual(check["measurement"]["added"], 0)
                    base = self.policy_base()
                    if override:
                        base["source"] = "--base"
                        selected = check["selection"]["selected"]
                        self.assertEqual(selected[archive], "lost its last production call")
                        self.assertEqual(selected[notes], "lost its last production call")
                        if not moved:
                            self.assertEqual(set(selected), {archive, notes})
                    self.assertEqual(check["measurement"]["base"], base)

    def test_a_dispatch_table_of_uncalled_functions_is_refused(self) -> None:
        self.base_commit({"pkg/app.py": DISPATCH_BASE})
        self.commit({"pkg/app.py": DISPATCH_TABLE})
        result, _document, check = self.run_shape()
        self.assertEqual(result.returncode, 1, output(result))
        subjects = self.uncalled_subjects(check)
        self.assertEqual(len(subjects), 3, subjects)
        for name in ("_run_check", "_run_files", "_run_tool"):
            self.assertEqual(
                sum(
                    subject.startswith(f"UNCALLED pkg/app.py:{name} ")
                    for subject in subjects
                ),
                1,
                subjects,
            )
        finding = check["findings"][0]
        self.assertEqual(
            finding["measurement"],
            {
                "rule": "UNCALLED",
                "file": "pkg/app.py",
                "name": "_run_check",
                "call_sites": 0,
                "direct_test": False,
            },
        )
        self.assertIn(
            "expected a direct test, a call by name, or the decision kept as "
            "data in its one owner",
            finding["subject"],
        )

    def test_a_direct_test_naming_each_table_entry_passes(self) -> None:
        self.base_commit({"pkg/app.py": DISPATCH_BASE})
        self.commit({
            "pkg/app.py": DISPATCH_TABLE, "tests/test_app.py": DISPATCH_TEST,
        })
        check = self.accepted()
        self.assertEqual(check["measurement"]["added"], 3)

    def test_a_function_called_once_by_name_is_not_uncalled(self) -> None:
        self.base_commit({"pkg/app.py": CALLED_BASE})
        self.commit({"pkg/app.py": CALLED_BY_NAME})
        check = self.accepted()
        self.assertEqual(check["measurement"]["added"], 1)

    def test_a_function_only_passed_as_a_keyword_is_uncalled(self) -> None:
        self.base_commit({"pkg/app.py": KEY_BASE})
        self.commit({"pkg/app.py": KEY_PASSED})
        self.assert_uncalled("by_length")

    def test_a_function_only_registered_in_a_table_is_uncalled(self) -> None:
        self.base_commit({"pkg/app.py": "TABLE = {}\n"})
        self.commit({"pkg/app.py": TABLE_REGISTERED})
        self.assert_uncalled("_files")

    def test_a_dead_function_is_uncalled(self) -> None:
        self.base_commit()
        self.commit({"pkg/app.py": DEAD_FUNCTION})
        self.assert_uncalled("lonely")

    def test_a_direct_test_naming_a_dead_function_passes(self) -> None:
        self.base_commit()
        self.commit({
            "pkg/app.py": DEAD_FUNCTION, "tests/test_app.py": DEAD_TEST,
        })
        self.accepted()

    def test_a_singledispatch_handler_is_uncalled(self) -> None:
        self.base_commit({"pkg/driver.py": SINGLEDISPATCH_BASE})
        self.commit({
            "pkg/app.py": SINGLEDISPATCH,
            "tests/test_app.py": SINGLEDISPATCH_RENDER_TEST,
        })
        self.assert_uncalled("_render_int")

    def test_a_direct_test_naming_a_singledispatch_handler_passes(self) -> None:
        self.base_commit({"pkg/driver.py": SINGLEDISPATCH_BASE})
        self.commit({
            "pkg/app.py": SINGLEDISPATCH,
            "tests/test_app.py": SINGLEDISPATCH_TEST,
        })
        self.accepted()

    def test_a_getattr_only_method_is_uncalled(self) -> None:
        self.base_commit({"pkg/driver.py": GETATTR_BASE})
        self.commit({"pkg/app.py": GETATTR_ONLY})
        self.assert_uncalled("Handler.handle")

    def test_a_direct_test_naming_a_getattr_only_method_passes(self) -> None:
        self.base_commit({"pkg/driver.py": GETATTR_BASE})
        self.commit({
            "pkg/app.py": GETATTR_ONLY, "tests/test_app.py": GETATTR_TEST,
        })
        self.accepted()

    def test_a_direct_test_naming_the_passed_function_passes(self) -> None:
        self.base_commit({"pkg/app.py": KEY_BASE})
        self.commit({
            "pkg/app.py": KEY_PASSED, "tests/test_app.py": KEY_TEST,
        })
        check = self.accepted()
        self.assertEqual(check["measurement"]["added"], 1)

    def test_an_edited_existing_function_is_not_added(self) -> None:
        self.base_commit({"pkg/app.py": EDITED_BASE})
        self.commit({"pkg/app.py": EDITED})
        check = self.accepted()
        self.assertEqual(check["measurement"]["added"], 0)


class DiffBaseTests(ShapeCase):
    """QG_DIFF_BASE names the change, and the measurement says which one."""

    def setUp(self) -> None:
        super().setUp()
        self.write_config(shape_config(table=SHAPE_TABLE.replace(
            'base = "HEAD^"', 'base = "HEAD"'
        )))

    def override_base(self) -> str:
        return self.git("rev-parse", "HEAD").stdout.strip()

    def test_the_override_base_judges_a_split_the_policy_base_would_hide(self) -> None:
        self.base_commit({"pkg/app.py": COMPLEX_BASE})
        base = self.override_base()
        self.commit({"pkg/app.py": CPF_FRAGMENT})
        result, _document, check = self.run_shape(env={"QG_DIFF_BASE": base})
        self.assertEqual(result.returncode, 1, output(result))
        self.assertEqual(len(check["findings"]), 1, check["findings"])
        subject = check["findings"][0]["subject"]
        self.assertIn("CPF pkg/app.py:process CC 7 -> 3", subject)
        self.assertIn("helper pkg/app.py:_step", subject)
        assert_base_measurement(self, check, base, "QG_DIFF_BASE")

    def test_the_clean_tree_passes_without_the_variable(self) -> None:
        self.base_commit({"pkg/app.py": COMPLEX_BASE})
        self.commit({"pkg/app.py": CPF_FRAGMENT})
        check = self.accepted()
        assert_base_measurement(self, check, self.override_base(), "base")

    def test_the_same_split_with_a_test_naming_the_helper_passes(self) -> None:
        self.base_commit({"pkg/app.py": COMPLEX_BASE})
        base = self.override_base()
        self.commit({"pkg/app.py": CPF_FRAGMENT, "tests/test_app.py": QF12_TEST})
        result, _document, check = self.run_shape(env={"QG_DIFF_BASE": base})
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(check["outcome"], "pass")
        assert_base_measurement(self, check, base, "QG_DIFF_BASE")

    def test_an_empty_value_is_a_configuration_error_naming_it(self) -> None:
        self.base_commit({"pkg/app.py": COMPLEX_BASE})
        self.commit({"pkg/app.py": CPF_FRAGMENT})
        document, _check = self.errored(env={"QG_DIFF_BASE": ""})
        self.assertIn("QG_DIFF_BASE", document["error"])

    def test_an_unresolvable_value_is_a_configuration_error_naming_it(self) -> None:
        self.base_commit({"pkg/app.py": COMPLEX_BASE})
        self.commit({"pkg/app.py": CPF_FRAGMENT})
        document, _check = self.errored(env={"QG_DIFF_BASE": "no-such-revision"})
        self.assertIn("QG_DIFF_BASE", document["error"])
        self.assertIn("no-such-revision", document["error"])


class ScopeTests(ShapeCase):
    def test_changed_scope_ignores_an_untouched_long_chain(self) -> None:
        self.base_commit({"pkg/chain.py": chain_module(6)})
        self.commit({"notes.md": "# the chain is untouched\n"})
        check = self.accepted()
        self.assertEqual(
            check["measurement"],
            {"functions": 0, "added": 0, "base": self.policy_base()},
        )

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
        self.commit({
            "pkg/app.py": PTW_BASE + "\n\ndef extra():\n    return 2\n",
            "tests/test_app.py": self.names_test("extra"),
        })
        check = self.accepted()
        self.assertEqual(
            check["measurement"],
            {"functions": 1, "added": 1, "base": self.policy_base()},
        )

    def test_changed_scope_selects_a_deletion_inside_a_function(self) -> None:
        self.base_commit({
            "pkg/app.py": (
                "def process(value):\n"
                "    total = value + 1\n"
                "    total = total * 2\n"
                "    return total\n"
            ),
            "tests/test_app.py": self.names_test("process"),
        })
        self.commit({"pkg/app.py": (
            "def process(value):\n"
            "    total = value + 1\n"
            "    return total\n"
        )})
        check = self.accepted()
        self.assertEqual(check["measurement"]["functions"], 1)
        self.assertEqual(check["measurement"]["added"], 0)

    def test_changed_scope_ignores_a_moved_unchanged_function(self) -> None:
        both = (
            "def first(value):\n"
            "    return value + 1\n"
            "\n\n"
            "def second(value):\n"
            "    return value + 2\n"
        )
        moved = (
            "def second(value):\n"
            "    return value + 2\n"
            "\n\n"
            "def first(value):\n"
            "    return value + 1\n"
        )
        self.base_commit({
            "pkg/app.py": both,
            "tests/test_app.py": self.names_test("first", "second"),
        })
        self.commit({"pkg/app.py": moved})
        check = self.accepted()
        self.assertEqual(
            check["measurement"],
            {"functions": 0, "added": 0, "base": self.policy_base()},
        )

    def test_changed_scope_selects_a_renamed_function(self) -> None:
        self.base_commit({"pkg/app.py": (
            "def before(value):\n"
            "    return value + 1\n"
        )})
        self.commit({
            "pkg/app.py": (
                "def after(value):\n"
                "    return value + 1\n"
            ),
            "tests/test_app.py": self.names_test("after"),
        })
        check = self.accepted()
        self.assertEqual(check["measurement"]["functions"], 1)
        self.assertEqual(check["measurement"]["added"], 1)

    def test_changed_scope_selects_a_decorator_change(self) -> None:
        self.base_commit({"pkg/app.py": (
            "def marker(function):\n"
            "    return function\n"
            "\n\n"
            "def decorated(value):\n"
            "    return value + 1\n"
        )})
        self.commit({
            "pkg/app.py": (
                "def marker(function):\n"
                "    return function\n"
                "\n\n"
                "@marker\n"
                "def decorated(value):\n"
                "    return value + 1\n"
            ),
            "tests/test_app.py": self.names_test("decorated"),
        })
        check = self.accepted()
        self.assertEqual(check["measurement"]["functions"], 1)
        self.assertEqual(check["measurement"]["added"], 0)

    def test_changed_scope_selects_a_nested_function_change(self) -> None:
        self.base_commit({"pkg/app.py": (
            "def outer(value):\n"
            "    def inner(item):\n"
            "        return item + 1\n"
            "\n"
            "    return inner(value)\n"
        )})
        self.commit({
            "pkg/app.py": (
                "def outer(value):\n"
                "    def inner(item):\n"
                "        return item + 2\n"
                "\n"
                "    return inner(value)\n"
            ),
            "tests/test_app.py": self.names_test("outer"),
        })
        check = self.accepted()
        self.assertEqual(check["measurement"]["functions"], 2)
        self.assertEqual(check["measurement"]["added"], 0)

    def test_changed_scope_judges_only_the_added_functions(self) -> None:
        """Change every function in the chain without adding any of them."""
        base = chain_module(6)
        self.base_commit({"pkg/chain.py": base})
        edited = base.replace("first = value + 1", "first = value + 2").replace(
            "total = value * 2", "total = value * 3"
        )
        self.commit({"pkg/chain.py": edited})
        check = self.accepted()
        self.assertEqual(
            check["measurement"],
            {"functions": 7, "added": 0, "base": self.policy_base()},
        )


class CallSiteTests(ShapeCase):
    """A selected Python file counts its call sites whatever its name."""

    HELPER = "VALUE = 0\n"

    def suffixless_config(self) -> None:
        self.write_config(shape_config(extra=(
            "\n[[rule]]\n"
            'pattern = "pkg/helper"\n'
            'class = "python"\n'
            'reason = "a Python program without the suffix"\n'
        )))

    def caller(self) -> str:
        return (
            "#!/usr/bin/env python3\n\n"
            "from pkg.app import render_json\n"
            "# a caller in a selected Python file without the .py suffix\n"
            "print(render_json({}))\n"
        )

    def test_a_caller_without_the_suffix_is_a_second_call_site(self) -> None:
        """The diff touches only pkg/app.py.

        The existing caller contributes only a mention of render_json.
        """
        self.suffixless_config()
        self.base_commit({"pkg/app.py": PTW_BASE, "pkg/helper": self.caller()})
        self.commit({"pkg/app.py": PTW_WRAPPED})
        check = self.accepted()
        self.assertEqual(
            check["measurement"],
            {"functions": 2, "added": 1, "base": self.policy_base()},
        )

    def test_the_helper_without_the_caller_is_single_use(self) -> None:
        self.suffixless_config()
        self.base_commit({"pkg/app.py": PTW_BASE, "pkg/helper": self.HELPER})
        self.commit({"pkg/app.py": PTW_WRAPPED, "pkg/helper": self.HELPER})
        finding = self.rejected()
        self.assertEqual(finding["measurement"]["call_sites"], 1)
        self.assertEqual(finding["measurement"]["rule"], "PTW-SU")


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


def function_node(source: str) -> Any:
    """The first function definition of a source snippet."""
    return ast.parse(source).body[0]


SHAPE_SPEC = ShapeSpec("changed", "HEAD", 6, 30, 0.95, "crap")


def shape_function(
    source: str, *, cc: int = 1, path: str = "pkg/app.py"
) -> ShapeFunction:
    """One shape function built from a source snippet."""
    node = function_node(source)
    return ShapeFunction(
        identity=f"{path}:{node.name}",
        path=path,
        name=node.name,
        node=node,
        start_line=node.lineno,
        end_line=node.end_lineno or node.lineno,
        cc=cc,
        final_name=node.name,
    )


CPF_HELPER_SOURCE = {
    False: "def step(value):\n    return value\n",
    True: "class Registry:\n    def step(self, value):\n        return value\n",
}
CPF_CALL = {
    False: "step(value)",
    True: "Registry().step(value)",
}
CPF_IMPORT = {False: "step", True: "Registry"}


class ProductionCallerTests(unittest.TestCase):
    """CPF counts production call sites, not calls made from test files."""

    def helper(self, method: bool) -> ShapeFunction:
        source = CPF_HELPER_SOURCE[method]
        return _file_index("pkg/app.py", source).functions[-1]

    def caller_source(self, method: bool, count: int) -> str:
        call = CPF_CALL[method]
        blocks = [
            f"def use_{index}(value):\n    return {call}\n"
            for index in range(1, count + 1)
        ]
        return "\n\n".join(blocks) if blocks else "VALUE = 0\n"

    def direct_test(self, method: bool) -> str:
        name = CPF_IMPORT[method]
        reference = f"{name}.step" if method else name
        return (
            "import unittest\n\n"
            f"from pkg.app import {name}\n\n\n"
            "class DirectTests(unittest.TestCase):\n"
            "    def test_name(self):\n"
            f"        self.assertIs({reference}, {reference})\n"
        )

    def indirect_test(self, method: bool) -> str:
        name = CPF_IMPORT[method]
        call = CPF_CALL[method].replace("value", "1")
        return (
            "import unittest\n\n"
            f"from pkg.app import {name}\n\n\n"
            "def exercise(value):\n"
            f"    return {call}\n\n\n"
            "class ExerciseTests(unittest.TestCase):\n"
            "    def test_exercise(self):\n"
            "        self.assertTrue(exercise(1))\n"
        )

    def cpf_findings(
        self, method: bool, production: int, test_kind: str
    ) -> list[Any]:
        helper = self.helper(method)
        indexes = [
            _file_index(
                "pkg/caller.py", self.caller_source(method, production)
            )
        ]
        if test_kind == "direct":
            indexes.append(
                _file_index("tests/test_app.py", self.direct_test(method))
            )
        elif test_kind == "indirect":
            indexes.append(
                _file_index("tests/test_app.py", self.indirect_test(method))
            )
        calls, tests = _uses(indexes, {helper.final_name})
        data = ShapeInput(
            (helper,), {}, (helper,), (helper,), (), calls, tests, SHAPE_SPEC, 6,
        )
        return _cpf_findings(data)

    def test_cpf_counts_only_production_callers(self) -> None:
        for method in (False, True):
            for production in range(3):
                for test_kind in ("none", "indirect", "direct"):
                    expected = production == 1 and test_kind != "direct"
                    with self.subTest(
                        method=method,
                        production=production,
                        test_kind=test_kind,
                    ):
                        self.assertEqual(
                            len(self.cpf_findings(
                                method, production, test_kind
                            )),
                            int(expected),
                        )


class HelperTests(unittest.TestCase):
    """Direct tests of the adapter's small parsing steps."""

    def test_a_methods_receiver_is_not_an_own_parameter(self) -> None:
        node = function_node("def method(self, data, flag=1):\n    return data\n")
        self.assertEqual(_own_names(node), ["data", "flag"])
        plain = function_node("def plain(value, data):\n    return data\n")
        self.assertEqual(_own_names(plain), ["value", "data"])

    def test_a_body_is_its_one_expression_or_return(self) -> None:
        expression = function_node('def f(a):\n    """Doc."""\n    g(a)\n')
        self.assertIsInstance(_body_value(expression), ast.Call)
        returning = function_node("def f(a):\n    return g(a)\n")
        self.assertIsInstance(_body_value(returning), ast.Call)
        self.assertIsNone(_body_value(function_node("def f(a):\n    pass\n")))
        two = function_node("def f(a):\n    g(a)\n    return a\n")
        self.assertIsNone(_body_value(two))

    def test_a_wrapper_forwards_each_own_parameter_once(self) -> None:
        wrapper = _wrapper(function_node(
            "def f(data, flag):\n    return g(data, flag, 2)\n"
        ))
        self.assertEqual(wrapper.callee, "g")
        self.assertEqual(wrapper.forwarded, ("data", "flag"))
        self.assertEqual(wrapper.constants, 1)
        self.assertIsNone(_wrapper(function_node(
            "def f(data, flag):\n    return g(data)\n"
        )))

    def test_forwarded_values_are_the_own_names_and_constants(self) -> None:
        def values(source: str) -> list[ast.AST]:
            return ast.parse(source).body[0].value.args

        self.assertEqual(
            _forwarded(values("f(data, flag, 2)"), ["data", "flag"], 1),
            ["data", "flag"],
        )
        self.assertIsNone(
            _forwarded(values("f(data)"), ["data", "flag"], 0)
        )
        self.assertIsNone(_forwarded(values("f(data, data)"), ["data"], 0))
        self.assertIsNone(_forwarded(values("f(data, flag)"), ["data"], 0))

    def test_a_test_class_keeps_a_walk_inside_a_test(self) -> None:
        suite = ast.parse("class SpecialTests:\n    pass\n").body[0]
        other = ast.parse("class Helper:\n    pass\n").body[0]
        function = function_node("def plain(a):\n    return a\n")
        self.assertTrue(_inside_test(suite, False))
        self.assertTrue(_inside_test(other, True))
        self.assertFalse(_inside_test(other, False))
        self.assertFalse(_inside_test(function, False))

    def test_a_test_function_contributes_the_names_it_mentions(self) -> None:
        tree = ast.parse(
            "def helper():\n    return 1\n\n"
            "class Suite:\n    def test_one(self):\n        helper()\n"
        )
        found: set[str] = set()
        _test_functions(tree.body, False, found)
        self.assertEqual(found, {"helper"})

    def test_referenced_names_include_attributes(self) -> None:
        tree = ast.parse("value = holder.method\nother\n")
        self.assertEqual(
            _references(tree), {"value", "holder", "method", "other"}
        )

    def test_diff_headers_name_their_paths(self) -> None:
        self.assertEqual(_after_path("b/pkg/app.py"), "pkg/app.py")
        self.assertIsNone(_after_path("/dev/null"))
        with self.assertRaises(policy.GateError):
            _after_path('"pkg/odd name.py"')

    def test_hunk_headers_give_added_lines(self) -> None:
        self.assertEqual(list(_added_lines("@@ -1 +2,3 @@")), [2, 3, 4])
        self.assertEqual(list(_added_lines("@@ -0,0 +1 @@")), [1])

    def test_hunks_read_added_lines_and_skip_deleted_paths(self) -> None:
        raw = (
            b"+++ b/pkg/app.py\n@@ -1 +2,2 @@\n+x\n+y\n"
            b"+++ /dev/null\n@@ -4 +0,0 @@\n-x\n"
        )
        self.assertEqual(
            _hunks(raw),
            ({"pkg/app.py"}, {"pkg/app.py": {2, 3}}),
        )

    def test_arguments_include_keyword_values_and_reject_unpacking(self) -> None:
        call = ast.parse("f(data, flag=2)").body[0].value
        values = _arguments(call)
        self.assertEqual([ast.unparse(value) for value in values], ["data", "2"])
        self.assertIsNone(
            _arguments(ast.parse("f(data, **options)").body[0].value)
        )

    def test_wrapper_call_needs_a_named_callee_and_no_unpacking(self) -> None:
        wrapper = _wrapper_call(
            ast.parse("f(data, 2)").body[0].value, ["data"]
        )
        self.assertEqual(
            (wrapper.callee, wrapper.forwarded, wrapper.constants),
            ("f", ("data",), 1),
        )
        self.assertIsNone(_wrapper_call(
            ast.parse("f(data, **options)").body[0].value, ["data"]
        ))
        self.assertIsNone(_wrapper_call(
            ast.parse("f(data)").body[0].value, ["f"]
        ))

    def test_crap_limit_returns_the_named_threshold(self) -> None:
        config = SimpleNamespace(checks={
            "crap": SimpleNamespace(adapter="python_crap", threshold=4.5),
        })
        self.assertEqual(_crap_limit(config, SHAPE_SPEC), 4.5)
        with self.assertRaises(policy.GateError):
            _crap_limit(SimpleNamespace(checks={}), SHAPE_SPEC)

    def test_uses_filters_call_sites_and_collects_test_names(self) -> None:
        site = CallSite(
            "render_json", "pkg.helper.render_json", "pkg/helper.py", 3, "main"
        )
        other = CallSite(
            "other", "other", "pkg/helper.py", 4, "main"
        )
        indexes = [
            FileIndex((), (site, other), frozenset({"render_json"})),
            FileIndex((), (), frozenset({"helper"})),
        ]
        calls, tests = _uses(indexes, {"render_json"})
        self.assertEqual(calls, {"render_json": (site,)})
        self.assertEqual(tests, frozenset({"render_json", "helper"}))

    def test_measured_paths_keep_production_files_in_scope(self) -> None:
        diff = Diff(frozenset({"pkg/app.py"}), {}, frozenset())
        context = SimpleNamespace(config=None, check=None, files=[], classes={})
        selected = (["pkg/app.py", "tests/test_app.py", "pkg/other.py"], {})
        with mock.patch("quality_gate.checks._select_files", return_value=selected):
            self.assertEqual(
                _measured_paths(context, SHAPE_SPEC, diff),
                ["pkg/app.py"],
            )
            tree_spec = ShapeSpec("tree", "HEAD", 6, 30, 0.95, "crap")
            self.assertEqual(
                _measured_paths(context, tree_spec, diff),
                ["pkg/app.py", "pkg/other.py"],
            )

    def test_touched_compares_tree_whole_files_and_added_lines(self) -> None:
        function = shape_function("def f():\n    return 1\n")
        changed = Diff(
            frozenset({"pkg/app.py"}),
            {"pkg/app.py": frozenset({1})},
            frozenset(),
        )
        self.assertTrue(_touched(SHAPE_SPEC, changed, function))
        outside = Diff(
            frozenset({"pkg/app.py"}),
            {"pkg/app.py": frozenset({3})},
            frozenset(),
        )
        self.assertFalse(_touched(SHAPE_SPEC, outside, function))
        whole = Diff(frozenset({"pkg/app.py"}), {}, frozenset({"pkg/app.py"}))
        self.assertTrue(_touched(SHAPE_SPEC, whole, function))
        tree_spec = ShapeSpec("tree", "HEAD", 6, 30, 0.95, "crap")
        self.assertTrue(
            _touched(tree_spec, Diff(frozenset(), {}, frozenset()), function)
        )

    def test_cpf_targets_need_a_payoff_within_the_limit(self) -> None:
        paid = shape_function("def paid():\n    return 1\n", cc=2)
        still_complex = shape_function(
            "def still_complex():\n    return 2\n", cc=7
        )
        data = ShapeInput(
            (paid, still_complex),
            {"pkg/app.py": {paid.identity: 7, still_complex.identity: 7}},
            (), (), (), {}, frozenset(), SHAPE_SPEC, 6,
        )
        self.assertEqual(_cpf_targets(data), {paid.identity: (7, paid)})

    def test_chain_edges_ignore_callers_outside_the_candidates(self) -> None:
        head = shape_function("def head():\n    return 1\n")
        tail = shape_function("def tail():\n    return 2\n")
        outside = shape_function("def outside():\n    return 3\n")
        candidates = (head, tail, outside)
        data = ShapeInput(
            candidates, {}, (), candidates, (),
            {
                "tail": (
                    CallSite(
                        "tail", "head.tail", "pkg/other.py", 1, head.identity
                    ),
                ),
                "outside": (
                    CallSite(
                        "outside", "x.outside", "pkg/other.py", 2, "elsewhere"
                    ),
                ),
            },
            frozenset(), SHAPE_SPEC, 6,
        )
        successors, heads = _chain_edges(
            data, {item.identity: item for item in candidates}
        )
        self.assertEqual(successors, {head.identity: [tail.identity]})
        self.assertEqual(heads, [head.identity, outside.identity])

    def test_normalised_tokens_drop_the_docstring_and_normalise_values(
        self,
    ) -> None:
        node = function_node(
            'def f(value):\n    """Doc."""\n    return value + 1\n'
        )
        self.assertEqual(
            _normalised_tokens(node), ("return", "ID", "+", "N")
        )

    def test_token_text_keeps_keywords_and_normalises_values(self) -> None:
        tokens = tokenize.generate_tokens(
            io.StringIO('if value: 1\n"text"\n').readline
        )
        rendered = [
            _token_text(token) for token in tokens
            if token.type in (
                tokenize.NAME, tokenize.NUMBER, tokenize.STRING
            )
        ]
        self.assertEqual(rendered, ["if", "ID", "N", "S"])

    def test_longest_common_run_finds_a_discontiguous_run(self) -> None:
        self.assertEqual(
            _longest_common_run(("a", "b", "c", "d"), ("x", "b", "c", "y")),
            2,
        )
        self.assertEqual(_longest_common_run(("a", "b"), ("c", "d")), 0)

    def test_clone_pairs_follow_source_order(self) -> None:
        functions: list[ShapeFunction] = []
        _collect_definitions(
            ast.parse(
                "\n" * 99 + "def late():\n    return 1\n"
            ).body,
            "", "pkg/a.py", functions,
        )
        _collect_definitions(
            ast.parse(
                "def early():\n    return 2\n"
            ).body,
            "", "pkg/z.py", functions,
        )
        tokens = {function.identity: ("ID", "ID") for function in functions}
        self.assertEqual(
            _clone_pairs(tuple(reversed(functions)), tokens, 2),
            [(functions[0].identity, functions[1].identity)],
        )

    def test_clone_finding_skips_an_empty_shorter_body(self) -> None:
        first = shape_function("def first():\n    return 1\n")
        second = shape_function("def second():\n    return 2\n")
        data = ShapeInput(
            (first, second), {}, (), (first, second), (), {},
            frozenset(), SHAPE_SPEC, 6,
        )
        tokens = {first.identity: ("ID",), second.identity: ()}
        self.assertIsNone(_clone_finding(data, first, second, tokens))

    def test_uncalled_findings_need_no_call_or_test(self) -> None:
        recursive = shape_function(
            "def recursive():\n    return recursive()\n"
        )
        named = shape_function("def named():\n    return 1\n")
        tested = shape_function("def tested():\n    return 2\n")
        lonely = shape_function("def lonely():\n    return 3\n")
        data = ShapeInput(
            (recursive, named, tested, lonely), {}, (),
            (recursive, named, tested, lonely), (lonely,),
            {
                "recursive": (
                    CallSite(
                        "recursive", "recursive", "pkg/app.py", 2,
                        recursive.identity,
                    ),
                ),
                "named": (
                    CallSite("named", "named", "pkg/other.py", 1, "entry"),
                ),
            },
            frozenset({"tested"}), SHAPE_SPEC, 6,
        )
        findings = _uncalled_findings(data)
        self.assertEqual(
            [item.measurement["name"] for item in findings],
            ["recursive", "lonely"],
        )
        self.assertEqual(findings[0].value, 1)

    def test_findings_are_in_subject_order(self) -> None:
        before = SimpleNamespace(subject="b")
        after = SimpleNamespace(subject="a")
        rules = (lambda data: [before], lambda data: [after])
        with mock.patch("quality_gate.python_shape.RULES", rules):
            self.assertEqual(_findings(None), [after, before])


class HelperInputTests(ShapeCase):
    """Direct tests of the adapter's git-backed steps."""

    def test_diff_lines_reports_untracked_files_whole(self) -> None:
        self.base_commit({"pkg/app.py": "VALUE = 0\n"})
        self.add_file("pkg/app.py", "VALUE = 2\n")
        self.add_file("pkg/new.py", "VALUE = 1\n")
        diff = _diff_lines(self.repo, "HEAD")
        self.assertEqual(
            diff.paths, frozenset({"pkg/app.py", "pkg/new.py"})
        )
        self.assertEqual(diff.added, {"pkg/app.py": frozenset({1})})
        self.assertEqual(diff.whole, frozenset({"pkg/new.py"}))

    def test_before_complexities_reads_the_base_tree(self) -> None:
        self.base_commit({"pkg/app.py": COMPLEX_BASE})
        before = _before_complexities(
            self.repo, "HEAD", ["pkg/app.py", "pkg/new.py"]
        )
        self.assertEqual(before["pkg/app.py"], {"pkg/app.py:process": 7})
        self.assertEqual(before["pkg/new.py"], {})

    def test_base_complexities_reduces_the_definitions(self) -> None:
        function = shape_function("def f():\n    return 1\n", cc=7)
        self.assertEqual(
            _base_complexities({"pkg/app.py": {function.identity: function}}),
            {"pkg/app.py": {function.identity: 7}},
        )

    def test_tree_selection_reads_every_and_added_function(self) -> None:
        index = _file_index(
            "pkg/app.py",
            "def first():\n    return 1\n\n\ndef second():\n    return 2\n",
        )
        diff = Diff(
            frozenset({"pkg/app.py"}),
            {"pkg/app.py": frozenset({1})},
            frozenset(),
        )
        functions, added = _tree_selection({"pkg/app.py": index}, diff)
        self.assertEqual(
            [function.name for function in functions], ["first", "second"]
        )
        self.assertEqual([function.name for function in added], ["first"])

    def test_added_functions_need_a_new_qualified_name(self) -> None:
        first = shape_function("def first():\n    return 1\n")
        second = shape_function("def second():\n    return 2\n")
        added = _added_functions(
            (first, second), {"pkg/app.py": {first.identity: first}}
        )
        self.assertEqual([function.name for function in added], ["second"])

    def test_scan_files_reads_selected_and_recognized_python(self) -> None:
        self.add_file("pkg/app.py", "VALUE = 0\n")
        self.add_file(
            "pkg/helper", "#!/usr/bin/env python3\nprint(render_json())\n"
        )
        self.add_file("pkg/shell", "#!/bin/sh\nrender_json()\n")
        self.add_file("pkg/command", "render_json()\n")
        context = SimpleNamespace(
            root=self.repo,
            files=["pkg/app.py"],
            inventory_files=["pkg/app.py", "pkg/helper", "pkg/shell", "pkg/command"],
        )
        indexes = _scan_files(context, context.files, {"pkg/app.py", "pkg/command"})
        self.assertEqual(set(indexes), {"pkg/helper", "pkg/command"})

    def shape_context(self, paths: list[str]) -> SimpleNamespace:
        config = policy.load_config(self.repo)
        return SimpleNamespace(
            root=self.repo, config=config, check=config.checks["shape"],
            files=paths, inventory_files=paths, classes=dict.fromkeys(paths, "python"),
        )

    def test_orphan_shape_input_reuses_each_revision_index(self) -> None:
        path = "pkg/app.py"
        other = "pkg/other.py"
        first = "def first():\n    return 1\n\n"
        before = first + "first()\n"
        after = first + "def second():\n    return 2\n\nsecond()\n"
        other_source = "def untouched():\n    return 3\n"
        self.base_commit({path: before, other: other_source})
        self.add_file(path, after)
        context = self.shape_context([path, path, other, other])
        base = DiffBase(self.git("rev-parse", "HEAD").stdout.strip(), "base")
        with mock.patch.object(python_shape, "_parse_tree", wraps=python_shape._parse_tree) as parse:
            data = _shape_input(context, SHAPE_SPEC, 6, base)
        self.assertCountEqual(
            parse.call_args_list, [
                mock.call(path, before), mock.call(path, after), mock.call(other, other_source),
            ],
        )
        self.assertEqual(
            [function.name for function in data.added], ["second"]
        )
        self.assertEqual(
            [function.name for function in data.candidates], ["second"]
        )
        self.assertEqual([function.name for function in data.functions], ["second"])
        self.assertEqual([function.name for function in data.orphans], ["first"])
        self.assertEqual(set(data.calls), {"second"})
        self.assertEqual(data.tests, frozenset())

    def test_orphan_invalid_deleted_base_source_names_the_path(self) -> None:
        path = "pkg/broken.py"
        self.base_commit({path: "def invalid(\n"})
        self.git("rm", "--", path)
        base = DiffBase(self.git("rev-parse", "HEAD").stdout.strip(), "base")
        with self.assertRaisesRegex(policy.GateError, r"cannot parse pkg/broken\.py"):
            _shape_input(self.shape_context([]), SHAPE_SPEC, 6, base)

    def test_orphan_deleted_base_source_exhausts_index_recursion(self) -> None:
        path = "pkg/deep.py"
        source = "+".join(["0"] * 1500) + "\n"
        self.assertIsInstance(ast.parse(source), ast.Module)
        self.base_commit({path: source})
        self.git("rm", "--", path)
        base = DiffBase(self.git("rev-parse", "HEAD").stdout.strip(), "base")
        with self.assertRaisesRegex(policy.GateError, r"pkg/deep\.py.*recursion"):
            _shape_input(self.shape_context([]), SHAPE_SPEC, 6, base)

    def test_orphan_definition_comparison_recursion_names_the_path(self) -> None:
        path = "pkg/app.py"
        self.base_commit({path: "def first():\n    return 1\n\nfirst()\n"})
        self.add_file(path, "def first():\n    return 2\n")
        base = DiffBase(self.git("rev-parse", "HEAD").stdout.strip(), "base")
        with mock.patch.object(ast, "dump", side_effect=RecursionError("definition recursion")):
            with self.assertRaisesRegex(policy.GateError, r"pkg/app\.py.*recursion"):
                _shape_input(self.shape_context([path]), SHAPE_SPEC, 6, base)

    def test_orphan_base_blob_classification_uses_the_bounded_shebang(self) -> None:
        prefix = b"#!/usr/bin/env "
        self.assertTrue(is_python_blob("pkg/legacy", prefix + b"python3\n"))
        self.assertFalse(is_python_blob("pkg/legacy", prefix + b" " * SHEBANG_LIMIT + b"python3\n"))
        self.assertTrue(is_python_blob("pkg/legacy.py", b""))

    def test_orphan_base_index_classifies_regular_blobs(self) -> None:
        self.write_config(shape_config(extra=(
            '\n[[rule]]\npattern = "pkg/policy"\nclass = "python"\nreason = "suffixless Python"\n'
        )))
        (self.repo / "pkg").mkdir()
        (self.repo / "pkg/link.py").symlink_to("policy")
        self.base_commit({
            "pkg/policy": "policy_call()\n",
            "pkg/legacy": "#!/usr/bin/env python3\nlegacy_call()\n",
            "pkg/shell": '#!/bin/sh\ncase "$1" in\nesac\n',
        })
        sources = python_shape._BaseSources(self.repo, "HEAD")
        rules = policy.load_config(self.repo).rules
        for path, name in (("pkg/policy", "policy_call"), ("pkg/legacy", "legacy_call")):
            with self.subTest(path=path):
                index = sources.python_index(path, rules, {"python"})
                self.assertIsNotNone(index)
                self.assertEqual([site.name for site in index.calls], [name])
        for path in ("pkg/shell", "pkg/link.py", "pkg/missing.py"):
            with self.subTest(path=path):
                self.assertIsNone(sources.python_index(path, rules, {"python"}))


SHIPPED_POLICY = (GATE / "quality-gate.toml").read_text(encoding="utf-8")
SHIPPED_FIXTURE_MODULES = """\
[modules.gate]
files = ["qg.py", "quality_gate/mod.py", "quality_gate/elisp/helper.el"]
entry_points = ["quality_gate/elisp/helper.el"]
allowed_dependencies = []

[modules.tests]
files = ["tests/test_mod.py", "tests/elisp/qg-elisp-tests.el"]
entry_points = []
allowed_dependencies = ["gate"]

"""

SHIPPED_FILES = {
    "qg.py": "VALUE = 1\n",
    "quality_gate/mod.py": "def build(value):\n    return value\n",
    "quality_gate/elisp/helper.el": "(defun helper ()\n  nil)\n(provide 'helper)\n",
    "tests/test_mod.py": (
        "import unittest\n"
        "\n"
        "\n"
        "class ModTests(unittest.TestCase):\n"
        "    def test_nothing(self):\n"
        "        self.assertTrue(True)\n"
    ),
    "tests/elisp/qg-elisp-tests.el": "(require 'ert)\n(require 'helper)\n",
    "quality-gate-crap.toml": baseline_text(
        [], check="crap", metric_version="python-lines/1"
    ),
    "quality-gate-verification.toml": baseline_text(
        [], check="verification", metric_version="verification/1"
    ),
    "Makefile": "check:\n\tpython3 -I qg.py check\n",
    ".github/workflows/check.yml": "name: check\n\non: push\n",
    "README.md": "# fixture\n",
    "LICENSE": "AGPL-3.0\n",
    ".gitignore": "__pycache__/\n",
}
SHIPPED_WRAPPER = """\
def build(value):
    return render(value)


def render(value):
    return _format(value, 2)


def _format(value, indented):
    return value
"""


class ShippedPolicyTests(FixtureCase):
    """The gate's own policy judges one change, named by its caller."""

    def setUp(self) -> None:
        super().setUp()
        start = SHIPPED_POLICY.index("[modules.core]")
        end = SHIPPED_POLICY.index("[checks.module-contracts]", start)
        self.write_config(SHIPPED_POLICY[:start] + SHIPPED_FIXTURE_MODULES + SHIPPED_POLICY[end:])
        (self.repo / "a.py").unlink()
        for relative, content in SHIPPED_FILES.items():
            self.add_file(relative, content)
        self.commit_all("base")

    def run_shipped_shape(
        self, env: dict[str, str] | None = None
    ) -> tuple[Any, dict[str, Any], dict[str, Any]]:
        result = self.run_qg_process(
            "check", "--json", "--only", "shape", env=env
        )
        document = self.parse_json(result)
        contract = self.check_by_id(document, "module-contracts")
        self.assertEqual(contract["outcome"], "pass", output(result))
        self.assertIsNotNone(contract["budget_seconds"])
        return result, document, self.check_by_id(document, "shape")

    def add_wrapper(self) -> str:
        self.add_file("quality_gate/mod.py", SHIPPED_WRAPPER)
        self.commit_all("add the wrapper")
        return self.git("rev-parse", "HEAD^").stdout.strip()

    def test_the_shipped_policy_fails_an_untested_wrapper_from_its_base(self) -> None:
        base = self.add_wrapper()
        result, _document, check = self.run_shipped_shape(
            env={"QG_DIFF_BASE": base}
        )
        self.assertEqual(result.returncode, 1, output(result))
        subjects = [item["subject"] for item in check["findings"]]
        self.assertEqual(len(subjects), 1, subjects)
        self.assertTrue(subjects[0].startswith("PTW-SU quality_gate/mod.py:render "), subjects)
        self.assertEqual(check["measurement"]["base"], {"commit": base, "source": "QG_DIFF_BASE"})

    def test_a_clean_tree_passes_without_the_variable(self) -> None:
        self.add_wrapper()
        result, _document, check = self.run_shipped_shape()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(check["outcome"], "pass")
        self.assertEqual(check["findings"], [])


MUTATIONS = {
    "CPF payoff": ("before is not None and before > data.limit >= function.cc", "False"),
    "PTW-SU rule": (
        "            _single_call_site(data, function) is not None",
        "            False",
    ),
    "SCC depth": ("if depth > data.spec.max_chain", "if False"),
    "LTC rule": (
        "    if (\n"
        "        not data.spec.clone_min_tokens <= run <= CLONE_MAX_TOKENS\n"
        "        or ratio < data.spec.clone_similarity\n"
        "    ):",
        "    if True:",
    ),
    "PTW-SU every parameter forwarded": (
        "forwarding = sorted(named) != sorted(own)",
        "forwarding = False",
    ),
    "PTW-SU zero parameters": (
        "if not named or forwarding or plain:",
        "if forwarding or plain:",
    ),
    "PTW-SU callee is a parameter": (
        "if values is None or callee is None or callee in own:",
        "if values is None or callee is None:",
    ),
    "PTW-SU one statement": (
        "if len(statements) != 1:",
        "if False:",
    ),
    "LTC similarity": (
        "or ratio < data.spec.clone_similarity",
        "or False",
    ),
    "LTC token cap": (
        "data.spec.clone_min_tokens <= run <= CLONE_MAX_TOKENS",
        "data.spec.clone_min_tokens <= run",
    ),
    "LTC ancestor": (
        "        second.name.startswith(first.name + \".\")\n"
        "        or first.name.startswith(second.name + \".\")",
        "        False",
    ),
    "changed scope judges the added": (
        "    return functions, added, added",
        "    return functions, added, functions",
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

    def assert_guard_keeps_its_fixture_passing(self, guard: str) -> None:
        """The fixture passes, and fails once the guard that holds it is gone."""
        result = self.run_copy(self.gate)
        self.assertEqual(result.returncode, 0, output(result))
        mutated = self.run_copy(self.mutated_gate(guard))
        self.assertEqual(mutated.returncode, 1, output(mutated))

    def test_cpf_needs_its_payoff(self) -> None:
        self.base_commit({"pkg/app.py": COMPLEX_BASE})
        self.commit({"pkg/app.py": CPF_FRAGMENT})
        self.assert_rule_dies_without_its_condition("CPF payoff")

    def test_ptw_su_needs_its_rule(self) -> None:
        self.base_commit({"pkg/app.py": PTW_BASE})
        self.commit({
            "pkg/app.py": PTW_WRAPPED,
            "tests/test_app.py": self.names_test("main"),
        })
        self.assert_rule_dies_without_its_condition("PTW-SU rule")

    def test_scc_needs_its_depth_limit(self) -> None:
        self.base_commit({"pkg/chain.py": "VALUE = 0\n"})
        self.commit({"pkg/chain.py": chain_module(6)})
        self.assert_rule_dies_without_its_condition("SCC depth")

    def test_ltc_needs_its_rule(self) -> None:
        self.base_commit({"pkg/app.py": "VALUE = 0\n"})
        self.commit({"pkg/app.py": LTC_DUPLICATE})
        self.assert_rule_dies_without_its_condition("LTC rule")

    def test_ptw_su_needs_every_parameter_forwarded(self) -> None:
        self.base_commit({"pkg/app.py": PTW_BASE})
        self.commit({
            "pkg/app.py": PTW_UNFORWARDED,
            "tests/test_app.py": self.names_test("main"),
        })
        self.assert_guard_keeps_its_fixture_passing(
            "PTW-SU every parameter forwarded"
        )

    def test_ptw_su_needs_a_forwarded_parameter(self) -> None:
        self.base_commit({"pkg/app.py": PTW_BASE})
        self.commit({"pkg/app.py": PTW_ZERO_PARAMETER})
        self.assert_guard_keeps_its_fixture_passing("PTW-SU zero parameters")

    def test_ptw_su_needs_the_callee_not_to_be_a_parameter(self) -> None:
        self.base_commit({"pkg/app.py": PTW_BASE})
        self.commit({"pkg/app.py": PTW_PARAMETER_CALLEE})
        self.assert_guard_keeps_its_fixture_passing(
            "PTW-SU callee is a parameter"
        )

    def test_ptw_su_needs_a_one_statement_body(self) -> None:
        self.base_commit({"pkg/app.py": PTW_BASE})
        self.commit({
            "pkg/app.py": PTW_MORE_THAN_ONE_STATEMENT,
            "tests/test_app.py": self.names_test("main"),
        })
        self.assert_guard_keeps_its_fixture_passing("PTW-SU one statement")

    def test_ltc_needs_its_similarity_bound(self) -> None:
        self.base_commit({"pkg/app.py": "VALUE = 0\n"})
        self.commit({"pkg/app.py": LTC_NEAR_MISS})
        self.assert_guard_keeps_its_fixture_passing("LTC similarity")

    def test_ltc_needs_its_token_cap(self) -> None:
        self.base_commit({"pkg/app.py": "VALUE = 0\n"})
        self.commit({"pkg/app.py": LTC_ABOVE_CAP})
        self.assert_guard_keeps_its_fixture_passing("LTC token cap")

    def test_ltc_needs_its_ancestor_exclusion(self) -> None:
        self.base_commit({"pkg/app.py": "VALUE = 0\n"})
        self.commit({"pkg/app.py": LTC_ANCESTOR})
        self.assert_guard_keeps_its_fixture_passing("LTC ancestor")

    def test_changed_scope_needs_to_judge_only_the_added(self) -> None:
        base = chain_module(6)
        self.base_commit({"pkg/chain.py": base})
        self.commit({"pkg/chain.py": base.replace(
            "first = value + 1", "first = value + 2"
        ).replace("total = value * 2", "total = value * 3")})
        self.assert_guard_keeps_its_fixture_passing(
            "changed scope judges the added"
        )


if __name__ == "__main__":
    unittest.main()
